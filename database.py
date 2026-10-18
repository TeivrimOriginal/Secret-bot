"""Хранилище: SQLite со ссылками, группами, passkey и обёрнутыми ключами.

Один файл БД (DB_PATH), пять таблиц:

    links      token -> file_id зашифрованного файла в Telegram + имя
    groups     чат, куда добавлен бот, и его кодовое слово
    passkeys   публичные ключи входа по отпечатку (приватный — на устройстве)
    challenges одноразовые challenge WebAuthn
    vault      копия кодового слова, обёрнутая мастер-ключом сервера
    settings   мастер-ключ и прочая служебная настройка

Слой намеренно двухуровневый:

    _имя — обычная функция, работает с sqlite3 напрямую. Её зовут тесты,
           демо-сервер и самопроверка, где цикла asyncio нет;
    имя   — await-обёртка того же через asyncio.to_thread. Её зовут хендлеры
           бота и сайт: держать GIL на записи в базу во время ответа
           Telegram не нужно.

sqlite3 сам по себе не асинхронный и блокирует поток, поэтому «просто
сделать await db.execute(...)» здесь нельзя — отсюда to_thread.
"""

import asyncio
import os
import sqlite3
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import DB_PATH, PW_CHALLENGE_TTL, PW_GRANT_TTL
from crypto import b64u

# Соединение открывается один раз на весь процесс и работает из нескольких
# потоков (бот, сайт, тесты), поэтому check_same_thread=False плюс общий
# лок на записи: пишем всегда под ним, читаем — тоже под ним, чтобы не
# поймать «database is locked».
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db_lock = threading.Lock()

with _db_lock:
    _db.execute(
        "CREATE TABLE IF NOT EXISTS links ("
        "token TEXT PRIMARY KEY, file_id TEXT NOT NULL, "
        "file_name TEXT NOT NULL, created REAL NOT NULL)"
    )
    _db.execute(
        "CREATE TABLE IF NOT EXISTS groups ("
        "chat_id INTEGER PRIMARY KEY, title TEXT NOT NULL, codeword TEXT)"
    )
    _db.execute(
        "CREATE TABLE IF NOT EXISTS passkeys ("
        "cred_id TEXT PRIMARY KEY, token TEXT NOT NULL, "
        "public_key BLOB NOT NULL, alg TEXT NOT NULL, "
        "counter INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL)"
    )
    _db.execute("CREATE INDEX IF NOT EXISTS passkeys_by_token ON passkeys(token)")
    _db.execute(
        "CREATE TABLE IF NOT EXISTS challenges ("
        "challenge TEXT PRIMARY KEY, token TEXT NOT NULL, "
        "kind TEXT NOT NULL, created REAL NOT NULL)"
    )
    _db.execute(
        "CREATE TABLE IF NOT EXISTS vault ("
        "token TEXT PRIMARY KEY, wrap BLOB NOT NULL, created REAL NOT NULL)"
    )
    _db.execute(
        "CREATE TABLE IF NOT EXISTS settings ("
        "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    _db.commit()


# --------------------------- Ссылки на файлы ---------------------------------

def _db_add(token: str, file_id: str, file_name: str) -> None:
    with _db_lock:
        _db.execute(
            "INSERT INTO links (token, file_id, file_name, created) VALUES (?, ?, ?, ?)",
            (token, file_id, file_name, time.time()),
        )
        _db.commit()


def _db_get(token: str) -> tuple[str, str] | None:
    with _db_lock:
        row = _db.execute(
            "SELECT file_id, file_name FROM links WHERE token = ?", (token,)
        ).fetchone()
    return (row[0], row[1]) if row else None


async def add_link(token: str, file_id: str, file_name: str) -> None:
    """Запоминает ссылку: token -> file_id зашифрованного файла в Telegram."""
    await asyncio.to_thread(_db_add, token, file_id, file_name)


# Имя, которое зовёт groups.py: одинаковый глагол в императиве читается
# там естественнее, чем add_link среди группы_* и codeword_*.
db_add_link = add_link


async def get_link(token: str) -> tuple[str, str] | None:
    """Возвращает (file_id, file_name) или None, если ссылки нет."""
    return await asyncio.to_thread(_db_get, token)


# ------------------------------- Группы --------------------------------------

def _group_upsert(chat_id: int, title: str) -> None:
    with _db_lock:
        _db.execute(
            "INSERT INTO groups (chat_id, title) VALUES (?, ?) "
            "ON CONFLICT(chat_id) DO UPDATE SET title = excluded.title",
            (chat_id, title),
        )
        _db.commit()


def _group_remove(chat_id: int) -> None:
    with _db_lock:
        _db.execute("DELETE FROM groups WHERE chat_id = ?", (chat_id,))
        _db.commit()


def _group_list() -> list[tuple[int, str]]:
    with _db_lock:
        rows = _db.execute("SELECT chat_id, title FROM groups").fetchall()
    return [(r[0], r[1]) for r in rows]


def _codeword_set(chat_id: int, codeword: str) -> None:
    with _db_lock:
        _db.execute("UPDATE groups SET codeword = ? WHERE chat_id = ?", (codeword, chat_id))
        _db.commit()


def _codeword_get(chat_id: int) -> str | None:
    with _db_lock:
        row = _db.execute(
            "SELECT codeword FROM groups WHERE chat_id = ?", (chat_id,)
        ).fetchone()
    return row[0] if row and row[0] else None


async def group_upsert(chat_id: int, title: str) -> None:
    """Запоминает группу, куда добавлен бот (или обновляет её название)."""
    await asyncio.to_thread(_group_upsert, chat_id, title)


async def group_remove(chat_id: int) -> None:
    """Забывает группу, из которой бота убрали."""
    await asyncio.to_thread(_group_remove, chat_id)


async def group_list() -> list[tuple[int, str]]:
    """Список (chat_id, title) всех известных групп."""
    return await asyncio.to_thread(_group_list)


async def codeword_set(chat_id: int, codeword: str) -> None:
    await asyncio.to_thread(_codeword_set, chat_id, codeword)


async def codeword_get(chat_id: int) -> str | None:
    """Кодовое слово группы; None — если оно ещё не задано."""
    return await asyncio.to_thread(_codeword_get, chat_id)


# ---------------------------- Мастер-ключ ------------------------------------

_MASTER_KEY: bytes | None = None


def _master_key() -> bytes:
    """32-байтный ключ сервера: шифрует копии кодовых слов и подписывает куки."""
    global _MASTER_KEY
    with _db_lock:
        row = _db.execute("SELECT value FROM settings WHERE key = 'master_key'").fetchone()
        if row is None:
            key = os.urandom(32)
            _db.execute("INSERT INTO settings (key, value) VALUES ('master_key', ?)", (key.hex(),))
            _db.commit()
        else:
            key = bytes.fromhex(row[0])
    _MASTER_KEY = key
    return key


async def master_key() -> bytes:
    """await-обёртка _master_key(). Перед стартом сервера ключ надо создать."""
    return await asyncio.to_thread(_master_key)


# Имя без подчёркивания для тех, кому мастер-ключ нужен СИНХРОННО и без
# цикла asyncio (подпись кук внутри passkey, тесты).
master_key_sync = _master_key


# ------------------------------- Passkey -------------------------------------

def _pw_add(token: str, cred_id: str, public_key: bytes, alg: str, counter: int) -> None:
    with _db_lock:
        _db.execute(
            "INSERT INTO passkeys (cred_id, token, public_key, alg, counter, created) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cred_id) DO UPDATE SET public_key = excluded.public_key, "
            "alg = excluded.alg, counter = excluded.counter",
            (cred_id, token, public_key, alg, counter, time.time()),
        )
        _db.commit()


def _pw_list(token: str) -> list[str]:
    with _db_lock:
        rows = _db.execute("SELECT cred_id FROM passkeys WHERE token = ?", (token,)).fetchall()
    return [r[0] for r in rows]


def _pw_get(cred_id: str) -> tuple[str, bytes, int] | None:
    """Возвращает (token, public_key, counter) по идентификатору ключа."""
    with _db_lock:
        row = _db.execute(
            "SELECT token, public_key, counter FROM passkeys WHERE cred_id = ?", (cred_id,)
        ).fetchone()
    return (row[0], row[1], row[2]) if row else None


def _pw_bump(cred_id: str, counter: int) -> None:
    with _db_lock:
        _db.execute("UPDATE passkeys SET counter = ? WHERE cred_id = ?", (counter, cred_id))
        _db.commit()


def _challenge_new(token: str, kind: str) -> str:
    """Создаёт одноразовый challenge (base64url) и чистит протухшие."""
    challenge = b64u(os.urandom(32))
    now = time.time()
    with _db_lock:
        _db.execute("DELETE FROM challenges WHERE created < ?", (now - PW_CHALLENGE_TTL,))
        _db.execute(
            "INSERT INTO challenges (challenge, token, kind, created) VALUES (?, ?, ?, ?)",
            (challenge, token, kind, now),
        )
        _db.commit()
    return challenge


def _challenge_take(token: str, kind: str, challenge: str) -> bool:
    """Гасит challenge: подходит только один раз и только для своей ссылки."""
    if not challenge:
        return False
    now = time.time()
    with _db_lock:
        row = _db.execute(
            "SELECT 1 FROM challenges WHERE challenge = ? AND token = ? AND kind = ? "
            "AND created >= ?",
            (challenge, token, kind, now - PW_CHALLENGE_TTL),
        ).fetchone()
        if row:
            _db.execute("DELETE FROM challenges WHERE challenge = ?", (challenge,))
            _db.commit()
    return bool(row)


async def passkey_add(token: str, cred_id: str, public_key: bytes, alg: str,
                      counter: int) -> None:
    await asyncio.to_thread(_pw_add, token, cred_id, public_key, alg, counter)


async def passkey_list(token: str) -> list[str]:
    """Идентификаторы ключей, созданных для ссылки."""
    return await asyncio.to_thread(_pw_list, token)


async def passkey_get(cred_id: str) -> tuple[str, bytes, int] | None:
    return await asyncio.to_thread(_pw_get, cred_id)


async def passkey_bump(cred_id: str, counter: int) -> None:
    await asyncio.to_thread(_pw_bump, cred_id, counter)


async def challenge_new(token: str, kind: str) -> str:
    return await asyncio.to_thread(_challenge_new, token, kind)


async def challenge_take(token: str, kind: str, challenge: str) -> bool:
    return await asyncio.to_thread(_challenge_take, token, kind, challenge)


# ------------------------- Обёрнутые кодовые слова ---------------------------

def _vault_put(token: str, wrap: bytes) -> None:
    with _db_lock:
        _db.execute(
            "INSERT INTO vault (token, wrap, created) VALUES (?, ?, ?) "
            "ON CONFLICT(token) DO UPDATE SET wrap = excluded.wrap, created = excluded.created",
            (token, wrap, time.time()),
        )
        _db.commit()


def _vault_get(token: str) -> bytes | None:
    with _db_lock:
        row = _db.execute("SELECT wrap FROM vault WHERE token = ?", (token,)).fetchone()
    return bytes(row[0]) if row else None


# token -> (обёрнутая копия кодового слова, срок годности)
_pending_vault: dict[str, tuple[bytes, float]] = {}


def _pending_set(token: str, password: str) -> None:
    """После верного кодового слова держим обёрнутую копию в памяти.

    Сохранится в базу только если человек создаст passkey — так база не
    хранит пароли от ссылок, которыми пользуются обычным способом.
    """
    now = time.time()
    for key in [k for k, (_, exp) in _pending_vault.items() if exp < now]:
        _pending_vault.pop(key, None)
    # AESGCM.encrypt возвращает только шифртекст+тег — nonce кладём сами
    nonce = os.urandom(12)
    wrap = nonce + AESGCM(_master_key()).encrypt(nonce, password.encode("utf-8"), None)
    _pending_vault[token] = (wrap, now + PW_GRANT_TTL)


def _pending_promote(token: str) -> bool:
    """Переносит отложенную копию в базу — вызывается при создании passkey."""
    entry = _pending_vault.pop(token, None)
    if not entry:
        return False
    _vault_put(token, entry[0])
    return True


def _vault_password(wrap: bytes) -> str:
    """Раскрывает сохранённую копию кодового слова ключом сервера."""
    return AESGCM(_master_key()).decrypt(wrap[:12], wrap[12:], None).decode("utf-8")


async def vault_get(token: str) -> bytes | None:
    return await asyncio.to_thread(_vault_get, token)


async def pending_set(token: str, password: str) -> None:
    await asyncio.to_thread(_pending_set, token, password)


async def pending_promote(token: str) -> bool:
    return await asyncio.to_thread(_pending_promote, token)


async def vault_password(wrap: bytes) -> str:
    return await asyncio.to_thread(_vault_password, wrap)


# Итоговая сводка для отладки: сколько чего в базе.
def stats() -> dict[str, Any]:
    """Счётчики по таблицам. Для /healthz и ручной проверки, не для сайта."""
    tables = ("links", "groups", "passkeys", "vault")
    with _db_lock:
        return {t: _db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}

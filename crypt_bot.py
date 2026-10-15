"""
Telegram-бот для шифрования и расшифровки файлов по паролю.

ЛИЧНЫЙ ЧАТ (как раньше):
    файл -> бот определяет режим по маркеру CRYPTv1\\0 -> пароль -> результат.

ГРУППА (бот — администратор с правом удаления сообщений):
    0. Админ группы заранее пишет боту в личку /setcode, выбирает группу
       и вводит кодовое слово этой группы (хранится в SQLite).
    1. Участник присылает НЕзашифрованный документ.
    2. Бот читает файл, удаляет оригинал, шифрует его кодовым словом группы,
       присылает в группу зашифрованный .enc и ссылку.
    3. Человек открывает ссылку, вводит кодовое слово — бот берёт
       зашифрованный файл из Telegram по file_id, расшифровывает
       и отдаёт на скачивание прямо со страницы.
    Уже зашифрованные файлы (с маркером) в группе бот не трогает.

Формат зашифрованного файла:
    [8 байт "CRYPTv1\\0"][16 байт соли][12 байт nonce][шифртекст + тег GCM]

PASSKEY (WebAuthn — отпечаток пальца, Face ID, Windows Hello):
    1. Человек открывает ссылку и один раз вводит кодовое слово — файл
       скачивается, браузеру ставится короткая «печать» (grant-кука).
    2. На странице появляется кнопка «Создать passkey»: браузер спрашивает
       биометрию/PIN и отдаёт серверу публичный ключ (аттестат не
       проверяем — у нас модель угрозы другая: доступ держит кодовое слово).
    3. В этот же момент в базу кладётся обёрнутая ключом сервера копия
       кодового слова (только для ссылок с passkey; без регистрации —
       не сохраняем, значение живёт в памяти PW_GRANT_TTL секунд).
    4. При следующем открытии кнопка «Войти по Face ID / отпечатку»:
       сервер выдаёт challenge, браузер подписывает его приватным ключом,
       мы проверяем подпись (ES256/RS256), ставим сессионную куку — и файл
       отдаётся по GET /d/<token>/get без ввода кодового слова.
    Проверки: тип clientData, одноразовость challenge, origin, rpIdHash,
    флаги UP и UV (пользователь реально подтвердил), подпись, счётчик.

ССЫЛКИ В TELEGRAM: отправляются явной разметкой <a href="...">, то есть
всегда кликабельны; в личном чате после шифрования тоже создаётся ссылка.

Настройки — переменные окружения (или константы ниже):
    BOT_TOKEN  — токен от @BotFather
    BASE_URL   — публичный адрес сайта БЕЗ слеша на конце, https://files.example.com
    WEB_HOST / WEB_PORT — где слушает встроенный веб-сервер (по умолчанию 0.0.0.0:8080)
    DB_PATH    — файл SQLite со ссылками (по умолчанию links.db)

Запуск: python crypt_bot.py
"""

import asyncio
import base64
import hashlib
import hmac
import html
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import quote, urlparse

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
# Для продакшена замените MemoryStorage на RedisStorage:
#   from aiogram.fsm.storage.redis import RedisStorage
#   storage = RedisStorage.from_url("redis://localhost:6379/0")
# MemoryStorage теряет состояния (и файлы в них) при перезапуске бота.
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    ChatMemberUpdated,
    Message,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiohttp import web
from cbor2 import CBORDecoder, loads as cbor_loads
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----------------------------- Настройки ------------------------------------

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080").rstrip("/")
# Сайт расшифровки: по умолчанию выключен (ENABLE_WEB=1 — включить).
# Ссылки в группе генерируются и сохраняются в базу независимо от этого флага.
ENABLE_WEB = os.getenv("ENABLE_WEB", "0") == "1"
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
DB_PATH = os.getenv("DB_PATH", "links.db")

# --------------------------- Passkey (WebAuthn) -----------------------------
# Вход на страницу по отпечатку пальца / Face ID вместо кодового слова.
# Порядок такой: человек один раз вводит кодовое слово -> может создать
# passkey на своём устройстве -> дальше открывает ссылку биометрией.
# Ключ от файла браузер не получает: passkey только подтверждает вход,
# а сохранённая (обёрнутая ключом сервера) копия кодового слова лежит в базе
# и используется только для ссылок, у которых passkey реально создан.
ENABLE_PASSKEY = os.getenv("ENABLE_PASSKEY", "1") == "1"
PW_GRANT_TTL = int(os.getenv("PW_GRANT_TTL", "600"))                  # окно регистрации после верного кодового слова
PW_CHALLENGE_TTL = int(os.getenv("PW_CHALLENGE_TTL", "300"))          # жизнь одноразового challenge
PW_SESSION_TTL = int(os.getenv("PW_SESSION_TTL", str(30 * 86400)))    # сколько живёт вход по passkey

# WebAuthn привязан к хосту BASE_URL: rpId — hostname, origin — адрес сайта.
_parts = urlparse(BASE_URL)
RP_ID = _parts.hostname or "localhost"
_PORT = _parts.port or (443 if _parts.scheme == "https" else 80)
ORIGIN = f"{_parts.scheme}://{RP_ID}" + (
    "" if (_parts.scheme, _PORT) in (("https", 443), ("http", 80)) else f":{_PORT}"
)

MAGIC = b"CRYPTv1\x00"          # магический маркер (8 байт)
SALT_SIZE = 16                   # размер соли
NONCE_SIZE = 12                  # размер nonce для AES-GCM
TAG_SIZE = 16                    # размер тега GCM
KDF_ITERATIONS = 600_000         # число итераций PBKDF2
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE
ENC_SUFFIX = ".enc"
MIN_CODEWORD_LEN = 8             # минимальная длина кодового слова группы

# Лимиты облачного Telegram Bot API: скачивание ботом — 20 МБ, отправка — 50 МБ.
MAX_DOWNLOAD_SIZE = 20 * 1024 * 1024
# В группе зашифрованный файл потом скачивается обратно (getFile, лимит 20 МБ),
# а он больше оригинала на HEADER_SIZE + TAG_SIZE байт — оставляем запас.
GROUP_MAX_SIZE = MAX_DOWNLOAD_SIZE - 1024

# Защита страницы от перебора кодового слова
MAX_FAILS = 5                    # неудачных попыток на ссылку...
FAIL_WINDOW = 15 * 60            # ...за это число секунд

ERR_WRONG_PASSWORD = "❌ Неверный пароль или файл повреждён"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("crypt_bot")

# Роутеры: личные чаты и группы обрабатываются раздельно
private_router = Router()
private_router.message.filter(F.chat.type == "private")
group_router = Router()
group_router.message.filter(F.chat.type.in_({"group", "supergroup"}))
# Служебные события (добавление/удаление бота в группе)
events_router = Router()

# PBKDF2 тяжёлый: ограничиваем число одновременных операций
CRYPTO_SEM = asyncio.Semaphore(2)


# ----------------------------- Состояния ------------------------------------

class CryptStates(StatesGroup):
    """Единственное состояние: ожидание пароля от пользователя."""
    waiting_for_password = State()


class SetCodeStates(StatesGroup):
    """Ожидание кодового слова группы (команда /setcode)."""
    waiting_for_codeword = State()


# ------------------------- Криптографические функции ------------------------

def is_encrypted(data: bytes) -> bool:
    """Проверяет, начинается ли файл с магического маркера CRYPTv1\\0."""
    return data[: len(MAGIC)] == MAGIC


def make_key(password: str, salt: bytes) -> bytes:
    """Выводит 32-байтный ключ из пароля через PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(data: bytes, password: str) -> bytes:
    """
    Шифрует данные AES-256-GCM.
    Возвращает: MAGIC + соль + nonce + (шифртекст + тег GCM).
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = make_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_file(data: bytes, password: str) -> bytes:
    """
    Расшифровывает данные формата CRYPTv1.
    Бросает InvalidTag при неверном пароле или повреждённых данных,
    ValueError — если файл слишком короткий или без маркера.
    """
    if not is_encrypted(data) or len(data) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("Некорректный формат зашифрованного файла")

    salt = data[len(MAGIC): len(MAGIC) + SALT_SIZE]
    nonce = data[len(MAGIC) + SALT_SIZE: HEADER_SIZE]
    ciphertext = data[HEADER_SIZE:]
    key = make_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


async def run_crypto(func, *args):
    """Запускает тяжёлую криптооперацию в потоке, не более 2 одновременно."""
    async with CRYPTO_SEM:
        return await asyncio.to_thread(func, *args)


# ------------------------------ База ссылок ---------------------------------

_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db_lock = threading.Lock()
with _db_lock:
    _db.execute(
        "CREATE TABLE IF NOT EXISTS links ("
        "token TEXT PRIMARY KEY, file_id TEXT NOT NULL, "
        "file_name TEXT NOT NULL, created REAL NOT NULL)"
    )
    _db.commit()


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


async def db_add(token: str, file_id: str, file_name: str) -> None:
    await asyncio.to_thread(_db_add, token, file_id, file_name)


async def db_get(token: str) -> tuple[str, str] | None:
    return await asyncio.to_thread(_db_get, token)


# Группы, куда добавлен бот, и кодовое слово каждой группы
with _db_lock:
    _db.execute(
        "CREATE TABLE IF NOT EXISTS groups ("
        "chat_id INTEGER PRIMARY KEY, title TEXT NOT NULL, codeword TEXT)"
    )
    _db.commit()


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


# --------------------------- База passkey -----------------------------------

# Таблицы: сами passkey, одноразовые challenge, обёрнутые копии кодовых слов
# (vault) и служебные настройки (в частности, ключ шифрования базы).
with _db_lock:
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
    challenge = _b64u(secrets.token_bytes(32))
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


def _sign(payload: str) -> str:
    return hmac.new(_master_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _grant_cookie(token: str) -> tuple[str, str]:
    """Кука «человек только что ввёл верное кодовое слово для этой ссылки»."""
    exp = int(time.time()) + PW_GRANT_TTL
    return f"pwgrant_{token}", f"{exp}|{_sign(f'grant|{token}|{exp}')}"


def _grant_valid(request: web.Request, token: str) -> bool:
    name, _expected = _grant_cookie(token)
    raw = request.cookies.get(name)
    if not raw or "|" not in raw:
        return False
    exp_s, sig = raw.split("|", 1)
    try:
        exp = int(exp_s)
    except ValueError:
        return False
    if exp <= time.time():
        return False
    # подпись считаем от exp, лежащего в куке, а не от «сейчас»:
    # иначе совпадает только если проверка попала в ту же секунду
    return hmac.compare_digest(sig, _sign(f"grant|{token}|{exp}"))


def _grant_set(response: web.Response, token: str) -> None:
    name, value = _grant_cookie(token)
    response.set_cookie(
        name, value, max_age=PW_GRANT_TTL, path=f"/d/{token}",
        httponly=True, secure=BASE_URL.startswith("https"), samesite="Lax",
    )


def _session_cookie(token: str, cred_id: str) -> tuple[str, str]:
    exp = int(time.time()) + PW_SESSION_TTL
    return f"pwsess_{token}", f"{cred_id}|{exp}|{_sign(f'sess|{token}|{cred_id}|{exp}')}"


def _session_valid(request: web.Request, token: str) -> str | None:
    """Возвращает cred_id, если стоит действительная сессия по passkey."""
    raw = request.cookies.get(f"pwsess_{token}")
    if not raw or raw.count("|") != 2:
        return None
    cred_id, exp_s, sig = raw.split("|")
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    if exp <= time.time():
        return None
    if not hmac.compare_digest(sig, _sign(f"sess|{token}|{cred_id}|{exp}")):
        return None
    return cred_id or None


def _session_set(response: web.Response, token: str, cred_id: str) -> None:
    name, value = _session_cookie(token, cred_id)
    response.set_cookie(
        name, value, max_age=PW_SESSION_TTL, path=f"/d/{token}",
        httponly=True, secure=BASE_URL.startswith("https"), samesite="Lax",
    )


# ----------------------------- Вспомогательное ------------------------------

def _result_name(file_name: str, mode: str) -> str:
    """Подбирает имя итогового файла."""
    if mode == "encrypt":
        return file_name + ENC_SUFFIX
    if file_name.lower().endswith(ENC_SUFFIX) and len(file_name) > len(ENC_SUFFIX):
        return file_name[: -len(ENC_SUFFIX)]
    return file_name + ".dec"


async def is_group_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    """Проверяет, что пользователь — создатель или администратор группы."""
    try:
        member = await bot.get_chat_member(chat_id, user_id)
    except Exception:
        return False
    return member.status in ("creator", "administrator")


async def safe_delete(bot: Bot, chat_id: int, message_id: int | None) -> bool:
    """
    Пытается удалить сообщение, возвращает True при успехе.
    Ошибки не критичны: сообщение могло быть удалено ранее, быть старше
    48 часов или у бота нет прав (в группах).
    """
    if message_id is None:
        return False
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
        return True
    except Exception:
        logger.warning("Не удалось удалить сообщение %s", message_id)
        return False


# ============================== ЛИЧНЫЙ ЧАТ ==================================

@private_router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext) -> None:
    """Краткая инструкция."""
    await state.clear()
    await message.answer(
        "🔐 Я шифрую и расшифровываю файлы по паролю.\n\n"
        "1. Отправьте мне файл (как документ).\n"
        "2. Я сам пойму, что делать: обычный файл — зашифрую "
        "(и сразу удалю оригинал из чата), зашифрованный мной — расшифрую.\n"
        "3. Напишите пароль — получите результат. "
        "Сообщение с паролем я тоже удалю.\n\n"
        "Алгоритм: AES-256-GCM + PBKDF2-SHA256.\n"
        "Лимит размера файла: 20 МБ.\n"
        "/cancel — отменить текущую операцию.\n\n"
        "👥 Группы: добавьте меня в группу администратором (право «Удаление "
        "сообщений»), затем администратор пишет мне здесь /setcode, выбирает "
        "группу и задаёт кодовое слово. После этого все файлы, присланные "
        "в группу, я шифрую этим словом и выдаю кликабельную ссылку "
        "на страницу скачивания.\n\n"
        "🔑 Passkey: открыв ссылку и введён один раз кодовое слово, можно "
        "создать passkey — дальше файл открывается по отпечатку пальца "
        "или Face ID, без ввода кодового слова."
    )


@private_router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    """Сбрасывает состояние."""
    await state.clear()
    await message.answer("Операция отменена. Отправьте новый файл.")


@private_router.message(Command("setcode"))
async def cmd_setcode(message: Message, state: FSMContext, bot: Bot) -> None:
    """Показывает группы, где пользователь админ и где есть бот."""
    await state.clear()
    mine = []
    for chat_id, title in await asyncio.to_thread(_group_list):
        if await is_group_admin(bot, chat_id, message.from_user.id):
            mine.append((chat_id, title))
    if not mine:
        await message.answer(
            "Не нашёл групп, где вы администратор, а я добавлен. "
            "Добавьте меня в группу админом (право «Удаление сообщений») "
            "и повторите /setcode."
        )
        return
    kb = InlineKeyboardBuilder()
    for chat_id, title in mine:
        kb.button(text=title[:60], callback_data=f"grp:{chat_id}")
    kb.adjust(1)
    await message.answer(
        "Для какой группы задать кодовое слово?", reply_markup=kb.as_markup()
    )


@private_router.callback_query(F.data.startswith("grp:"))
async def on_group_chosen(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    """Группа выбрана — ждём кодовое слово."""
    chat_id = int(call.data.split(":", 1)[1])
    if not await is_group_admin(bot, chat_id, call.from_user.id):
        await call.answer("Вы не администратор этой группы", show_alert=True)
        return
    title = dict(await asyncio.to_thread(_group_list)).get(chat_id)
    if title is None:
        await call.answer("Группа не найдена", show_alert=True)
        return
    await state.set_state(SetCodeStates.waiting_for_codeword)
    await state.update_data(chat_id=chat_id, title=title)
    await bot.send_message(
        call.from_user.id,
        f"Введите кодовое слово для «{html.escape(title)}» "
        f"(не короче {MIN_CODEWORD_LEN} символов). Сообщение я удалю.\n"
        "Файлы, зашифрованные раньше, останутся со старым словом.\n"
        "/cancel — отмена.",
    )
    await call.answer()


@private_router.message(
    SetCodeStates.waiting_for_codeword, F.text, ~F.text.startswith("/")
)
async def on_codeword(message: Message, state: FSMContext, bot: Bot) -> None:
    """Сохраняет кодовое слово группы."""
    codeword = message.text.strip()
    await safe_delete(bot, message.chat.id, message.message_id)

    if len(codeword) < MIN_CODEWORD_LEN:
        await message.answer(
            f"❌ Слишком короткое слово (минимум {MIN_CODEWORD_LEN} символов). "
            "Введите другое или /cancel."
        )
        return

    data = await state.get_data()
    chat_id: int = data["chat_id"]
    title: str = data["title"]
    await state.clear()

    if not await is_group_admin(bot, chat_id, message.from_user.id):
        await message.answer("❌ Вы больше не администратор этой группы.")
        return

    await asyncio.to_thread(_codeword_set, chat_id, codeword)
    await message.answer(
        f"✅ Кодовое слово для «{html.escape(title)}» сохранено. "
        "Теперь файлы, присланные в группу, будут шифроваться им."
    )


@private_router.message(F.document)
async def on_document(message: Message, state: FSMContext, bot: Bot) -> None:
    """
    Принимает документ, определяет режим по магическому маркеру
    и запрашивает пароль. Незашифрованный файл сразу удаляется из чата.
    """
    doc = message.document

    if doc.file_size and doc.file_size > MAX_DOWNLOAD_SIZE:
        await message.answer("❌ Файл слишком большой: бот может скачать не более 20 МБ.")
        return

    try:
        buffer = io.BytesIO()
        await bot.download(doc, destination=buffer)
        file_bytes = buffer.getvalue()
    except Exception:
        logger.exception("Не удалось скачать файл")
        await message.answer("❌ Не удалось скачать файл. Попробуйте ещё раз.")
        return

    # Режим определяется ТОЛЬКО по магическому маркеру, не по имени файла
    mode = "decrypt" if is_encrypted(file_bytes) else "encrypt"

    # Сразу удаляем незашифрованный файл из чата: данные уже в памяти бота.
    if mode == "encrypt":
        await safe_delete(bot, message.chat.id, message.message_id)

    await state.set_state(CryptStates.waiting_for_password)
    await state.update_data(
        file_bytes=file_bytes,
        file_name=doc.file_name or "file",
        mode=mode,
    )

    if mode == "decrypt":
        await message.answer("🔓 Файл зашифрован. Введите пароль для расшифровки:")
    else:
        await message.answer(
            "🔒 Файл получен и удалён из чата. Введите пароль для шифрования:"
        )


@private_router.message(CryptStates.waiting_for_password, F.text)
async def on_password(message: Message, state: FSMContext, bot: Bot) -> None:
    """Принимает пароль, выполняет операцию и отправляет результат."""
    password = message.text
    data = await state.get_data()
    file_bytes: bytes = data["file_bytes"]
    file_name: str = data["file_name"]
    mode: str = data["mode"]

    await safe_delete(bot, message.chat.id, message.message_id)

    try:
        token = None
        if mode == "encrypt":
            result = await run_crypto(encrypt_file, file_bytes, password)
            token = secrets.token_urlsafe(16)
            link = f"{BASE_URL}/d/{token}"
            caption = (
                "✅ Файл зашифрован.\n\n"
                f'🔗 <a href="{html.escape(link)}">{html.escape(link)}</a>\n\n'
                "Ссылка открывается прямо здесь в Telegram. Один раз введите "
                "на странице пароль — и можно создать passkey, дальше вход "
                "по Face ID / отпечатку без пароля."
            )
        else:
            result = await run_crypto(decrypt_file, file_bytes, password)
            caption = "✅ Файл расшифрован"

        sent = await message.answer_document(
            BufferedInputFile(result, filename=_result_name(file_name, mode)),
            caption=caption,
        )
        # ссылку запоминаем только для зашифрованного результата
        if token and sent.document:
            await db_add(token, sent.document.file_id, file_name)
    except InvalidTag:
        await message.answer(ERR_WRONG_PASSWORD)
    except ValueError:
        logger.warning("Некорректный формат зашифрованного файла")
        await message.answer(ERR_WRONG_PASSWORD)
    except Exception:
        logger.exception("Ошибка при обработке файла")
        await message.answer("❌ Произошла внутренняя ошибка. Попробуйте позже.")
    finally:
        await state.clear()


# ================================= ГРУППА ===================================

_warned: dict[int, float] = {}   # chat_id -> когда последний раз предупреждали


@events_router.my_chat_member()
async def on_bot_membership(event: ChatMemberUpdated) -> None:
    """Запоминает группы, куда добавили бота, и забывает те, откуда убрали."""
    if event.chat.type not in ("group", "supergroup"):
        return
    status = event.new_chat_member.status
    if status in ("member", "administrator"):
        await asyncio.to_thread(_group_upsert, event.chat.id, event.chat.title or str(event.chat.id))
    elif status in ("left", "kicked"):
        await asyncio.to_thread(_group_remove, event.chat.id)


@group_router.message(F.document)
async def on_group_document(message: Message, bot: Bot) -> None:
    """
    Файл в группе: читаем -> удаляем оригинал -> шифруем кодовым словом группы
    -> отправляем .enc со ссылкой. Уже зашифрованные файлы игнорируются.
    Если у группы нет кодового слова, файл не трогаем.
    """
    doc = message.document
    chat = message.chat
    await asyncio.to_thread(_group_upsert, chat.id, chat.title or str(chat.id))

    codeword = await asyncio.to_thread(_codeword_get, chat.id)
    if not codeword:
        # Предупреждаем не чаще раза в 10 минут, чтобы не спамить
        if time.time() - _warned.get(chat.id, 0) > 600:
            _warned[chat.id] = time.time()
            await message.answer(
                "⚠️ Для этой группы не задано кодовое слово, файлы не шифруются. "
                "Администратор: напишите мне в личку /setcode."
            )
        return

    if doc.file_size and doc.file_size > GROUP_MAX_SIZE:
        await message.answer(
            "❌ Файл слишком большой: бот может обработать не более ~20 МБ."
        )
        return

    try:
        buffer = io.BytesIO()
        await bot.download(doc, destination=buffer)
        file_bytes = buffer.getvalue()
    except Exception:
        logger.exception("Не удалось скачать файл из группы")
        await message.answer("❌ Не удалось скачать файл. Отправьте его ещё раз.")
        return

    # Зашифрованные файлы (в т.ч. наши же .enc) не трогаем
    if is_encrypted(file_bytes):
        return

    # Оригинал удаляем сразу. Если не получилось — файл НЕ обрабатываем.
    if not await safe_delete(bot, chat.id, message.message_id):
        await message.answer(
            "⚠️ Не могу удалить файл. Сделайте меня администратором "
            "с правом «Удаление сообщений». Файл не обработан."
        )
        return

    file_name = doc.file_name or "file"
    user = message.from_user
    sender = html.escape(user.full_name) if user else "участника"

    try:
        encrypted = await run_crypto(encrypt_file, file_bytes, codeword)
        token = secrets.token_urlsafe(16)
        link = f"{BASE_URL}/d/{token}"

        sent = await message.answer_document(
            BufferedInputFile(encrypted, filename=_result_name(file_name, "encrypt")),
            caption=(
                f"🔒 Файл <b>{html.escape(file_name)}</b> от {sender} зашифрован.\n\n"
                f'🔗 <a href="{html.escape(link)}">{html.escape(link)}</a>\n\n'
                "Откройте ссылку и введите кодовое слово группы, чтобы скачать "
                "файл. Один раз можно создать passkey — дальше группа открывает "
                "ссылку по Face ID / отпечатку."
            ),
        )
        # file_id именно зашифрованного файла, отправленного ботом
        if sent.document:
            await db_add(token, sent.document.file_id, file_name)
    except Exception:
        logger.exception("Ошибка при шифровании файла в группе")
        await message.answer(
            "❌ Не удалось обработать файл. Оригинал уже удалён — "
            "отправьте его ещё раз."
        )


# ============================ PASSKEY (WEBAUTHN) ============================

def _b64u(data: bytes) -> str:
    """Base64url без '=' — формат challenge/id в WebAuthn."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _rp_hash() -> bytes:
    try:
        host = RP_ID.encode("idna")
    except Exception:
        host = RP_ID.encode("ascii", "ignore")
    return hashlib.sha256(host).digest()


def _client_data_error(client_json: bytes, expected_type: str, challenge: str) -> str | None:
    """Проверяет clientDataJSON. Возвращает текст ошибки или None, если всё верно."""
    try:
        data = json.loads(client_json)
    except Exception:
        return "Некорректный clientDataJSON"
    if not isinstance(data, dict):
        return "Некорректный clientDataJSON"
    if data.get("type") != expected_type:
        return "Неверный тип операции WebAuthn"
    if not hmac.compare_digest(str(data.get("challenge", "")), challenge):
        return "Challenge не совпадает (страницу нужно открыть заново)"
    if data.get("origin") != ORIGIN:
        return f"Неверный origin: ожидается {ORIGIN}"
    if data.get("crossOrigin"):
        return "Запрещён встроенный (cross-origin) вызов"
    return None


def _parse_auth_data(auth: bytes) -> tuple[int, int, str | None, dict | None]:
    """Разбирает authenticator data: флаги, счётчик, credId и COSE-ключ."""
    if len(auth) < 37:
        raise ValueError("Слишком короткие authenticator data")
    rp_hash, flags = auth[:32], auth[32]
    counter = int.from_bytes(auth[33:37], "big")
    if not hmac.compare_digest(rp_hash, _rp_hash()):
        raise ValueError(f"rpIdHash не совпадает (ожидается {RP_ID})")
    cred_id, cose = None, None
    if flags & 0x40:  # AT — есть данные аттестованного ключа
        if len(auth) < 55:
            raise ValueError("Оборванные данные ключа")
        cred_len = int.from_bytes(auth[53:55], "big")
        end = 55 + cred_len
        if len(auth) < end:
            raise ValueError("Оборванный идентификатор ключа")
        cred_id = _b64u(auth[55:end])
        try:
            # ровно один CBOR-объект: следом может идти CBOR с расширениями
            cose = CBORDecoder(io.BytesIO(auth[end:])).decode()
        except Exception:
            raise ValueError("Не удалось разобрать публичный ключ")
    return flags, counter, cred_id, cose


def _cose_public_key(cose: object):
    """COSE-ключ (CBOR-словарь) -> публичный ключ cryptography."""
    if not isinstance(cose, dict):
        raise ValueError("Публичный ключ не словарь")
    kty = cose.get(1)
    if kty == 2:  # EC2: P-256
        if cose.get(-1) != 1:
            raise ValueError("Поддерживается только кривая P-256")
        x = int.from_bytes(cose[-2], "big")
        y = int.from_bytes(cose[-3], "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if kty == 3:  # RSA
        n = int.from_bytes(cose[-1], "big")
        e = int.from_bytes(cose[-2], "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise ValueError(f"Неподдерживаемый тип ключа: {kty}")


def _alg_name(key) -> str:
    return "ES256" if isinstance(key, ec.EllipticCurvePublicKey) else "RS256"


def webauthn_register(client_json: bytes, attestation_object: bytes, challenge: str):
    """Разбирает ответ браузера при создании passkey.

    Аттестат (attStmt) намеренно не проверяем: ключ хранится только у нас,
    а «кто имеет право создать ключ» уже решает кодовое слово.
    Возвращает (cred_id, DER-публичный ключ, алгоритм, счётчик).
    """
    err = _client_data_error(client_json, "webauthn.create", challenge)
    if err:
        raise ValueError(err)
    try:
        att = cbor_loads(attestation_object)
    except Exception:
        raise ValueError("Некорректный attestationObject")
    auth = att.get("authData") if isinstance(att, dict) else None
    if not isinstance(auth, (bytes, bytearray)):
        raise ValueError("В ответе нет authenticator data")
    flags, counter, cred_id, cose = _parse_auth_data(bytes(auth))
    if not flags & 0x01:
        raise ValueError("Аутентификатор не подтвердил присутствие пользователя")
    if not flags & 0x04:
        raise ValueError("Нужен подтверждённый вход: отпечаток, Face ID или PIN")
    if not cred_id or cose is None:
        raise ValueError("Аутентификатор не передал ключ")
    key = _cose_public_key(cose)
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return cred_id, der, _alg_name(key), counter


def webauthn_assert(
    client_json: bytes, auth_data: bytes, signature: bytes, challenge: str, public_key: bytes
) -> int:
    """Проверяет вход по passkey (assertion). Возвращает новый счётчик."""
    err = _client_data_error(client_json, "webauthn.get", challenge)
    if err:
        raise ValueError(err)
    flags, counter, _cred_id, _cose = _parse_auth_data(auth_data)
    if not flags & 0x01:
        raise ValueError("Аутентификатор не подтвердил присутствие пользователя")
    if not flags & 0x04:
        raise ValueError("Нужен подтверждённый вход: отпечаток, Face ID или PIN")
    key = serialization.load_der_public_key(public_key)
    signed = auth_data + hashlib.sha256(client_json).digest()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError("Неподдерживаемый тип ключа passkey")
    except InvalidSignature:
        raise ValueError("Подпись passkey не прошла")
    return counter


def _json_error(message: str, status: int = 400) -> web.Response:
    return web.json_response({"error": message}, status=status)


# ================================== САЙТ ====================================

PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Расшифровка файла</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,sans-serif;max-width:420px;margin:12vh auto;padding:0 16px}
h1{font-size:1.4rem}
input,button{width:100%;box-sizing:border-box;padding:12px;font-size:1rem;margin-top:10px;border-radius:8px;border:1px solid #8886}
button{background:#2a7ae4;color:#fff;border:0;cursor:pointer}
button.sec{background:#444b57}
button:disabled{opacity:.6;cursor:default}
a.btn{display:block;text-align:center;padding:12px;margin-top:10px;border-radius:8px;background:#2a7ae4;color:#fff;text-decoration:none}
.err{color:#d33;margin-top:12px}
.hint{color:#777;font-size:.85rem;margin-top:8px;min-height:1.1em}
.divider{margin-top:16px;padding-top:12px;border-top:1px solid #8886;font-size:.78rem;color:#999;text-transform:uppercase}
</style></head><body>
<h1>🔐 Расшифровка файла</h1>
<p>Файл: <b>%NAME%</b></p>
%BLOCKS%
<form method="post" action="/d/%TOKEN%" id="dl-form" autocomplete="off">
<input type="password" name="password" placeholder="Кодовое слово" autofocus>
<button type="submit">Расшифровать и скачать</button>
</form>
<div class="hint" id="pw-status"></div>
%ERROR%
<script>
const TOKEN = "%TOKEN%";
function el(id){return document.getElementById(id);}
function statusMsg(msg){const s=el('pw-status'); if(s) s.textContent = msg || '';}
function toB64(buf){let s='';const b=new Uint8Array(buf);for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
function fromB64(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const bin=atob(s);const a=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);return a;}
async function postJSON(url, payload){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload || {})});
  let data = {};
  try{ data = await r.json(); }catch(e){}
  if(!r.ok) throw new Error(data.error || ('Ошибка сервера ' + r.status));
  return data;
}
async function passkeyCreate(){
  const btn = el('pw-setup'); if(btn) btn.disabled = true;
  statusMsg('Подтвердите создание passkey на устройстве…');
  try{
    const opt = await postJSON('/d/' + TOKEN + '/pw/register/options');
    const pk = opt.publicKey;
    pk.challenge = fromB64(pk.challenge);
    pk.user.id = fromB64(pk.user.id);
    if(pk.excludeCredentials) pk.excludeCredentials = pk.excludeCredentials.map(c=>({type:c.type,id:fromB64(c.id)}));
    const cred = await navigator.credentials.create({publicKey: pk});
    await postJSON('/d/' + TOKEN + '/pw/register/verify', {
      id: toB64(cred.rawId), type: cred.type,
      clientDataJSON: toB64(cred.response.clientDataJSON),
      attestationObject: toB64(cred.response.attestationObject)
    });
    statusMsg('✅ Passkey создан — дальше вход по биометрии.');
    setTimeout(()=>location.reload(), 800);
  }catch(e){ statusMsg('❌ ' + (e && e.message ? e.message : e)); if(btn) btn.disabled = false; }
}
async function passkeyLogin(){
  const btn = el('pw-login'); if(btn) btn.disabled = true;
  statusMsg('Подтвердите вход на устройстве…');
  try{
    const opt = await postJSON('/d/' + TOKEN + '/pw/login/options');
    const pk = opt.publicKey;
    pk.challenge = fromB64(pk.challenge);
    pk.allowCredentials = (pk.allowCredentials || []).map(c=>({type:c.type,id:fromB64(c.id)}));
    const cred = await navigator.credentials.get({publicKey: pk});
    await postJSON('/d/' + TOKEN + '/pw/login/verify', {
      id: toB64(cred.rawId), type: cred.type,
      clientDataJSON: toB64(cred.response.clientDataJSON),
      authenticatorData: toB64(cred.response.authenticatorData),
      signature: toB64(cred.response.signature)
    });
    location.href = '/d/' + TOKEN + '/get';
  }catch(e){
    statusMsg('❌ ' + (e && e.name === 'NotAllowedError' ? 'Вход отменён или не подтверждён' : (e && e.message ? e.message : e)));
    if(btn) btn.disabled = false;
  }
}
if(el('pw-setup')) el('pw-setup').addEventListener('click', passkeyCreate);
if(el('pw-login')) el('pw-login').addEventListener('click', passkeyLogin);
const form = el('dl-form');
if(form) form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = form.querySelector('button'); if(btn) btn.disabled = true;
  statusMsg('Проверяем кодовое слово…');
  try{
    const r = await fetch(form.action, {method:'POST', body: new FormData(form)});
    if(!r.ok){
      let msg = 'Ошибка ' + r.status;
      try{
        const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
        const err = doc.querySelector('.err');
        if(err) msg = err.textContent;
      }catch(e){}
      throw new Error(msg);
    }
    const blob = await r.blob();
    const cd = r.headers.get('Content-Disposition') || '';
    let name = 'file';
    const m1 = cd.match(/filename\\*=UTF-8''([^;]+)/i);
    const m2 = cd.match(/filename="([^"]+)"/i);
    if(m1){ try{ name = decodeURIComponent(m1[1]); }catch(e){ name = m1[1]; } }
    else if(m2) name = m2[1];
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>{ try{ URL.revokeObjectURL(a.href); }catch(e){} }, 60000);
    statusMsg('✅ Файл скачан');
    setTimeout(()=>location.reload(), 700);
  }catch(e){ statusMsg('❌ ' + (e && e.message ? e.message : e)); if(btn) btn.disabled = false; }
});
</script>
</body></html>"""

# token -> (число неудач, время первой неудачи)
_fails: dict[str, tuple[int, float]] = {}


def _is_locked(token: str) -> bool:
    entry = _fails.get(token)
    if not entry:
        return False
    count, first = entry
    if time.time() - first > FAIL_WINDOW:
        _fails.pop(token, None)
        return False
    return count >= MAX_FAILS


def _register_fail(token: str) -> None:
    count, first = _fails.get(token, (0, time.time()))
    if time.time() - first > FAIL_WINDOW:
        count, first = 0, time.time()
    _fails[token] = (count + 1, first)


def render_page(
    name: str,
    error: str = "",
    status: int = 200,
    token: str = "",
    blocks: str = "",
) -> web.Response:
    err_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    body = (
        PAGE.replace("%NAME%", html.escape(name))
        .replace("%ERROR%", err_html)
        .replace("%TOKEN%", html.escape(token))
        .replace("%BLOCKS%", blocks)
    )
    return web.Response(text=body, content_type="text/html", status=status)


def content_disposition(name: str) -> str:
    """Заголовок Content-Disposition с поддержкой юникода в имени."""
    ascii_name = re.sub(r'[^A-Za-z0-9._ -]', "_", name.encode("ascii", "ignore").decode()) or "file"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"


async def _fetch_and_decrypt(bot: Bot, file_id: str, file_name: str, password: str) -> bytes:
    """Скачивает зашифрованный файл из Telegram и расшифровывает его."""
    buf = io.BytesIO()
    await bot.download(file_id, destination=buf)
    return await run_crypto(decrypt_file, buf.getvalue(), password)


def _file_response(data: bytes, file_name: str) -> web.Response:
    return web.Response(
        body=data,
        content_type="application/octet-stream",
        headers={
            "Content-Disposition": content_disposition(file_name),
            "Cache-Control": "no-store",
        },
    )


def _page_blocks(request: web.Request, token: str, auth_ok: bool, grant_ok: bool) -> str:
    """Кнопки passkey под ситуацию: уже вошёл / можно создавать / можно войти."""
    if not ENABLE_PASSKEY:
        return ""
    blocks = []
    if auth_ok:
        blocks.append(
            f'<a class="btn" href="/d/{html.escape(token)}/get">'
            "⬇️ Скачать файл (вход по passkey пройден)</a>"
        )
    has_pw = bool(_pw_list(token))
    if grant_ok:
        blocks.append('<div class="divider">Кодовое слово подтверждено</div>')
        blocks.append('<button class="sec" id="pw-setup" type="button">'
                      "🔑 Создать passkey (Face ID / отпечаток)</button>")
        if has_pw:
            blocks.append('<button class="sec" id="pw-login" type="button">'
                          "🙂 Войти по passkey</button>")
    elif has_pw:
        blocks.append('<div class="divider">Вход без кодового слова</div>')
        blocks.append('<button class="sec" id="pw-login" type="button">'
                      "🙂 Войти по Face ID / отпечатку</button>")
    return "\n".join(blocks)


async def web_form(request: web.Request) -> web.Response:
    """GET /d/{token} — страница ввода кодового слова (и кнопок passkey)."""
    token = request.match_info["token"]
    rec = await db_get(token)
    if not rec:
        return web.Response(status=404, text="Ссылка недействительна")
    auth_ok = _session_valid(request, token) is not None
    grant_ok = _grant_valid(request, token)
    blocks = _page_blocks(request, token, auth_ok, grant_ok)
    return render_page(rec[1], token=token, blocks=blocks)


async def web_download(request: web.Request) -> web.Response:
    """POST /d/{token} — проверка кодового слова и выдача расшифрованного файла."""
    token = request.match_info["token"]
    rec = await db_get(token)
    if not rec:
        return web.Response(status=404, text="Ссылка недействительна")
    file_id, file_name = rec

    if _is_locked(token):
        return render_page(
            file_name, "Слишком много неверных попыток. Попробуйте позже.", 429
        )

    form = await request.post()
    password = form.get("password", "")
    if not isinstance(password, str) or not password.strip():
        return render_page(file_name, "Введите кодовое слово.", 400)
    password = password.strip()  # так же, как при шифровании (подпись .strip())

    bot: Bot = request.app["bot"]
    try:
        data = await _fetch_and_decrypt(bot, file_id, file_name, password)
    except (InvalidTag, ValueError):
        _register_fail(token)
        return render_page(file_name, "Неверное кодовое слово.", 403)
    except Exception:
        logger.exception("Ошибка расшифровки на сайте")
        return render_page(file_name, "Внутренняя ошибка.", 500)

    _fails.pop(token, None)
    response = _file_response(data, file_name)
    if ENABLE_PASSKEY:
        # Открываем окно регистрации passkey и держим обёрнутую копию
        # кодового слова в памяти — в базу она попадёт только при
        # создании passkey (см. _pending_promote).
        await asyncio.to_thread(_pending_set, token, password)
        _grant_set(response, token)
    return response


async def web_get(request: web.Request) -> web.Response:
    """GET /d/{token}/get — выдача файла после входа по passkey."""
    token = request.match_info["token"]
    rec = await db_get(token)
    if not rec:
        return web.Response(status=404, text="Ссылка недействительна")
    file_id, file_name = rec

    if _session_valid(request, token) is None:
        return render_page(
            file_name, "Войдите по passkey или введите кодовое слово.", 403,
            token=token, blocks=_page_blocks(request, token, False, _grant_valid(request, token)),
        )

    wrap = await asyncio.to_thread(_vault_get, token)
    if not wrap:
        return render_page(
            file_name,
            "Ключ для этой ссылки не сохранён — введите кодовое слово ещё раз.",
            403, token=token, blocks=_page_blocks(request, token, True, _grant_valid(request, token)),
        )
    password = await asyncio.to_thread(_vault_password, wrap)

    bot: Bot = request.app["bot"]
    try:
        data = await _fetch_and_decrypt(bot, file_id, file_name, password)
    except (InvalidTag, ValueError):
        logger.error("Сохранённый ключ не подошёл для %s", token[:8])
        return render_page(file_name, "Не удалось расшифровать файл сохранённым ключом.", 500)
    except Exception:
        logger.exception("Ошибка выдачи файла по passkey")
        return render_page(file_name, "Не удалось получить файл из Telegram.", 502)
    return _file_response(data, file_name)


# ------------------------- Эндпоинты passkey --------------------------------

async def pw_register_options(request: web.Request) -> web.Response:
    """POST /d/{token}/pw/register/options — challenge для создания passkey."""
    if not ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    token = request.match_info["token"]
    if not await db_get(token):
        return _json_error("Ссылка недействительна", 404)
    if not _grant_valid(request, token):
        return _json_error("Сначала введите кодовое слово для этой ссылки", 403)
    challenge = await asyncio.to_thread(_challenge_new, token, "register")
    creds = await asyncio.to_thread(_pw_list, token)
    options = {
        "publicKey": {
            "rp": {"name": "Secret-bot", "id": RP_ID},
            "user": {
                "id": _b64u(hashlib.sha256(f"{RP_ID}|{token}".encode()).digest()),
                "name": f"link-{token[:10]}",
                "displayName": f"Ссылка {token[:10]}",
            },
            "challenge": challenge,
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
            "timeout": 60000,
            "excludeCredentials": [{"type": "public-key", "id": c} for c in creds],
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "required",
            },
            "attestation": "none",
        }
    }
    return web.json_response(options)


async def pw_register_verify(request: web.Request) -> web.Response:
    """POST /d/{token}/pw/register/verify — сохраняет passkey и ключ ссылки."""
    if not ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    token = request.match_info["token"]
    if not await db_get(token):
        return _json_error("Ссылка недействительна", 404)
    if not _grant_valid(request, token):
        return _json_error("Сначала введите кодовое слово для этой ссылки", 403)
    try:
        body = await request.json()
    except Exception:
        return _json_error("Некорректный запрос")
    try:
        client_json = _unb64u(str(body.get("clientDataJSON", "")))
        attestation_object = _unb64u(str(body.get("attestationObject", "")))
        challenge = str(json.loads(client_json).get("challenge", ""))
    except Exception:
        return _json_error("Некорректный ответ браузера")
    if not await asyncio.to_thread(_challenge_take, token, "register", challenge):
        return _json_error("Challenge устарел — нажмите кнопку ещё раз")
    try:
        cred_id, public_key, alg, counter = webauthn_register(
            client_json, attestation_object, challenge
        )
    except ValueError as exc:
        return _json_error(str(exc))
    await asyncio.to_thread(_pw_add, token, cred_id, public_key, alg, counter)
    if not await asyncio.to_thread(_pending_promote, token):
        logger.warning("Passkey создан без сохранённого ключа для %s", token[:8])
    logger.info("Passkey создан: %s… (ссылка %s)", cred_id[:12], token[:8])
    return web.json_response({"ok": True})


async def pw_login_options(request: web.Request) -> web.Response:
    """POST /d/{token}/pw/login/options — challenge для входа по passkey."""
    if not ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    token = request.match_info["token"]
    if not await db_get(token):
        return _json_error("Ссылка недействительна", 404)
    creds = await asyncio.to_thread(_pw_list, token)
    if not creds:
        return _json_error("Для этой ссылки passkey ещё не создан", 400)
    challenge = await asyncio.to_thread(_challenge_new, token, "login")
    options = {
        "publicKey": {
            "rpId": RP_ID,
            "challenge": challenge,
            "timeout": 60000,
            "allowCredentials": [{"type": "public-key", "id": c} for c in creds],
            "userVerification": "required",
        }
    }
    return web.json_response(options)


async def pw_login_verify(request: web.Request) -> web.Response:
    """POST /d/{token}/pw/login/verify — проверка подписи и выдача сессии."""
    if not ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    token = request.match_info["token"]
    if not await db_get(token):
        return _json_error("Ссылка недействительна", 404)
    try:
        body = await request.json()
    except Exception:
        return _json_error("Некорректный запрос")
    cred_id = str(body.get("id", ""))
    record = await asyncio.to_thread(_pw_get, cred_id) if cred_id else None
    if not record or record[0] != token:
        return _json_error("passkey не найден — войдите кодовым словом", 404)
    try:
        client_json = _unb64u(str(body.get("clientDataJSON", "")))
        auth_data = _unb64u(str(body.get("authenticatorData", "")))
        signature = _unb64u(str(body.get("signature", "")))
        challenge = str(json.loads(client_json).get("challenge", ""))
    except Exception:
        return _json_error("Некорректный ответ браузера")
    if not await asyncio.to_thread(_challenge_take, token, "login", challenge):
        return _json_error("Challenge устарел — нажмите кнопку ещё раз")
    _token, public_key, counter_stored = record
    try:
        counter = webauthn_assert(client_json, auth_data, signature, challenge, public_key)
    except ValueError as exc:
        return _json_error(str(exc), 403)
    if counter > 0 and counter_stored > 0 and counter <= counter_stored:
        logger.warning("Счётчик passkey не вырос (%s <= %s)", counter, counter_stored)
        return _json_error("Счётчик ключа не изменился — вход запрещён", 403)
    if counter:
        await asyncio.to_thread(_pw_bump, cred_id, counter)
    logger.info("Вход по passkey: %s… (ссылка %s)", cred_id[:12], token[:8])
    response = web.json_response({"ok": True})
    _session_set(response, token, cred_id)
    return response


def build_web_app(bot: Bot) -> web.Application:
    app = web.Application(client_max_size=64 * 1024)
    app["bot"] = bot
    app.router.add_get("/d/{token}", web_form)
    app.router.add_post("/d/{token}", web_download)
    app.router.add_get("/d/{token}/get", web_get)
    app.router.add_post("/d/{token}/pw/register/options", pw_register_options)
    app.router.add_post("/d/{token}/pw/register/verify", pw_register_verify)
    app.router.add_post("/d/{token}/pw/login/options", pw_login_options)
    app.router.add_post("/d/{token}/pw/login/verify", pw_login_verify)
    return app


# -------------------------------- Запуск ------------------------------------

async def main() -> None:
    """Точка входа: запускает веб-сервер и long polling."""
    # Ключ базы готовим заранее: им подписываются куки и шифруются
    # сохранённые копии кодовых слов для входа по passkey.
    await asyncio.to_thread(_master_key)
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(private_router)
    dp.include_router(group_router)
    dp.include_router(events_router)

    runner = None
    if ENABLE_WEB:
        runner = web.AppRunner(build_web_app(bot))
        await runner.setup()
        await web.TCPSite(runner, WEB_HOST, WEB_PORT).start()
        logger.info("Сайт запущен на %s:%s, ссылки вида %s/d/<token>", WEB_HOST, WEB_PORT, BASE_URL)
    else:
        logger.info("Сайт выключен (ENABLE_WEB=0): бот только шифрует и выдаёт ссылки")

    try:
        logger.info("Бот запущен")
        await dp.start_polling(bot)
    finally:
        if runner:
            await runner.cleanup()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())

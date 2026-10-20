"""Хранилище состояний бота (FSM) в той же SQLite, что и остальные данные.

Зачем оно нужно. `MemoryStorage` из aiogram держит состояния в памяти
процесса. В состоянии лежит не только «какой сейчас режим», но и **сам
файл**: `on_document` кладёт байты в `state.update_data(file_bytes=...)`,
а следующий шаг — ввод пароля — читает их оттуда.

На рабочей машине это незаметно: процесс живёт, пока открыт терминал.
На PaaS (Render, Northflank, Railway, Fly) процесс перезапускается при
каждом деплое и при засыпании. Человек отправляет файл боту, отвечает
«введите пароль», а через минуту сервис перезапустился — и ввод пароля
падает с KeyError, потому что байтов больше нет. Файл при этом остался
в Telegram: он не потерялся, но путь к нему потерялся.

Своё хранилище решает это: состояние лежит в той же базе, что и ссылки,
и переживает перезапуск. Живучесть базы — уже задача хостинга (диск),
а не этого модуля.

Что именно хранится:

    fsm_state   ключ -> состояние (строка) и JSON с данными
    fsm_data    ключ -> JSON с данными

Данные — это байты файла в base64. Да, это раздувает базу: файл до
20 МБ превращается примерно в 27 МБ текста. Цена — медленная запись и
строка в базе, которая больше файла. Альтернативы нет: состояние
должно пережить рестарт, а файл лежит в Telegram — его можно забрать
заново по `file_id`, но `file_id` тоже нужно где-то сохранить, и это
ровно то же самое, что хранить файл.

Файлы крупнее лимита Telegram всё равно не доедут, поэтому ограничение
тот же, что и у бота: 20 МБ.

Ключи хранения aiogram (`StorageKey`) состоят из bot_id, chat_id, user_id
и необязательных thread_id / business_connection_id. Все поля нужны:
в группе один и тот же пользователь в разных темах — это разные
состояния, и склеить их нельзя.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from typing import Any

from aiogram.fsm.storage.base import BaseStorage, StateType, StorageKey

from config import FSM_TTL

# Отдельное соединение: основная база (database.py) открывается при импорте
# и используется от многих потоков. Здесь то же самое, но своё соединение
# даёт независимую транзакцию — запись состояния не может заблокировать
# чтение ссылок и наоборот.
_conn: sqlite3.Connection | None = None
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    """Открывает соединение с базой состояний (лениво, один раз)."""
    global _conn
    if _conn is None:
        # Тот же файл базы, что и у database.py: DB_PATH из config.
        from config import DB_PATH

        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with _lock:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS fsm_state ("
                "key TEXT PRIMARY KEY, state TEXT, data TEXT, "
                "updated REAL NOT NULL)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS fsm_state_updated "
                "ON fsm_state(updated)"
            )
            conn.commit()
        _conn = conn
    return _conn


def _key_of(key: StorageKey) -> str:
    """Собирает строковый ключ из полей StorageKey.

    Разделитель — `:`. Значения — числа и строки без двоеточия, поэтому
    ключ однозначен: (1, 23) и (12, 3) дают разные строки.
    """
    return ":".join(
        str(part)
        for part in (
            key.bot_id,
            key.chat_id,
            key.user_id,
            key.thread_id if key.thread_id is not None else "-",
            key.business_connection_id or "-",
            key.destiny,
        )
    )


def _encode(data: dict[str, Any]) -> str:
    """Данные состояния -> JSON. Байты файла кодируются в base64."""
    safe: dict[str, Any] = {}
    for name, value in data.items():
        if isinstance(value, (bytes, bytearray)):
            safe[name] = {
                "__bytes__": base64.b64encode(bytes(value)).decode("ascii"),
            }
        else:
            safe[name] = value
    return json.dumps(safe, ensure_ascii=False)


def _decode(raw: str | None) -> dict[str, Any]:
    """JSON -> данные состояния. Байты файла возвращаются как bytes."""
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    out: dict[str, Any] = {}
    for name, value in loaded.items():
        if isinstance(value, dict) and "__bytes__" in value:
            try:
                out[name] = base64.b64decode(value["__bytes__"])
            except (TypeError, ValueError):
                out[name] = b""
        else:
            out[name] = value
    return out


def _purge_expired() -> None:
    """Удаляет состояния, которые старше FSM_TTL.

    Без этого база растёт бесконечно: каждый отправленный файл оставляет
    после себя запись с его байтами. TTL — это страховка от утечки памяти
    на диске при долгой работе сервиса.
    """
    conn = _connect()
    with _lock:
        conn.execute(
            "DELETE FROM fsm_state WHERE updated < ?", (time.time() - FSM_TTL,)
        )
        conn.commit()


class SQLiteStorage(BaseStorage):
    """FSM-хранилище поверх SQLite. Переживает перезапуск процесса.

    Интерфейс — ровно тот, что требует aiogram: set_state, get_state,
    set_data, get_data, update_data, close.
    """

    def __init__(self) -> None:
        _connect()
        _purge_expired()

    async def set_state(self, key: StorageKey, state: StateType = None) -> None:
        conn = _connect()
        with _lock:
            conn.execute(
                "INSERT INTO fsm_state (key, state, data, updated) "
                "VALUES (?, ?, '', ?) "
                "ON CONFLICT(key) DO UPDATE SET state = excluded.state, "
                "updated = excluded.updated",
                (_key_of(key), state.state if state else None, time.time()),
            )
            conn.commit()

    async def get_state(self, key: StorageKey) -> str | None:
        conn = _connect()
        with _lock:
            row = conn.execute(
                "SELECT state FROM fsm_state WHERE key = ?", (_key_of(key),)
            ).fetchone()
        return row[0] if row else None

    async def set_data(self, key: StorageKey, data: dict[str, Any]) -> None:
        conn = _connect()
        with _lock:
            conn.execute(
                "INSERT INTO fsm_state (key, state, data, updated) "
                "VALUES (?, NULL, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET data = excluded.data, "
                "updated = excluded.updated",
                (_key_of(key), _encode(data), time.time()),
            )
            conn.commit()

    async def get_data(self, key: StorageKey) -> dict[str, Any]:
        conn = _connect()
        with _lock:
            row = conn.execute(
                "SELECT data FROM fsm_state WHERE key = ?", (_key_of(key),)
            ).fetchone()
        return _decode(row[0] if row else None)

    async def update_data(
        self, key: StorageKey, data: dict[str, Any]
    ) -> dict[str, Any]:
        current = await self.get_data(key)
        current.update(data)
        await self.set_data(key, current)
        return current.copy()

    async def close(self) -> None:
        """Закрывает соединение. Вызывается при остановке бота."""
        global _conn
        with _lock:
            if _conn is not None:
                _conn.close()
                _conn = None

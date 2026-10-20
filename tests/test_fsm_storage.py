"""Тесты хранилища состояний бота (fsm_storage.py).

Проверяется ровно то, ради чего хранилище и написано: **состояние переживает
перезапуск процесса**.

Сценарий, который это ломает без SQLite-хранилища: человек отправляет боту
файл, бот просит пароль, в состоянии лежат байты файла. На PaaS процесс в
этот момент перезапускается (деплой, засыпание, переезд на другой инстанс).
С `MemoryStorage` байты исчезают, и следующий шаг — ввод пароля — падает:
KeyError на `file_bytes`. Файл при этом остался в Telegram, он не потерялся,
потерялся путь к нему.

Тест имитирует перезапуск буквально: закрывает соединение, создаёт новое
хранилище, читает состояние заново. Это не «другой объект в том же
процессе», а новое соединение с тем же файлом базы — ровно то, что
происходит после рестарта.

Хранилище проверяется отдельно от бота: здесь нет Telegram, нет сети и
нет файлов — только база и ключи StorageKey.
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def storage_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Готовит окружение с отдельной базой и перезагружает модули.

    Модуль `fsm_storage` читает DB_PATH при первом соединении, поэтому
    переменная окружения должна быть выставлена ДО его импорта. Импорт
    делается здесь заново — иначе тест дергал бы чужую (рабочую) базу
    бота.
    """
    db_path = tmp_path / "fsm-test.db"
    monkeypatch.setenv("DB_PATH", str(db_path))

    # Убираем модули, которые могли быть импортированы раньше: у них
    # уже открыто соединение с чужой базой.
    for name in ("fsm_storage", "config"):
        sys.modules.pop(name, None)

    importlib.import_module("config")
    module = importlib.import_module("fsm_storage")
    module._conn = None  # соединение ещё не открыто — откроется с нужным DB_PATH

    yield db_path

    module._conn = None
    for name in ("fsm_storage", "config"):
        sys.modules.pop(name, None)


def _key(chat_id: int = 42, user_id: int = 42):
    """Ключ хранения aiogram в виде, который ждёт хранилище."""
    from aiogram.fsm.storage.base import StorageKey

    return StorageKey(bot_id=1, chat_id=chat_id, user_id=user_id, destiny="default")


def test_a_state_survives_a_restart(storage_env: Path) -> None:
    """Главное свойство: состояние не пропадает при перезапуске.

    Сценарий 1:1 повторяет то, что происходит на PaaS — процесс умирает и
    поднимается заново, а человек в это время вводит пароль.
    """
    module = sys.modules["fsm_storage"]

    first = module.SQLiteStorage()
    payload = b"file bytes \x00\x01\x02 with binary inside"

    # Бот принял файл и положил его в состояние.
    import asyncio

    asyncio.run(first.update_data(_key(), {"file_bytes": payload, "mode": "encrypt"}))

    # --- перезапуск процесса ---
    asyncio.run(first.close())
    module._conn = None

    # Новый процесс, та же база.
    second = module.SQLiteStorage()
    restored = asyncio.run(second.get_data(_key()))

    assert restored["file_bytes"] == payload, "байты файла не пережили рестарт"
    assert restored["mode"] == "encrypt"
    asyncio.run(second.close())


def test_the_state_name_survives_a_restart(storage_env: Path) -> None:
    """Имя состояния тоже должно переживать рестарт."""
    module = sys.modules["fsm_storage"]
    from aiogram.fsm.state import State, StatesGroup

    class Sample(StatesGroup):
        waiting = State()

    first = module.SQLiteStorage()
    import asyncio

    asyncio.run(first.set_state(_key(), Sample.waiting))
    asyncio.run(first.close())
    module._conn = None

    second = module.SQLiteStorage()
    assert asyncio.run(second.get_state(_key())) == Sample.waiting.state
    asyncio.run(second.close())


def test_different_chats_do_not_share_state(storage_env: Path) -> None:
    """Ключ обязан различать чаты.

    Один и тот же человек в личке и в группе — это два разных состояния.
    Если ключ строится только по user_id, то ввод пароля в группе увидит
    файл, присланный в личке.
    """
    module = sys.modules["fsm_storage"]
    storage = module.SQLiteStorage()
    import asyncio

    asyncio.run(storage.update_data(_key(chat_id=1), {"file_bytes": b"personal"}))
    asyncio.run(storage.update_data(_key(chat_id=2), {"file_bytes": b"group"}))

    assert asyncio.run(storage.get_data(_key(chat_id=1)))["file_bytes"] == b"personal"
    assert asyncio.run(storage.get_data(_key(chat_id=2)))["file_bytes"] == b"group"
    asyncio.run(storage.close())


def test_threads_of_one_chat_do_not_share_state(storage_env: Path) -> None:
    """Темы внутри одной группы — тоже разные состояния."""
    module = sys.modules["fsm_storage"]
    storage = module.SQLiteStorage()
    import asyncio
    from aiogram.fsm.storage.base import StorageKey

    plain = StorageKey(bot_id=1, chat_id=9, user_id=9, destiny="default")
    thread = StorageKey(bot_id=1, chat_id=9, user_id=9, thread_id=5, destiny="default")

    asyncio.run(storage.update_data(plain, {"file_bytes": b"main"}))
    asyncio.run(storage.update_data(thread, {"file_bytes": b"topic"}))

    assert asyncio.run(storage.get_data(plain))["file_bytes"] == b"main"
    assert asyncio.run(storage.get_data(thread))["file_bytes"] == b"topic"
    asyncio.run(storage.close())


def test_unknown_key_gives_empty_data(storage_env: Path) -> None:
    """Нет состояния — это пустые данные, а не исключение."""
    module = sys.modules["fsm_storage"]
    storage = module.SQLiteStorage()
    import asyncio

    assert asyncio.run(storage.get_data(_key(chat_id=999))) == {}
    assert asyncio.run(storage.get_state(_key(chat_id=999))) is None
    asyncio.run(storage.close())


def test_old_states_are_purged(storage_env: Path) -> None:
    """Состояния старше TTL не копятся в базе.

    В каждом состоянии лежит файл. Если их не вычищать, база растёт
    бесконечно, и на бесплатном хостинге с небольшим диском это
    закончится. TTL — FSM_TTL из config, по умолчанию час.
    """
    module = sys.modules["fsm_storage"]
    import asyncio
    import time

    storage = module.SQLiteStorage()
    asyncio.run(storage.update_data(_key(chat_id=7), {"file_bytes": b"stale"}))

    # Делаем запись старше TTL и чистим.
    conn = module._connect()
    with module._lock:
        conn.execute(
            "UPDATE fsm_state SET updated = ? WHERE key = ?",
            (time.time() - module.FSM_TTL - 60, module._key_of(_key(chat_id=7))),
        )
        conn.commit()

    module._purge_expired()

    remaining = conn.execute(
        "SELECT COUNT(*) FROM fsm_state WHERE key = ?",
        (module._key_of(_key(chat_id=7)),),
    ).fetchone()[0]
    assert remaining == 0, "протухшее состояние осталось в базе"
    asyncio.run(storage.close())


def test_the_table_is_created_in_the_existing_database(storage_env: Path) -> None:
    """Хранилище не плодит отдельные файлы баз.

    Таблица fsm_state появляется в том же файле, что и links/passkeys.
    Отдельная база означала бы, что её надо отдельно копировать, отдельно
    подключать как том и отдельно забыть при бэкапе.
    """
    module = sys.modules["fsm_storage"]
    storage = module.SQLiteStorage()
    conn = module._connect()
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "fsm_state" in tables

    # Таблица лежит в том же файле, что и остальные данные: путь базы
    # совпадает с DB_PATH, а не с отдельным файлом рядом.
    import asyncio

    listed = conn.execute("PRAGMA database_list").fetchone()
    assert listed is not None
    assert os.path.samefile(str(storage_env), listed[2])

    asyncio.run(storage.close())


def test_the_key_is_built_without_collisions(storage_env: Path) -> None:
    """Ключ из StorageKey не должен смешивать разные наборы полей."""
    module = sys.modules["fsm_storage"]
    from aiogram.fsm.storage.base import StorageKey

    a = StorageKey(bot_id=1, chat_id=23, user_id=1, destiny="default")
    b = StorageKey(bot_id=12, chat_id=3, user_id=1, destiny="default")
    assert module._key_of(a) != module._key_of(b)

    c = StorageKey(bot_id=1, chat_id=23, user_id=1, thread_id=1, destiny="default")
    d = StorageKey(bot_id=1, chat_id=23, user_id=1, thread_id=2, destiny="default")
    assert module._key_of(c) != module._key_of(d)

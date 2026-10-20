"""Точка входа бота: собирает роутеры, поднимает сайт и запускает polling.

Модуль-монолит разобран на части, каждая занимается своим делом:

    config.py      настройки из переменных окружения (ничего не делает)
    crypto.py      AES-256-GCM + PBKDF2: синхронные функции и await-обёртки
    database.py    SQLite: ссылки, группы, passkey, обёрнутые кодовые слова
    passkey.py     разбор WebAuthn и подписанные куки grant/сессия
    private.py     хендлеры личного чата (пароль от пользователя)
    groups.py      хендлеры групп (кодовое слово группы + ссылка)
    web_app.py     сайт на FastAPI: страница, выдача файла, эндпоинты passkey
    launcher.py    конфиг secret-bot.env, --version, --selftest
    crypt_bot.py   этот файл: связывает всё вместе и запускает

ЛИЧНЫЙ ЧАТ (private.py):
    файл -> бот определяет режим по маркеру CRYPTv1\\0 -> пароль -> результат.

ГРУППА (groups.py, бот — администратор с правом удаления сообщений):
    0. Админ группы заранее пишет боту в личку /setcode, выбирает группу
       и вводит кодовое слово этой группы (хранится в SQLite).
    1. Участник присылает НЕзашифрованный документ.
    2. Бот читает файл, удаляет оригинал, шифрует его кодовым словом группы,
       присылает в группу зашифрованный .enc и ссылку.
    3. Человек открывает ссылку, вводит кодовое слово — бот берёт
       зашифрованный файл из Telegram по file_id, расшифровывает
       и отдаёт на скачивание прямо со страницы (web_app.py).
    Уже зашифрованные файлы (с маркером) в группе бот не трогает.

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

Настройки — переменные окружения (или константы в config.py).

Запуск: python launcher.py
Проверка без Telegram: python pw-demo-server.py  (см. README.md)
"""

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

import database
from config import (
    BASE_URL,
    BOT_TOKEN,
    ENABLE_PASSKEY,
    ENABLE_WEB,
    FAIL_WINDOW,
    MAX_FAILS,
    ORIGIN,
    RP_ID,
    WEB_HOST,
    WEB_PORT,
)
from crypto import (  # noqa: F401 — переэкспорт для внешних скриптов, см. ниже
    decrypt_file_sync,
    encrypt_file_sync,
    is_encrypted,
    make_key,
    run_crypto,
)
from database import (  # noqa: F401 — переэкспорт для внешних скриптов, см. ниже
    _challenge_new,
    _challenge_take,
    _db,
    _db_add,
    _db_get,
    _db_lock,
    _master_key,
    _pending_promote,
    _pending_set,
    _pending_vault,
    _pw_add,
    _pw_bump,
    _pw_get,
    _pw_list,
    _vault_get,
    _vault_password,
    _vault_put,
)
from fsm_storage import SQLiteStorage
from groups import events_router, group_router
from passkey import (
    b64u,
    grant_cookie,
    grant_valid,
    rp_hash,
    session_cookie,
    session_valid,
    unb64u,
    webauthn_assert,
    webauthn_register,
)
from private import private_router

# Переэкспорт выше — не для красоты: pw-demo-server.py, test-passkey.py и
# --selftest в launcher.py импортируют crypt_bot и берут оттуда крипту,
# базу и разбор WebAuthn. Новый код должен импортировать модули напрямую
# (import crypto / import database / import passkey), а не этот файл.

# Старые имена с подчёркиванием — для test-passkey.py, который зовёт cb._b64u(),
# cb._rp_hash() и cb._grant_valid(). Убрать их можно вместе с этим файлом,
# когда тест переедет на `import passkey`.
_b64u = b64u
_unb64u = unb64u
_rp_hash = rp_hash
_grant_cookie = grant_cookie
_grant_valid = grant_valid
_session_cookie = session_cookie
_session_valid = session_valid

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("crypt_bot")


# -------------------------------- Запуск ------------------------------------

async def start_site(bot: Bot, host: str, port: int):
    """Поднимает сайт (FastAPI + uvicorn) в ТЕКУЩЕМ event loop.

    Возвращает (server, task) — останавливать через stop_site(). Привязка к
    текущему циклу намеренная: aiohttp-сессия Telegram создана в этом цикле,
    и вызов bot.download() из чужого цикла (например, из отдельного потока)
    сломал бы выдачу файла. Сигналами владеет aiogram, поэтому uvicorn их не
    перехватывает.

    Отдельная функция — чтобы обвязку сайта можно было проверить без бота
    (см. live_site_tests в test-passkey.py и pw-demo-server.py).
    """
    import contextlib

    import uvicorn

    from web_app import create_app

    class _SiteServer(uvicorn.Server):
        """uvicorn без перехвата сигналов.

        Если сигналы перехватит uvicorn, Ctrl+C остановит сайт, а polling
        повиснет. Сайт закрываем сами — server.should_exit в stop_site().
        """

        def capture_signals(self):
            return contextlib.nullcontext()

    server = _SiteServer(uvicorn.Config(
        create_app(bot), host=host, port=port,
        log_level="warning", access_log=False,
    ))
    task = asyncio.create_task(server.serve())
    # Ждём, пока порт реально поднимется: если адрес занят, ошибка всплывёт
    # здесь, а не потонет в логах polling'а.
    while not server.started and not task.done():
        await asyncio.sleep(0.05)
    if task.done():
        task.result()
    return server, task


async def stop_site(server, task) -> None:
    """Останавливает сайт, поднятый start_site()."""
    if server is not None:
        server.should_exit = True
    if task is not None:
        await asyncio.wait([task], timeout=5)


async def main() -> None:
    """Точка входа: сайт на FastAPI (uvicorn) и long polling бота."""
    # Ключ базы готовим заранее: им подписываются куки и шифруются
    # сохранённые копии кодовых слов для входа по passkey.
    await database.master_key()
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=SQLiteStorage())
    dp.include_router(private_router)
    dp.include_router(group_router)
    dp.include_router(events_router)

    server = None
    site_task = None
    if ENABLE_WEB:
        server, site_task = await start_site(bot, WEB_HOST, WEB_PORT)
        logger.info("Сайт (FastAPI/uvicorn) на %s:%s, ссылки вида %s/d/<token>",
                    WEB_HOST, WEB_PORT, BASE_URL)
    else:
        logger.info("Сайт выключен (ENABLE_WEB=0): бот только шифрует и выдаёт ссылки")

    try:
        logger.info("Бот запущен")
        await dp.start_polling(bot)
    finally:
        await stop_site(server, site_task)
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())

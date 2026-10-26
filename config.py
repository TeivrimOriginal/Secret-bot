"""Настройки Secret-bot: только чтение переменных окружения, без побочных эффектов.

Здесь нет ни базы, ни сети, ни файлов — только значения. Порядок импорта
важен: `launcher.py` подставляет BOT_TOKEN/BASE_URL из secret-bot.env
ДО импорта бота, и модуль подхватывает их ровно один раз — при импорте.
Поэтому читать настройки нужно через `import config`, а не через os.getenv
в других модулях.

Полная таблица переменных — в README.md, раздел «Настройки».
"""

import os
from urllib.parse import urlparse

# ------------------------------- Бот и сайт ----------------------------------

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080").rstrip("/")
# Сайт расшифровки по умолчанию выключен (ENABLE_WEB=1 — включить).
# Ссылки в группе генерируются и сохраняются в базу независимо от этого флага.
ENABLE_WEB = os.getenv("ENABLE_WEB", "0") == "1"
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
# Порт сайта. Сначала WEB_PORT (явное намерение), потом PORT — так задают
# порт все PaaS: Render, Northflank, Railway, Fly. Без этого сайт поднялся бы
# на 8080, а платформа ждала бы соединения на своём порту и уронила сервис
# по таймауту — с логом, в котором ни слова о настоящей причине.
WEB_PORT = int(os.getenv("WEB_PORT") or os.getenv("PORT") or "8080")
DB_PATH = os.getenv("DB_PATH", "links.db")

# --------------------------- Telegram Mini App -------------------------------
# Мини-апп — статическая страница на GitHub Pages; сюда его адрес и откуда
# пускать запросы. MINIAPP_URL пуст — бот просто не ставит кнопку приложения.
MINIAPP_URL = os.getenv(
    "MINIAPP_URL", "https://teivrimoriginal.github.io/Secret-bot/"
).rstrip("/")
# Origins, которым сайт разрешает CORS-запросы к /api/app/* (через запятую).
# По умолчанию — origin самого мини-аппа и локальная разработка.
MINIAPP_ALLOW_ORIGINS = [
    o.strip().rstrip("/")
    for o in os.getenv(
        "MINIAPP_ALLOW_ORIGINS",
        f"{MINIAPP_URL},http://localhost:8080,http://127.0.0.1:8080",
    ).split(",")
    if o.strip()
]
# Свежесть initData: старше этого срока запрос мини-аппа отвергается.
MINIAPP_AUTH_TTL = int(os.getenv("MINIAPP_AUTH_TTL", "86400"))

# --------------------------- Passkey (WebAuthn) ------------------------------
# Вход на страницу по отпечатку пальца / Face ID вместо кодового слова.
# Порядок такой: человек один раз вводит кодовое слово -> может создать
# passkey на своём устройстве -> дальше открывает ссылку биометрией.
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

# ---------------------------- Формат файла -----------------------------------

MAGIC = b"CRYPTv1\x00"          # магический маркер (8 байт)
SALT_SIZE = 16                  # размер соли
NONCE_SIZE = 12                 # размер nonce для AES-GCM
TAG_SIZE = 16                   # размер тега GCM
KDF_ITERATIONS = 600_000        # число итераций PBKDF2
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE
ENC_SUFFIX = ".enc"
MIN_CODEWORD_LEN = 8            # минимальная длина кодового слова группы

# ------------------------------- Лимиты --------------------------------------

# Лимиты облачного Telegram Bot API: скачивание ботом — 20 МБ, отправка — 50 МБ.
MAX_DOWNLOAD_SIZE = 20 * 1024 * 1024
# В группе зашифрованный файл потом скачивается обратно (getFile, лимит 20 МБ),
# а он больше оригинала на HEADER_SIZE + TAG_SIZE байт — оставляем запас.
GROUP_MAX_SIZE = MAX_DOWNLOAD_SIZE - 1024

# Защита страницы от перебора кодового слова
MAX_FAILS = int(os.getenv("MAX_FAILS", "5"))        # неудачных попыток на ссылку...
FAIL_WINDOW = int(os.getenv("FAIL_WINDOW", "900"))   # ...за это число секунд

# ------------------------------ Состояния бота -------------------------------
# Сколько живёт состояние бота (в нём лежит и сам файл, ждущий пароля).
# По умолчанию час: человек обычно вводит пароль сразу, а запись с байтами
# файла не должна лежать в базе вечно.
FSM_TTL = int(os.getenv("FSM_TTL", "3600"))

ERR_WRONG_PASSWORD = "❌ Неверный пароль или файл повреждён"

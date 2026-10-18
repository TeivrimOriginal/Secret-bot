"""Точка входа: и для запуска из исходников, и для собранного .exe.

Зачем отдельный файл: собранной программе нужно решить несколько задач
ДО импорта crypt_bot (он читает настройки из окружения на уровне модуля):
    * прочитать конфиг secret-bot.env рядом с программой;
    * выбрать каталог для базы (в собранном виде — %APPDATA%, иначе база
      оказалась бы в Program Files, куда писать нельзя);
    * ответить на --version и --selftest.

Использование:
    SecretBot.exe                 обычный запуск (нужен BOT_TOKEN)
    SecretBot.exe --version       версия
    SecretBot.exe --selftest      самопроверка сборки, без Telegram
    SecretBot.exe --help          справка

Конфиг: файл secret-bot.env (KEY=VALUE, строки с # игнорируются).
Ищется по порядку: $SECRET_BOT_ENV, рядом с программой, текущий каталог,
%APPDATA%\\SecretBot. Переменные окружения имеют приоритет над файлом.
"""

import os
import sys

VERSION = "1.2.0"
APP_NAME = "Secret-bot"
DATA_DIR_NAME = "SecretBot"
ENV_FILE_NAME = "secret-bot.env"

USAGE = f"""{APP_NAME} {VERSION} — шифрование файлов в Telegram и выдача
расшифровки по ссылке с входом по passkey.

    {APP_NAME}.exe              запустить бота и сайт (нужен BOT_TOKEN)
    {APP_NAME}.exe --selftest   проверить сборку, не обращаясь к Telegram
    {APP_NAME}.exe --version    показать версию
    {APP_NAME}.exe --help       эта справка

Настройки берутся из файла {ENV_FILE_NAME} (рядом с программой, в текущем
каталоге или в %APPDATA%\\{DATA_DIR_NAME}) либо из переменных окружения.
Минимум для работы: BOT_TOKEN и BASE_URL. Подробности — в README.md.
"""


def _setup_console() -> None:
    """Консоль Windows по умолчанию cp1251 — иначе печать emoji падает.

    errors=\"replace\" страхует от неожиданных символов: лучше «?» в выводе,
    чем UnicodeEncodeError на середине самопроверки.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _app_dir() -> str:
    """Каталог, где лежит программа (для .exe — рядом с исполняемым файлом)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _data_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, DATA_DIR_NAME)


def _env_candidates() -> list[str]:
    candidates = []
    explicit = os.environ.get("SECRET_BOT_ENV")
    if explicit:
        candidates.append(explicit)
    candidates.append(os.path.join(_app_dir(), ENV_FILE_NAME))
    candidates.append(os.path.join(os.getcwd(), ENV_FILE_NAME))
    candidates.append(os.path.join(_data_dir(), ENV_FILE_NAME))
    return candidates


def _load_env_file(path: str) -> int:
    """Читает KEY=VALUE. Окружение имеет приоритет — ставим через setdefault."""
    loaded = 0
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)
                loaded += 1
    return loaded


def load_config() -> str | None:
    """Подхватывает первый найденный конфиг. Возвращает путь или None."""
    for path in _env_candidates():
        if path and os.path.isfile(path):
            _load_env_file(path)
            return path
    return None


def _prepare_data_dir() -> None:
    """В собранном виде база должна лежать в каталоге, куда можно писать."""
    if not os.environ.get("DB_PATH") and getattr(sys, "frozen", False):
        data_dir = _data_dir()
        os.makedirs(data_dir, exist_ok=True)
        os.environ["DB_PATH"] = os.path.join(data_dir, "links.db")


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_selftest() -> int:
    """Проверяет сборку без Telegram: крипто, база, сайт и /healthz."""
    import asyncio
    import json
    import tempfile
    import urllib.request

    os.environ.setdefault("BASE_URL", "http://localhost:8099")
    os.environ["DB_PATH"] = tempfile.mktemp(prefix="secretbot-selftest-", suffix=".db")

    problems: list[str] = []
    print(f"{APP_NAME} {VERSION} — самопроверка сборки")
    print(f"  Python: {sys.version.split()[0]}  frozen={getattr(sys, 'frozen', False)}")
    print(f"  Каталог: {_app_dir()}")

    try:
        import crypt_bot as cb
    except Exception as exc:  # noqa: BLE001 — самопроверка обязана показать причину
        print(f"  ❌ импорт crypt_bot: {exc!r}")
        return 1
    print(f"  ✅ импорт crypt_bot (RP_ID={cb.RP_ID})")

    # Модули, на которые разбит бот: каждый должен импортироваться сам
    # по себе — иначе в собранном .exe не хватит скрытого импорта.
    try:
        for module in ("config", "crypto", "database", "passkey",
                       "private", "groups", "web_app"):
            __import__(module)
        print("  ✅ модули пакета импортируются по одному")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"импорт модуля: {exc!r}")

    try:
        for module in ("fastapi", "uvicorn", "aiogram", "cbor2", "cryptography",
                       "python_multipart"):
            __import__(module)
        print("  ✅ зависимости на месте")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"импорт зависимости: {exc!r}")

    # Шифрование/расшифровка
    payload = b"selftest payload\n" * 20
    try:
        blob = cb.encrypt_file_sync(payload, "selftest-codeword")
        ok_marker = cb.is_encrypted(blob)
        restored = cb.decrypt_file_sync(blob, "selftest-codeword")
        if ok_marker and restored == payload:
            print("  ✅ шифрование и расшифровка")
        else:
            problems.append("крипто: неверный результат")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"крипто: {exc!r}")

    # База
    try:
        cb._db_add("selftest-token", "file-id", "имя.txt")
        row = cb._db_get("selftest-token")
        if row and row[0] == "file-id":
            print("  ✅ база SQLite пишется и читается")
        else:
            problems.append(f"база: неожиданный ответ {row!r}")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"база: {exc!r}")

    # Сайт: поднимаем в том же цикле и стучимся из отдельного потока
    port = _free_port()

    def http_get(path: str):
        """Возвращает (код, тело) либо (None, текст ошибки)."""
        import urllib.error

        url = f"http://127.0.0.1:{port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return None, repr(exc)

    async def site_check() -> dict:
        class DummyBot:  # сайту нужен только bot.download, а он тут не зовётся
            pass

        server, task = await cb.start_site(DummyBot(), "127.0.0.1", port)
        try:
            results = {}
            for path in ("/", "/healthz", "/d/selftest-token", "/d/no-such-token",
                         "/manifest.webmanifest", "/sw.js",
                         "/icon-192.png", "/icon-512.png"):
                results[path] = await asyncio.to_thread(http_get, path)
            return results
        finally:
            await cb.stop_site(server, task)

    try:
        pages = asyncio.run(site_check())
        health_code, health_body = pages["/healthz"]
        if health_code == 200 and json.loads(health_body) == {"ok": True}:
            print(f"  ✅ /healthz отвечает (порт {port})")
        else:
            problems.append(f"сайт: /healthz -> {health_code} {health_body!r}")

        page_code, page_body = pages["/d/selftest-token"]
        if page_code == 200 and "selftest-token" in page_body:
            print("  ✅ страница /d/<token> отдаётся")
        else:
            problems.append(f"сайт: /d/selftest-token -> {page_code}")

        # Заставка нужна мобильной обёртке: она открывает адрес сайта целиком
        index_code, index_body = pages["/"]
        if index_code == 200 and 'id="link"' in index_body:
            print("  ✅ заставка / отдаётся")
        else:
            problems.append(f"сайт: / -> {index_code}")

        miss_code, _ = pages["/d/no-such-token"]
        if miss_code == 404:
            print("  ✅ неизвестная ссылка -> 404")
        else:
            problems.append(f"сайт: /d/no-such-token -> {miss_code} (ждали 404)")

        # PWA: манифест, service worker и иконки для ярлыка на экране Android
        mf_code, mf_body = pages["/manifest.webmanifest"]
        if mf_code == 200 and '"name"' in mf_body and '"icons"' in mf_body:
            print("  ✅ PWA: манифест отдаётся")
        else:
            problems.append(f"PWA: манифест -> {mf_code}")
        sw_code, sw_body = pages["/sw.js"]
        if sw_code == 200 and "caches" in sw_body and "serviceWorker" not in sw_body:
            print("  ✅ PWA: service worker отдаётся")
        else:
            problems.append(f"PWA: sw.js -> {sw_code}")
        for size in (192, 512):
            ic_code, _ = pages[f"/icon-{size}.png"]
            if ic_code == 200:
                print(f"  ✅ PWA: иконка {size} отдаётся")
            else:
                problems.append(f"PWA: иконка {size} -> {ic_code}")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"сайт: {exc!r}")

    if problems:
        print("\n❌ САМОПРОВЕРКА НЕ ПРОШЛА:")
        for item in problems:
            print(f"  - {item}")
        return 1
    print("\n✅ САМОПРОВЕРКА ПРОШЛА — сборка рабочая")
    return 0


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    argv = list(sys.argv[1:] if argv is None else argv)

    if "--help" in argv or "-h" in argv:
        print(USAGE)
        return 0
    if "--version" in argv:
        print(f"{APP_NAME} {VERSION}")
        return 0

    if "--selftest" in argv:
        # Даже для самопроверки читаем конфиг: она должна видеть те же
        # BASE_URL/DB_PATH, что и рабочий запуск.
        load_config()
        return run_selftest()

    config_path = load_config()
    _prepare_data_dir()

    if not os.environ.get("BOT_TOKEN"):
        print(f"BOT_TOKEN не задан.\n\n{USAGE}")
        print(f"Подсказка: создайте {ENV_FILE_NAME} рядом с программой "
              f"({os.path.join(_app_dir(), ENV_FILE_NAME)}) и впишите туда\n"
              "    BOT_TOKEN=123456:AA...\n"
              "    BASE_URL=https://ваш-домен\n"
              "    ENABLE_WEB=1")
        return 2

    if config_path:
        print(f"Конфиг: {config_path}")

    import asyncio
    import logging

    import crypt_bot

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        asyncio.run(crypt_bot.main())
    except KeyboardInterrupt:
        print("\nОстановлено пользователем")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

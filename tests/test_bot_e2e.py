"""Сквозной тест бота против фейкового Telegram API.

Это проверка того, что не проверяет `--selftest`: полный путь пользователя.

    человек -> бот (документ) -> пароль -> ссылка -> страница -> файл

Настоящий Telegram здесь не нужен и невозможен: нужен живой токен, а тест
должен запускаться где угодно и всегда. Вместо него поднимается маленький
HTTP-сервер, который говорит на языке Bot API: `getMe`, `getUpdates`,
`sendMessage`, `sendDocument`, `getFile`, `deleteMessage`, `deleteWebhook`.
Он же отдаёт «файл» — те самые байты, которые человек «прислал».

Что это доказывает:

* бот получает обновление, скачивает документ, шифрует и отдаёт ссылку;
* ссылка ведёт на работающую страницу;
* ввод кодового слова на странице возвращает исходный файл;
* ссылка попадает в базу, а сайт достаёт файл из Telegram по file_id;
* состояние бота (в нём лежат байты файла) переживает перезапуск.

Что это НЕ доказывает: работу с настоящим Telegram (формат обновлений там
может отличаться), лимиты Telegram и поведение при обрыве связи.

Про формат запросов. aiogram отправляет ВСЕ методы как
`multipart/form-data`, а не как JSON — это видно в
`AiohttpSession.build_form_data`. Первый вариант этого теста ждал JSON и
падал на `json.loads` multipart-тела: соединение рвалось, и бот не мог
скачать файл. Тело здесь разбирается правильно.

Запуск:
    python tests/test_bot_e2e.py
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Настройки читаются при импорте config, поэтому окружение готовится ДО
# импорта модулей бота.
_TMP = tempfile.mkdtemp(prefix="secretbot-e2e-")
os.environ["DB_PATH"] = str(Path(_TMP) / "links.db")
os.environ["BOT_TOKEN"] = "123456:AAEfakefakefakefakefakefakefakefake"
os.environ["ENABLE_WEB"] = "1"
os.environ["BASE_URL"] = "http://127.0.0.1:1"  # переопределится ниже
os.environ["LOG_LEVEL"] = "ERROR"

PASSED: list[str] = []
FAILED: list[str] = []


def ok(name: str, cond: bool, detail: str = "") -> bool:
    if cond:
        PASSED.append(name)
        print(f"  OK    {name}")
    else:
        FAILED.append(f"{name} — {detail}")
        print(f"  FAIL  {name}  {detail}")
    return bool(cond)


# --------------------------------------------------------------------------
# Фейковый Telegram Bot API
# --------------------------------------------------------------------------

#: «Файл», который человек присылает боту.
FAKE_FILE = b"secret payload \x00\x01\x02 \xff\xfe binary tail"
#: Кодовое слово, которым «человек» открывает ссылку.
PASSWORD = "correct horse battery staple"

#: file_id -> (байты, имя). Сюда попадает и исходный файл, и отправленный ботом.
_STORED: dict[str, tuple[bytes, str]] = {}
#: Очередь входящих обновлений.
_UPDATES: list[dict[str, Any]] = []
#: Тексты, которые бот отправлял в чат (по порядку).
_SENT: list[str] = []
_COUNTER = {"n": 0}


def _parse_multipart(raw: bytes, content_type: str) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    """Разбирает тело запроса на поля и файлы.

    aiogram (через aiohttp `FormData`) отправляет **два разных формата**:

    * `application/x-www-form-urlencoded` — когда файла в методе нет
      (например `getFile` с одним `file_id`);
    * `multipart/form-data` — когда файл есть (`sendDocument`).

    Первый вариант этого теста понимал только multipart и на `getFile`
    получал пустое тело, а сервер отвечал «file not found». Формат
    определяется по заголовку, а не по догадкам.
    """
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}

    ctype = (content_type or "").lower()
    if "multipart/form-data" not in ctype:
        # urlencoded: file_id=incoming-file
        from urllib.parse import parse_qsl

        for name, value in parse_qsl(raw.decode("utf-8", "replace")):
            fields[name] = value
        return fields, files

    match = re.search(r"boundary=\"?([^\";]+)\"?", content_type or "")
    if not match:
        return {"__raw__": raw.decode("utf-8", "replace")}, {}

    boundary = ("--" + match.group(1)).encode()
    raw_parts: dict[str, tuple[str, bytes]] = {}
    plain: dict[str, str] = {}
    for part in raw.split(boundary):
        if part in (b"", b"--", b"--\r\n", b"\r\n"):
            continue
        part = part.lstrip(b"\r\n")
        head, sep, body = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        body = body.rstrip(b"\r\n")
        headers = head.decode("utf-8", "replace")
        name_match = re.search(r'name="([^"]+)"', headers)
        if not name_match:
            continue
        name = name_match.group(1)
        file_match = re.search(r'filename="([^"]*)"', headers)
        if file_match:
            raw_parts[name] = (file_match.group(1), body)
        else:
            plain[name] = body.decode("utf-8", "replace")

    # aiohttp кладёт файл в отдельную часть с именем-идентификатором
    # (например `e_dggdkkBXMNAQ`), а в поле `document` пишет ссылку
    # вида `attach://e_dggdkkBXMNAQ`. Настоящий Telegram такие ссылки
    # разворачивает сам; здесь нужно развернуть их вручную, иначе файл
    # приходит пустым.
    for name, value in list(plain.items()):
        if value.startswith("attach://"):
            attached = value[len("attach://"):]
            if attached in raw_parts:
                files[name] = raw_parts[attached]
                plain[name] = ""
                continue
    fields.update({k: v for k, v in plain.items() if v != ""})
    files.update({k: v for k, v in raw_parts.items() if k not in files})
    return fields, files


def _message_payload(text: str | None = None, document: dict[str, Any] | None = None) -> dict[str, Any]:
    """Объект Message в том виде, в каком его ждёт aiogram."""
    message: dict[str, Any] = {
        "message_id": 2000 + _COUNTER["n"],
        "date": int(time.time()),
        "chat": {"id": 1, "type": "private", "first_name": "Tester"},
        "from": {"id": 1, "is_bot": False, "first_name": "Tester"},
    }
    if text is not None:
        message["text"] = text
    if document is not None:
        message["document"] = document
    return message


class _TelegramHandler(BaseHTTPRequestHandler):
    """Говорит на языке Bot API — ровно те вызовы, что делает aiogram."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        """Тишина: иначе каждый запрос печатается в stdout."""

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 — имя задано BaseHTTPRequestHandler
        path = self.path
        if "/file/bot" in path:
            # Скачивание файла: /file/bot<token>/<file_path>
            file_path = path.rsplit("/", 1)[-1]
            for file_id, (data, _name) in _STORED.items():
                if file_path == file_id:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
            self._send_json({"ok": False, "description": "file not found"}, 404)
            return
        self._send_json({"ok": False, "description": "not found"}, 404)

    def _read_body(self) -> bytes:
        """Читает тело запроса.

        aiogram (через aiohttp `FormData`) отправляет multipart **чанками**:
        заголовка `Content-Length` нет, есть `Transfer-Encoding: chunked`.
        Наивное чтение по Content-Length давало 0 байт, и файл приходил
        пустым — бот «отправлял» пустой документ, а тест радостно
        отчитывался: «отправил зашифрованный файл».
        """
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            chunks: list[bytes] = []
            while True:
                size_line = self.rfile.readline().strip()
                if not size_line:
                    break
                try:
                    size = int(size_line.split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline()  # завершающий CRLF
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()  # CRLF после части
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def do_POST(self) -> None:  # noqa: N802
        raw = self._read_body()
        fields, files = _parse_multipart(raw, self.headers.get("Content-Type", ""))
        path = self.path

        if path.endswith("/sendDocument"):
            filename, data = files.get("document", ("file.bin", b""))
            _COUNTER["n"] += 1
            file_id = f"fake-file-{_COUNTER['n']}"
            _STORED[file_id] = (data, filename)
            # Ссылка на расшифровку приходит подписью к документу
            # (caption), а не отдельным сообщением — её тоже надо видеть.
            caption = fields.get("caption", "")
            if caption:
                _SENT.append(caption)
            self._send_json({
                "ok": True,
                "result": _message_payload(document={
                    "file_id": file_id,
                    "file_unique_id": file_id,
                    "file_name": filename,
                    "file_size": len(data),
                    "mime_type": "application/octet-stream",
                }),
            })
            return

        if path.endswith("/sendMessage"):
            _SENT.append(fields.get("text", ""))
            self._send_json({"ok": True, "result": _message_payload(text=fields.get("text", ""))})
            return

        if path.endswith("/getFile"):
            file_id = fields.get("file_id", "")
            if file_id not in _STORED:
                self._send_json({"ok": False, "description": "file not found"})
                return
            self._send_json({
                "ok": True,
                "result": {
                    "file_id": file_id,
                    "file_unique_id": file_id,
                    "file_size": len(_STORED[file_id][0]),
                    "file_path": file_id,
                },
            })
            return

        if path.endswith("/getMe"):
            self._send_json({
                "ok": True,
                "result": {
                    "id": 123456,
                    "is_bot": True,
                    "first_name": "Secret",
                    "username": "secret_test_bot",
                    "can_join_groups": True,
                    "can_read_all_group_messages": True,
                    "supports_inline_queries": False,
                },
            })
            return

        if path.endswith("/getUpdates"):
            # Настоящий Telegram держит соединение и ждёт обновлений.
            # Здесь возвращаем сразу, но с паузой, иначе polling
            # превращается в горячий цикл и съедает CPU.
            time.sleep(0.05)
            updates = list(_UPDATES)
            _UPDATES.clear()
            self._send_json({"ok": True, "result": updates})
            return

        if path.endswith("/deleteWebhook"):
            self._send_json({"ok": True, "result": True})
            return

        if path.endswith("/deleteMessage"):
            self._send_json({"ok": True, "result": True})
            return

        self._send_json({"ok": True, "result": True})


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _make_update(text: str | None = None, file_id: str | None = None) -> dict[str, Any]:
    """Собирает обновление в формате, который понимает aiogram."""
    message: dict[str, Any] = {
        "message_id": len(_UPDATES) + 1,
        "date": int(time.time()),
        "chat": {"id": 1, "type": "private", "first_name": "Tester"},
        "from": {"id": 1, "is_bot": False, "first_name": "Tester"},
    }
    if text is not None:
        message["text"] = text
    if file_id is not None:
        message["document"] = {
            "file_id": file_id,
            "file_unique_id": file_id,
            "file_name": "payload.bin",
            "file_size": len(FAKE_FILE),
            "mime_type": "application/octet-stream",
        }
    return {"update_id": len(_UPDATES) + 1000, "message": message}


async def _http(url: str, data: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    """HTTP-запрос к сайту.

    urllib блокирующий, поэтому он выполняется в отдельном потоке. Иначе
    запрос занимает event loop, в котором живёт uvicorn, и сервер не может
    ответить — клиент висит до таймаута. Это тот же класс ошибки, что и
    с остановкой сайта: тест упирается в то, как устроен event loop, а не
    в код бота.
    """
    import urllib.error
    import urllib.request

    def _do() -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=data, headers=headers or {})
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    return await asyncio.to_thread(_do)


# --------------------------------------------------------------------------
# Сценарий
# --------------------------------------------------------------------------


async def _scenario(site_port: int, tg_port: int) -> dict[str, Any]:
    """Гоняет бота и проверяет сайт — в одном event loop.

    Почему всё в одном цикле: сайт поднимается как asyncio-задача внутри
    loop'а (`crypt_bot.start_site`). Если проверки сайта выполнять из
    другого `asyncio.run`, loop уже закрыт, uvicorn остановлен, и клиент
    получает «connection refused» — тест врал о том, что сайт не
    работает, хотя он работал. Проверки — внутри того же цикла, где живёт
    сервер.
    """
    from aiogram import Bot, Dispatcher
    from aiogram.client.session.aiohttp import AiohttpSession
    from aiogram.client.telegram import TelegramAPIServer

    import config
    import crypt_bot
    import database
    from crypto import is_encrypted
    from fsm_storage import SQLiteStorage

    api = TelegramAPIServer.from_base(f"http://127.0.0.1:{tg_port}")
    session = AiohttpSession(api=api)
    bot = Bot(token=os.environ["BOT_TOKEN"], session=session)

    dp = Dispatcher(storage=SQLiteStorage())
    dp.include_router(crypt_bot.private_router)
    dp.include_router(crypt_bot.group_router)
    dp.include_router(crypt_bot.events_router)

    server, site_task = await crypt_bot.start_site(bot, "127.0.0.1", site_port)

    try:
        # Файл, который «прислал» человек: кладём в фейковый Telegram и
        # сообщаем боту обновление с этим file_id.
        _STORED["incoming-file"] = (FAKE_FILE, "payload.bin")
        _UPDATES.append(_make_update(file_id="incoming-file"))

        async def pump() -> None:
            await dp.start_polling(bot, allowed_updates=["message"])

        polling = asyncio.create_task(pump())
        try:
            # Ждём, пока бот попросит пароль.
            for _ in range(150):
                await asyncio.sleep(0.1)
                if any("парол" in text.lower() for text in _SENT):
                    break

            # --- состояние бота переживает перезапуск ---
            # Самое важное для деплоя: на PaaS процесс перезапускается при
            # каждом деплое. Если бы состояние жило в памяти, человек
            # прислал бы файл, а через минуту ввод пароля падал бы — файл
            # остался бы в Telegram, но путь к нему потерялся бы.
            #
            # Проверка делается здесь, пока бот ЖДЁТ пароль: после
            # ввода пароля хендлер вызывает state.clear(), и состояния
            # с файлом уже не существует — так и задумано.
            print("\n--- состояние бота переживает перезапуск ---")
            from fsm_storage import SQLiteStorage

            # Новое соединение с той же базой — это и есть новый процесс.
            fresh = SQLiteStorage()
            state = await fresh.get_data(_storage_key(chat_id=1, user_id=1))
            ok("состояние бота прочитано новым соединением", bool(state),
               "состояние пустое")
            ok("файл, ждущий пароля, не потерялся", state.get("file_bytes") == FAKE_FILE,
               f"{len(state.get('file_bytes') or b'')} байт вместо {len(FAKE_FILE)}")
            ok("в состоянии есть режим операции", state.get("mode") == "encrypt",
               str(state.get("mode")))
            await fresh.close()

            # Человек вводит пароль.
            _UPDATES.append(_make_update(text=PASSWORD))
            # Ждём, пока бот отправит зашифрованный файл.
            for _ in range(150):
                await asyncio.sleep(0.1)
                if any(name.endswith(".enc") for _data, name in _STORED.values()):
                    break
        finally:
            polling.cancel()
            try:
                await polling
            except asyncio.CancelledError:
                pass

        # --- что сделал бот ---
        print("\n--- что сделал бот ---")
        sent = list(_SENT)
        ok("бот попросил пароль", any("парол" in t.lower() for t in sent), str(sent[-2:]))

        # Отправленный ботом файл — тот, что не «входящий».
        incoming = {"incoming-file"}
        enc_files = [(fid, data, name) for fid, (data, name) in _STORED.items()
                     if fid not in incoming and name.endswith(".enc")]
        ok("бот отправил зашифрованный файл", bool(enc_files), f"stored={list(_STORED)}")

        if enc_files:
            _fid, sent_bytes, sent_name = enc_files[0]
            ok("отправленный файл помечен как зашифрованный", is_encrypted(sent_bytes),
               "маркер CRYPTv1 не найден")
            ok("имя файла получило суффикс .enc", sent_name.endswith(".enc"), sent_name)
            ok("зашифрованный файл больше исходного (есть соль и nonce)",
               len(sent_bytes) > len(FAKE_FILE),
               f"{len(sent_bytes)} против {len(FAKE_FILE)}")
            # Расшифровка тем же паролем даёт исходные байты.
            from crypto import decrypt_file_sync

            restored = decrypt_file_sync(sent_bytes, PASSWORD)
            ok("зашифрованный файл расшифровывается правильным паролем",
               restored == FAKE_FILE, f"{len(restored)} байт против {len(FAKE_FILE)}")

        ok("бот отправил ссылку в чат", any("/d/" in t for t in sent),
           "в сообщениях нет ссылки")

        rows = database.stats()
        ok("ссылка записана в базу", rows.get("links", 0) >= 1, str(rows))

        # --- сайт ---
        print("\n--- сайт ---")
        tokens = list(database._db.execute("SELECT token, file_id FROM links"))
        ok("в базе есть токен ссылки", bool(tokens), "таблица links пуста")

        if tokens:
            token, file_id = tokens[0]
            status, body = await _http(f"http://127.0.0.1:{site_port}/d/{token}")
            ok("страница ссылки открывается", status == 200, f"status={status}")
            ok("на странице есть поле кодового слова",
               b"password" in body.lower() or "пароль".encode() in body.lower(), "")

            # Ввод кодового слова -> файл.
            form = ("password=" + PASSWORD.replace(" ", "+")).encode()
            status, body = await _http(
                f"http://127.0.0.1:{site_port}/d/{token}",
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            ok("ввод кодового слова отдаёт файл", status == 200, f"status={status}")
            ok("файл после расшифровки совпадает с исходным", body == FAKE_FILE,
               f"получено {len(body)} байт, ожидалось {len(FAKE_FILE)}")

            # Неверный пароль.
            status, body = await _http(
                f"http://127.0.0.1:{site_port}/d/{token}",
                data=b"password=wrong",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            ok("неверный пароль не отдаёт файл", status != 200 or body != FAKE_FILE,
               f"status={status}, {len(body)} байт")

        status, _ = await _http(f"http://127.0.0.1:{site_port}/d/no-such-token")
        ok("неизвестная ссылка -> 404", status == 404, f"status={status}")

        status, body = await _http(f"http://127.0.0.1:{site_port}/healthz")
        ok("/healthz отвечает", status == 200 and b'"ok":true' in body.replace(b" ", b""),
           f"status={status} body={body[:60]}")
    finally:
        await crypt_bot.stop_site(server, site_task)
        await bot.session.close()
    return {"sent": list(_SENT)}


def _storage_key(chat_id: int, user_id: int):
    """Ключ хранения aiogram для личного чата."""
    from aiogram.fsm.storage.base import StorageKey

    return StorageKey(bot_id=123456, chat_id=chat_id, user_id=user_id,
                      destiny="default")


def main() -> int:
    print("=== сквозной тест бота против фейкового Telegram API ===")

    tg_port = _free_port()
    tg = ThreadingHTTPServer(("127.0.0.1", tg_port), _TelegramHandler)
    threading.Thread(target=tg.serve_forever, daemon=True).start()
    print(f"  фейковый Telegram API: http://127.0.0.1:{tg_port}")

    site_port = _free_port()
    os.environ["BASE_URL"] = f"http://127.0.0.1:{site_port}"

    import config

    config.BASE_URL = f"http://127.0.0.1:{site_port}"
    config.ORIGIN = f"http://127.0.0.1:{site_port}"
    config.RP_ID = "127.0.0.1"

    try:
        asyncio.run(_scenario(site_port, tg_port))
    finally:
        tg.shutdown()

    print(f"\npassed: {len(PASSED)}   failed: {len(FAILED)}")
    for failure in FAILED:
        print(f"  FAILED: {failure}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())

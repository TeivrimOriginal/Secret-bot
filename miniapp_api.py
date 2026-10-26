"""Telegram Mini App API для Secret-bot.

Маршруты:
    GET  /api/app/config       — конфиг для фронтенда (BASE_URL, MINIAPP_URL)
    GET  /api/app/me           — профиль текущего пользователя
    GET  /api/app/links        — список ссылок пользователя
    POST /api/app/revoke       — отозвать ссылку ({"token": "..."})
    POST /api/app/notify       — бот шлёт сообщение пользователю (help/links/custom)

Проверка подлинности:
    Заголовок `X-Telegram-Init-Data` содержит строку initData от Telegram.
    Сервер проверяет HMAC-SHA256 (key = HMAC("WebAppData", BOT_TOKEN)),
    свежесть auth_date (MINIAPP_AUTH_TTL) и origin.

CORS:
    Middleware разрешает запросы только с origin'ов из MINIAPP_ALLOW_ORIGINS.
"""

import hashlib
import hmac
import json
import logging
import time
from urllib.parse import parse_qsl
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

import database
from config import (
    BASE_URL,
    BOT_TOKEN,
    MINIAPP_ALLOW_ORIGINS,
    MINIAPP_AUTH_TTL,
    MINIAPP_URL,
)

logger = logging.getLogger("cryptbot.miniapp")

router = APIRouter(prefix="/api/app")

# --------------------------- Проверка initData --------------------------------


def _parse_init_data(raw: str) -> dict[str, str]:
    """Разбирает initData на ключи (как query-string)."""
    return dict(parse_qsl(raw, keep_blank_values=True))


def _verify_init_data(init_data: str) -> tuple[bool, dict[str, Any] | None]:
    """Проверяет подпись и свежесть initData.

    Возвращает (ok, user_dict) — при успехе user_dict = {id, username, ...}.
    """
    try:
        data = _parse_init_data(init_data)
    except Exception:
        return False, None

    auth_date = data.get("auth_date")
    if not auth_date:
        return False, None
    try:
        auth_ts = int(auth_date)
    except ValueError:
        return False, None
    if time.time() - auth_ts > MINIAPP_AUTH_TTL:
        return False, None

    # Telegram подписывает через hash = HMAC("WebAppData", BOT_TOKEN)
    sign = data.pop("hash", None)
    if not sign:
        return False, None

    data_check_arr = sorted(f"{k}={v}" for k, v in data.items())
    data_check_string = "\n".join(data_check_arr)

    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode("ascii"), hashlib.sha256).digest()
    computed = hmac.new(secret, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed, sign):
        return False, None

    user_json = data.get("user")
    user = json.loads(user_json) if user_json else {}
    return True, user


# ------------------------------ CORS middleware -------------------------------


def _cors_headers(origin: str) -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data",
        "Access-Control-Max-Age": "86400",
    }


async def cors_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin", "")
        if origin in MINIAPP_ALLOW_ORIGINS:
            return Response(status_code=200, headers=_cors_headers(origin))
        return Response(status_code=403)

    origin = request.headers.get("Origin", "")
    response = await call_next(request)
    if origin in MINIAPP_ALLOW_ORIGINS:
        for k, v in _cors_headers(origin).items():
            response.headers[k] = v
    return response


# -------------------------- Хелпер для ответов --------------------------------


def _json_response(data: Any, status: int = 200, origin: str | None = None) -> Response:
    headers = {}
    if origin and origin in MINIAPP_ALLOW_ORIGINS:
        headers.update(_cors_headers(origin))
    return JSONResponse(data, status_code=status, headers=headers if headers else None)


def _error(message: str, status: int = 400, origin: str | None = None) -> Response:
    return _json_response({"error": message}, status=status, origin=origin)


# ------------------------------- Эндпоинты ------------------------------------


@router.get("/config")
async def get_config(request: Request) -> Response:
    """Конфиг для фронтенда: адреса и флаги."""
    origin = request.headers.get("Origin", "")
    return _json_response(
        {
            "base_url": BASE_URL,
            "miniapp_url": MINIAPP_URL,
            "allow_origins": MINIAPP_ALLOW_ORIGINS,
        },
        origin=origin,
    )


@router.get("/me")
async def get_me(request: Request) -> Response:
    """Профиль пользователя: id, username, first_name, last_seen."""
    origin = request.headers.get("Origin", "")
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    ok, user = _verify_init_data(init_data)
    if not ok:
        return _error("Invalid or expired initData", 401, origin)

    user_id = user.get("id")
    if not isinstance(user_id, int):
        return _error("Invalid user id", 400, origin)

    db_user = await database.user_get(user_id)
    if db_user is None:
        # Пользователь ещё не запускал бота — вернём минимум из initData
        return _json_response(
            {
                "user_id": user_id,
                "username": user.get("username"),
                "first_name": user.get("first_name"),
                "last_seen": None,
            },
            origin=origin,
        )

    chat_id, username, first_name = db_user
    return _json_response(
        {
            "user_id": user_id,
            "username": username,
            "first_name": first_name,
            "chat_id": chat_id,
        },
        origin=origin,
    )


@router.get("/links")
async def get_links(request: Request) -> Response:
    """Список ссылок пользователя (token, file_name, created)."""
    origin = request.headers.get("Origin", "")
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    ok, user = _verify_init_data(init_data)
    if not ok:
        return _error("Invalid or expired initData", 401, origin)

    user_id = user.get("id")
    if not isinstance(user_id, int):
        return _error("Invalid user id", 400, origin)

    links = await database.user_links(user_id)
    return _json_response({"links": links}, origin=origin)


@router.post("/revoke")
async def revoke_link(request: Request) -> Response:
    """Отозвать ссылку: {"token": "..."}."""
    origin = request.headers.get("Origin", "")
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    ok, user = _verify_init_data(init_data)
    if not ok:
        return _error("Invalid or expired initData", 401, origin)

    user_id = user.get("id")
    if not isinstance(user_id, int):
        return _error("Invalid user id", 400, origin)

    try:
        body = await request.json()
    except Exception:
        return _error("Invalid JSON", 400, origin)

    token = body.get("token")
    if not isinstance(token, str) or not token:
        return _error("Missing token", 400, origin)

    deleted = await database.link_revoke(token, user_id)
    if not deleted:
        return _error("Link not found or not yours", 404, origin)

    return _json_response({"ok": True}, origin=origin)


# Простой rate-limiter in-memory: {user_id: [ts1, ts2, ...]}
_rate_limit: dict[int, list[float]] = {}


def _rate_check(user_id: int, limit: int = 5, window: float = 60.0) -> bool:
    now = time.time()
    timestamps = _rate_limit.get(user_id, [])
    timestamps = [t for t in timestamps if now - t < window]
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    _rate_limit[user_id] = timestamps
    return True


@router.post("/notify")
async def notify_user(request: Request) -> Response:
    """Бот отправляет сообщение пользователю.

    Тело: {"kind": "help"|"links"|"custom", "text": "..."} (для kind=custom).
    kind=help — краткая справка, links — список активных ссылок, custom — текст ≤500.
    """
    origin = request.headers.get("Origin", "")
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    ok, user = _verify_init_data(init_data)
    if not ok:
        return _error("Invalid or expired initData", 401, origin)

    user_id = user.get("id")
    if not isinstance(user_id, int):
        return _error("Invalid user id", 400, origin)

    if not _rate_check(user_id):
        return _error("Too many requests", 429, origin)

    try:
        body = await request.json()
    except Exception:
        return _error("Invalid JSON", 400, origin)

    kind = body.get("kind", "help")
    if kind not in ("help", "links", "custom"):
        return _error("Invalid kind", 400, origin)

    text = body.get("text", "")
    if kind == "custom":
        if not isinstance(text, str) or not text or len(text) > 500:
            return _error("text required (≤500 chars)", 400, origin)

    # Получим chat_id из БД (бот писал этому пользователю раньше)
    db_user = await database.user_get(user_id)
    if db_user is None:
        return _error("User not found (bot never messaged you)", 404, origin)

    chat_id = db_user[0]

    # Формируем сообщение
    if kind == "help":
        msg = (
            "🔐 Secret-bot Mini App\n\n"
            "• Отправьте файл боту — он зашифрует и даст ссылку.\n"
            "• В группе с кодовым словом файлы шифруются автоматически.\n"
            "• Открыв ссылку, введите слово и создайте passkey для входа по Face ID.\n\n"
            "Мини-апп показывает ваши ссылки и позволяет отозвать их."
        )
    elif kind == "links":
        links = await database.user_links(user_id)
        if not links:
            msg = "У вас пока нет ссылок."
        else:
            lines = [f"• {l['file_name']} — /d/{l['token']}" for l in links[:10]]
            msg = "Ваши ссылки:\n" + "\n".join(lines)
    else:
        msg = text

    # Отправляем через бота (нужен доступ к боту — передаётся через app.state)
    bot = request.app.state.bot
    try:
        await bot.send_message(chat_id=chat_id, text=msg)
    except Exception as e:
        logger.exception("notify send_message failed")
        return _error(f"Failed to send: {e}", 500, origin)

    return _json_response({"ok": True, "sent_to": chat_id}, origin=origin)
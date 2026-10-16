"""Сайт бота на FastAPI: страница кодового слова, выдача файла, passkey.

Веб-слой вынесен из crypt_bot.py и переведён с aiohttp на FastAPI.
Бот (aiogram) и сайт работают в одном процессе и в одном event loop:
uvicorn запускается как asyncio-задача, сигналами главного цикла
занимается aiogram (см. crypt_bot.main()).

Маршруты:
    GET  /d/{token}                        страница ввода кодового слова
    POST /d/{token}                        проверка слова и выдача файла
    GET  /d/{token}/get                    файл после входа по passkey
    POST /d/{token}/pw/register/options    challenge для создания passkey
    POST /d/{token}/pw/register/verify     сохранение passkey и ключа ссылки
    POST /d/{token}/pw/login/options       challenge для входа по passkey
    POST /d/{token}/pw/login/verify        проверка подписи, выдача сессии
    GET  /healthz                          проверка, что сайт жив
    GET  /manifest.webmanifest             PWA-манифест (Android)
    GET  /sw.js                            service worker (офлайн)
    GET  /icon-192.png, /icon-512.png      иконки PWA

Криптография, база, разбор WebAuthn и хендлеры бота остались
в crypt_bot.py — этот модуль только адаптирует их к HTTP.
"""

import asyncio
import hashlib
import html
import io
import json
import logging
import os
import re
import time
from urllib.parse import quote

from aiogram import Bot
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

import crypt_bot as cb
from cryptography.exceptions import InvalidTag

logger = logging.getLogger("cryptbot.web")

LINK_GONE = "Ссылка недействительна"

# ================================== САЙТ ====================================

PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#1a56a0">
<title>Расшифровка файла</title>
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon-192.png" type="image/png">
<link rel="apple-touch-icon" href="/icon-192.png">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Secret-bot">
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
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js').catch(function(){ /* офлайн-кэш не критичен */ });
}
</script>
</body></html>"""

# ------------------------------- PWA (Android) --------------------------------
# Страница уже адаптивная (viewport, max-width 420px), поэтому для Android
# достаточно PWA: ярлык на главном экране через «Добавить на главный экран»
# в Chrome. Без манифеста и service worker браузер такое не предложит.

MANIFEST = {
    "name": "Secret-bot — расшифровка файла",
    "short_name": "Secret-bot",
    "description": "Расшифровка файла по ссылке из Telegram",
    "start_url": ".",
    "scope": ".",
    "display": "standalone",
    "orientation": "portrait",
    "background_color": "#1a56a0",
    "theme_color": "#1a56a0",
    "lang": "ru",
    "icons": [
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png",
         "purpose": "any"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
         "purpose": "any"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
         "purpose": "maskable"},
    ],
}

SW_JS = """// Secret-bot: минимальный service worker, чтобы страницу можно было
// поставить на главный экран Android и открывать без сети.
const CACHE = 'secret-bot-v1';
const CORE = ['/icon-192.png', '/icon-512.png', '/manifest.webmanifest'];
self.addEventListener('install', function(e){
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(CORE); })
    .then(function(){ return self.skipWaiting(); }));
});
self.addEventListener('activate', function(e){
  e.waitUntil(caches.keys().then(function(keys){
    return Promise.all(keys.filter(function(k){ return k !== CACHE; })
      .map(function(k){ return caches.delete(k); }));
  }).then(function(){ return self.clients.claim(); }));
});
self.addEventListener('fetch', function(e){
  const req = e.request;
  if(req.method !== 'GET') return;
  let url;
  try{ url = new URL(req.url); }catch(err){ return; }
  if(url.origin !== self.location.origin) return;
  if(req.mode === 'navigate'){
    // Страницы: сначала сеть, при недоступности — из кэша.
    e.respondWith(fetch(req).then(function(r){
      const copy = r.clone();
      caches.open(CACHE).then(function(c){ c.put(req, copy); }).catch(function(){});
      return r;
    }).catch(function(){ return caches.match(req); }));
    return;
  }
  // Статика: сначала кэш.
  e.respondWith(caches.match(req).then(function(hit){
    if(hit) return hit;
    return fetch(req).then(function(r){
      if(r.ok){
        const copy = r.clone();
        caches.open(CACHE).then(function(c){ c.put(req, copy); }).catch(function(){});
      }
      return r;
    });
  }));
});
"""

# token -> (число неудач, время первой неудачи)
_fails: dict[str, tuple[int, float]] = {}


def _is_locked(token: str) -> bool:
    entry = _fails.get(token)
    if not entry:
        return False
    count, first = entry
    if time.time() - first > cb.FAIL_WINDOW:
        _fails.pop(token, None)
        return False
    return count >= cb.MAX_FAILS


def _register_fail(token: str) -> None:
    count, first = _fails.get(token, (0, time.time()))
    if time.time() - first > cb.FAIL_WINDOW:
        count, first = 0, time.time()
    _fails[token] = (count + 1, first)


def render_page(
    name: str,
    error: str = "",
    status: int = 200,
    token: str = "",
    blocks: str = "",
) -> HTMLResponse:
    err_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    body = (
        PAGE.replace("%NAME%", html.escape(name))
        .replace("%ERROR%", err_html)
        .replace("%TOKEN%", html.escape(token))
        .replace("%BLOCKS%", blocks)
    )
    return HTMLResponse(body, status_code=status)


def content_disposition(name: str) -> str:
    """Заголовок Content-Disposition с поддержкой юникода в имени."""
    ascii_name = re.sub(r'[^A-Za-z0-9._ -]', "_", name.encode("ascii", "ignore").decode()) or "file"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _bot(request: Request) -> Bot:
    return request.app.state.bot


async def _fetch_and_decrypt(bot: Bot, file_id: str, file_name: str, password: str) -> bytes:
    """Скачивает зашифрованный файл из Telegram и расшифровывает его."""
    buf = io.BytesIO()
    await bot.download(file_id, destination=buf)
    return await cb.run_crypto(cb.decrypt_file, buf.getvalue(), password)


def _file_response(data: bytes, file_name: str) -> Response:
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": content_disposition(file_name),
            "Cache-Control": "no-store",
        },
    )


def _apply_grant(response: Response, token: str) -> None:
    """Ставит короткую «печать»: человек только что ввёл верное слово."""
    name, value = cb._grant_cookie(token)
    response.set_cookie(
        name, value, max_age=cb.PW_GRANT_TTL, path=f"/d/{token}",
        httponly=True, secure=cb.BASE_URL.startswith("https"), samesite="lax",
    )


def _apply_session(response: Response, token: str, cred_id: str) -> None:
    """Ставит долгую сессию после входа по passkey."""
    name, value = cb._session_cookie(token, cred_id)
    response.set_cookie(
        name, value, max_age=cb.PW_SESSION_TTL, path=f"/d/{token}",
        httponly=True, secure=cb.BASE_URL.startswith("https"), samesite="lax",
    )


def _page_blocks(token: str, auth_ok: bool, grant_ok: bool) -> str:
    """Кнопки passkey под ситуацию: уже вошёл / можно создавать / можно войти."""
    if not cb.ENABLE_PASSKEY:
        return ""
    blocks = []
    if auth_ok:
        blocks.append(
            f'<a class="btn" href="/d/{html.escape(token)}/get">'
            "⬇️ Скачать файл (вход по passkey пройден)</a>"
        )
    has_pw = bool(cb._pw_list(token))
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


# ------------------------------- Страница и файл -----------------------------

async def web_form(token: str, request: Request) -> Response:
    """GET /d/{token} — страница ввода кодового слова (и кнопок passkey)."""
    rec = await cb.db_get(token)
    if not rec:
        return PlainTextResponse(LINK_GONE, status_code=404)
    auth_ok = cb._session_valid(request.cookies, token) is not None
    grant_ok = cb._grant_valid(request.cookies, token)
    return render_page(rec[1], token=token, blocks=_page_blocks(token, auth_ok, grant_ok))


async def web_download(token: str, request: Request) -> Response:
    """POST /d/{token} — проверка кодового слова и выдача расшифрованного файла."""
    rec = await cb.db_get(token)
    if not rec:
        return PlainTextResponse(LINK_GONE, status_code=404)
    file_id, file_name = rec

    if _is_locked(token):
        return render_page(
            file_name, "Слишком много неверных попыток. Попробуйте позже.", 429
        )

    form = await request.form()
    password = form.get("password", "")
    if not isinstance(password, str) or not password.strip():
        return render_page(file_name, "Введите кодовое слово.", 400)
    password = password.strip()  # так же, как при шифровании (подпись .strip())

    try:
        data = await _fetch_and_decrypt(_bot(request), file_id, file_name, password)
    except (InvalidTag, ValueError):
        _register_fail(token)
        return render_page(file_name, "Неверное кодовое слово.", 403)
    except Exception:
        logger.exception("Ошибка расшифровки на сайте")
        return render_page(file_name, "Внутренняя ошибка.", 500)

    _fails.pop(token, None)
    response = _file_response(data, file_name)
    if cb.ENABLE_PASSKEY:
        # Открываем окно регистрации passkey и держим обёрнутую копию
        # кодового слова в памяти — в базу она попадёт только при
        # создании passkey (см. _pending_promote).
        await asyncio.to_thread(cb._pending_set, token, password)
        _apply_grant(response, token)
    return response


async def web_get(token: str, request: Request) -> Response:
    """GET /d/{token}/get — выдача файла после входа по passkey."""
    rec = await cb.db_get(token)
    if not rec:
        return PlainTextResponse(LINK_GONE, status_code=404)
    file_id, file_name = rec
    grant_ok = cb._grant_valid(request.cookies, token)

    if cb._session_valid(request.cookies, token) is None:
        return render_page(
            file_name, "Войдите по passkey или введите кодовое слово.", 403,
            token=token, blocks=_page_blocks(token, False, grant_ok),
        )

    wrap = await asyncio.to_thread(cb._vault_get, token)
    if not wrap:
        return render_page(
            file_name,
            "Ключ для этой ссылки не сохранён — введите кодовое слово ещё раз.",
            403, token=token, blocks=_page_blocks(token, True, grant_ok),
        )
    password = await asyncio.to_thread(cb._vault_password, wrap)

    try:
        data = await _fetch_and_decrypt(_bot(request), file_id, file_name, password)
    except (InvalidTag, ValueError):
        logger.error("Сохранённый ключ не подошёл для %s", token[:8])
        return render_page(file_name, "Не удалось расшифровать файл сохранённым ключом.", 500)
    except Exception:
        logger.exception("Ошибка выдачи файла по passkey")
        return render_page(file_name, "Не удалось получить файл из Telegram.", 502)
    return _file_response(data, file_name)


# ------------------------- Эндпоинты passkey --------------------------------

async def pw_register_options(token: str, request: Request) -> Response:
    """POST /d/{token}/pw/register/options — challenge для создания passkey."""
    if not cb.ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    if not await cb.db_get(token):
        return _json_error("Ссылка недействительна", 404)
    if not cb._grant_valid(request.cookies, token):
        return _json_error("Сначала введите кодовое слово для этой ссылки", 403)
    challenge = await asyncio.to_thread(cb._challenge_new, token, "register")
    creds = await asyncio.to_thread(cb._pw_list, token)
    options = {
        "publicKey": {
            "rp": {"name": "Secret-bot", "id": cb.RP_ID},
            "user": {
                "id": cb._b64u(hashlib.sha256(f"{cb.RP_ID}|{token}".encode()).digest()),
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
    return JSONResponse(options)


async def pw_register_verify(token: str, request: Request) -> Response:
    """POST /d/{token}/pw/register/verify — сохраняет passkey и ключ ссылки."""
    if not cb.ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    if not await cb.db_get(token):
        return _json_error("Ссылка недействительна", 404)
    if not cb._grant_valid(request.cookies, token):
        return _json_error("Сначала введите кодовое слово для этой ссылки", 403)
    try:
        body = await request.json()
    except Exception:
        return _json_error("Некорректный запрос")
    try:
        client_json = cb._unb64u(str(body.get("clientDataJSON", "")))
        attestation_object = cb._unb64u(str(body.get("attestationObject", "")))
        challenge = str(json.loads(client_json).get("challenge", ""))
    except Exception:
        return _json_error("Некорректный ответ браузера")
    if not await asyncio.to_thread(cb._challenge_take, token, "register", challenge):
        return _json_error("Challenge устарел — нажмите кнопку ещё раз")
    try:
        cred_id, public_key, alg, counter = cb.webauthn_register(
            client_json, attestation_object, challenge
        )
    except ValueError as exc:
        return _json_error(str(exc))
    await asyncio.to_thread(cb._pw_add, token, cred_id, public_key, alg, counter)
    if not await asyncio.to_thread(cb._pending_promote, token):
        logger.warning("Passkey создан без сохранённого ключа для %s", token[:8])
    logger.info("Passkey создан: %s… (ссылка %s)", cred_id[:12], token[:8])
    return JSONResponse({"ok": True})


async def pw_login_options(token: str, request: Request) -> Response:
    """POST /d/{token}/pw/login/options — challenge для входа по passkey."""
    if not cb.ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    if not await cb.db_get(token):
        return _json_error("Ссылка недействительна", 404)
    creds = await asyncio.to_thread(cb._pw_list, token)
    if not creds:
        return _json_error("Для этой ссылки passkey ещё не создан", 400)
    challenge = await asyncio.to_thread(cb._challenge_new, token, "login")
    options = {
        "publicKey": {
            "rpId": cb.RP_ID,
            "challenge": challenge,
            "timeout": 60000,
            "allowCredentials": [{"type": "public-key", "id": c} for c in creds],
            "userVerification": "required",
        }
    }
    return JSONResponse(options)


async def pw_login_verify(token: str, request: Request) -> Response:
    """POST /d/{token}/pw/login/verify — проверка подписи и выдача сессии."""
    if not cb.ENABLE_PASSKEY:
        return _json_error("Passkey выключен", 403)
    if not await cb.db_get(token):
        return _json_error("Ссылка недействительна", 404)
    try:
        body = await request.json()
    except Exception:
        return _json_error("Некорректный запрос")
    cred_id = str(body.get("id", ""))
    record = await asyncio.to_thread(cb._pw_get, cred_id) if cred_id else None
    if not record or record[0] != token:
        return _json_error("passkey не найден — войдите кодовым словом", 404)
    try:
        client_json = cb._unb64u(str(body.get("clientDataJSON", "")))
        auth_data = cb._unb64u(str(body.get("authenticatorData", "")))
        signature = cb._unb64u(str(body.get("signature", "")))
        challenge = str(json.loads(client_json).get("challenge", ""))
    except Exception:
        return _json_error("Некорректный ответ браузера")
    if not await asyncio.to_thread(cb._challenge_take, token, "login", challenge):
        return _json_error("Challenge устарел — нажмите кнопку ещё раз")
    _token, public_key, counter_stored = record
    try:
        counter = cb.webauthn_assert(client_json, auth_data, signature, challenge, public_key)
    except ValueError as exc:
        return _json_error(str(exc), 403)
    if counter > 0 and counter_stored > 0 and counter <= counter_stored:
        logger.warning("Счётчик passkey не вырос (%s <= %s)", counter, counter_stored)
        return _json_error("Счётчик ключа не изменился — вход запрещён", 403)
    if counter:
        await asyncio.to_thread(cb._pw_bump, cred_id, counter)
    logger.info("Вход по passkey: %s… (ссылка %s)", cred_id[:12], token[:8])
    response = JSONResponse({"ok": True})
    _apply_session(response, token, cred_id)
    return response


async def healthz() -> dict:
    """GET /healthz — сайт жив, мастер-ключ доступен."""
    await asyncio.to_thread(cb._master_key)
    return {"ok": True}


def _static_path(name: str) -> str:
    """Путь к файлу в static/ рядом с web_app.py."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", name)


def pwa_manifest() -> JSONResponse:
    """GET /manifest.webmanifest — описание PWA для установки на экран."""
    return JSONResponse(MANIFEST)


def pwa_sw() -> Response:
    """GET /sw.js — service worker."""
    return Response(SW_JS, media_type="application/javascript",
                    headers={"Cache-Control": "no-cache"})


def pwa_icon(size: int):
    """GET /icon-{size}.png — иконка. Фабрика: размер подставляется в путь."""

    async def handler() -> Response:
        path = _static_path(f"icon-{size}.png")
        if not os.path.isfile(path):
            return PlainTextResponse("нет иконки", status_code=404)
        with open(path, "rb") as handle:
            data = handle.read()
        return Response(data, media_type="image/png",
                        headers={"Cache-Control": "public, max-age=86400"})

    return handler


def create_app(bot: Bot) -> FastAPI:
    """Собирает FastAPI-приложение сайта. Бот нужен, чтобы отдать файл."""
    app = FastAPI(
        title="Secret-bot",
        docs_url=None, redoc_url=None, openapi_url=None,  # документации API не нужно
    )
    app.state.bot = bot
    app.add_api_route("/d/{token}", web_form, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/d/{token}", web_download, methods=["POST"], response_class=Response)
    app.add_api_route("/d/{token}/get", web_get, methods=["GET"], response_class=Response)
    app.add_api_route("/d/{token}/pw/register/options", pw_register_options,
                      methods=["POST"], response_class=JSONResponse)
    app.add_api_route("/d/{token}/pw/register/verify", pw_register_verify,
                      methods=["POST"], response_class=JSONResponse)
    app.add_api_route("/d/{token}/pw/login/options", pw_login_options,
                      methods=["POST"], response_class=JSONResponse)
    app.add_api_route("/d/{token}/pw/login/verify", pw_login_verify,
                      methods=["POST"], response_class=JSONResponse)
    app.add_api_route("/healthz", healthz, methods=["GET"], response_class=JSONResponse)
    # PWA: манифест, service worker и иконки для установки на экран Android
    app.add_api_route("/manifest.webmanifest", pwa_manifest,
                      methods=["GET"], response_class=JSONResponse)
    app.add_api_route("/sw.js", pwa_sw, methods=["GET"], response_class=Response)
    app.add_api_route("/icon-192.png", pwa_icon(192),
                      methods=["GET"], response_class=Response)
    app.add_api_route("/icon-512.png", pwa_icon(512),
                      methods=["GET"], response_class=Response)
    return app

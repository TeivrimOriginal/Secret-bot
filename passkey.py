"""Вход по отпечатку пальца / Face ID: разбор WebAuthn и куки grant/сессии.

Здесь две вещи, которые неразрывно связаны с ключом:

    1. Проверка ответа аутентификатора — webauthn_register() при создании
       ключа и webauthn_assert() при входе. Ключ остаётся на устройстве,
       сервер видит только публичную часть и подпись.
    2. Две подписанные куки, из-за которых этот модуль и лежит рядом с БД:
       grant — «человек только что ввёл верное кодовое слово для этой
       ссылки» (окно PW_GRANT_TTL, нужно для регистрации ключа);
       session — «вход по passkey подтверждён» (PW_SESSION_TTL, нужен,
       чтобы отдать файл вообще без кодового слова).

Что проверяется и почему:
    clientData.type      — чтобы ответ на «создание» нельзя было скормить
                           как ответ на «вход»;
    challenge            — одноразовый, гасится в БД при первом использовании;
    origin               — ровно ORIGIN, адрес нашего сайта;
    crossOrigin          — запрещён встроенный вызов из чужого фрейма;
    rpIdHash             — ключ создан для нашего хоста, а не для чужого;
    флаги UP и UV        — пользователь реально присутствовал и подтвердил
                           биометрией/PIN (userVerification: required);
    подпись ES256/RS256  — по(authData + SHA256(clientDataJSON));
    счётчик              — не рос между входами -> отказ (клон ключа).

Аттестат (attStmt) намеренно НЕ проверяется: ключ хранится только у нас, а
право его создать и так определяется кодовым словом. Доказывать подлинность
модели устройства здесь нечего.
"""

import hashlib
import hmac
import io
import json
import time
from collections.abc import Mapping

from cbor2 import CBORDecoder, loads as cbor_loads
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import config
import database
from crypto import b64u, unb64u

# --------------------------- Разбор ответа браузера --------------------------

def rp_hash() -> bytes:
    try:
        host = config.RP_ID.encode("idna")
    except Exception:
        host = config.RP_ID.encode("ascii", "ignore")
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
    if data.get("origin") != config.ORIGIN:
        return f"Неверный origin: ожидается {config.ORIGIN}"
    if data.get("crossOrigin"):
        return "Запрещён встроенный (cross-origin) вызов"
    return None


def _parse_auth_data(auth: bytes) -> tuple[int, int, str | None, dict | None]:
    """Разбирает authenticator data: флаги, счётчик, credId и COSE-ключ."""
    if len(auth) < 37:
        raise ValueError("Слишком короткие authenticator data")
    # локальная переменная названа *_bytes, а не rp_hash: иначе она
    # перекрыла бы функцию rp_hash() при переименовании
    rp_hash_bytes, flags = auth[:32], auth[32]
    counter = int.from_bytes(auth[33:37], "big")
    if not hmac.compare_digest(rp_hash_bytes, rp_hash()):
        raise ValueError(f"rpIdHash не совпадает (ожидается {config.RP_ID})")
    cred_id, cose = None, None
    if flags & 0x40:  # AT — есть данные аттестованного ключа
        if len(auth) < 55:
            raise ValueError("Оборванные данные ключа")
        cred_len = int.from_bytes(auth[53:55], "big")
        end = 55 + cred_len
        if len(auth) < end:
            raise ValueError("Оборванный идентификатор ключа")
        cred_id = b64u(auth[55:end])
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


# --------------------------- Куки: grant и сессия ----------------------------

def sign(payload: str) -> str:
    return hmac.new(database.master_key_sync(), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def grant_cookie(token: str) -> tuple[str, str]:
    """Кука «человек только что ввёл верное кодовое слово для этой ссылки»."""
    exp = int(time.time()) + config.PW_GRANT_TTL
    return f"pwgrant_{token}", f"{exp}|{sign(f'grant|{token}|{exp}')}"


def grant_valid(cookies: Mapping[str, str], token: str) -> bool:
    """Проверяет «печать» по словарю кук запроса (без привязки к HTTP-фреймворку)."""
    name, _expected = grant_cookie(token)
    raw = cookies.get(name)
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
    return hmac.compare_digest(sig, sign(f"grant|{token}|{exp}"))


def session_cookie(token: str, cred_id: str) -> tuple[str, str]:
    exp = int(time.time()) + config.PW_SESSION_TTL
    return f"pwsess_{token}", f"{cred_id}|{exp}|{sign(f'sess|{token}|{cred_id}|{exp}')}"


def session_valid(cookies: Mapping[str, str], token: str) -> str | None:
    """Возвращает cred_id, если стоит действительная сессия по passkey."""
    raw = cookies.get(f"pwsess_{token}")
    if not raw or raw.count("|") != 2:
        return None
    cred_id, exp_s, sig = raw.split("|")
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    if exp <= time.time():
        return None
    if not hmac.compare_digest(sig, sign(f"sess|{token}|{cred_id}|{exp}")):
        return None
    return cred_id or None

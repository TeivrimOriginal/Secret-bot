"""Шифрование и расшифровка файлов: AES-256-GCM, ключ из пароля через PBKDF2.

Формат зашифрованного файла:
    [8 байт "CRYPTv1\\0"][16 байт соли][12 байт nonce][шифртекст + тег GCM]

На каждую операцию две обёртки, и разница между ними не в алгоритме, а в том,
где он выполняется:

    encrypt_file_sync / decrypt_file_sync — обычные функции. Нужны там, где
        цикла asyncio нет: демо-сервер, самопроверка сборки, тесты.
    encrypt_file / decrypt_file — await-обёртки. PBKDF2 на 600 000 итераций
        считает миллионы SHA-256 и держит GIL, поэтому работа уходит в поток,
        а CRYPTO_SEM не даёт шифровать больше двух файлов одновременно —
        иначе на телефоне и на слабом VPS всё встаёт колом.

Режим работы бота определяется ТОЛЬКО по маркеру is_encrypted(), а не по
имени файла: .enc можно переименовать, маркер — нет.
"""

import asyncio
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import HEADER_SIZE, KDF_ITERATIONS, MAGIC, NONCE_SIZE, SALT_SIZE, TAG_SIZE

__all__ = [
    "MAGIC", "HEADER_SIZE",
    "is_encrypted", "make_key",
    "encrypt_file_sync", "decrypt_file_sync",
    "encrypt_file", "decrypt_file", "run_crypto",
    "b64u", "unb64u",
    "InvalidTag",
]

# PBKDF2 тяжёлый: ограничиваем число одновременных операций
CRYPTO_SEM = asyncio.Semaphore(2)


def b64u(data: bytes) -> str:
    """Base64url без '=' — формат challenge/credId в WebAuthn и в ссылках."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    """Обратная к b64u: восстанавливает padding, которого нет в строке."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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


def encrypt_file_sync(data: bytes, password: str) -> bytes:
    """
    Шифрует данные AES-256-GCM.
    Возвращает: MAGIC + соль + nonce + (шифртекст + тег GCM).
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = make_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_file_sync(data: bytes, password: str) -> bytes:
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


async def encrypt_file(data: bytes, password: str) -> bytes:
    """await-обёртка encrypt_file_sync: считает в потоке, не блокируя цикл."""
    return await run_crypto(encrypt_file_sync, data, password)


async def decrypt_file(data: bytes, password: str) -> bytes:
    """await-обёртка decrypt_file_sync. Плохой пароль — InvalidTag."""
    return await run_crypto(decrypt_file_sync, data, password)

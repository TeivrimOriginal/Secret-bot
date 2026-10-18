import html
import io
import logging
import secrets
import time
from aiogram import Bot, F, Router
from aiogram.types import BufferedInputFile, ChatMemberUpdated, Message

from config import BASE_URL, GROUP_MAX_SIZE, ENC_SUFFIX
from crypto import is_encrypted, encrypt_file
from database import group_upsert, group_remove, codeword_get, db_add_link

logger = logging.getLogger("crypt_bot")
group_router = Router()
group_router.message.filter(F.chat.type.in_({"group", "supergroup"}))
events_router = Router()

_warned: dict[int, float] = {}

@events_router.my_chat_member()
async def on_bot_membership(event: ChatMemberUpdated) -> None:
    if event.chat.type not in ("group", "supergroup"):
        return
    status = event.new_chat_member.status
    if status in ("member", "administrator"):
        await group_upsert(event.chat.id, event.chat.title or str(event.chat.id))
    elif status in ("left", "kicked"):
        await group_remove(event.chat.id)

async def safe_delete(bot: Bot, chat_id: int, message_id: int | None) -> bool:
    if message_id is None:
        return False
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
        return True
    except Exception:
        return False

def _result_name(file_name: str, mode: str) -> str:
    if mode == "encrypt":
        return file_name + ENC_SUFFIX
    return file_name

@group_router.message(F.document)
async def on_group_document(message: Message, bot: Bot) -> None:
    doc = message.document
    chat = message.chat
    await group_upsert(chat.id, chat.title or str(chat.id))

    codeword = await codeword_get(chat.id)
    if not codeword:
        if time.time() - _warned.get(chat.id, 0) > 600:
            _warned[chat.id] = time.time()
            await message.answer(
                "⚠️ Для этой группы не задано кодовое слово. Администратор: напишите мне в личку /setcode."
            )
        return

    if doc.file_size and doc.file_size > GROUP_MAX_SIZE:
        await message.answer("❌ Файл слишком большой для обработки (~20 МБ лимит).")
        return

    try:
        buffer = io.BytesIO()
        await bot.download(doc, destination=buffer)
        file_bytes = buffer.getvalue()
    except Exception:
        await message.answer("❌ Не удалось скачать файл.")
        return

    if is_encrypted(file_bytes):
        return

    if not await safe_delete(bot, chat.id, message.message_id):
        await message.answer("⚠️ Не могу удалить оригинал. Сделайте меня администратором с правом удаления сообщений.")
        return

    file_name = doc.file_name or "file"
    user = message.from_user
    sender = html.escape(user.full_name) if user else "участника"

    try:
        encrypted = await encrypt_file(file_bytes, codeword)
        token = secrets.token_urlsafe(16)
        link = f"{BASE_URL}/d/{token}"

        sent = await message.answer_document(
            BufferedInputFile(encrypted, filename=_result_name(file_name, "encrypt")),
            caption=(
                f"🔒 Файл <b>{html.escape(file_name)}</b> от {sender} зашифрован.\n\n"
                f"🔗 {link}\n\n"
                "Откройте ссылку и введите кодовое слово группы для скачивания."
            ),
        )
        await db_add_link(token, sent.document.file_id, file_name)
    except Exception:
        logger.exception("Ошибка шифрования файла в группе")
        await message.answer("❌ Ошибка обработки файла.")

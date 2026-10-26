"""Личный чат с ботом: шифрование и расшифровка по паролю.

Хендлеры идут в порядке «пользователь что-то делает»:

    /start, /cancel   — справка и сброс состояния
    /setcode          — админ выбирает группу и задаёт её кодовое слово
    документ          — бот читает файл, определяет режим по маркеру
                        CRYPTv1\\0, удаляет незашифрованный оригинал из чата
    текст в состоянии  — пароль; на выходе зашифрованный файл + ссылка

Файл в чате живёт только пока FSM его помнит: незашифрованный оригинал мы
сразу удаляем из Telegram, чтобы он не лежал в переписке, а незашифрованный
файл в памяти — до ввода пароля. MemoryStorage при перезапуске всё это
теряет, и пользователю приходится присылать файл заново: для продакшена
нужно заменить его на RedisStorage (см. комментарий в main()).
"""

import html
import io
import logging
import secrets

from aiogram import Bot, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from cryptography.exceptions import InvalidTag

import crypto
import database
from database import user_upsert
from config import (
    BASE_URL,
    ENC_SUFFIX,
    ERR_WRONG_PASSWORD,
    MAX_DOWNLOAD_SIZE,
    MIN_CODEWORD_LEN,
)

logger = logging.getLogger("crypt_bot.private")

private_router = Router()
private_router.message.filter(F.chat.type == "private")


class CryptStates(StatesGroup):
    """Ожидание пароля от пользователя."""

    waiting_for_password = State()


class SetCodeStates(StatesGroup):
    """Ожидание кодового слова группы (команда /setcode)."""

    waiting_for_codeword = State()


# ----------------------------- Вспомогательное ------------------------------

def _result_name(file_name: str, mode: str) -> str:
    """Подбирает имя итогового файла."""
    if mode == "encrypt":
        return file_name + ENC_SUFFIX
    if file_name.lower().endswith(ENC_SUFFIX) and len(file_name) > len(ENC_SUFFIX):
        return file_name[: -len(ENC_SUFFIX)]
    return file_name + ".dec"


async def is_group_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    """Проверяет, что пользователь — создатель или администратор группы."""
    try:
        member = await bot.get_chat_member(chat_id, user_id)
    except Exception:
        return False
    return member.status in ("creator", "administrator")


async def safe_delete(bot: Bot, chat_id: int, message_id: int | None) -> bool:
    """
    Пытается удалить сообщение, возвращает True при успехе.
    Ошибки не критичны: сообщение могло быть удалено ранее, быть старше
    48 часов или у бота нет прав (в группах).
    """
    if message_id is None:
        return False
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
        return True
    except Exception:
        logger.warning("Не удалось удалить сообщение %s", message_id)
        return False


# ------------------------------- Команды -------------------------------------

@private_router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext) -> None:
    """Краткая инструкция."""
    await state.clear()
    await message.answer(
        "🔐 Я шифрую и расшифровываю файлы по паролю.\n\n"
        "1. Отправьте мне файл (как документ).\n"
        "2. Я сам пойму, что делать: обычный файл — зашифрую "
        "(и сразу удалю оригинал из чата), зашифрованный мной — расшифрую.\n"
        "3. Напишите пароль — получите результат. "
        "Сообщение с паролем я тоже удалю.\n\n"
        "Алгоритм: AES-256-GCM + PBKDF2-SHA256.\n"
        "Лимит размера файла: 20 МБ.\n"
        "/cancel — отменить текущую операцию.\n\n"
        "👥 Группы: добавьте меня в группу администратором (право «Удаление "
        "сообщений»), затем администратор пишет мне здесь /setcode, выбирает "
        "группу и задаёт кодовое слово. После этого все файлы, присланные "
        "в группу, я шифрую этим словом и выдаю кликабельную ссылку "
        "на страницу скачивания.\n\n"
        "🔑 Passkey: открыв ссылку и введён один раз кодовое слово, можно "
        "создать passkey — дальше файл открывается по отпечатку пальца "
        "или Face ID, без ввода кодового слова."
    )


@private_router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    """Сбрасывает состояние."""
    await state.clear()
    await message.answer("Операция отменена. Отправьте новый файл.")


# ------------------------- Кодовое слово группы -----------------------------

@private_router.message(Command("setcode"))
async def cmd_setcode(message: Message, state: FSMContext, bot: Bot) -> None:
    """Показывает группы, где пользователь админ и где есть бот."""
    await state.clear()
    mine = []
    for chat_id, title in await database.group_list():
        if await is_group_admin(bot, chat_id, message.from_user.id):
            mine.append((chat_id, title))
    if not mine:
        await message.answer(
            "Не нашёл групп, где вы администратор, а я добавлен. "
            "Добавьте меня в группу админом (право «Удаление сообщений») "
            "и повторите /setcode."
        )
        return
    kb = InlineKeyboardBuilder()
    for chat_id, title in mine:
        kb.button(text=title[:60], callback_data=f"grp:{chat_id}")
    kb.adjust(1)
    await message.answer(
        "Для какой группы задать кодовое слово?", reply_markup=kb.as_markup()
    )


@private_router.callback_query(F.data.startswith("grp:"))
async def on_group_chosen(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    """Группа выбрана — ждём кодовое слово."""
    chat_id = int(call.data.split(":", 1)[1])
    if not await is_group_admin(bot, chat_id, call.from_user.id):
        await call.answer("Вы не администратор этой группы", show_alert=True)
        return
    title = dict(await database.group_list()).get(chat_id)
    if title is None:
        await call.answer("Группа не найдена", show_alert=True)
        return
    await state.set_state(SetCodeStates.waiting_for_codeword)
    await state.update_data(chat_id=chat_id, title=title)
    await bot.send_message(
        call.from_user.id,
        f"Введите кодовое слово для «{html.escape(title)}» "
        f"(не короче {MIN_CODEWORD_LEN} символов). Сообщение я удалю.\n"
        "Файлы, зашифрованные раньше, останутся со старым словом.\n"
        "/cancel — отмена.",
    )
    await call.answer()


@private_router.message(
    SetCodeStates.waiting_for_codeword, F.text, ~F.text.startswith("/")
)
async def on_codeword(message: Message, state: FSMContext, bot: Bot) -> None:
    """Сохраняет кодовое слово группы."""
    codeword = message.text.strip()
    await safe_delete(bot, message.chat.id, message.message_id)

    if len(codeword) < MIN_CODEWORD_LEN:
        await message.answer(
            f"❌ Слишком короткое слово (минимум {MIN_CODEWORD_LEN} символов). "
            "Введите другое или /cancel."
        )
        return

    data = await state.get_data()
    chat_id: int = data["chat_id"]
    title: str = data["title"]
    await state.clear()

    if not await is_group_admin(bot, chat_id, message.from_user.id):
        await message.answer("❌ Вы больше не администратор этой группы.")
        return

    await database.codeword_set(chat_id, codeword)
    await message.answer(
        f"✅ Кодовое слово для «{html.escape(title)}» сохранено. "
        "Теперь файлы, присланные в группу, будут шифроваться им."
    )


# ------------------------------ Файлы в личке --------------------------------

@private_router.message(F.document)
async def on_document(message: Message, state: FSMContext, bot: Bot) -> None:
    """
    Принимает документ, определяет режим по магическому маркеру
    и запрашивает пароль. Незашифрованный файл сразу удаляется из чата.
    """
    doc = message.document

    if doc.file_size and doc.file_size > MAX_DOWNLOAD_SIZE:
        await message.answer("❌ Файл слишком большой: бот может скачать не более 20 МБ.")
        return

    # Запомним пользователя, чтобы бот мог потом написать ему из мини-аппа.
    if message.from_user:
        await database.user_upsert(
            message.from_user.id,
            message.chat.id,
            message.from_user.username,
            message.from_user.full_name,
        )

    try:
        buffer = io.BytesIO()
        await bot.download(doc, destination=buffer)
        file_bytes = buffer.getvalue()
    except Exception:
        logger.exception("Не удалось скачать файл")
        await message.answer("❌ Не удалось скачать файл. Попробуйте ещё раз.")
        return

    # Режим определяется ТОЛЬКО по магическому маркеру, не по имени файла
    mode = "decrypt" if crypto.is_encrypted(file_bytes) else "encrypt"

    # Сразу удаляем незашифрованный файл из чата: данные уже в памяти бота.
    if mode == "encrypt":
        await safe_delete(bot, message.chat.id, message.message_id)

    await state.set_state(CryptStates.waiting_for_password)
    await state.update_data(
        file_bytes=file_bytes,
        file_name=doc.file_name or "file",
        mode=mode,
    )

    if mode == "decrypt":
        await message.answer("🔓 Файл зашифрован. Введите пароль для расшифровки:")
    else:
        await message.answer(
            "🔒 Файл получен и удалён из чата. Введите пароль для шифрования:"
        )


@private_router.message(CryptStates.waiting_for_password, F.text)
async def on_password(message: Message, state: FSMContext, bot: Bot) -> None:
    """Принимает пароль, выполняет операцию и отправляет результат."""
    password = message.text
    data = await state.get_data()
    file_bytes: bytes = data["file_bytes"]
    file_name: str = data["file_name"]
    mode: str = data["mode"]

    await safe_delete(bot, message.chat.id, message.message_id)

    try:
        token = None
        if mode == "encrypt":
            result = await crypto.encrypt_file(file_bytes, password)
            token = secrets.token_urlsafe(16)
            link = f"{BASE_URL}/d/{token}"
            caption = (
                "✅ Файл зашифрован.\n\n"
                f'🔗 <a href="{html.escape(link)}">{html.escape(link)}</a>\n\n'
                "Ссылка открывается прямо здесь в Telegram. Один раз введите "
                "на странице пароль — и можно создать passkey, дальше вход "
                "по Face ID / отпечатку без пароля."
            )
        else:
            result = await crypto.decrypt_file(file_bytes, password)
            caption = "✅ Файл расшифрован"

        sent = await message.answer_document(
            BufferedInputFile(result, filename=_result_name(file_name, mode)),
            caption=caption,
        )
        # ссылку запоминаем только для зашифрованного результата
        if token and sent.document:
            await database.add_link(token, sent.document.file_id, file_name)
    except InvalidTag:
        await message.answer(ERR_WRONG_PASSWORD)
    except ValueError:
        logger.warning("Некорректный формат зашифрованного файла")
        await message.answer(ERR_WRONG_PASSWORD)
    except Exception:
        logger.exception("Ошибка при обработке файла")
        await message.answer("❌ Произошла внутренняя ошибка. Попробуйте позже.")
    finally:
        await state.clear()

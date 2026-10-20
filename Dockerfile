# syntax=docker/dockerfile:1.7
# =====================================================================================
# Secret-bot — образ для деплоя на PaaS (Render, Northflank, Railway, Fly, VPS).
#
# Бот (aiogram, long polling) и сайт (FastAPI/uvicorn) живут в одном процессе:
# сайт отдаёт файл, скачивая его из Telegram по file_id через bot.download(),
# поэтому разделить их на два контейнера нельзя без общей базы и бота.
#
# Собирается из локального кода, не из репозитория: COPY берёт то, что
# лежит рядом, и в образ попадает ровно проверенная версия.
# =====================================================================================

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Зависимости — отдельным слоем: правка кода не пересобирает pip.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py crypto.py database.py fsm_storage.py passkey.py \
     private.py groups.py web_app.py crypt_bot.py launcher.py ./
COPY static ./static

# Данные (база SQLite) — в отдельном каталоге, который на PaaS монтируют
# как диск. Если каталог не смонтирован, ссылка пропадёт при рестарте.
ENV DB_PATH=/data/links.db \
    ENABLE_WEB=1 \
    WEB_HOST=0.0.0.0 \
    LOG_LEVEL=INFO
RUN mkdir -p /data && chmod 777 /data

# Непривилегированный пользователь: на PaaS процесс и так обычно не root,
# и внутри образа это то же самое — меньше прав, меньше риска.
RUN useradd --create-home --uid 10001 secretbot \
    && chown -R secretbot:secretbot /app /data
USER secretbot

EXPOSE 8080

# Проверка живости: платформа должна знать, что сервис поднялся.
# /healthz отдаёт 200 и {"ok": true}, если мастер-ключ доступен.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORT','8080')+'/healthz',timeout=4).status==200 else 1)"

# launcher.py читает BOT_TOKEN и BASE_URL из окружения, поднимает бота
# и сайт в одном процессе.
CMD ["python", "-u", "launcher.py"]

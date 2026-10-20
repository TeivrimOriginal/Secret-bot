"""Проверка Dockerfile без Docker.

На этой машине Docker не установлен, поэтому `docker build` не запустить.
Но Dockerfile всё равно проверяем: он должен собирать образ, в котором
бот и сайт действительно работают.

Что проверяется:

  * Dockerfile разбирается и содержит обязательные шаги;
  * все файлы, которые он копирует, существуют (иначе сборка падает на
    COPY с непонятной ошибкой);
  * образ запускает `launcher.py`, а не что-то другое;
  * каталог данных создан и доступен непривилегированному пользователю;
  * версия Python из образа не ниже той, на которой код проверен;
  * healthcheck бьёт в существующий маршрут `/healthz`;
  * порт по умолчанию совпадает с тем, который читает `config.py`.

Использование: python scripts/verify_dockerfile.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
CONFIG = ROOT / "config.py"

PASSED: list[str] = []
FAILED: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    if condition:
        PASSED.append(label)
        print(f"  PASS  {label}")
    else:
        FAILED.append(f"{label} — {detail}")
        print(f"  FAIL  {label}  {detail}")
    return bool(condition)


def main() -> int:
    print("=== проверка Dockerfile (Docker на машине нет) ===")

    if not check("Dockerfile есть", DOCKERFILE.is_file()):
        return 1

    text = DOCKERFILE.read_text(encoding="utf-8")

    # --- базовые шаги ---
    # FROM ищется построчно: в начале файла может стоять директива
    # `# syntax=docker/dockerfile:1.7`, и `text.startswith("FROM ")`
    # на такой файл ругается, хотя образ вполне рабочий.
    from_line = re.search(r"^FROM\s+(\S+)", text, re.MULTILINE)
    check("задан базовый образ", from_line is not None, text[:120])
    check("есть WORKDIR", re.search(r"^WORKDIR\s+\S+", text, re.MULTILINE) is not None, "")
    check("есть CMD", re.search(r"^CMD\s+", text, re.MULTILINE) is not None, "")
    check("указано EXPOSE", re.search(r"^EXPOSE\s+\d+", text, re.MULTILINE) is not None, "")

    # --- копируемые файлы существуют ---
    copied: list[str] = []
    for match in re.finditer(r"^COPY\s+(.*)$", text, re.MULTILINE):
        parts = match.group(1).split()
        if parts and parts[0].startswith("--"):
            parts = parts[1:]
        # пропускаем пары "источник назначение"
        for name in parts[:-1]:
            if name.startswith("--"):
                continue
            copied.append(name)
    missing = [name for name in copied if not (ROOT / name).exists()]
    check("все копируемые файлы существуют", not missing, f"нет: {missing}")

    # --- точка входа ---
    cmd = re.search(r"^CMD\s+\[(.*)\]", text, re.MULTILINE)
    check("CMD запускает launcher.py", cmd is not None and "launcher.py" in cmd.group(1),
       cmd.group(1) if cmd else "нет CMD")
    check("CMD использует python -u (логи сразу видны)",
          cmd is not None and '"-u"' in cmd.group(1),
          cmd.group(1) if cmd else "нет CMD")

    # --- пользователь и каталог данных ---
    check("образ работает не под root",
          re.search(r"^USER\s+(?!root)\S+", text, re.MULTILINE) is not None, "")
    check("каталог данных создан при сборке",
          re.search(r"^RUN\s+.*mkdir\s+-p", text, re.MULTILINE) is not None, "")
    check("каталогу данных выданы права",
          re.search(r"^RUN\s+.*chmod", text, re.MULTILINE) is not None, "")

    # --- путь базы совпадает с config.py ---
    env_db = re.search(r"^ENV\s+DB_PATH=(\S+)", text, re.MULTILINE)
    check("в образе задан DB_PATH", env_db is not None, "")
    db_path = env_db.group(1) if env_db else ""
    check("путь базы внутри /data (каталог в образе)",
          db_path.startswith("/data/"), db_path)
    check("путь базы соответствует каталогу из mkdir",
          bool(db_path) and f"mkdir -p /data" in text, db_path)

    # --- порт ---
    env_port = re.search(r"^EXPOSE\s+(\d+)", text, re.MULTILINE)
    check("порт указан в EXPOSE", env_port is not None, "")
    port = env_port.group(1) if env_port else "8080"
    # Порт по умолчанию должен совпадать с тем, который читает config.py.
    # Строка выглядит так:
    #   WEB_PORT = int(os.getenv("WEB_PORT") or os.getenv("PORT") or "8080")
    # Разбирать её регуляркой с вложенными скобками неудобно, поэтому
    # берём последнюю строку в кавычках после `or`.
    config_text = CONFIG.read_text(encoding="utf-8")
    web_port_line = next(
        (line for line in config_text.splitlines()
         if line.strip().startswith("WEB_PORT =")),
        "",
    )
    check("в config.py есть WEB_PORT", bool(web_port_line), "")
    default = re.findall(r'"(\d+)"', web_port_line)
    check("в config.py есть значение порта по умолчанию", bool(default),
          web_port_line)
    check("порт по умолчанию совпадает с config.py",
          bool(default) and default[-1] == port,
          f"в образе {port}, в config.py {default[-1] if default else '?'}")
    check("config.py читает PORT (так задают порт все PaaS)",
          'os.getenv("PORT")' in config_text, "")

    # --- healthcheck бьёт в существующий маршрут ---
    health = re.search(r"HEALTHCHECK.*?CMD\s+(.*)", text, re.DOTALL)
    check("healthcheck определён", health is not None, "")
    if health:
        body = health.group(1)
        check("healthcheck проверяет /healthz", "/healthz" in body, body[:120])
        check("healthcheck читает порт из PORT", "PORT" in body, body[:120])

    # --- маршрут /healthz реально есть в коде ---
    web_app = (ROOT / "web_app.py").read_text(encoding="utf-8")
    check("маршрут /healthz есть в web_app.py", '"/healthz"' in web_app, "")

    # --- версия Python ---
    from_match = re.search(r"^FROM\s+python:(\d+)\.(\d+)", text, re.MULTILINE)
    if check("в образе задан python", from_match is not None, ""):
        minor = int(from_match.group(2))
        check("версия Python не ниже 3.11 (нужен PEP 669 для pytest-asyncio)",
              minor >= 11, f"python 3.{minor}")

    # --- .dockerignore не пускает секреты ---
    if check(".dockerignore есть", DOCKERIGNORE.is_file()):
        ignore = DOCKERIGNORE.read_text(encoding="utf-8")
        for pattern in ("secret-bot.env", "*.db", ".venv/"):
            check(f".dockerignore исключает {pattern}", pattern in ignore, "")

    # --- в образ не попадают тесты и Android ---
    if check(".dockerignore есть", DOCKERIGNORE.is_file()):
        ignore = DOCKERIGNORE.read_text(encoding="utf-8")
        check(".dockerignore исключает tests/", "tests/" in ignore, "")
        check(".dockerignore исключает android/", "android/" in ignore, "")

    print(f"passed: {len(PASSED)}   failed: {len(FAILED)}")
    for failure in FAILED:
        print(f"  FAILED: {failure}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())

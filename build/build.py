"""Сборка Secret-bot: .exe (PyInstaller) + установщик (Inno Setup).

Запуск:  python build\\build.py
(или build\\build.ps1 — это тонкая обёртка, вызывающая этот файл)

Почему на Python, а не на PowerShell: сборку нужно уметь проверить и
повторить, а Windows PowerShell 5.1 в этом окружении вёл себя
непредсказуемо с не-ASCII скриптами (падал на ровном месте, при том что
парсер синтаксис принимал). Python здесь уже проверен сквозными тестами.

Версия берётся из launcher.py (VERSION = "...") — один источник правды.
Результат:
    build\\dist\\SecretBot\\                     распакованная программа
    build\\dist\\SecretBot-<ver>-setup.exe      установщик
"""

import os
import re
import shutil
import subprocess
import sys

BUILD_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BUILD_DIR)
SPEC = os.path.join(BUILD_DIR, "secret-bot.spec")
ISS = os.path.join(BUILD_DIR, "installer.iss")
ICON = os.path.join(BUILD_DIR, "secret-bot.ico")
DIST = os.path.join(BUILD_DIR, "dist")
WORK = os.path.join(BUILD_DIR, "work")
EXE = os.path.join(DIST, "SecretBot", "SecretBot.exe")


def step(text: str) -> None:
    print(f"\n=== {text} ===", flush=True)


def fail(text: str) -> "None":
    print(f"ОШИБКА: {text}", flush=True)
    sys.exit(1)


def run(args, **kwargs) -> subprocess.CompletedProcess:
    """Запускает команду, стримит вывод в консоль и возвращает результат."""
    printable = " ".join(str(a) for a in args)
    print(f"> {printable}", flush=True)
    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run(args, env=env, **kwargs)
    return proc


def read_version() -> str:
    with open(os.path.join(ROOT, "launcher.py"), encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        fail('в launcher.py не найдена строка VERSION = "..."')
    return match.group(1)


def find_iscc() -> str | None:
    found = shutil.which("ISCC.exe") or shutil.which("ISCC")
    if found:
        return found
    for candidate in (
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
        r"C:\ProgramData\chocolatey\bin\ISCC.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def human(path: str) -> str:
    return f"{os.path.getsize(path) / 1024 / 1024:.1f} МБ"


def main() -> int:
    version = read_version()
    step(f"Версия {version}")

    # --- иконка ---------------------------------------------------------
    if not os.path.isfile(ICON):
        step("Иконка")
        if run([sys.executable, os.path.join(BUILD_DIR, "make-icon.py")]).returncode:
            fail("не удалось создать иконку")
    else:
        step(f"Иконка уже есть: {ICON}")

    # --- проверки перед сборкой ----------------------------------------
    # Компилируем ВСЕ модули пакета, а не только точки входа: бот разбит
    # на config/crypto/database/passkey/private/groups, и опечатка в любом
    # из них иначе всплыла бы только в собранном .exe.
    step("Компиляция")
    if run([
        sys.executable, "-m", "py_compile",
        *[os.path.join(ROOT, name) for name in (
            "launcher.py", "config.py", "crypto.py", "database.py",
            "passkey.py", "private.py", "groups.py", "crypt_bot.py", "web_app.py",
        )],
    ]).returncode:
        fail("py_compile")

    step("Самопроверка из исходников")
    if run([sys.executable, os.path.join(ROOT, "launcher.py"), "--selftest"]).returncode:
        fail("самопроверка из исходников не прошла")

    # --- PyInstaller ----------------------------------------------------
    step("PyInstaller (onedir)")
    if run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--log-level", "WARN",
        "--distpath", DIST, "--workpath", WORK, SPEC,
    ]).returncode:
        fail("PyInstaller")

    if not os.path.isfile(EXE):
        fail(f"нет собранного exe: {EXE}")
    total = 0
    for dirpath, _dirnames, filenames in os.walk(os.path.join(DIST, "SecretBot")):
        for name in filenames:
            total += os.path.getsize(os.path.join(dirpath, name))
    print(f"  SecretBot.exe: {human(EXE)}")
    print(f"  каталог целиком: {total / 1024 / 1024:.1f} МБ")

    # --- проверка собранного exe ---------------------------------------
    step("Самопроверка собранного exe")
    if run([EXE, "--selftest"]).returncode:
        fail("собранный exe не прошёл самопроверку")
    run([EXE, "--version"])

    # --- Inno Setup -----------------------------------------------------
    step("Inno Setup")
    iscc = find_iscc()
    if not iscc:
        fail("ISCC.exe не найден — установите Inno Setup 6")
    print(f"  ISCC: {iscc}")
    if run([iscc, f"/DMyAppVersion={version}", ISS], cwd=ROOT).returncode:
        fail("Inno Setup")

    setup = os.path.join(DIST, f"SecretBot-{version}-setup.exe")
    if not os.path.isfile(setup):
        fail(f"нет установщика: {setup}")

    step("Готово")
    print(f"  установщик: {setup}")
    print(f"  размер:     {human(setup)}")
    print()
    print("Проверка установки (тихая, в тестовый каталог):")
    test_dir = os.path.join(os.environ.get("LOCALAPPDATA", ROOT),
                            "Programs", "Secret-bot-test")
    print(f'  "{setup}" /VERYSILENT /SUPPRESSMSGBOXES /DIR="{test_dir}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())

# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller-сборка Secret-bot в каталог (onedir).

Запуск:  pyinstaller --noconfirm --clean build/secret-bot.spec
Обычно вызывается через build/build.ps1 — он же собирает установщик.

onedir, а не onefile: uvicorn/fastapi тянут много подпакетов, и onefile
заставляет распаковываться при каждом старте. Установщик всё равно
упакует каталог в один setup.exe.
"""

import os

from PyInstaller.utils.hooks import collect_all

PROJECT = os.path.dirname(os.path.abspath(SPECPATH))       # .../secret-bot
ENTRY = os.path.join(PROJECT, "launcher.py")
ICON = os.path.join(PROJECT, "build", "secret-bot.ico")

datas, binaries, hiddenimports = [], [], []
for package in (
    "aiogram", "fastapi", "starlette", "uvicorn", "cbor2", "cryptography",
    "python_multipart", "multipart", "pydantic", "anyio",
):
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    except Exception:                       # пакет не установлен — не беда
        hiddenimports.append(package)
        continue
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

# uvicorn подтягивает реализации динамически — их не видно статически
hiddenimports += [
    "uvicorn.logging",
    "uvicorn.loops", "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan", "uvicorn.lifespan.on", "uvicorn.lifespan.off",
]

a = Analysis(
    [ENTRY],
    pathex=[PROJECT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # unittest исключать НЕЛЬЗЯ: aiogram делает
    # `from unittest.mock import sentinel` (types/base.py, dispatcher/event/bases.py),
    # и без него собранный exe падает на импорте crypt_bot.
    excludes=[
        "tkinter", "pytest", "httpx", "httpcore",
        "PIL", "numpy", "pandas", "matplotlib",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecretBot",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    icon=ICON if os.path.isfile(ICON) else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="SecretBot",
)

"""Проверка Android-исходников без Android SDK.

На этой машине SDK нет, поэтому `gradle assembleDebug` не запустить. Что
можно — убедиться, что Java хотя бы разбирается: javac без android.jar
даст «package android.* does not exist», но на СИНТАКСИЧЕСКУЮ ошибку
(лишняя скобка, забытая точка с запятой) он тоже ругается — и вот это уже
наша поломка.

Запуск: python android/check-java.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JAVA_ROOT = os.path.join(HERE, "app", "src", "main", "java")
SOURCES = [os.path.join(JAVA_ROOT, "com", "secretbot", "app", "MainActivity.java")]

# Ошибки, которые ожидаемы без android.jar и которые НЕ являются поломкой.
BENIGN = (
    "does not exist",                  # package android.* / R
    "cannot find symbol",              # те же классы и их методы
    "does not override or implement",  # супертипы не найдены, @Override ругается зря
)


def check() -> int:
    javac = shutil.which("javac")
    if not javac:
        print("javac не найден — проверка пропущена (нужен JDK)")
        return 0

    for path in SOURCES:
        if not os.path.isfile(path):
            print(f"НЕТ ФАЙЛА: {path}")
            return 1

    with tempfile.TemporaryDirectory() as out:
        proc = subprocess.run([javac, "-d", out, "-nowarn", *SOURCES],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace")

    problems, benign = [], 0
    for line in proc.stderr.splitlines():
        if "error:" not in line:
            continue
        text = line.split("error:", 1)[1].strip()
        if any(mark in text for mark in BENIGN):
            benign += 1
        else:
            problems.append(line.strip())

    if problems:
        print(f"❌ {len(problems)} настоящих ошибок:")
        for item in problems:
            print("   " + item)
        return 1

    print(f"✅ Java разбирается: синтаксических ошибок нет "
          f"(ожидаемых «нет android.jar» — {benign})")
    return 0


if __name__ == "__main__":
    sys.exit(check())

"""Проверка, что нужные классы РЕАЛЬНО попали внутрь собранного dex.

Зачем: «исходник написан» и «класс в apk» — разные утверждения. Класс можно
забыть включить в исходники Gradle, переименовать пакет или собрать apk из
старого кеша, и всё это выглядит как успешная сборка, пока функция не
отвалится у пользователя на телефоне.

Имена классов и методов dex держит как обычные строки в таблице строк, поэтому
их видно прямой проверкой байтов — разбирать dex не нужно.

Запуск: python android/verify-dex.py [путь-к-apk]
"""

import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_APK = os.path.join(HERE, "app", "build", "outputs", "apk", "debug",
                           "app-debug.apk")

# Что обязано быть в apk. Имя класса и имя метода — по отдельности: наличие
# класса не значит, что метод survived оптимизацию.
REQUIRED = [
    "MainActivity",          # точка входа
    "FileBridge",            # класс моста
    "saveBase64",            # метод, который зовёт страница
    "BridgeLogic",           # логика без android.*
    "safeName",              # имя файла
    "checkPayload",          # проверка размера
    "estimatedBytes",        # подсчёт размера
    "MAX_BYTES",             # лимит
    "AndroidFile",           # имя моста для JS
]


def main() -> int:
    apk = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_APK
    if not os.path.isfile(apk):
        print(f"FAIL: нет apk: {apk}\n      Соберите: ./gradlew :app:assembleDebug")
        return 1

    print(f"apk: {apk}")
    with zipfile.ZipFile(apk) as archive:
        dexes = [n for n in archive.namelist() if n.endswith(".dex")]
        if not dexes:
            print("FAIL: внутри нет ни одного classes.dex")
            return 1
        print(f"файлов dex: {len(dexes)} ({', '.join(dexes)})")
        blobs = {name: archive.read(name) for name in dexes}

    total = sum(len(b) for b in blobs.values())
    print(f"dex суммарно: {total / 1024:.0f} КБ")

    problems = []
    for needle in REQUIRED:
        # DEX-строка может лежать в любом из файлов dex при нескольких
        # модулях, поэтому ищем по всем сразу.
        found_in = [name for name, blob in blobs.items()
                    if needle.encode() in blob]
        if found_in:
            print(f"OK: {needle} — в {', '.join(found_in)}")
        else:
            print(f"FAIL: {needle} не найден в dex")
            problems.append(needle)

    if problems:
        print("\nFAILURES: в apk нет: " + ", ".join(problems))
        return 1
    print(f"\nSUCCESS: все {len(REQUIRED)} имён на месте — код действительно в apk")
    return 0


if __name__ == "__main__":
    sys.exit(main())

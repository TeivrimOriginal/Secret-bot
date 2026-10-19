"""Сборка и запуск настоящих Java-тестов логики моста.

BridgeLogic намеренно написан без импортов android.* — именно поэтому его
можно скомпилировать обычным javac и выполнить на этой машине. Android-часть
(MainActivity) так проверить нельзя: там Activity, WebView, Toast, нужен
телефон. Всё, что можно проверить без телефона, проверяем здесь.

Запуск: python android/test-bridge.py

Требуется JDK (java/javac в PATH или JAVA_HOME). Нет JDK — скрипт скажет об
этом и вернёт код 0: отсутствие инструмента не повод объявлять тесты зелёными
или красными, это отсутствие данных.
"""

import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "app", "src", "main", "java", "com", "secretbot", "app")
TEST = os.path.join(HERE, "test", "java", "com", "secretbot", "app")
CLASSES = os.path.join(HERE, "build", "test-classes")

# BridgeLogic не должен тянуть android.* — иначе смысл проверки теряется и
# javac упадёт на отсутствии android.jar. Смотрим только код: упоминания
# android.* в комментариях и строках не считаются (иначе проверка ругается на
# собственное объяснение того, что импортов нет).
FORBIDDEN_IMPORT = re.compile(r"^\s*import\s+android\.", re.M)


def strip_comments(source: str) -> str:
    """Убираем комментарии, чтобы анализировать код, а не прозу."""
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    return re.sub(r"//[^\n]*", " ", source)


def jdk_tool(name: str) -> str:
    """Ищем javac/java: сначала JAVA_HOME, потом PATH."""
    home = os.environ.get("JAVA_HOME")
    if home:
        for sub in ("bin", "bin\\"):
            candidate = os.path.join(home, sub, name + (".exe" if os.name == "nt" else ""))
            if os.path.isfile(candidate):
                return candidate
    found = shutil.which(name)
    if found:
        return found
    home = shutil.which("java")
    if home:
        candidate = os.path.join(os.path.dirname(home), name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(candidate):
            return candidate
    return ""


def main() -> int:
    javac = jdk_tool("javac")
    java = jdk_tool("java")
    if not javac or not java:
        print("SKIP: не найден JDK (нужны javac и java). Поставьте JDK 17+ "
              "или задайте JAVA_HOME.")
        return 0

    logic = os.path.join(SRC, "BridgeLogic.java")
    test = os.path.join(TEST, "BridgeLogicTest.java")
    for path in (logic, test):
        if not os.path.isfile(path):
            print(f"FAIL: нет файла {path}")
            return 1

    # Проверка самого свойства: логика обязана компилироваться без android.jar.
    with open(logic, encoding="utf-8") as handle:
        body = strip_comments(handle.read())
    if FORBIDDEN_IMPORT.search(body):
        print(f"FAIL: {os.path.basename(logic)} импортирует android.* — "
              "тогда его не проверить без телефона")
        return 1

    shutil.rmtree(CLASSES, ignore_errors=True)
    os.makedirs(CLASSES, exist_ok=True)

    compile_proc = subprocess.run(
        [javac, "-encoding", "UTF-8", "-d", CLASSES, logic, test],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if compile_proc.returncode != 0:
        print("FAIL: javac не собрал тесты")
        print(compile_proc.stderr.strip())
        return 1
    print("javac: собрано без ошибок")

    run_proc = subprocess.run(
        [java, "-Dfile.encoding=UTF-8", "-cp", CLASSES,
         "com.secretbot.app.BridgeLogicTest"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(run_proc.stdout.strip())
    if run_proc.returncode != 0:
        print("FAIL: тесты Java провалились")
        print(run_proc.stderr.strip())
        return 1
    print("SUCCESS: логика моста проверена настоящим запуском java")
    return 0


if __name__ == "__main__":
    sys.exit(main())

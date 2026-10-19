"""Проверка собранного APK: манифест, иконки, подпись, deep link.

Запуск: python android/verify-apk.py [путь-к-apk]
По умолчанию берётся app/build/outputs/apk/debug/app-debug.apk.

Что проверяет:
  1. Файл существует и это zip с AndroidManifest.xml и classes.dex.
  2. aapt разбирает манифест: пакет, ярлык, иконка, стартовая Activity.
  3. Deep link secretbot://open есть (через dump xmltree — в badging его нет).
  4. Иконки mipmap-* реально внутри (без них иконка в лаунчере пустая).
  5. APK подписан (через apksigner: AGP 8 ставит подпись v2/v3, а не v1,
     поэтому файлов META-INF/*.RSA в архиве может не быть вовсе).

Смысл: «сборка прошла» ничего не значит, если внутри нет иконок или apk не
подписан. Именно такие вещи и проверяются здесь.
"""

import os
import re
import subprocess
import sys
import zipfile

# Консоль Windows по умолчанию cp1251 и не умеет печатать галочки/эмодзи.
# Переключаем stdout на UTF-8 с заменой непечатных символов, иначе скрипт
# падает с UnicodeEncodeError уже после успешных всех проверок.
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_APK = os.path.join(HERE, "app", "build", "outputs", "apk", "debug",
                           "app-debug.apk")


def sdk_root() -> str:
    """Путь к SDK: сначала local.properties, потом переменные окружения."""
    props = os.path.join(HERE, "local.properties")
    if os.path.isfile(props):
        with open(props, encoding="utf-8") as handle:
            match = re.search(r"^sdk\.dir=(.+)$", handle.read(), re.M)
            if match:
                return (match.group(1).strip()
                        .replace("\\\\", "\\").replace("\\:", ":"))
    return (os.environ.get("ANDROID_HOME")
            or os.environ.get("ANDROID_SDK_ROOT") or "")


def build_tool(name: str) -> str:
    """Ищем aapt/aapt2/apksigner в build-tools — берём старшую установленную версию.

    apksigner лежит в lib/ рядом с aapt2, поэтому ищем отдельно, иначе
    проверка подписи всегда падает с «нет apksigner».
    """
    root = sdk_root()
    build_tools = os.path.join(root, "build-tools")
    if not os.path.isdir(build_tools):
        return ""
    versions = sorted(os.listdir(build_tools), reverse=True)
    for version in versions:
        base = os.path.join(build_tools, version)
        candidates = [os.path.join(base, name), os.path.join(base, "lib", name)]
        if name.endswith(".jar"):
            # имя уже с расширением — иначе получится apksigner.jar.jar
            candidates = [c if c.endswith(".jar") else c + ".jar"
                          for c in candidates]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
    return ""


def run(command: list) -> str:
    """Запуск внешней утилиты, при любой ошибке возвращаем пустой вывод."""
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def main() -> int:
    apk = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_APK
    if not os.path.isfile(apk):
        print(f"FAIL: нет apk: {apk}\n      Соберите: ./gradlew :app:assembleDebug")
        return 1

    print(f"apk: {apk}")
    print(f"размер: {os.path.getsize(apk) / 1024:.0f} КБ")
    problems: list = []

    # --- 1. содержимое архива ---
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        for required in ("AndroidManifest.xml", "classes.dex"):
            if required not in names:
                problems.append(f"внутри нет {required}")

        icons = [n for n in names if n.startswith("res/") and "mipmap" in n]
        print(f"иконок внутри: {len(icons)}")
        if not icons:
            problems.append("внутри нет иконок mipmap — иконка в лаунчере пустая")

    # --- 2. подпись: сперва v1 (файлы в архиве), иначе apksigner (v2/v3) ---
    signed = any(n.startswith("META-INF/")
                 and n.endswith((".RSA", ".DSA", ".EC")) for n in names)
    how = "v1 (META-INF)"
    if not signed:
        apksigner = build_tool("apksigner.jar")
        if not apksigner:
            how = "не проверена: apksigner не найден"
        else:
            output = run(["java", "-jar", apksigner, "verify", "-v", apk])
            signed = "Verifies" in output or "Verified using" in output
            how = "apksigner: " + (output.strip().splitlines()[0]
                                   if output.strip() else "пустой вывод")
    print(f"подпись: {'есть' if signed else 'НЕТ'} ({how})")
    if not signed:
        problems.append("apk не подписан — телефон его не поставит")

    # --- 3. манифест через aapt ---
    aapt = build_tool("aapt.exe") or build_tool("aapt")
    aapt2 = build_tool("aapt2.exe") or build_tool("aapt2")
    badging = run([aapt2 or aapt, "dump", "badging", apk]) if (aapt2 or aapt) else ""
    if not badging:
        print("WARN: aapt не найден — манифест не проверен")
    else:
        wanted = {
            "пакет com.secretbot.app": r"^package: name='com\.secretbot\.app'",
            "ярлык Secret-bot": r"application-label:'Secret-bot'",
            "иконка в манифесте": r"application-icon-\d+:",
            "стартовая Activity":
                r"launchable-activity: name='com\.secretbot\.app\.MainActivity'",
        }
        for title, pattern in wanted.items():
            found = re.search(pattern, badging, re.M) is not None
            print(f"{'OK' if found else 'FAIL'}: {title}")
            if not found:
                problems.append(f"манифест: {title}")

    # --- 4. deep link: в badging его нет, нужен разбор дерева манифеста ---
    deep = False
    if aapt:
        tree = run([aapt, "dump", "xmltree", apk, "AndroidManifest.xml"])
        deep = 'android:scheme' in tree and '"secretbot"' in tree
    print(f"{'OK' if deep else 'FAIL'}: deep link secretbot://open в манифесте")
    if not deep:
        problems.append("в манифесте нет схемы secretbot")

    if problems:
        print("\nFAILURES:")
        for item in problems:
            print("   - " + item)
        return 1
    print("\nSUCCESS: APK в порядке — манифест, иконки, подпись, deep link")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Прогон APK на настоящем Android — в эмуляторе, без телефона и без Wi-Fi пары.

Зачем: телефон по Wi-Fi пока не подключается, а все прежние проверки
(verify-apk, verify-dex, test-bridge) смотрят на байты, а не на работу
приложения. Здесь APK реально запускается, WebView реально грузит страницу,
и результат вызова моста реально читается — через devtools WebView, который
включён в debug-сборке.

Проверяемое (каждый пункт — отдельный замер, не вывод на глаз):
  1. приложение запускается и не падает;
  2. мост AndroidFile виден из страницы (typeof AndroidFile !== 'undefined');
  3. saveBase64 возвращает true и кладёт файл с верным содержимым;
  4. путь из имени файла не даёт выхода из каталога;
  5. чужой хост перехватывается: страница остаётся на своём месте;
  6. devtools-сокет открыт и отвечает — приложение можно разобрать повторно;
  7. в logcat нет FATAL / ANR.

Страница-испытатель генерируется самим скриптом и отдаётся локальным
сервером, результат она приносит обратно обычным fetch — так не нужен
websocket-клиент, а проверка не зависит от того, установлен ли какой-то пакет.

Запуск:  python android/run-emulator.py            (собрать — отдельно)
         python android/run-emulator.py --keep     (не гасить эмулятор)
         python android/run-emulator.py --reuse    (использую уже поднятый)
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AVD = "secretbot"
IMAGE = "system-images;android-34;default;x86_64"
PKG = "com.secretbot.app"
APK = os.path.join(HERE, "app", "build", "outputs", "apk", "debug",
                   "app-debug.apk")

CHECKS = []


def ok(title: str, passed: bool, detail: str = "") -> None:
    CHECKS.append((title, passed))
    mark = "ok " if passed else "ПРОВАЛ"
    line = f"  {mark} {title}"
    if detail and not passed:
        line += f" — {detail}"
    print(line, flush=True)


def step(text: str) -> None:
    print(f"=== {text}", flush=True)


def sdk_root() -> str:
    return (os.environ.get("ANDROID_SDK_ROOT")
            or os.environ.get("ANDROID_HOME")
            or r"F:\tmp\opencode\tools\android-sdk")


def tool(*parts) -> str:
    return os.path.join(sdk_root(), *parts)


def avd_home(path: str = "") -> str:
    """Где лежат AVD.

    По умолчанию Windows кладёт их в %USERPROFILE%\\.android\\avd — на диск C:,
    где места почти никогда нет: на этой машине C: отдавал 4.7 ГБ, а образ
    android-34 требует под userdata 7.4 ГБ, и эмулятор умирал с
    `FATAL | Not enough space to create userdata partition` ещё до старта —
    то есть до запуска самого приложения, и по логу это выглядело бы как
    поломка теста. Инструменты лежат на другом диске, поэтому AVD по
    умолчанию кладём рядом с ними: там же есть место и то же семейство
    путей, что и SDK.

    Переопределяется переменной ANDROID_AVD_HOME либо флагом --avd-home.
    """
    if path:
        home = path
    else:
        home = os.environ.get("ANDROID_AVD_HOME") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(sdk_root()))),
            "android-avd")
    os.makedirs(home, exist_ok=True)
    os.environ["ANDROID_AVD_HOME"] = home
    return home


def run(cmd, timeout=180, stdin=None):
    """Запуск с внятным результатом. .bat на Windows берём через cmd /c."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    if sys.platform == "win32" and cmd[0].lower().endswith((".bat", ".cmd")):
        cmd = ["cmd", "/c"] + list(cmd)
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout)
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or ""), "таймаут"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or ""), ""


ADB = tool("platform-tools", "adb.exe")
if os.name == "nt" and not os.path.isfile(ADB):
    ADB = shutil.which("adb") or ADB


def adb(*args, serial: str = "", timeout=180, stdin=None):
    if serial:
        args = ["-s", serial] + list(args)
    return run([ADB, *args], timeout=timeout, stdin=stdin)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


# ------------------------------------------------------------- страница

PAGE = """<!doctype html>
<meta charset="utf-8">
<title>secretbot e2e</title>
<pre id="out">работаю…</pre>
<script>
const REPORT = { bridge: false, steps: [] };
const log = (t) => { REPORT.steps.push(t); document.getElementById('out').textContent = REPORT.steps.join('\\n'); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function send() {
  try {
    await fetch('/result?payload=' + encodeURIComponent(JSON.stringify(REPORT)));
  } catch (e) {
    REPORT.sendFailed = String(e);
  }
}

async function main() {
  try {
    REPORT.url = location.href;
    REPORT.bridge = (typeof AndroidFile !== 'undefined');
    log('мост виден: ' + REPORT.bridge);
    if (REPORT.bridge) {
      REPORT.okWrite = AndroidFile.saveBase64('QUJDREVG', 'e2e-test.txt');
      log('запись обычного файла -> ' + REPORT.okWrite);
      REPORT.okBadName = AndroidFile.saveBase64('QUJDREVG', '../../e2e-escape.txt');
      log('запись с выходом из каталога -> ' + REPORT.okBadName);
    }
  } catch (e) {
    REPORT.error = String(e);
    log('исключение: ' + REPORT.error);
  }
  await sleep(1000);
  await send();
  log('уезжаю на чужой хост…');
  REPORT.before = location.href;
  try { location.href = 'http://e2e-foreign-host.invalid/leak'; }
  catch (e) { REPORT.navError = String(e); }
  await sleep(2000);
  REPORT.after = location.href;
  REPORT.foreignBlocked = (REPORT.after === REPORT.before);
  log('хост перехвачен: ' + REPORT.foreignBlocked);
  await send();
}
main();
</script>
"""


class Site:
    """Локальный сервер: отдаёт страницу и принимает её отчёт."""

    def __init__(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import urlparse, parse_qs
        self.report = None
        self.event = threading.Event()
        self.port = free_port()

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path in ("/", "/index.html"):
                    body = PAGE.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif parsed.path == "/result":
                    payload = parse_qs(parsed.query).get("payload", [""])[0]
                    try:
                        outer.report = json.loads(payload)
                    except ValueError:
                        outer.report = {"raw": payload}
                    outer.event.set()
                    self.send_response(204)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# ------------------------------------------------------------- устройство


def wait_boot(timeout: int, serial: str = "") -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        args = ["shell", "getprop", "sys.boot_completed"]
        if serial:
            args = ["-s", serial] + args
        rc, out, _ = adb(*args)
        if rc == 0:
            # Вывод getprop на Android может содержать \r, \n, лидирующий
            # мусор от stderr предыдущей команды и прочее. Берём первую цифру.
            digit = out.lstrip()[:1]
            if digit == "1":
                return True
        time.sleep(3)
    return False


def devtools_port(pid: str):
    """Порт devtools: вперёд на abstract-сокет WebView, потом /json."""
    target = f"localabstract:webview_devtools_remote_{pid}"
    port = free_port()
    rc, _, err = adb("forward", f"tcp:{port}", target)
    if rc != 0:
        return None, f"adb forward: {err or 'отказ'}"
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/json", timeout=5) as response:
            return (port, json.loads(response.read().decode("utf-8"))), ""
    except Exception as exc:                    # noqa: BLE001 — отчёт в проверку
        return None, repr(exc)


def device_file(path: str) -> bytes:
    """Прочитать файл приложения. Shell на Android 11+ не видит каталог
    Android/data, поэтому читаем от имени самого приложения (apk debug)."""
    rc, out, _ = adb("shell", "run-as", PKG, "cat", path)
    if rc != 0:
        return b""
    return out.encode("utf-8", "replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Прогон apk на эмуляторе")
    parser.add_argument("--keep", action="store_true",
                        help="не выключать эмулятор в конце")
    parser.add_argument("--reuse", action="store_true",
                        help="использовать уже поднятый эмулятор")
    parser.add_argument("--avd", default=DEFAULT_AVD, help="имя AVD")
    parser.add_argument("--avd-home", default="",
                        help="каталог AVD (по умолчанию рядом с SDK, не на C:)")
    parser.add_argument("--boot-timeout", type=int, default=300,
                        help="сколько ждать загрузки, сек")
    parser.add_argument("--page-timeout", type=int, default=60,
                        help="сколько ждать отчёта страницы, сек")
    args = parser.parse_args()

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    if not os.path.isfile(APK):
        print(f"FAIL: нет apk: {APK}\n      Соберите: gradle :app:assembleDebug")
        return 1

    emulator = tool("emulator", "emulator.exe")
    avdmanager = tool("cmdline-tools", "latest", "bin", "avdmanager.bat")
    image_dir = tool("system-images", "android-34", "default", "x86_64")

    step("Подготовка окружения")
    ok("adb найден", os.path.isfile(ADB), ADB)
    ok("эмулятор установлен", os.path.isfile(emulator), emulator)
    if not os.path.isfile(emulator):
        print("      sdkmanager \"emulator\"")
        return 1
    ok("системный образ установлен", os.path.isfile(
        os.path.join(image_dir, "system.img")), image_dir)
    if not os.path.isfile(os.path.join(image_dir, "system.img")):
        print(f'      sdkmanager "{IMAGE}"')
        return 1
    ok("apk собран", os.path.isfile(APK), APK)

    step("AVD")
    home = avd_home(args.avd_home)
    print(f"  каталог AVD: {home}")
    free = shutil.disk_usage(home).free
    # Образ android-34 создаёт userdata около 7.4 ГБ; сверху нужен запас
    # на снапшоты и кеш. Проверяем заранее — иначе до провала доходит только
    # после старта, а причина тогда читается как ошибка эмулятора.
    ok("места для образа хватает", free > 9 * 1024 ** 3,
       f"свободно {free / 1024 ** 3:.1f} ГБ, нужно больше 9 ГБ")
    if free <= 9 * 1024 ** 3:
        print("      --avd-home на диск с большим объёмом")
        return 1

    rc, list_out, _ = run([avdmanager, "list", "avd", "-c"])
    names = [line.strip() for line in list_out.splitlines() if line.strip()]
    if args.avd in names:
        print(f"  AVD {args.avd} уже есть")
    else:
        print(f"  создаю AVD {args.avd} …")
        rc, out, _ = run([avdmanager, "create", "avd", "-n", args.avd,
                          "-k", IMAGE, "--force"], stdin="no\n", timeout=300)
        ok(f"AVD {args.avd} создан", rc == 0, out[-500:])
        if rc != 0:
            return 1

    step("Запуск эмулятора")
    started_here = False
    rc, devices, _ = adb("devices")
    connected = [line.split("\t")[0] for line in devices.splitlines()
                 if "\tdevice" in line]
    if args.reuse or connected:
        print(f"  уже подключено: {connected or 'нет'}")
    else:
        log_path = os.path.join(os.path.dirname(APK), "emulator.log")
        with open(log_path, "w", encoding="utf-8") as log_file:
            subprocess.Popen(
                [emulator, "-avd", args.avd, "-no-window", "-no-audio",
                 "-no-boot-anim", "-no-snapshot", "-gpu", "swiftshader_indirect",
                 "-port", "5554"],
                stdout=log_file, stderr=subprocess.STDOUT,
                cwd=os.path.dirname(emulator))
        started_here = True
        print(f"  запущен headless, лог: {log_path}")

    print("  ждём загрузки …")
    serial = connected[0] if connected else ""
    if not wait_boot(args.boot_timeout, serial):
        ok("эмулятор загрузился", False, f"за {args.boot_timeout} с")
        if started_here and not args.keep:
            adb("emu", "kill")
        return 1
    ok("эмулятор загрузился", True)
    rc, build, _ = adb("shell", "getprop", "ro.build.version.sdk")
    print(f"  API {build.strip()}")

    step("Установка apk")
    rc, out, _ = adb("install", "-r", APK, serial=serial)
    ok("apk установлен", rc == 0 and "Success" in out, out.strip()[-300:])

    step("Система: кому открывать внешние ссылки")
    # Приложение уводит чужой хост системным интентом ACTION_VIEW. Если в
    # системе нет ни одного обработчика, startActivity бросит
    # ActivityNotFoundException — то есть проверка «чужой хост перехвачен»
    # упадёт на живом устройстве, а без этого замера причина была бы не видна.
    rc, resolve, _ = adb("shell", "cmd", "package", "resolve-activity",
                         "-a", "android.intent.action.VIEW",
                         "-d", "http://e2e-foreign-host.invalid/leak")
    summary = " ".join(resolve.split())
    print("  " + summary[:200])
    ok("в системе есть обработчик внешних ссылок",
       "packageName" in summary or "Resolving activity" in summary,
       summary[-200:])

    step("Локальный сайт для страницы")
    site = Site()
    site.start()
    url = f"http://10.0.2.2:{site.port}/index.html"
    print(f"  {url}")

    step("Запуск приложения по deep link")
    adb("logcat", "-c")
    rc, out, _ = adb("shell", "am", "start",
                     "-a", "android.intent.action.VIEW",
                     "-d", f"secretbot://open?url={url}")
    ok("am start принят", rc == 0 and "Error" not in out, out.strip()[-300:])

    print("  ждём отчёта страницы …")
    got = site.event.wait(args.page_timeout)
    ok("страница ответила через мост", got, "отчёт не пришёл")
    report = site.report or {}

    if got:
        print(f"  отчёт: {json.dumps(report, ensure_ascii=False)[:400]}")
        ok("мост AndroidFile виден из страницы", report.get("bridge") is True,
           str(report.get("bridge")))
        if "error" in report:
            ok("исключений в мосте не было", False, str(report.get("error")))
        ok("saveBase64 вернул true", report.get("okWrite") is True,
           str(report.get("okWrite")))
        ok("имя с выходом из каталога обработано",
           report.get("okBadName") is True, str(report.get("okBadName")))
        ok("чужой хост перехвачен, страница осталась на месте",
           report.get("foreignBlocked") is True,
           f"до={report.get('before')} после={report.get('after')}")
        ok("глубокая ссылка открыла нужный адрес",
           str(report.get("url", "")).startswith(f"http://10.0.2.2:{site.port}"),
           str(report.get("url")))

    step("Файл на устройстве")
    rc, ls_out, _ = adb("shell", "run-as", PKG, "ls", "-1",
                        "/sdcard/Android/data/com.secretbot.app/files/Download")
    names = [line.strip() for line in ls_out.splitlines() if line.strip()]
    print("  каталог: " + (", ".join(names) or "(пусто)"))
    ok("файл e2e-test.txt создан", "e2e-test.txt" in names, ls_out.strip())
    ok("выход из каталога не случился",
       not any("e2e-escape.txt" == n or n.startswith("..") for n in names),
       repr(names))
    content = device_file(
        "/sdcard/Android/data/com.secretbot.app/files/Download/e2e-test.txt")
    ok("содержимое файла верное", content == b"ABCDEF", repr(content[:40]))

    step("devtools WebView")
    rc, pid_out, _ = adb("shell", "pidof", PKG)
    pid = pid_out.strip().split()[0] if pid_out.strip() else ""
    ok("приложение живо (pid)", bool(pid), pid_out.strip())
    if pid:
        info, err = devtools_port(pid)
        ok("devtools-сокет отвечает", info is not None, err)
        if info:
            port, targets = info
            pages = [t for t in targets if t.get("type") == "page"]
            ok("страница видна в devtools", bool(pages),
               json.dumps(targets)[:200])
            if pages:
                print(f"  {pages[0].get('url', '')[:80]}")

    step("Logcat: падений нет")
    rc, crash, _ = adb("logcat", "-d", "-b", "crash")
    bad = [line for line in crash.splitlines()
           if PKG in line or "FATAL" in line]
    ok("в буфере crash нет записей о приложении", not bad, " | ".join(bad[:4]))

    step("Скриншот")
    shot = os.path.join(HERE, "test-output", "emulator.png")
    os.makedirs(os.path.dirname(shot), exist_ok=True)
    try:
        proc = subprocess.run([ADB, "exec-out", "screencap", "-p"],
                              capture_output=True, timeout=60)
        if proc.returncode == 0 and proc.stdout.startswith(b"\x89PNG"):
            with open(shot, "wb") as handle:
                handle.write(proc.stdout)
            print(f"  {shot} ({len(proc.stdout)} байт)")
            ok("скриншот снят", True)
        else:
            ok("скриншот снят", False, proc.stdout[:40])
    except Exception as exc:                     # noqa: BLE001
        ok("скриншот снят", False, repr(exc))

    site.stop()
    if started_here and not args.keep:
        print("  выключаю эмулятор")
        adb("emu", "kill")
    elif started_here:
        print("  эмулятор оставлен (--keep): adb -s emulator-5554 shell")

    failed = [title for title, passed in CHECKS if not passed]
    print(f"\nпроверок: {len(CHECKS)}, провалов: {len(failed)}")
    for title in failed:
        print(f"  ПРОВАЛ: {title}")
    if failed:
        return 1
    print("ВСЁ ПРОШЛО")
    return 0


if __name__ == "__main__":
    sys.exit(main())

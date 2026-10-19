"""Поиск устройства Android в сети и подключение по коду Wi-Fi отладки.

Зачем: `adb pair` требует `IP:пОРТ` + код. Код с экрана телефона сам по себе
непригоден — без адреса его некуда прислать. Обе величины напечатаны в одном
окне на телефоне, но и то, и другое умеет отдавать сам телефон: он
рекламирует `adb-IP:пОРТ` через mDNS.

Порядок работы и что это доказывает:
  1. mDNS. Android публикует `_adb-tls-connect._tcp` всегда, пока включена
     беспроводная отладка, и `_adb-tls-pairing._tcp` — только когда открыто
     окно с парным кодом. По наличию этих двух сервисов видно и адрес, и то,
     связаны мы или нет.
  2. SRV-запись даёт порт, A-запись — адрес. Их не нужно угадывать сканом.
  3. `adb pair ip:port КОД` при наличии pairing-сервиса, затем `adb connect`.
  4. Скан портов — только как запасной путь, если mDNS молчит.

Запуск:
  python android/find-device.py                     # найти и сказать, что не так
  python android/find-device.py --pair-code 210235  # найти и связать
"""

import argparse
import ipaddress
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ADB_NAME = "adb.exe" if os.name == "nt" else "adb"
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

SVC_CONNECT = "_adb-tls-connect._tcp.local"
SVC_PAIRING = "_adb-tls-pairing._tcp.local"
SERVICES = (SVC_PAIRING, SVC_CONNECT)


def find_adb() -> str:
    """Ищем adb: сначала SDK рядом с переменной окружения, потом PATH."""
    root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    if root:
        candidate = os.path.join(root, "platform-tools", ADB_NAME)
        if os.path.isfile(candidate):
            return candidate
    return shutil.which("adb") or ""


def log(title: str) -> None:
    print(f"=== {title}", flush=True)


# ---------------------------------------------------------- mDNS-парсер


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple:
    """Читает имя из DNS-ответа с поддержкой сжатия (указателей 0xC0).

    Сжатие обязательно в mDNS: повторяющиеся имена сервер подменяет на
    ссылку с старшим битом 1. Без поддержки указателей разбор уходит по
    касательной и мы теряем порт — а порт-то и нужен.
    """
    if depth > 10:
        return "", offset
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return ".".join(labels), offset + 1
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            rest, _ = read_name(data, pointer, depth + 1)
            labels.append(rest)
            return ".".join(labels), offset + 2
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), offset


def parse_record(data: bytes, offset: int) -> tuple:
    """Один RR: (имя, тип, класс, TTL, rdata, смещение после)."""
    name, offset = read_name(data, offset)
    if offset + 10 > len(data):
        return name, 0, 0, 0, b"", len(data)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlength]
    return name, rtype, rclass, ttl, rdata, offset + rdlength


def parse_srv(rdata: bytes, data: bytes) -> tuple:
    """SRV: приоритет, вес, ПОРТ, цель. Порт — то, что нам и нужно."""
    if len(rdata) < 6:
        return None, ""
    port = struct.unpack("!H", rdata[4:6])[0]
    target, _ = read_name(rdata, 6)
    if not target:
        target, _ = read_name(data, 0)
    return port, target


def parse_txt(rdata: bytes) -> dict:
    out = {}
    idx = 0
    while idx < len(rdata):
        length = rdata[idx]
        idx += 1
        chunk = rdata[idx:idx + length]
        idx += length
        if b"=" in chunk:
            key, _, value = chunk.partition(b"=")
            out[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
        elif chunk:
            out[chunk.decode("utf-8", "replace")] = ""
    return out


def rr_names(data: bytes) -> tuple:
    """Все имена из ответа: имена записей, рdata PTR и цель SRV.

    Нужна отдельной функцией из-за найденной поломки: раньше проверялось
    `name.encode() in data` — имя искалось сырыми байтами в пакете. В mDNS
    повторяющиеся имена заменены указателем 0xC0, и вопрос в ответе
    байтами не встречается. Фильтр отбрасывал ЖИВОЙ ответ телефона, а в отчёт
    уходило «телефон не рекламирует adb». Сверять надо разобранные имена.
    """
    names = set()
    if len(data) < 12:
        return names, 0, 0, 0, 0
    _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        qname, offset = read_name(data, offset)
        if qname:
            names.add(qname.lower())
        offset += 4
    for _ in range(an + ns + ar):
        if offset >= len(data):
            break
        rrname, offset = read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rrname:
            names.add(rrname.lower())
        if rtype == 12:                       # PTR: само имя сервиса
            target, _ = read_name(rdata, 0)
            if target:
                names.add(target.lower())
        elif rtype == 33 and len(rdata) >= 6:  # SRV: цель экземпляра
            target, _ = read_name(rdata, 6)
            if target:
                names.add(target.lower())
    return names, qd, an, ns, ar


def query_service(name: str, wait: float = 4.0, attempts: int = 3) -> list:
    """PTR-запрос и разбор ответов.

    Слушаем на том же сокете, что и отправляем: Android отвечает на порт
    источника, а при другом сокете ответ просто не доходит. Запрос шлём
    несколько раз — одно потерянное объявление на мгновение есть, а вывод
    вида «телефон не найден» из-за этого врал бы.

    Имена сверяем РАЗОБРАННЫМИ (см. rr_names), а не байтами.
    """
    results = []
    stat = {"got": 0, "matched": 0}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_REUSEPORT — чтобы встать на 5353 рядом с демоном adb. Рабочий
        # mdns_probe.py поднялся именно с ним, а find-device без него падал на
        # свой порт и первым замером ничего не получал.
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        try:
            sock.bind(("", MDNS_PORT))
        except OSError:
            sock.bind(("", 0))          # 5353 занят adb — слушаем свой порт
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            socket.inet_aton(MDNS_GROUP)
                            + socket.inet_aton("0.0.0.0"))
        except OSError:
            pass

        packet = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        for label in name.split("."):
            if label:
                packet += bytes([len(label)]) + label.encode()
        packet += b"\x00" + struct.pack("!HH", 12, 1)

        # На машине несколько сетевых интерфейсов (Ethernet, VPN, Bluetooth),
        # и multicast без явного выбора уходит на интерфейс дефолтного маршрута.
        # Здесь это Radmin VPN: пакет уезжал в туннель, телефон его не видел,
        # ответов не было, а телефон в двух метрах считался «не в сети».
        # Ядро не позволяет явно адресовать интерфейс по имени в сокете, поэтому
        # шлём с каждой локальной адресации по очереди — вопрос дешёвый,
        # зато покрытие полное.
        sources = []
        try:
            infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            sources = sorted({info[4][0] for info in infos})
        except OSError:
            pass
        sources = [s for s in sources if not s.startswith(("127.", "169.254."))]
        if not sources:
            sources = [None]
        print(f"  ({name}: шлём с: {', '.join(s or 'система' for s in sources)})")

        deadline = time.time() + wait
        seen = set()
        sent, next_send = 0, 0.0
        sent_from = []
        while time.time() < deadline:
            if sent < attempts and time.time() >= next_send:
                for src in sources:
                    if src:
                        try:
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                            socket.inet_aton(src))
                        except OSError as exc:
                            # Раньше здесь стоял молчаливый continue, и если
                            # сетевой интерфейс не выбрался, пакет не уходил
                            # вовсе — а в отчёте это выглядело как «телефон
                            # не рекламирует adb». Теперь причина видна.
                            print(f"      интерфейс {src} не выбран: {exc}")
                            continue
                    try:
                        sock.sendto(packet, (MDNS_GROUP, MDNS_PORT))
                        sent_from.append(src or "система")
                    except OSError as exc:
                        print(f"      не ушло с {src}: {exc}")
                sent += 1
                next_send = time.time() + 1.0
            sock.settimeout(min(1.0, max(0.05, deadline - time.time())))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            stat["got"] += 1
            stat.setdefault("sources", []).append(addr[0])

            names, qd, an, ns, ar = rr_names(data)
            if name.lower() not in names:
                continue          # чужой сервис, а не наше эхо
            stat["matched"] += 1

            offset = 12
            for _ in range(qd):
                _, offset = read_name(data, offset)
                offset += 4
            port, txt, target = None, {}, ""
            for _ in range(an + ns + ar):
                if offset >= len(data):
                    break
                rrname, rrtype, rrclass, ttl, rdata, offset = parse_record(data, offset)
                if rrclass & 0x8000:       # cache-flush bit — не игнорируем
                    rrclass &= 0x7FFF
                if rrtype == 33 and not port:              # SRV
                    port, target = parse_srv(rdata, data)
                elif rrtype == 16:                         # TXT
                    txt.update(parse_txt(rdata))
            if port:
                key = (addr[0], port)
                if key not in seen:
                    seen.add(key)
                    results.append({"ip": addr[0], "port": port,
                                    "target": target, "txt": txt, "service": name})
        sock.close()
        if not results and sent_from:
            print(f"  ({name}: отправлено с {', '.join(sent_from)})")
    except OSError as exc:
        results.append({"error": str(exc), "service": name})
    # Итог разбора нужен: «ответов нет» бывает двух видов — не пришло ничего
    # вовсе, либо пришло, но имя сервиса не разобралось. Из первого делают
    # неверный вывод «телефона нет», а второй указывает прямо на баг парсера.
    if not results:
        sources = ", ".join(stat.get("sources", [])) or "—"
        print(f"  ({name}: пакетов {stat['got']} [{sources}], "
              f"с нашим именем {stat['matched']}, SRV-ответов без результата "
              f"посчитаны в matched)")
    return results


# ------------------------------------------------------ adb и проверки


def adb_run(adb: str, args: list, timeout: int = 60) -> tuple:
    if not adb:
        return 1, "adb не найден (нужен ANDROID_SDK_ROOT или PATH)"
    try:
        proc = subprocess.run([adb] + args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"не запустился adb: {exc}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def classify_tls(ip: str, port: int, timeout: float = 3.0) -> tuple:
    """Говорит ли порт TLS. adb всегда — TLS, иначе это не adb."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(timeout)
    try:
        probe.connect((ip, port))
    except OSError as exc:
        return False, f"TCP не открылся: {exc}"
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        wrapped = ctx.wrap_socket(probe, server_hostname=ip)
        size = len(wrapped.getpeercert(True) or b"")
        wrapped.close()
        return True, f"TLS принят, сертификат байт: {size}"
    except ssl.SSLError as exc:
        text = str(exc).lower()
        if any(w in text for w in ("certificate", "alert", "handshake",
                                   "protocol", "want", "unknown ca")):
            return True, f"TLS: отвергли нас, но протокол его — {str(exc)[:80]}"
        return False, f"не TLS — {str(exc)[:80]}"
    except (ConnectionResetError, ConnectionAbortedError) as exc:
        return True, f"TLS: сброс после ClientHello ({type(exc).__name__})"
    except OSError as exc:
        return False, f"не TLS — закрыто без ответа ({exc})"
    finally:
        try:
            probe.close()
        except OSError:
            pass


def scan_alive(subnet: str) -> list:
    """Живые хосты по TCP. Ping не годится: ICMP режут роутеры."""
    hosts = [str(h) for h in ipaddress.ip_network(subnet)]
    alive, lock, index = [], threading.Lock(), 0

    def worker():
        nonlocal index
        while True:
            with lock:
                if index >= len(hosts):
                    return
                ip = hosts[index]
                index += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            try:
                sock.connect((ip, 9))
                with lock:
                    alive.append(ip)
            except ConnectionRefusedError:
                with lock:
                    alive.append(ip)     # RST = жив
            except OSError:
                pass
            finally:
                sock.close()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(128)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return sorted(alive, key=lambda h: int(h.rsplit(".", 1)[1]))


def scan_ports(ip: str, timeout: float = 0.5, workers: int = 400) -> list:
    todo = list(range(1, 65536))
    found, lock, index = [], threading.Lock(), 0

    def worker():
        nonlocal index
        while True:
            with lock:
                if index >= len(todo):
                    return
                port = todo[index]
                index += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((ip, port))
                with lock:
                    found.append(port)
            except OSError:
                pass
            finally:
                sock.close()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return sorted(found)


# ------------------------------------------------------------- main


def scan_and_pair(adb: str, ip: str, code: str, wait: int) -> int:
    """Порт пары ищем сканом по уже известному адресу телефона.

    mDNS умеет молчать при полностью живой отладке — на машине несколько
    интерфейсов, и multicast уезжает не туда. Адрес при этом уже известен
    (его телефон отдавал раньше: 192.168.0.103:40217). Искать mDNS не нужно:
    когда на экране телефона откроют окно с кодом, на том же адресе
    ПОЯВИТСЯ новый открытый порт. Это и есть порт пары, и он виден
    даже при мёртвом mDNS.

    Скрипт берёт базовый снимок портов, затем ждёт появления нового.
    """
    wait_left = max(0, wait)
    log(f"базовый скан {ip}: 1024-65535")
    baseline = scan_ports(ip, timeout=0.4)
    print("  открыто сейчас: " + (", ".join(str(p) for p in baseline) or "ничего"))

    # Служба на телефоне умеет молчать при живой сети: телефон отвечает на ARP,
    # но сокет adbd уже закрыт (отладка ушла в сон/выключилась). Раньше скрипт
    # тут же падал с «телефон не отвечает совсем», хотя стоило подождать —
    # телефон просыпается за пару секунд, как только экран разблокируют.
    deadline = time.time() + wait_left if wait_left else 0
    while not baseline and deadline and time.time() < deadline:
        print("  портов нет — ждём, пока служба отладки на телефоне поднимется "
              "(разблокируйте экран, чтобы отладка ожила)", flush=True)
        time.sleep(5)
        baseline = scan_ports(ip, timeout=0.4)
        if baseline:
            print("  поднялась: " + ", ".join(str(p) for p in baseline))
    if not baseline:
        print("  телефон не отвечает совсем — проверьте, что он в той же сети")
        return 2

    fresh = []
    if deadline:
        log("ждём появления нового порта — окно с кодом на телефоне")
        tick = 0
        while time.time() < deadline and not fresh:
            time.sleep(5)
            tick += 1
            now = scan_ports(ip, timeout=0.4)
            fresh = [p for p in now if p not in baseline]
            gone = [p for p in baseline if p not in now]
            if tick % 3 == 0 or fresh:
                state = "открыто: " + (", ".join(str(p) for p in now) or "ничего")
                print(f"  [{tick * 5} с] {state}", flush=True)
            if gone:
                print(f"  закрылись: {', '.join(str(p) for p in gone)}")
                baseline = [p for p in baseline if p not in gone]
        if not fresh:
            print("  новый порт не появился — экран пары за время не открыли "
                  "либо молчит не только mDNS, но и весь сетевой стек телефона")
            return 4
        print("  НОВЫЙ ПОРТ: " + ", ".join(str(p) for p in fresh))
    else:
        fresh = []

    if not code:
        if fresh:
            print(f"  Это скорее всего порт пары: {ip}:{fresh[0]}")
            print("  Повторите с --pair-code КОД, напечатанный в том же окне.")
        return 0

    log("adb pair")
    for port in sorted(fresh or baseline):
        target = f"{ip}:{port}"
        rc, text = adb_run(adb, ["pair", target, code])
        print(f"  {target}: {text}", flush=True)
        if rc == 0 and "successfully" in text.lower():
            log("adb connect")
            for port in baseline:
                ctext = adb_run(adb, ["connect", f"{ip}:{port}"])[1]
                print(f"  {ip}:{port}: {ctext}")
                if "connected" in ctext and "cannot" not in ctext:
                    dcode, devices = adb_run(adb, ["devices"])
                    print("  " + devices.replace("\n", "\n  "))
                    return 0
            return 5
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Поиск Android для Wi-Fi отладки")
    parser.add_argument("--pair-code", default="",
                        help="парный код с экрана телефона")
    parser.add_argument("--subnet", default="", help="подсеть, например 192.168.0.0/24")
    parser.add_argument("--scan", action="store_true",
                        help="запасной путь: полный скан портов вместо mDNS")
    parser.add_argument("--connect-only", action="store_true",
                        help="не пытаться связать, только найти и подключиться")
    parser.add_argument("--host", default="",
                        help="адрес телефона, если известен, например 192.168.0.103: "
                             "порт пары ищется сканом, mDNS не нужен")
    parser.add_argument("--wait", type=int, default=None, metavar="СЕК",
                        help="ждать появления окна пары на телефоне столько секунд "
                             "и связать сразу, как оно появится")
    args = parser.parse_args()

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    adb = find_adb()

    # --- известный адрес: mDNS не нужен, берём порт сканом ---
    if args.host:
        ip = args.host.split(":")[0]
        # Код дают вместе с открытым окном, а окно живёт минуты. Если время
        # не указано явно — ждём, но не вечно.
        wait = args.wait if args.wait is not None else (240 if args.pair_code else 0)
        return scan_and_pair(adb, ip, args.pair_code, wait)

    # --- 1. mDNS: адрес и порты идут из рук телефона ---
    log("mDNS: что телефон рекламирует")
    found = {}
    for service in SERVICES:
        answers = query_service(service)
        if not answers:
            print(f"  {service}: ответов нет")
            continue
        for answer in answers:
            if "error" in answer:
                print(f"  {service}: ошибка {answer['error']}")
                continue
            found[answer["service"]] = answer
            ident = answer["txt"].get("adb") or answer["target"] or "?"
            print(f"  {service} -> {answer['ip']}:{answer['port']}  "
                  f"устройство={ident}")
            for key, value in list(answer["txt"].items())[:4]:
                shown = value if len(value) <= 46 else value[:46] + "…"
                print(f"      {key}={shown}")

    pairing = found.get(SVC_PAIRING)
    connect = found.get(SVC_CONNECT)

    # --- ожидание окна пары ---
    # Парный код живёт около двух минут и одноразовый, а pair-сервис
    # рекламируется только пока окно открыто. Поэтому ждём появления сервиса и
    # связываемся мгновенно: так гонка со сроком жизни кода исчезает.
    if args.wait and not pairing:
        log(f"ждём, пока на телефоне откроют окно пары ({args.wait} с)")
        deadline = time.time() + args.wait
        while time.time() < deadline and not pairing:
            time.sleep(1.0)
            for service in SERVICES:
                for answer in query_service(service, wait=1.5, attempts=1):
                    if "error" in answer:
                        continue
                    found[answer["service"]] = answer
            pairing = found.get(SVC_PAIRING)
            if not connect:
                connect = found.get(SVC_CONNECT)
            if pairing:
                print(f"  pair-сервис появился: {pairing['ip']}:{pairing['port']}")
        if not pairing:
            print("  окно пары так и не открылось за отведённое время")
            return 4

    # --- 2. что это значит для нас ---
    log("состояние")
    if not pairing and not connect:
        print("  телефон не рекламирует adb.")
        print("  Вывод: телефон не в этой сети, либо Wi-Fi отладка выключена "
              "(Параметры → Для разработчиков → Беспроводная отладка).")
    elif not pairing and connect:
        print("  беспроводная отладка ВКЛЮЧЕНА, но мы не связаны с телефоном.")
        print(f"  Телефон слушает на {connect['ip']}:{connect['port']}, "
              "однако pair-сервис не рекламируется.")
        print("  Значит, на телефоне сейчас не открыто окно «Подключить устройство "
              "с кодом пары» — там же печатается код и адрес вида "
              f"{connect['ip']}:<пОРТ>.")

    # --- 3. подключение / пара ---
    if connect:
        log("adb connect")
        code, text = adb_run(adb, ["connect", f"{connect['ip']}:{connect['port']}"])
        print("  " + text)
        if "connected" in text and "cannot" not in text:
            print("  Устройство подключено, установка apk возможна.")
        elif "pair" in text.lower():
            print("  Нужна пара: откройте окно с кодом на телефоне и повторите "
                  "с --pair-code.")

    if args.pair_code and pairing:
        log("adb pair")
        target = f"{pairing['ip']}:{pairing['port']}"
        code, text = adb_run(adb, ["pair", target, args.pair_code])
        print(f"  {target}: {text}")
        if code == 0 and "successfully" in text.lower():
            if connect:
                _, ctext = adb_run(adb, ["connect",
                                         f"{connect['ip']}:{connect['port']}"])
                print(f"  connect: {ctext}")
            return 0
        return 1

    if args.pair_code and not pairing:
        log("adb pair")
        print("  Парить нечего: pair-сервис не рекламируется, значит код "
              "просрочен или окно закрыто. Код живёт около двух минут и "
              "одноразовый.")
        return 3

    # --- 4. запасной путь ---
    if args.scan and not found:
        log("запасной путь: скан портов")
        subnet = args.subnet
        if not subnet:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("8.8.8.8", 80))
                mine = sock.getsockname()[0]
            finally:
                sock.close()
            subnet = mine.rsplit(".", 1)[0] + ".0/24"
        for ip in scan_alive(subnet):
            print(f"  {ip}: " + ", ".join(str(p) for p in scan_ports(ip)))

    if not found:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Проверки логики поиска устройства — без сети, без телефона, без adb.

Зачем отдельный файл. В `find-device.py` уже найдены три ошибки, каждая из
которых выглядела как «телефона нет в сети»:

1. имя сервиса искалось сырыми байтами в пакете, а mDNS сжимает имена
   указателем 0xC0 — живой ответ телефона отбрасывался;
2. multicast уходил в VPN-интерфейс, а не в Ethernet;
3. мигнувший connect-порт объявлялся «новым портом пары», и `adb pair`
   уходил не на тот порт.

Пункты 1 и 3 проверяются здесь разбором и арифметикой: и то, и другое —
чистые функции над байтами и множествами. Пункт 2 проверяем только руками:
он про маршрутизацию конкретной машины.

Запуск: python android/test-find-device.py
"""

import importlib.util
import os
import struct
import sys

CHECKS = []


def ok(title: str, passed: bool, detail: str = "") -> None:
    CHECKS.append((title, passed))
    mark = "ok " if passed else "ПРОВАЛ"
    line = f"  {mark} {title}"
    if detail and not passed:
        line += f" — {detail}"
    print(line, flush=True)


def load_module():
    """Загружаем find-device.py как модуль.

    Имя файла с дефисом обычным import не берётся, поэтому через importlib.
    `__name__` при этом не `__main__`, значит `main()` не запустится и ни
    одного пакета в сеть не уйдёт.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "find-device.py")
    spec = importlib.util.spec_from_file_location("find_device", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def name_bytes(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def mdns_packet(compressed: bool) -> bytes:
    """Ответ mDNS: PTR на сервис и SRV с портом 40217.

    `compressed=True` — так делает телефон: имена заменены указателем 0xC00C
    на вопрос. Именно этот случай ломала прежняя проверка по сырым байтам.
    """
    service = "_adb-tls-connect._tcp.local"
    instance = "adb-AN2FVB1721003844-TNwDeW." + service

    # Заголовок: ответ, 1 вопрос, 1 запись ответа, 0 authority, 1 additional.
    data = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 1)

    # Вопрос (offset 12 — на него и указывает сжатие).
    data += name_bytes(service) + struct.pack("!HH", 12, 1)

    ptr_name = b"\xc0\x0c" if compressed else name_bytes(service)
    ptr_rdata = b"\xc0\x0c" if compressed else name_bytes(instance)
    data += (ptr_name + struct.pack("!HHIH", 12, 1, 120, len(ptr_rdata))
             + ptr_rdata)

    srv_name = b"\xc0\x0c" if compressed else name_bytes(instance)
    srv_rdata = (struct.pack("!HHH", 0, 0, 40217)
                 + (b"\xc0\x0c" if compressed else name_bytes(instance)))
    data += (srv_name + struct.pack("!HHIH", 33, 0x8001, 120, len(srv_rdata))
             + srv_rdata)
    return data


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    module = load_module()

    print("Разбор mDNS (ошибка №1: фильтр по сырым байтам):")
    for compressed in (False, True):
        data = mdns_packet(compressed)
        names, qd, an, ns, ar = module.rr_names(data)
        kind = "со сжатием" if compressed else "без сжатия"
        ok(f"имя сервиса разобрано ({kind})",
           "_adb-tls-connect._tcp.local" in names, repr(sorted(names)))
        ok(f"счётчики записей верны ({kind})", (qd, an, ns, ar) == (1, 1, 0, 1),
           f"{qd},{an},{ns},{ar}")
        # Прежняя проверка искала имя СЫРЫМИ байтами. Это не работает даже без
        # сжатия: в DNS имя — это последовательность строк с байтом длины
        # впереди, а не текст с точками; точки появляются только при разборе.
        # Поэтому фильтр выбрасывал живой ответ телефона всегда, а не только
        # когда имя сжато указателем.
        raw = b"_adb-tls-connect._tcp.local" in data
        ok(f"сырыми байтами имя не находится ({kind}) — потому и нужен разбор",
           raw is False, f"raw={raw}")

    print("Номера портов (ошибка №3: мигнувший порт объявлялся новым):")
    fresh, gone = module.port_diff([40217], {40217})
    ok("тот же порт — не новый", fresh == [] and gone == [], f"{fresh} {gone}")

    fresh, gone = module.port_diff([], {40217})
    ok("порт пропал — видно пропажу, новых нет",
       fresh == [] and gone == [40217], f"{fresh} {gone}")

    fresh, gone = module.port_diff([40217], {40217})   # вернулся после мигания
    ok("порт вернулся после мигания — по-прежнему не новый",
       fresh == [] and gone == [], f"{fresh} {gone}")

    fresh, gone = module.port_diff([40217, 41877], {40217})
    ok("настоящий новый порт найден", fresh == [41877] and gone == [],
       f"{fresh} {gone}")

    fresh, gone = module.port_diff([41877, 42000], {40217, 41877})
    ok("новых два, пропал один",
       fresh == [42000] and gone == [40217], f"{fresh} {gone}")

    print("Разбор SRV (порт пары берётся из записи, а не угадывается):")

    def find_srv(packet):
        """Находит SRV в настоящем пакете и разбирает его как в бою.

        Через parse_record — потому что важен именно абсолютный адрес rdata:
        указатель сжатия отсчитывается от начала пакета, и подсунуть функции
        искусственный rdata (первая версия этого теста) значит проверить
        не то. Проверяем на пакете, который целиком лежит в памяти.
        """
        _, qd, an, ns, ar = module.rr_names(packet)
        offset = 12
        for _ in range(qd):
            _, offset = module.read_name(packet, offset)
            offset += 4
        for _ in range(an + ns + ar):
            rrname, rtype, rclass, ttl, rdata, rdata_at, offset = \
                module.parse_record(packet, offset)
            if rtype == 33:
                return module.parse_srv(rdata, packet, rdata_at)
        return None, ""

    port, target = find_srv(mdns_packet(compressed=True))
    ok("порт из SRV прочитан", port == 40217, repr(port))
    ok("цель SRV разобрана по указателю сжатия",
       target == "_adb-tls-connect._tcp.local", repr(target))

    port, target = find_srv(mdns_packet(compressed=False))
    ok("та же цель без сжатия — имя экземпляра",
       target == "adb-AN2FVB1721003844-TNwDeW._adb-tls-connect._tcp.local",
       repr(target))

    print("Разбор TXT:")
    chunk = b"v=ADB_SECURE_SERVICE_VERSION"
    txt = module.parse_txt(bytes([len(chunk)]) + chunk)
    ok("ключ и значение TXT разобраны",
       txt.get("v") == "ADB_SECURE_SERVICE_VERSION", repr(txt))

    failed = [title for title, passed in CHECKS if not passed]
    print(f"\nпроверок: {len(CHECKS)}, провалов: {len(failed)}")
    if failed:
        for title in failed:
            print(f"  ПРОВАЛ: {title}")
        return 1
    print("ВСЁ ПРОШЛО")
    return 0


if __name__ == "__main__":
    sys.exit(main())

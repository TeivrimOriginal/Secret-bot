"""Разведка mDNS: что реально прилетает в ответ на запрос об adb.

Пишет ВСЕ полученные пакеты, без фильтра по имени. Нужно понять одну вещь:
телефон молчит, или отвечает так, что наш фильтр его отбрасывает (имя в
ответе сжато указателем и байтами в пакете не встречается).

Запуск: python mdns_probe.py [имя-сервиса]
"""
import argparse
import socket
import struct
import sys
import time

GROUP = "224.0.0.251"
PORT = 5353


def read_name(data, offset, depth=0):
    if depth > 12:
        return "", offset
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return ".".join(labels), offset + 1
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            rest, _ = read_name(data, ptr, depth + 1)
            labels.append(rest)
            return ".".join(labels), offset + 2
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), offset


def main():
    # argparse, а не sys.argv[1]: нужен рабочий --help, чтобы общий прогон
    # test-passkey.py мог проверить этот скрипт, не трогая сеть. Ловить ошибки
    # разбора нужно до того, как они превратятся в бессмысленный mDNS-запрос.
    parser = argparse.ArgumentParser(
        description="Разведка mDNS: пишет все пакеты в ответ на запрос об adb")
    parser.add_argument("service", nargs="?",
                        default="_adb-tls-connect._tcp.local",
                        help="имя сервиса (по умолчанию _adb-tls-connect._tcp.local)")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    name = args.service
    print(f"запрос: {name}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    bound = None
    for port in (PORT, 0):
        try:
            sock.bind(("", port))
            bound = port
            break
        except OSError:
            continue
    print(f"привязан к порту {bound} "
          f"({'это 5353' if bound == PORT else 'свой порт, ответ придёт ему'})")

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(GROUP) + socket.inet_aton("0.0.0.0"))
    sock.settimeout(6.0)

    packet = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    for label in name.split("."):
        if label:
            packet += bytes([len(label)]) + label.encode()
    packet += b"\x00" + struct.pack("!HH", 12, 1)

    for attempt in range(3):
        sock.sendto(packet, (GROUP, PORT))
        print(f"запрос отправлен (попытка {attempt + 1})")
        time.sleep(2.0)

    print("--- пакеты за 6 с ---")
    got = 0
    deadline = time.time() + 6
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        got += 1
        raw = "есть" if name.encode() in data else "НЕТ (имя сжато или чужое)"
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            _, offset = read_name(data, offset)
            offset += 4
        types = []
        port = None
        target = ""
        txt = {}
        for _ in range(an + ns + ar):
            if offset >= len(data):
                break
            rr, offset = read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            types.append(f"{rr}={rtype}")
            if rtype == 33 and rdlen >= 6:
                port = struct.unpack("!H", rdata[4:6])[0]
                target, _ = read_name(rdata, 6)
            elif rtype == 16:
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    i += 1
                    chunk = rdata[i:i + ln]
                    i += ln
                    if b"=" in chunk:
                        k, _, v = chunk.partition(b"=")
                        txt[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
        print(f"  от {addr[0]}:{addr[1]}  байт={len(data)}  имя-в-пакете:{raw}")
        print(f"      RR: {types}")
        if port:
            print(f"      SRV порт={port} цель={target}")
        if txt:
            shown = {k: (v[:40] + "…" if len(v) > 40 else v) for k, v in list(txt.items())[:5]}
            print(f"      TXT: {shown}")
    print(f"всего пакетов: {got}")
    sock.close()


if __name__ == "__main__":
    main()

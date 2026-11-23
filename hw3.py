#!/usr/bin/env python3
import argparse
import ipaddress
import logging
import os
import random
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Set, Tuple

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.sendrecv import send, sr1
from scapy.config import conf

conf.verb = 0

PROTO_TCP = "tcp"
PROTO_UDP = "udp"
PORT_MIN = 1
PORT_MAX = 65535
DEFAULT_PORTS = range(1, 1025)
SYN_ACK_FLAGS = 0x12


def _normalize_proto(raw: str) -> str:
    proto = raw.strip().lower()
    if proto not in (PROTO_TCP, PROTO_UDP):
        raise ValueError(f"Неподдерживаемый протокол: '{raw}'")
    return proto


def _parse_port_token(token: str) -> range:
    token = token.strip()
    if not token:
        raise ValueError("Пустой элемент списка портов")
    if "-" in token:
        lo_s, hi_s = token.split("-", 1)
        try:
            lo, hi = int(lo_s), int(hi_s)
        except ValueError as exc:
            raise ValueError(f"Некорректный диапазон портов '{token}'") from exc
        if not (PORT_MIN <= lo <= hi <= PORT_MAX):
            raise ValueError(f"Диапазон вне допустимых границ {PORT_MIN}..{PORT_MAX}: '{token}'")
        return range(lo, hi + 1)
    try:
        port = int(token)
    except ValueError as exc:
        raise ValueError(f"Некорректный порт '{token}'") from exc
    if not (PORT_MIN <= port <= PORT_MAX):
        raise ValueError(f"Порт вне допустимых границ {PORT_MIN}..{PORT_MAX}: '{token}'")
    return range(port, port + 1)


class SpecExpander:
    @staticmethod
    def expand(spec: str) -> Set[Tuple[str, int]]:
        if "/" not in spec:
            proto = _normalize_proto(spec)
            return {(proto, p) for p in range(PORT_MIN, PORT_MAX + 1)}

        proto_raw, ports_raw = spec.split("/", 1)
        proto = _normalize_proto(proto_raw)
        if not ports_raw.strip():
            raise ValueError(f"Пустой список портов в спецификации: '{spec}'")

        result: Set[Tuple[str, int]] = set()
        for chunk in ports_raw.split(","):
            for p in _parse_port_token(chunk):
                result.add((proto, p))
        return result


class ScanPlan:
    def __init__(self, specs: Iterable[str]):
        self._specs = list(specs)

    def targets(self) -> List[Tuple[str, int]]:
        collected: Set[Tuple[str, int]] = set()
        if not self._specs:
            for p in DEFAULT_PORTS:
                collected.add((PROTO_TCP, p))
                collected.add((PROTO_UDP, p))
        else:
            for spec in self._specs:
                collected |= SpecExpander.expand(spec)
        return sorted(collected, key=lambda t: (t[1], t[0]))


class Cli:
    @staticmethod
    def parse(argv: List[str]) -> argparse.Namespace:
        ap = argparse.ArgumentParser(prog="portscan", description="TCP SYN и UDP сканер портов")
        ap.add_argument("--timeout", type=float, default=2.0,
                        help="Таймаут ожидания ответа в секундах (по умолчанию 2с)")
        ap.add_argument("-j", "--num-threads", type=int, default=10, help="Число потоков")
        ap.add_argument("-v", "--verbose", action="store_true", help="Подробный режим")
        ap.add_argument("-g", "--guess", action="store_true",
                        help="Определение протокола прикладного уровня")
        ap.add_argument("ip_address", help="Целевой IP-адрес")
        ap.add_argument("specs", nargs="*",
                        help="Спецификации вида {tcp|udp}[/[PORT|PORT-PORT],...]")
        ns = ap.parse_args(argv)

        try:
            ipaddress.ip_address(ns.ip_address)
        except ValueError as exc:
            ap.error(f"Некорректный IP-адрес '{ns.ip_address}': {exc}")
        if ns.timeout <= 0:
            ap.error("--timeout должен быть больше 0")
        if ns.num_threads < 1:
            ap.error("--num-threads должен быть не меньше 1")
        return ns


class SynProbe:
    @staticmethod
    def probe(ip: str, port: int, timeout: float) -> Optional[Tuple[str, int]]:
        src_port = random.randint(1025, 65535)
        seq = random.randint(0, (1 << 32) - 1)
        probe = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S", seq=seq)
        reply = sr1(probe, timeout=timeout, verbose=0)
        if reply is None or not reply.haslayer(TCP):
            return None
        t = reply[TCP]
        if (t.flags & SYN_ACK_FLAGS) != SYN_ACK_FLAGS:
            return None
        teardown = IP(dst=ip) / TCP(sport=t.dport, dport=port, seq=t.ack, flags="R")
        send(teardown, verbose=0)
        return (PROTO_TCP.upper(), port)


class UdpProbe:
    @staticmethod
    def probe(ip: str, port: int, timeout: float) -> Optional[Tuple[str, int]]:
        src_port = random.randint(1025, 65535)
        probe = IP(dst=ip) / UDP(sport=src_port, dport=port)
        reply = sr1(probe, timeout=timeout, verbose=0)
        if reply is None:
            return (PROTO_UDP.upper(), port)
        if reply.haslayer(ICMP):
            ic = reply[ICMP]
            if ic.type == 3 and ic.code == 3:
                return None
        if reply.haslayer(UDP):
            return (PROTO_UDP.upper(), port)
        return None


class ProbeDispatcher:
    @staticmethod
    def run(ip: str, proto: str, port: int, timeout: float) -> Optional[Tuple[str, int]]:
        if proto == PROTO_TCP:
            return SynProbe.probe(ip, port, timeout)
        if proto == PROTO_UDP:
            return UdpProbe.probe(ip, port, timeout)
        return None


class TcpEchoServer:
    @staticmethod
    def serve(host: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(5)
            while True:
                client, _ = srv.accept()
                client.close()


class UdpEchoServer:
    @staticmethod
    def serve(host: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
            srv.bind((host, port))
            while True:
                payload, peer = srv.recvfrom(1024)
                srv.sendto(b"pong\n", peer)


class Runner:
    @staticmethod
    def execute(argv: List[str]) -> int:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Ошибка: для работы scapy с raw-сокетами требуются права root "
                  "(запустите через sudo).", file=sys.stderr)
            return 1

        ns = Cli.parse(argv)

        try:
            plan = ScanPlan(ns.specs).targets()
        except ValueError as exc:
            print(f"Ошибка в параметрах запуска: {exc}", file=sys.stderr)
            return 2

        hits: List[Tuple[str, int]] = []
        with ThreadPoolExecutor(max_workers=ns.num_threads) as pool:
            pending = [
                pool.submit(ProbeDispatcher.run, ns.ip_address, proto, port, ns.timeout)
                for proto, port in plan
            ]
            for fut in as_completed(pending):
                outcome = fut.result()
                if outcome is not None:
                    hits.append(outcome)

        for proto, port in sorted(hits, key=lambda t: (t[1], t[0])):
            print(f"{proto} {port}")
        return 0


def launch_servers() -> None:
    host = "127.0.0.1"
    threading.Thread(target=TcpEchoServer.serve, args=(host, 15001), daemon=True).start()
    threading.Thread(target=UdpEchoServer.serve, args=(host, 15002), daemon=True).start()
    print("Listeners started on TCP 15001 and UDP 15002. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) == 1:
        launch_servers()
    else:
        sys.exit(Runner.execute(sys.argv[1:]))
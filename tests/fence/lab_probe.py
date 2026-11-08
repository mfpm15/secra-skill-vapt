#!/usr/bin/env python3
"""Lab-only socket and process probe. Never installed as a production adapter."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def connect(host: str, port: int, mode: str) -> None:
    print("LAB_PROBE_STARTED", flush=True)
    if mode == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"lab", (host, port))
    else:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.connect((host, port))


def family(marker: str, level: int) -> None:
    path = Path(marker)
    with path.open("a", encoding="ascii") as file:
        file.write(str(os.getpid()) + "\n")
        file.flush()
        os.fsync(file.fileno())
    if level > 0:
        subprocess.Popen([sys.executable, __file__, "family", marker,
                          str(level - 1)], stdin=subprocess.DEVNULL)
    time.sleep(90)


def allocate() -> None:
    print("LAB_PROBE_STARTED", flush=True)
    chunks = []
    while len(chunks) < 800:
        chunks.append(bytearray(1024 * 1024))
        time.sleep(0.002)
    time.sleep(90)


def spin() -> None:
    print("LAB_PROBE_STARTED", flush=True)
    until = time.monotonic() + 90
    while time.monotonic() < until:
        pass


def main():
    action = sys.argv[1]
    if action == "connect":
        connect(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif action == "family":
        family(sys.argv[2], int(sys.argv[3]))
    elif action == "allocate":
        allocate()
    elif action == "spin":
        spin()
    elif action == "sleep":
        time.sleep(90)
    else:
        sys.exit(64)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""UDP echo server for the exit-node benchmark.

Echoes every datagram back and records which source addresses it saw. That
record is the actual proof of source NAT: packets originate from a client at
10.99.0.1 inside the tunnel, so if this server sees them arriving from the
gateway's own LAN address, the translation worked.
"""

import signal
import socket
import sys
from collections import Counter


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # A large receive buffer, so a burst is not lost to the kernel before this
    # single-threaded loop gets to it — that would be measuring Python, not the
    # device.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", port))

    sources: Counter[str] = Counter()
    packets = 0
    payload_bytes = 0

    def report(*_args: object) -> None:
        print(f"packets received: {packets}")
        print(f"payload bytes:    {payload_bytes}")
        print("observed source addresses:")
        for address, count in sources.most_common():
            print(f"  {address}  x{count}")
        sys.stdout.flush()
        sys.exit(0)

    signal.signal(signal.SIGINT, report)
    signal.signal(signal.SIGTERM, report)

    while True:
        data, addr = sock.recvfrom(65535)
        packets += 1
        payload_bytes += len(data)
        sources[addr[0]] += 1
        sock.sendto(data, addr)


if __name__ == "__main__":
    main()

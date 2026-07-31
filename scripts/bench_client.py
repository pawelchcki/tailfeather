#!/usr/bin/env python3
"""Load generator for the exit-node benchmark.

Sends UDP through the tunnel and counts what comes back, so the figure reported
is delivered round-trip goodput rather than what was merely offered.

Sending and receiving run on separate threads. A single-threaded loop that
alternates between the two spends its time in the receive timeout and ends up
measuring its own pacing rather than the device's capacity.

Offered load is swept across a range of rates. A single blast only reveals the
saturated behaviour, which is mostly loss; sweeping shows both the rate the
device sustains cleanly and the ceiling it tops out at.
"""

import socket
import sys
import threading
import time


def measure(server, payload_size, duration, rate_pps):
    """Offer `rate_pps` (or as fast as possible if None) and count replies."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.2)

    payload = bytes(payload_size)
    stop = threading.Event()
    counters = {"sent": 0, "received": 0, "bytes": 0}

    def send_loop():
        interval = 1.0 / rate_pps if rate_pps else 0.0
        next_send = time.monotonic()
        while not stop.is_set():
            try:
                sock.sendto(payload, server)
                counters["sent"] += 1
            except OSError:
                time.sleep(0.001)
                continue
            if interval:
                next_send += interval
                delay = next_send - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                else:
                    # Behind schedule: give up on catching up rather than
                    # bursting, which would distort the offered rate.
                    next_send = time.monotonic()

    def recv_loop():
        while not stop.is_set():
            try:
                data, _ = sock.recvfrom(65535)
                counters["received"] += 1
                counters["bytes"] += len(data)
            except socket.timeout:
                continue
            except OSError:
                break

    sender = threading.Thread(target=send_loop, daemon=True)
    receiver = threading.Thread(target=recv_loop, daemon=True)

    start = time.monotonic()
    receiver.start()
    sender.start()
    time.sleep(duration)
    stop.set()
    sender.join(timeout=1)
    # Let replies still in flight arrive before the books are closed.
    time.sleep(0.3)
    receiver.join(timeout=1)
    elapsed = time.monotonic() - start
    sock.close()

    sent = counters["sent"]
    received = counters["received"]
    return {
        "offered_pps": rate_pps,
        "sent": sent,
        "received": received,
        "bytes": counters["bytes"],
        "elapsed": elapsed,
        "loss": 100.0 * (sent - received) / sent if sent else 0.0,
        "pps": received / elapsed,
        # Each delivered payload crossed the device twice: outbound through NAT
        # and inbound through the tunnel.
        "mbps_one_way": counters["bytes"] * 8 / elapsed / 1e6,
        "mbps_both": counters["bytes"] * 2 * 8 / elapsed / 1e6,
    }


def main() -> None:
    server_ip = sys.argv[1]
    port = int(sys.argv[2])
    duration = float(sys.argv[3])
    payload_size = int(sys.argv[4])
    server = (server_ip, port)

    # Bounded rates only. An unlimited blast offers hundreds of Mbit/s, which
    # does not probe the device's ceiling so much as bury it: the result is
    # congestion collapse and a throughput figure lower than at a tenth the
    # load.
    rates = [100, 150, 200, 250, 300, 400, 600]
    if len(sys.argv) > 5 and sys.argv[5].strip():
        rates = [int(r) for r in sys.argv[5].split(",")]
    results = []

    header = f"{'offered':>12} {'echoed pps':>11} {'loss':>7} {'Mbit/s 1-way':>13} {'Mbit/s both':>12}"
    print(header)
    print("-" * len(header))

    for rate in rates:
        result = measure(server, payload_size, duration, rate)
        results.append(result)
        offered = f"{rate} pps" if rate else "max"
        print(
            f"{offered:>12} {result['pps']:>11.0f} {result['loss']:>6.1f}% "
            f"{result['mbps_one_way']:>13.2f} {result['mbps_both']:>12.2f}"
        )
        # Let the device drain between steps so one step's backlog is not
        # counted against the next.
        time.sleep(1.0)

    best = max(results, key=lambda r: r["mbps_both"])
    clean = [r for r in results if r["loss"] < 5.0]
    print()
    print(f"peak: {best['mbps_both']:.2f} Mbit/s through the device "
          f"({best['mbps_one_way']:.2f} Mbit/s of payload each way, {best['pps']:.0f} pps)")
    if clean:
        best_clean = max(clean, key=lambda r: r["mbps_both"])
        offered = f"{best_clean['offered_pps']} pps" if best_clean["offered_pps"] else "max"
        print(f"sustained below 5% loss: {best_clean['mbps_both']:.2f} Mbit/s at {offered} offered")
    else:
        print("no offered rate stayed below 5% loss")


if __name__ == "__main__":
    main()

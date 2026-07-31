#!/usr/bin/env python3
"""HTTP server for the forwarding test.

Two endpoints:

  /whoami  reports the source address the request arrived from, which is the
           proof of translation — the client is inside the tunnel, so seeing
           the gateway's own address means NAT did its job.
  /data    a body of a known size, for measuring TCP throughput.
"""

import signal
import socketserver
import sys
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

CHUNK = 64 * 1024

sources: Counter[str] = Counter()
body_size = 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        client = self.client_address[0]
        sources[client] += 1

        if self.path == "/whoami":
            body = f"client address as seen by the server: {client}\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(body_size))
            self.end_headers()
            # Written in chunks so the whole body is not held in memory, and so
            # a stalled transfer shows up as a stalled write rather than one
            # enormous buffered send.
            remaining = body_size
            block = bytes(CHUNK)
            while remaining > 0:
                n = min(CHUNK, remaining)
                self.wfile.write(block[:n])
                remaining -= n
            return

        self.send_error(404)

    def log_message(self, *_args: object) -> None:
        # The default handler logs to stderr per request, which would interleave
        # noisily with the transfer measurement.
        pass


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    global body_size
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    body_size = (int(sys.argv[2]) if len(sys.argv) > 2 else 1) * 1024 * 1024

    server = Server(("0.0.0.0", port), Handler)

    def report(*_args: object) -> None:
        print("observed client addresses:")
        for address, count in sources.most_common():
            print(f"  {address}  x{count}")
        sys.stdout.flush()
        sys.exit(0)

    signal.signal(signal.SIGINT, report)
    signal.signal(signal.SIGTERM, report)
    server.serve_forever()


if __name__ == "__main__":
    main()

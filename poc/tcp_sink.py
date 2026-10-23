#!/usr/bin/env python3
"""Localhost syslog sink: accepts one connection and records the raw bytes received.

Used to prove LOG4J-SDID-INJECTION end-to-end: the bytes Log4j puts on the
wire are captured verbatim, so an injected CRLF and a forged syslog record are
directly observable.

Usage: tcp_sink.py <port> <output-file> [seconds]
"""
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 5140
outfile = sys.argv[2] if len(sys.argv) > 2 else "wire.bin"
duration = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
srv.settimeout(duration)
print(f"listening on 127.0.0.1:{port}", flush=True)

data = b""
try:
    conn, addr = srv.accept()
    conn.settimeout(duration)
    print(f"accepted from {addr}", flush=True)
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
except socket.timeout:
    print("no connection received", flush=True)
finally:
    with open(outfile, "wb") as fh:
        fh.write(data)
    print(f"wrote {len(data)} bytes to {outfile}", flush=True)
    srv.close()

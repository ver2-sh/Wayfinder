#!/usr/bin/env python3
"""A generic reconnecting application. Run as an authorized local application account."""
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import threading
import time

SERVICE = "echo.private.v1"

def socket_path():
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/run"))
    if not (runtime / "wayfinder").is_dir():
        runtime = Path("/run")
    return str(runtime / "wayfinder/app.sock")

def read_exact(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError("Connection closed")
        data += chunk
    return data

def receive(stream):
    size = struct.unpack("!I", read_exact(stream, 4))[0]
    if not 0 < size <= 128 * 1024:
        raise ValueError("Invalid frame")
    return json.loads(read_exact(stream, size))

def send(stream, value):
    data = json.dumps(value).encode()
    stream.sendall(struct.pack("!I", len(data)) + data)

def connect():
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(5)
    stream.connect(socket_path())
    return stream

def main():
    credential = secrets.token_hex(32)
    listener = socket.create_server(("127.0.0.1", 0))
    slots = threading.BoundedSemaphore(16)
    def serve(stream):
        try:
            with stream:
                stream.settimeout(5)
                head = receive(stream)
                if head.get("version") != 1 or head.get("service") != SERVICE or not secrets.compare_digest(head.get("credential", ""), credential):
                    return
                send(stream, {"version": 1, "ready": True})
                while data := stream.recv(32768):
                    stream.sendall(data)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            slots.release()
    def accept():
        while True:
            stream, _ = listener.accept()
            if slots.acquire(blocking=False):
                threading.Thread(target=serve, args=(stream,), daemon=True).start()
            else:
                stream.close()
    threading.Thread(target=accept, daemon=True).start()
    while True:
        try:
            with connect() as session:
                send(session, {"op": "register_service", "service": SERVICE,
                               "address": "%s:%s" % listener.getsockname(), "credential": credential})
                if "error" in receive(session):
                    raise ValueError("Registration rejected")
                while True:
                    time.sleep(1)
                    send(session, {"op": "status"})
                    receive(session)
        except (OSError, EOFError, ValueError):
            time.sleep(1)

if __name__ == "__main__":
    main()

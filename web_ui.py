#!/usr/bin/env python3
"""Local browser UI for T-Nocker. Binds only to loopback."""

import argparse
import importlib.util
import json
from pathlib import Path
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("t_nocker", ROOT / "T-Nocker1.1.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

STATE = {"current": None, "previous": None, "local": None}
LOCK = threading.Lock()
SCAN_LOCK = threading.Lock()


def run_scan(data):
    if not isinstance(data, dict) or data.get("authorized") is not True:
        raise ValueError("Bestätige die Berechtigung für das Zielsystem.")
    host = data.get("host")
    if not isinstance(host, str) or not host or len(host) > 253 or any(c.isspace() for c in host):
        raise ValueError("Gib einen gültigen Hostnamen oder eine IP-Adresse ein.")
    try:
        start = scanner.port_number(str(data.get("start")))
        end = scanner.port_number(str(data.get("end")))
        timeout = scanner.timeout_seconds(str(data.get("timeout", 0.5)))
    except argparse.ArgumentTypeError as exc:
        raise ValueError(str(exc)) from exc
    if start > end or end - start + 1 > 256:
        raise ValueError("Wähle einen aufsteigenden Bereich mit höchstens 256 Ports.")
    try:
        addresses = scanner.resolve(host)
    except OSError as exc:
        raise ValueError(f"DNS-Auflösung fehlgeschlagen: {exc}") from exc
    if not addresses or len(addresses) > 8:
        raise ValueError("Das Ziel liefert keine oder zu viele TCP-Adressen (maximal 8).")
    if (end - start + 1) * len(addresses) * timeout > 30:
        raise ValueError("Der Bereich kann zu lange dauern. Reduziere Ports oder Timeout (Budget: 30 s).")
    # Capture scanner output; only structured results reach the browser.
    import contextlib
    import io
    started = time.monotonic()
    with contextlib.redirect_stdout(io.StringIO()):
        opened, errors = scanner.scan(addresses, start, end, timeout)
    elapsed = time.monotonic() - started
    args = argparse.Namespace(host=host, start_port=start, end_port=end, timeout=timeout)
    return scanner.sors_observation(args, addresses, opened, errors, elapsed)


class Handler(BaseHTTPRequestHandler):
    def common_headers(self, content_type):
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'")

    def valid_host(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")

    def send_data(self, code, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.common_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not self.valid_host():
            return self.send_data(403, {"error": "Ungültiger Host-Header."})
        path = urlparse(self.path).path
        if path == "/api/state":
            with LOCK:
                return self.send_data(200, STATE.copy())
        if path == "/api/export":
            with LOCK:
                snapshot = STATE["current"]
                local = STATE["local"]
            if snapshot is None:
                return self.send_data(404, {"error": "Noch kein Scan vorhanden."})
            output = dict(snapshot)
            if local is not None:
                output["local_bpfdoor_indicators"] = local
            return self.send_data(200, output)
        if path not in ("/", "/index.html", "/style.css", "/app.js"):
            return self.send_data(404, {"error": "Nicht gefunden."})
        file = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        mime = "text/html" if file.endswith(".html") else "text/css" if file.endswith(".css") else "text/javascript"
        raw = (ROOT / "ui" / file).read_bytes()
        self.send_response(200)
        self.common_headers(mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if not self.valid_host():
            return self.send_data(403, {"error": "Ungültiger Host-Header."})
        origin = self.headers.get("Origin", "")
        if origin not in (f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"):
            return self.send_data(403, {"error": "Ungültiger Ursprung."})
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.send_data(415, {"error": "JSON erforderlich."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Ungültige Anfragegröße.")
            data = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self.send_data(400, {"error": "Ungültige JSON-Anfrage."})
        path = urlparse(self.path).path
        if path == "/api/scan":
            if not SCAN_LOCK.acquire(blocking=False):
                return self.send_data(409, {"error": "Ein Scan läuft bereits."})
            try:
                snapshot = run_scan(data)
                with LOCK:
                    STATE["previous"] = STATE["current"]
                    STATE["current"] = snapshot
                    result = STATE.copy()
                return self.send_data(200, result)
            except ValueError as exc:
                return self.send_data(400, {"error": str(exc)})
            finally:
                SCAN_LOCK.release()
        if path == "/api/local":
            from bpfdoor_local import check_local
            report = check_local()
            with LOCK:
                STATE["local"] = report
                result = STATE.copy()
            return self.send_data(200, result)
        return self.send_data(404, {"error": "Nicht gefunden."})


def main():
    parser = argparse.ArgumentParser(description="Lokale T-Nocker Browseroberfläche")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port muss zwischen 1024 und 65535 liegen")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"T-Nocker: http://127.0.0.1:{args.port}", flush=True)
    print("Beenden mit Ctrl+C", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())

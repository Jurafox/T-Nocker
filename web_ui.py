#!/usr/bin/env python3
"""Local SORS matrix UI. Binds only to loopback."""

import argparse
import json
from pathlib import Path
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from sors_modules import load_registry

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "frontend" / "dist" if (ROOT / "frontend" / "dist" / "index.html").exists() else ROOT / "ui"
REGISTRY = load_registry()

STATE = {"current": None, "previous": None, "local": None}
OBSERVATIONS = []
LOCK = threading.Lock()
SCAN_LOCK = threading.Lock()


def run_scan(data):
    """Compatibility result for the existing scan view."""
    return REGISTRY.run("t_nocker", data)["coverage"]["legacy_snapshot"]


def remember(item):
    with LOCK:
        OBSERVATIONS.append(item)
        del OBSERVATIONS[:-100]


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
        if path == "/api/modules":
            return self.send_data(200, {"modules": REGISTRY.manifests()})
        if path == "/api/observations":
            with LOCK:
                return self.send_data(200, {"schema": "sors.observations.v1", "items": OBSERVATIONS.copy()})
        if path == "/api/export":
            with LOCK:
                snapshot = STATE["current"]
                local = STATE["local"]
            if snapshot is None:
                return self.send_data(404, {"error": "Noch kein Scan vorhanden."})
            output = dict(snapshot)
            if local is not None:
                output["local_bpfdoor_indicators"] = local
            with LOCK:
                output["sors_observations"] = OBSERVATIONS.copy()
            return self.send_data(200, output)
        relative = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        file = (STATIC / relative).resolve()
        if not file.is_relative_to(STATIC.resolve()) or not file.is_file():
            return self.send_data(404, {"error": "Nicht gefunden."})
        mime = ("text/html" if file.suffix == ".html" else "text/css" if file.suffix == ".css"
                else "text/javascript" if file.suffix == ".js" else "font/woff2" if file.suffix == ".woff2"
                else "font/woff" if file.suffix == ".woff" else "font/ttf" if file.suffix == ".ttf"
                else "image/svg+xml" if file.suffix == ".svg" else "application/octet-stream")
        raw = file.read_bytes()
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
        path = urlparse(self.path).path
        limit = 1_500_000 if path.startswith("/api/modules/") and path.endswith("/run") else 4096
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= limit:
                raise ValueError("Ungültige Anfragegröße.")
            data = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self.send_data(400, {"error": "Ungültige JSON-Anfrage."})
        if path == "/api/scan":
            if not SCAN_LOCK.acquire(blocking=False):
                return self.send_data(409, {"error": "Ein Scan läuft bereits."})
            try:
                result_observation = REGISTRY.run("t_nocker", data)
                snapshot = result_observation["coverage"]["legacy_snapshot"]
                with LOCK:
                    STATE["previous"] = STATE["current"]
                    STATE["current"] = snapshot
                    OBSERVATIONS.append(result_observation)
                    del OBSERVATIONS[:-100]
                    result = STATE.copy()
                return self.send_data(200, result)
            except ValueError as exc:
                return self.send_data(400, {"error": str(exc)})
            finally:
                SCAN_LOCK.release()
        if path == "/api/local":
            result_observation = REGISTRY.run("packet_sockets", data)
            report = result_observation["coverage"]["report"]
            with LOCK:
                STATE["local"] = report
                OBSERVATIONS.append(result_observation)
                del OBSERVATIONS[:-100]
                result = STATE.copy()
            return self.send_data(200, result)
        if path.startswith("/api/modules/") and path.endswith("/run"):
            module_id = path.split("/")[3]
            manifest = next((m for m in REGISTRY.manifests() if m["id"] == module_id), None)
            if manifest is None:
                return self.send_data(404, {"error": "Modul nicht installiert."})
            if manifest["input_kind"] != "text_file":
                return self.send_data(400, {"error": "Dieses Modul verwendet seinen eigenen geschützten Ablauf."})
            try:
                item = REGISTRY.run(module_id, data)
            except ValueError as exc:
                return self.send_data(400, {"error": str(exc)})
            remember(item)
            return self.send_data(200, {"observation": item})
        return self.send_data(404, {"error": "Nicht gefunden."})


def main():
    parser = argparse.ArgumentParser(description="Lokale SORS Matrix")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port muss zwischen 1024 und 65535 liegen")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"SORS: http://127.0.0.1:{args.port}", flush=True)
    print("Beenden mit Ctrl+C", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())

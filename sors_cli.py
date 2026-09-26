#!/usr/bin/env python3
"""Run installed SORS modules and emit neutral observation JSON."""

import argparse
import json
from pathlib import Path
import sys

from sors_modules import load_registry


def main(argv=None):
    parser = argparse.ArgumentParser(description="SORS Zustandsmatrix: modulare Beobachtungen")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("modules", help="installierte Module anzeigen")
    sub.add_parser("packet-sockets", help="lokale Linux-Packet-Sockets prüfen")
    importer = sub.add_parser("import-wireshark", help="gespeicherten TShark-TSV-Export einlesen")
    importer.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    registry = load_registry()
    if args.command == "modules":
        print(json.dumps(registry.manifests(), ensure_ascii=False, indent=2))
        return 0
    try:
        if args.command == "packet-sockets":
            item = registry.run("packet_sockets", {})
        else:
            if args.file.stat().st_size > 1_000_000:
                raise ValueError("TSV-Datei ist größer als 1 MB.")
            item = registry.run("wireshark_fields", {"text": args.file.read_text(encoding="utf-8")})
    except (OSError, UnicodeError, ValueError, KeyError) as exc:
        print(f"SORS: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(item, ensure_ascii=False, indent=2))
    return 0 if item["status"] == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())

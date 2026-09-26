"""Import a bounded, payload-free TShark TSV field export."""

import csv
import io
import ipaddress
import math
from collections import Counter

from sors_modules import observation

FIELDS = ("frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport")
MAX_BYTES = 1_000_000
MAX_ROWS = 10000


class WiresharkFields:
    manifest = {"id": "wireshark_fields", "name": "Wireshark-Feldimport", "input_kind": "text_file",
                "description": "Importiert TShark-Felder aus einer gespeicherten Aufnahme; keine Live-Erfassung und keine Nutzdaten."}

    def run(self, payload):
        raw = payload.get("text") if isinstance(payload, dict) else None
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_BYTES:
            raise ValueError("TSV-Datei fehlt oder ist größer als 1 MB.")
        reader = csv.DictReader(io.StringIO(raw), delimiter="\t")
        if reader.fieldnames != list(FIELDS):
            raise ValueError("Unerwartete TShark-Spalten oder Reihenfolge. Verwende den dokumentierten Exportbefehl.")
        flows = Counter()
        rows = invalid = 0
        for row in reader:
            if rows >= MAX_ROWS:
                raise ValueError("Mehr als 10 000 Pakete. Exportiere einen kleineren Ausschnitt.")
            rows += 1
            try:
                src = ipaddress.ip_address(row["ip.src"] or row["ipv6.src"])
                dst = ipaddress.ip_address(row["ip.dst"] or row["ipv6.dst"])
                protocol = "tcp" if row["tcp.dstport"] else "udp"
                port = int(row["tcp.dstport"] or row["udp.dstport"])
                if not 1 <= port <= 65535 or not row["frame.time_epoch"]:
                    raise ValueError("Missing field")
                timestamp = float(row["frame.time_epoch"])
                if not math.isfinite(timestamp) or timestamp < 0:
                    raise ValueError("Invalid timestamp")
                flows[(str(src), str(dst), protocol, port)] += 1
            except (ValueError, TypeError, KeyError):
                invalid += 1
        top = [{"source": a, "destination": b, "protocol": proto, "destination_port": port,
                "packets": count} for (a, b, proto, port), count in flows.most_common(100)]
        return observation("wireshark_fields", "capture_import", "partial" if invalid else "complete",
                           {"top_flows": top, "packet_rows": rows, "invalid_rows": invalid},
                           {"source_format": "tshark.fields.tsv", "retained_flows": len(top),
                            "distinct_flows": len(flows), "payload_included": False,
                            "note": "Nur exportierte Pakete; keine Aussage über den gesamten Netzwerkverkehr."})


def create_module():
    return WiresharkFields()

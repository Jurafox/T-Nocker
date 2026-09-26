"""Adapter around the existing sequential TCP connect scanner."""

import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import time

from sors_modules import observation

spec = importlib.util.spec_from_file_location("t_nocker", Path(__file__).resolve().parents[1] / "T-Nocker1.1.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class PortScan:
    manifest = {"id": "t_nocker", "name": "T-Nocker · Portscanner", "input_kind": "form",
                "description": "Autorisierter TCP-Connect-Scan eines Hosts; keine Dienst- oder Schwachstellenbewertung."}

    def run(self, data):
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
        started = time.monotonic()
        with contextlib.redirect_stdout(io.StringIO()):
            opened, errors = scanner.scan(addresses, start, end, timeout)
        legacy = scanner.sors_observation(
            argparse.Namespace(host=host, start_port=start, end_port=end, timeout=timeout),
            addresses, opened, errors, time.monotonic() - started)
        return observation("t_nocker", host, legacy["status"],
                           {"open_endpoints": opened, "scan_errors": errors},
                           {"target": host, "resolved_addresses": legacy["resolved_addresses"],
                            "ports": legacy["ports"], "timeout_seconds": timeout,
                            "legacy_snapshot": legacy})


def create_module():
    return PortScan()

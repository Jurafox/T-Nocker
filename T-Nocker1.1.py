#!/usr/bin/env python3
"""Sequential TCP connect scanner for explicitly authorized targets."""

import argparse
from datetime import datetime, timezone
import errno
import json
import math
from pathlib import Path
import socket
import sys
import time

from bpfdoor_local import check_local

EXPECTED_RESULTS = {
    errno.ECONNREFUSED,
    errno.ETIMEDOUT,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EADDRNOTAVAIL,
}




def port_number(value):
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535")
    return port


def timeout_seconds(value):
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be greater than zero and at most 60 seconds") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise argparse.ArgumentTypeError("timeout must be greater than zero and at most 60 seconds")
    return timeout


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Sequential TCP connect scan of one host. Scan only systems you own or are explicitly authorized to test.",
        epilog="A port without an 'Open' line may be closed, filtered or unreachable. Stay within your authorized scope and time window.",
    )
    parser.add_argument("host", help="hostname or IPv4/IPv6 address")
    parser.add_argument("start_port", type=port_number)
    parser.add_argument("end_port", type=port_number)
    parser.add_argument("--timeout", type=timeout_seconds, default=1.0, metavar="SECONDS",
                        help="connection timeout per address (default: 1.0; maximum: 60)")
    parser.add_argument("--sors-export", metavar="FILE", type=Path,
                        help="write a versioned JSON scan observation for later SORS ingestion")
    parser.add_argument("--local-bpfdoor-check", action="store_true",
                        help="read-only packet-socket process check on this Linux host")
    args = parser.parse_args(argv)
    if args.start_port > args.end_port:
        parser.error("start_port must not exceed end_port")
    return args


def resolve(host):
    records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    # Keep the entire IPv6 sockaddr, including its scope ID for link-local addresses.
    return list(dict.fromkeys((family, sockaddr) for family, _, _, _, sockaddr in records))


def endpoint(family, sockaddr, port):
    address = sockaddr[0]
    if family == socket.AF_INET6:
        return f"[{address}%{sockaddr[3]}]:{port}" if sockaddr[3] else f"[{address}]:{port}"
    return f"{address}:{port}"


def scan(addresses, start_port, end_port, timeout):
    open_ports = []
    errors = []
    for port in range(start_port, end_port + 1):
        for family, sockaddr in addresses:
            destination = (sockaddr[0], port, *sockaddr[2:])
            label = endpoint(family, sockaddr, port)
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex(destination)
            except socket.timeout:
                continue
            except OSError as exc:
                errors.append(f"{label}: {exc}")
                continue
            if result == 0:
                open_ports.append(label)
                print(f"Open: {label}")
            elif result not in EXPECTED_RESULTS:
                errors.append(f"{label}: {errno.errorcode.get(result, result)}")
    return open_ports, errors


def sors_observation(args, addresses, open_ports, errors, elapsed, local_report=None):
    """Stable scan facts; learning and risk assessment belong to SORS."""
    observation = {
        "schema": "t-nocker.scan.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "target": args.host,
        "resolved_addresses": [
            {"family": "IPv6" if family == socket.AF_INET6 else "IPv4",
             "address": sockaddr[0], "scope_id": sockaddr[3] if family == socket.AF_INET6 else 0}
            for family, sockaddr in addresses
        ],
        "ports": {"start": args.start_port, "end": args.end_port},
        "timeout_seconds": args.timeout,
        "status": "partial" if errors else "complete",
        "open_endpoints": open_ports,
        "scan_errors": errors,
        "duration_seconds": round(elapsed, 3),
    }
    if local_report is not None:
        observation["local_bpfdoor_indicators"] = local_report
    return observation


def main(argv=None):
    args = parse_args(argv)
    try:
        addresses = resolve(args.host)
    except (socket.gaierror, OSError) as exc:
        print(f"Host resolution failed for {args.host!r}: {exc}", file=sys.stderr)
        return 2
    if not addresses:
        print(f"No TCP addresses found for {args.host!r}", file=sys.stderr)
        return 2
    start = time.monotonic()
    try:
        open_ports, errors = scan(addresses, args.start_port, args.end_port, args.timeout)
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130
    elapsed = time.monotonic() - start
    local_report = check_local() if args.local_bpfdoor_check else None
    if local_report is not None:
        print(f"Local packet-socket check: {local_report['status']}")
        for process in local_report["processes"]:
            print(f"  PID {process['pid']}: {process['assessment']} ({', '.join(process['signals'])})")
        if local_report.get("errors"):
            print(f"  {len(local_report['errors'])} process inspection error(s)", file=sys.stderr)
    if args.sors_export is not None:
        observation = sors_observation(args, addresses, open_ports, errors, elapsed, local_report)
        try:
            args.sors_export.write_text(json.dumps(observation, indent=2, ensure_ascii=False) + "\n",
                                        encoding="utf-8")
        except OSError as exc:
            print(f"Could not write SORS export {args.sors_export}: {exc}", file=sys.stderr)
            return 1
    for error in errors:
        print(f"Scan error: {error}", file=sys.stderr)
    print(f"Complete: {len(open_ports)} open endpoint(s), {elapsed:.2f}s")
    return 1 if errors or (local_report is not None and local_report["status"] != "complete") else 0


if __name__ == "__main__":
    sys.exit(main())

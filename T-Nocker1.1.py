#!/usr/bin/env python3
"""Small, sequential TCP connect scanner for authorized targets."""

import argparse
import errno
import socket
import sys
import time


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
        raise argparse.ArgumentTypeError("timeout must be a number greater than zero") from exc
    if not 0 < timeout <= 60:
        raise argparse.ArgumentTypeError("timeout must be greater than zero and at most 60 seconds")
    return timeout


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Sequential TCP connect scan of one host. Scan only systems you own or are explicitly authorized to test.",
        epilog="A closed port is not displayed; filtered or unreachable ports may time out. Use only within the scope and time window of your authorization.",
    )
    parser.add_argument("host", help="hostname or IPv4/IPv6 address")
    parser.add_argument("start_port", type=port_number)
    parser.add_argument("end_port", type=port_number)
    parser.add_argument("--timeout", type=timeout_seconds, default=1.0, metavar="SECONDS",
                        help="connection timeout per address (default: 1.0; maximum: 60)")
    args = parser.parse_args(argv)
    if args.start_port > args.end_port:
        parser.error("start_port must not exceed end_port")
    return args


def resolve(host):
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    # Preserve DNS order; avoid duplicate attempts for the same address.
    return list(dict.fromkeys((family, sockaddr[0]) for family, _, _, _, sockaddr in addresses))


def scan(addresses, start_port, end_port, timeout):
    open_ports = []
    errors = set()
    for port in range(start_port, end_port + 1):
        for family, address in addresses:
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((address, port))
            except OSError as exc:
                errors.add(f"{address}:{port}: {exc}")
                continue
            if result == 0:
                open_ports.append((address, port))
                print(f"Open: {address}:{port}")
            elif result not in (errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH,
                                errno.ENETUNREACH, errno.EADDRNOTAVAIL):
                errors.add(f"{address}:{port}: {errno.errorcode.get(result, result)}")
    return open_ports, errors


def main(argv=None):
    args = parse_args(argv)
    try:
        addresses = resolve(args.host)
    except socket.gaierror as exc:
        print(f"DNS resolution failed for {args.host!r}: {exc}", file=sys.stderr)
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
    for error in sorted(errors):
        print(f"Scan error: {error}", file=sys.stderr)
    print(f"Complete: {len(open_ports)} open endpoint(s), {time.monotonic() - start:.2f}s")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

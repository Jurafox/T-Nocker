# T-Nocker

Small sequential TCP connect scanner for Python 3.

## Usage

```sh
python3 T-Nocker1.1.py HOST START_PORT END_PORT [--timeout SECONDS] [--sors-export FILE]
python3 T-Nocker1.1.py 127.0.0.1 20 25 --timeout 0.5 --sors-export scan.json
```

Ports must be between 1 and 65535, with the start no greater than the end. The timeout applies to each connection attempt and defaults to 1 second (maximum 60 seconds). Hostnames are resolved once at the start; each returned IPv4 or IPv6 address is scanned in sequence. Open endpoints are printed as `address:port`. A lack of output for a port does not prove the host is secure: the port may be closed, filtered, or unreachable. A wide range or several resolved addresses can take a long time.

Only scan systems you own or for which you have explicit permission, within the agreed scope and time window. Check the applicable law, network policy, and provider terms before scanning. This notice is general guidance, not legal advice.

Exit codes: `0` completed without unexpected socket errors; `1` one or more socket errors or export failure; `2` invalid host resolution; `130` interrupted. Invalid CLI arguments are rejected by argparse with exit code `2`.

## SORS observation export

SORS means **Self Learning Observation and Risk System**. T-Nocker can export a snapshot of observed TCP endpoints as versioned JSON. This is a data handoff for a future SORS adapter, not a claim that SORS currently ingests this format or that T-Nocker computes a risk score.

```json
{
  "schema": "t-nocker.scan.v1",
  "observed_at": "2026-09-26T08:00:00+00:00",
  "target": "127.0.0.1",
  "resolved_addresses": [{"family": "IPv4", "address": "127.0.0.1", "scope_id": 0}],
  "ports": {"start": 20, "end": 25},
  "timeout_seconds": 0.5,
  "status": "complete",
  "open_endpoints": ["127.0.0.1:22"],
  "scan_errors": [],
  "duration_seconds": 0.02
}
```

`status` is `partial` if unexpected scan errors occurred. Scans are comparable only when target, resolved addresses, port range and relevant settings match. An endpoint absent from `open_endpoints` is **not** proven closed; it may have timed out or been unreachable. SORS should compare observations over time and decide how to interpret anomalies and risk. Keep each export under a distinct filename if you need a history.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

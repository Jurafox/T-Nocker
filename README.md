# T-Nocker

Small sequential TCP connect scanner for Python 3.

## Usage

```sh
python3 T-Nocker1.1.py HOST START_PORT END_PORT [--timeout SECONDS]
python3 T-Nocker1.1.py 127.0.0.1 20 25 --timeout 0.5
```

Ports must be between 1 and 65535, with the start no greater than the end. The timeout applies to each connection attempt and defaults to 1 second (maximum 60 seconds). Hostnames are resolved once at the start; each returned IPv4 or IPv6 address is scanned in sequence. Open endpoints are printed as `address:port`. A lack of output for a port does not prove the host is secure: the port may be closed, filtered, or unreachable. A wide range or several resolved addresses can take a long time.

Only scan systems you own or for which you have explicit permission, within the agreed scope and time window. Check the applicable law, network policy, and provider terms before scanning. This notice is general guidance, not legal advice.

Exit codes: `0` completed without unexpected socket errors; `1` one or more socket errors; `2` invalid host resolution; `130` interrupted. Invalid CLI arguments are rejected by argparse with exit code `2`.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

# T-Nocker

Small sequential TCP connect scanner for Python 3, with an optional read-only local Linux indicator check.

## Usage

```sh
python3 T-Nocker1.1.py HOST START_PORT END_PORT [--timeout SECONDS] [--sors-export FILE]
python3 T-Nocker1.1.py 127.0.0.1 20 25 --timeout 0.5 --sors-export scan.json
python3 T-Nocker1.1.py 127.0.0.1 1 1 --local-bpfdoor-check --sors-export local-check.json
```

Keep `T-Nocker1.1.py` and `bpfdoor_local.py` together. The standard library is sufficient.

Ports must be between 1 and 65535, with the start no greater than the end. The timeout applies to each connection attempt and defaults to 1 second (maximum 60 seconds). Hostnames are resolved once at the start; each returned IPv4 or IPv6 address is scanned in sequence. Open endpoints are printed as `address:port`. A lack of output for a port does not prove the host is secure: the port may be closed, filtered, or unreachable. A wide range or several resolved addresses can take a long time.

Only scan systems you own or for which you have explicit permission, within the agreed scope and time window. Check the applicable law, network policy, and provider terms before scanning. This notice is general guidance, not legal advice.

Exit codes: `0` completed without unexpected socket errors; `1` one or more socket errors, export failure or partial/unsupported local check; `2` invalid host resolution; `130` interrupted. Invalid CLI arguments are rejected by argparse with exit code `2`.

## BPFDoor-like indicators (local Linux host)

`--local-bpfdoor-check` reads `/proc/net/packet` and maps packet-socket inodes to process file descriptors under `/proc/PID/fd`. It recognizes both raw and datagram packet sockets because BPFDoor variants have used both. A packet socket alone is an **inventory** item; a packet socket held by a process with a deleted executable or an executable under `/tmp` or `/dev/shm` is marked **investigate**. No packets are sent by this module and no processes or firewall rules are changed. The report is included under `local_bpfdoor_indicators` in the SORS export.

This is a behavioral lead, **not a BPFDoor diagnosis**. Legitimate programs can capture packets. Lack of access to other processes, network namespaces, transient processes and other evasion techniques can cause incomplete or missed observations. `partial` and `unsupported` are not clean results. The check does not inspect signatures, memory, kernel state, or a remote host. For a suspected compromise, examine the affected host using a trusted incident response workflow.

## SORS observation export

SORS means **Self Learning Observation and Risk System**. T-Nocker can export a snapshot of observed TCP endpoints as versioned JSON (`--sors-export FILE`). This is a data handoff for a future SORS adapter, not a claim that SORS currently ingests this format or that T-Nocker computes a risk score. The optional local indicator report is part of the same snapshot.

The schema identifier is `t-nocker.scan.v1`; fields include UTC `observed_at`, `target`, `resolved_addresses`, `ports`, `timeout_seconds`, `status`, `open_endpoints`, `scan_errors`, and `duration_seconds`. Scans are comparable only when target, resolved addresses, port range and relevant settings match. An endpoint absent from `open_endpoints` is **not** proven closed; it may have timed out or been unreachable. SORS should compare observations over time and decide how to interpret anomalies and risk. Keep each export under a distinct filename if you need a history.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## Lokale Browseroberfläche

```sh
python3 web_ui.py
```

Öffne `http://127.0.0.1:8765` im Browser. Die Anwendung bindet ausschließlich an `127.0.0.1`. Das bereitgestellte Paket enthält die gebaute React-Oberfläche mit Palantirs quelloffenem Blueprint-Toolkit und benötigt zum Start nur Python 3. `web_ui.py`, `T-Nocker1.1.py`, `bpfdoor_local.py` und `frontend/dist` müssen nebeneinander liegen. Im Browser kannst du einen autorisierten TCP-Scan starten, den lokalen Packet-Socket-Check ausführen, die letzten zwei vergleichbaren Scans dieser Sitzung gegenüberstellen und die aktuelle Beobachtung als JSON für SORS herunterladen. Ohne Administratorrechte kann der lokale Check `partial` melden. Die letzten Ergebnisse liegen nur im Arbeitsspeicher und verschwinden beim Beenden des Servers.

Aus einem Git-Checkout baust du das Frontend einmal mit Node.js und npm:

```sh
cd frontend
npm ci
npm run build
cd ..
python3 web_ui.py
```

Wenn `frontend/dist` noch nicht existiert, zeigt der Python-Server vorübergehend die frühere HTML-Oberfläche aus `ui` an. Der Quellcode der React-Oberfläche liegt unter `frontend/src`; ihre Komponenten stammen aus `@blueprintjs/core`. Backend und SORS-Datenschema bleiben davon unabhängig.

Die Browseroberfläche begrenzt einzelne Scans auf 256 Ports, acht aufgelöste Adressen und ein rechnerisches Zeitbudget von 30 Sekunden. Sie führt keine Remote-BPFDoor-Prüfung durch; der lokale Check betrifft immer den Rechner, auf dem der Server läuft. Die Anwendung nutzt das unter Apache 2.0 veröffentlichte Blueprint-Toolkit, jedoch keine Palantir-Plattform oder proprietäre Gotham-Bestandteile.

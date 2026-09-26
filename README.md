
## Lokale Browseroberfläche

```sh
python3 web_ui.py
```

Öffne `http://127.0.0.1:8765` im Browser. Die Anwendung bindet ausschließlich an `127.0.0.1` und benötigt keine Zusatzpakete. `web_ui.py`, `T-Nocker1.1.py`, `bpfdoor_local.py` und der Ordner `ui` müssen nebeneinander liegen. Im Browser kannst du einen autorisierten TCP-Scan starten, den lokalen Packet-Socket-Check ausführen, die letzten zwei vergleichbaren Scans dieser Sitzung gegenüberstellen und die aktuelle Beobachtung als JSON für SORS herunterladen. Ohne Administratorrechte kann der lokale Check `partial` melden. Die letzten Ergebnisse liegen nur im Arbeitsspeicher und verschwinden beim Beenden des Servers.

Die Browseroberfläche begrenzt einzelne Scans auf 256 Ports, acht aufgelöste Adressen und ein rechnerisches Zeitbudget von 30 Sekunden. Sie führt keine Remote-BPFDoor-Prüfung durch; der lokale Check betrifft immer den Rechner, auf dem der Server läuft. Die Weboberfläche ist ein eigenständiges Analysewerkzeug und verwendet keine Bestandteile oder Markenoberfläche von Palantir.

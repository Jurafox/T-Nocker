"""Read-only Linux packet-socket inventory for BPFDoor-like indicators.

A finding is a lead for investigation, never a malware verdict.
"""

import os
from pathlib import Path
import re

SOCKET_LINK = re.compile(r"^socket:\[(\d+)\]$")


def packet_sockets(proc=Path("/proc")):
    """Return packet socket inode metadata from this network namespace."""
    result = {}
    lines = (proc / "net/packet").read_text(encoding="ascii").splitlines()
    if not lines:
        return result
    headers = lines[0].split()
    for line in lines[1:]:
        columns = line.split()
        if len(columns) != len(headers):
            continue
        row = dict(zip(headers, columns))
        inode = row.get("Inode")
        if inode and inode.isdecimal():
            result[inode] = {"type": row.get("Type"), "protocol": row.get("Proto"),
                             "interface": row.get("Iface")}
    return result


def inspect_process(proc, pid, sockets):
    """Inspect one PID; processes can vanish while /proc is traversed."""
    folder = proc / str(pid)
    matched = []
    try:
        for fd in (folder / "fd").iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:
                continue
            match = SOCKET_LINK.fullmatch(link)
            if match and match.group(1) in sockets:
                matched.append({"inode": match.group(1), **sockets[match.group(1)]})
    except FileNotFoundError:
        return None
    if not matched:
        return None
    try:
        exe = os.readlink(folder / "exe")
    except (FileNotFoundError, PermissionError):
        exe = None
    try:
        name = (folder / "comm").read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, PermissionError):
        name = None
    signals = ["packet_socket"]
    if exe and exe.endswith(" (deleted)"):
        signals.append("deleted_executable")
    if exe and (exe.startswith("/dev/shm/") or exe.startswith("/tmp/")):
        signals.append("temporary_executable")
    return {"pid": pid, "executable": exe, "process_name": name,
            "sockets": matched, "signals": signals,
            "assessment": "investigate" if len(signals) > 1 else "inventory"}


def check_local(proc=Path("/proc")):
    """Inventory packet socket owners without reading packets or modifying processes."""
    if os.name != "posix" or not (proc / "net/packet").exists():
        return {"status": "unsupported", "processes": [], "errors": ["Linux /proc/net/packet unavailable"]}
    try:
        sockets = packet_sockets(proc)
    except OSError as exc:
        return {"status": "partial", "processes": [], "errors": [f"cannot read packet table: {exc}"]}
    if not sockets:
        return {"status": "complete", "processes": [],
                "unattributed_packet_socket_inodes": [], "errors": [],
                "inaccessible_processes": 0,
                "note": "No packet sockets visible in this network namespace at this instant; this does not exclude BPFDoor."}
    processes = []
    errors = []
    inaccessible = 0
    try:
        pids = sorted(int(p.name) for p in proc.iterdir() if p.name.isdecimal())
    except OSError as exc:
        return {"status": "partial", "processes": [], "errors": [f"cannot list processes: {exc}"]}
    for pid in pids:
        try:
            process = inspect_process(proc, pid, sockets)
        except PermissionError:
            inaccessible += 1
            continue
        except OSError as exc:
            errors.append(f"PID {pid}: {exc}")
            continue
        if process:
            processes.append(process)
    owned = {s["inode"] for process in processes for s in process["sockets"]}
    return {"status": "partial" if errors or inaccessible or set(sockets) - owned else "complete",
            "processes": processes,
            "unattributed_packet_socket_inodes": sorted(set(sockets) - owned),
            "inaccessible_processes": inaccessible,
            "errors": errors,
            "note": "Packet sockets may be legitimate. This is a local indicator check, not BPFDoor confirmation."}

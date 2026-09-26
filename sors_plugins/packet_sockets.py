"""Local read-only process adapter; findings are not malware diagnoses."""

from bpfdoor_local import check_local
from sors_modules import observation


class PacketSockets:
    manifest = {"id": "packet_sockets", "name": "Lokale Packet-Sockets", "input_kind": "local",
                "description": "Ordnet Linux-Packet-Sockets lokalen Prozessen zu; BPFDoor-Hinweise sind Ermittlungsansätze."}

    def run(self, payload):
        report = check_local()
        return observation("packet_sockets", "local_host", report["status"],
                           {"processes": report["processes"],
                            "unattributed_packet_socket_inodes": report.get("unattributed_packet_socket_inodes", [])},
                           {"report": report, "inaccessible_processes": report.get("inaccessible_processes", 0),
                            "errors": report.get("errors", [])})


def create_module():
    return PacketSockets()

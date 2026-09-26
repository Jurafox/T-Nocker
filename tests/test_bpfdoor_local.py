import pathlib
import tempfile
import unittest
from unittest.mock import patch

import bpfdoor_local
from bpfdoor_local import check_local


class LocalCheckTests(unittest.TestCase):
    def test_packet_socket_with_deleted_executable_is_investigation_lead(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            (proc / "net").mkdir()
            (proc / "net/packet").write_text(
                "sk RefCnt Type Proto Iface R Rmem User Inode\n"
                "0000 3 3 0008 2 1 0 0 12345\n", encoding="ascii")
            (proc / "42/fd").mkdir(parents=True)
            (proc / "42/fd/3").symlink_to("socket:[12345]")
            (proc / "42/exe").symlink_to("/dev/shm/fake (deleted)")
            (proc / "42/cmdline").write_bytes(b"fake\0")
            report = check_local(proc)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["processes"][0]["assessment"], "investigate")
        self.assertIn("deleted_executable", report["processes"][0]["signals"])
        self.assertIn("temporary_executable", report["processes"][0]["signals"])

    def test_unattributed_packet_socket_is_partial_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            (proc / "net").mkdir()
            (proc / "net/packet").write_text(
                "sk RefCnt Type Proto Iface R Rmem User Inode\n"
                "0000 3 2 0008 2 1 0 0 999\n", encoding="ascii")
            report = check_local(proc)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["unattributed_packet_socket_inodes"], ["999"])

    def test_inaccessible_processes_are_counted_without_long_error_list(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            (proc / "net").mkdir()
            (proc / "net/packet").write_text(
                "sk RefCnt Type Proto Iface R Rmem User Inode\n"
                "0000 3 2 0008 2 1 0 0 999\n", encoding="ascii")
            (proc / "42").mkdir()
            with patch.object(bpfdoor_local, "inspect_process", side_effect=PermissionError):
                report = check_local(proc)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["inaccessible_processes"], 1)
        self.assertEqual(report["errors"], [])


if __name__ == "__main__":
    unittest.main()

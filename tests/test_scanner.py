import contextlib
import importlib.util
import io
import pathlib
import socket
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "T-Nocker1.1.py"
spec = importlib.util.spec_from_file_location("t_nocker", SCRIPT)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class FakeSocket:
    instances = []
    outcomes = []

    def __init__(self, family, kind):
        self.closed = False
        self.family = family
        self.destination = None
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, destination):
        self.destination = destination
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class ScannerTests(unittest.TestCase):
    def setUp(self):
        FakeSocket.instances = []
        FakeSocket.outcomes = []

    def test_every_connection_closes_and_reports_only_open_ports(self):
        FakeSocket.outcomes = [0, 111, socket.timeout()]
        addresses = [(socket.AF_INET, ("127.0.0.1", 0))]
        with patch.object(scanner.socket, "socket", FakeSocket), contextlib.redirect_stdout(io.StringIO()) as output:
            found, errors = scanner.scan(addresses, 8000, 8002, 0.25)
        self.assertEqual(found, ["127.0.0.1:8000"])
        self.assertEqual(errors, [])
        self.assertEqual([s.destination for s in FakeSocket.instances],
                         [("127.0.0.1", 8000), ("127.0.0.1", 8001), ("127.0.0.1", 8002)])
        self.assertTrue(all(s.closed and s.timeout == 0.25 for s in FakeSocket.instances))
        self.assertIn("Open: 127.0.0.1:8000", output.getvalue())

    def test_ipv6_scope_is_preserved(self):
        FakeSocket.outcomes = [0]
        with patch.object(scanner.socket, "socket", FakeSocket), contextlib.redirect_stdout(io.StringIO()):
            found, _ = scanner.scan([(socket.AF_INET6, ("fe80::1", 0, 0, 3))], 443, 443, 1)
        self.assertEqual(FakeSocket.instances[0].destination, ("fe80::1", 443, 0, 3))
        self.assertEqual(found, ["[fe80::1%3]:443"])

    def test_unexpected_socket_error_is_reported_and_closed(self):
        FakeSocket.outcomes = [OSError("resource exhausted")]
        with patch.object(scanner.socket, "socket", FakeSocket), contextlib.redirect_stdout(io.StringIO()):
            found, errors = scanner.scan([(socket.AF_INET, ("127.0.0.1", 0))], 80, 80, 1)
        self.assertEqual(found, [])
        self.assertIn("resource exhausted", errors[0])
        self.assertTrue(FakeSocket.instances[0].closed)

    def test_invalid_args(self):
        for args in (["localhost", "0", "80"], ["localhost", "80", "1"],
                     ["localhost", "1", "2", "--timeout", "nan"],
                     ["localhost", "1", "2", "--timeout", "inf"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    scanner.parse_args(args)
                self.assertEqual(caught.exception.code, 2)

    def test_dns_failure_returns_two(self):
        with patch.object(scanner, "resolve", side_effect=socket.gaierror(-2, "no such host")), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            code = scanner.main(["invalid.example", "1", "2"])
        self.assertEqual(code, 2)
        self.assertIn("Host resolution failed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()

import unittest

from sors_modules import Registry, load_registry, observation
from sors_plugins.wireshark_fields import FIELDS, WiresharkFields


class SorsModulesTests(unittest.TestCase):
    def test_builtin_modules_have_distinct_contracts(self):
        registry = load_registry()
        modules = {item["id"]: item for item in registry.manifests()}
        self.assertEqual(set(modules), {"t_nocker", "packet_sockets", "wireshark_fields"})
        self.assertEqual(modules["t_nocker"]["input_kind"], "form")
        self.assertEqual(modules["wireshark_fields"]["input_kind"], "text_file")

    def test_registry_rejects_duplicate_and_invalid_module_results(self):
        class Fake:
            manifest = {"id": "example", "input_kind": "local"}
            def run(self, payload):
                return {"schema": "wrong"}
        registry = Registry()
        registry.register(Fake())
        with self.assertRaises(ValueError):
            registry.register(Fake())
        with self.assertRaises(ValueError):
            registry.run("example", {})
        with self.assertRaises(ValueError):
            observation("Bad ID", "host", "complete", {})

    def test_wireshark_import_aggregates_without_payload(self):
        header = "\t".join(FIELDS)
        row = "\t".join(("1780000000.1", "192.0.2.1", "198.51.100.2", "", "", "54321", "443", "", ""))
        result = WiresharkFields().run({"text": header + "\n" + row + "\n" + row + "\n"})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["facts"]["top_flows"][0]["packets"], 2)
        self.assertEqual(result["facts"]["top_flows"][0]["destination_port"], 443)
        self.assertFalse(result["coverage"]["payload_included"])

    def test_wireshark_partial_and_wrong_header(self):
        header = "\t".join(FIELDS)
        row = "\t".join(("1780000000.1", "not-an-ip", "198.51.100.2", "", "", "1", "2", "", ""))
        result = WiresharkFields().run({"text": header + "\n" + row + "\n"})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["facts"]["invalid_rows"], 1)
        with self.assertRaises(ValueError):
            WiresharkFields().run({"text": "wrong\theader\n"})


if __name__ == "__main__":
    unittest.main()

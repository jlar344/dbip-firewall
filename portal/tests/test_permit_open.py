import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from permit_open import (
    PermitOpenError,
    key_options_prefix,
    local_listen_port,
    parse_permit_open,
)


class ParsePermitOpenTests(unittest.TestCase):
    def test_single_pgbouncer_dest(self):
        self.assertEqual(parse_permit_open("127.0.0.1:6432"), [("127.0.0.1", 6432)])

    def test_two_engines(self):
        self.assertEqual(
            parse_permit_open("127.0.0.1:3306,127.0.0.1:6432"),
            [("127.0.0.1", 3306), ("127.0.0.1", 6432)],
        )

    def test_rejects_ssh_options(self):
        with self.assertRaises(PermitOpenError):
            parse_permit_open('restrict,permitopen="127.0.0.1:6432"')
        with self.assertRaises(PermitOpenError):
            parse_permit_open("127.0.0.1:6432;command=/bin/bash")
        with self.assertRaises(PermitOpenError):
            parse_permit_open("127.0.0.1:6432 127.0.0.1:9999")

    def test_rejects_bad_port(self):
        with self.assertRaises(PermitOpenError):
            parse_permit_open("127.0.0.1:99999")
        with self.assertRaises(PermitOpenError):
            parse_permit_open("127.0.0.1:0")

    def test_local_port_offset(self):
        self.assertEqual(local_listen_port(6432), 16432)
        self.assertEqual(local_listen_port(3306), 13306)
        self.assertEqual(local_listen_port(5432), 15432)

    def test_key_options_only_configured_dests(self):
        prefix = key_options_prefix([("127.0.0.1", 6432)])
        self.assertIn('permitopen="127.0.0.1:6432"', prefix)
        self.assertNotIn("3306", prefix)
        self.assertNotIn("5432", prefix)
        self.assertTrue(prefix.startswith("restrict,port-forwarding,"))


if __name__ == "__main__":
    unittest.main()

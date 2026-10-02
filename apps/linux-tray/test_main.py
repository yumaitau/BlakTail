"""Unit tests for the tray's pure helpers: python3 -m unittest apps/linux-tray/test_main.py"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import main  # noqa: E402


class StatusParsing(unittest.TestCase):
    def test_malformed_output_is_not_joined(self):
        self.assertFalse(main.parse_status("joined\nnode: x")["joined"])
        self.assertFalse(main.parse_status("[]")["joined"])

    def test_summary_names_relay_and_failovers_without_colour(self):
        status = main.parse_status(
            json.dumps(
                {
                    "joined": True,
                    "dns_name": "laptop.org.blaktail",
                    "address": "100.64.0.7/32",
                    "coordinator": "https://coord.example.org.au",
                    "credential": "expires at Unix 2000 (in 1 day(s))",
                    "peers": [{"name": "server"}],
                    "dns_health": "ok",
                    "active_relay": "192.0.2.2:3478",
                    "relay_failovers": 2,
                }
            )
        )
        text = main.summarise(status, "active")
        self.assertIn("Service: active", text)
        self.assertIn("Peers: 1", text)
        self.assertIn("Relay: 192.0.2.2:3478", text)
        self.assertIn("Relay failovers since start: 2", text)

    def test_not_enrolled_summary(self):
        self.assertIn("Not enrolled", main.summarise({"joined": False}, "inactive"))

    def test_enrolment_url_is_found_in_agent_output(self):
        line = "https://console.example.org.au/enroll?code=ABCD-EFGH\n"
        self.assertEqual(
            main.find_enrolment_url(line),
            "https://console.example.org.au/enroll?code=ABCD-EFGH",
        )
        self.assertIsNone(main.find_enrolment_url("Code: ABCD-EFGH"))


if __name__ == "__main__":
    unittest.main()

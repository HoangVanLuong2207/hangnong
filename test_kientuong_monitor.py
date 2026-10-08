import unittest

import master_server as master


class KientuongProbeSummaryTest(unittest.TestCase):
    def test_404_is_down(self):
        summary = master._kientuong_probe_summary({
            "apis": {"kientuong_player": {"status": 404}},
            "elapsed_ms": 123,
        })
        self.assertTrue(summary["probe_succeeded"])
        self.assertFalse(summary["available"])
        self.assertEqual(summary["http_status"], 404)

    def test_successful_http_response_is_ready(self):
        summary = master._kientuong_probe_summary({
            "apis": {"kientuong_player": {"status": 200}},
        })
        self.assertTrue(summary["probe_succeeded"])
        self.assertTrue(summary["available"])

    def test_network_or_server_error_is_unknown(self):
        for http_status in (0, 500):
            with self.subTest(http_status=http_status):
                summary = master._kientuong_probe_summary({
                    "apis": {"kientuong_player": {"status": http_status}},
                })
                self.assertIsNone(summary["available"])


if __name__ == "__main__":
    unittest.main()

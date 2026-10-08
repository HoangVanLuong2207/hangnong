import tempfile
import unittest
from pathlib import Path
from unittest import mock

import master_server as master


class SatelliteIdleRestartTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = master.LocalStore(Path(self.temp.name) / "master.db")
        self.server = master.CoordinatorServer(("127.0.0.1", 0), master.MasterHandler, self.store, "test-token")
        master._save_settings(self.store, {
            "satellite_targets": "https://normal.example",
            "vvip_satellite_targets": "https://vvip.example\nhttps://normal.example/",
        })
        self.clock = mock.patch.object(master.time, "monotonic", return_value=0).start()
        self.restart = mock.patch.object(master, "restart_satellite", return_value={"ok": True}).start()
        self.env = mock.patch.dict(master.os.environ, {"SATELLITE_CONTROL_TOKEN": ""}).start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.server.server_close()
        self.store._conn.close()
        self.temp.cleanup()

    def tick(self, seconds):
        self.clock.return_value = seconds
        self.server.restart_idle_satellites()

    def test_restart_both_pools_once_after_five_minutes(self):
        self.tick(0)
        self.tick(299)
        self.restart.assert_not_called()
        self.tick(300)
        self.assertEqual(self.restart.call_count, 2)
        self.assertEqual({c.args[0]["url"] for c in self.restart.call_args_list},
                         {"https://normal.example", "https://vvip.example"})
        self.assertTrue(all(c.args[1] == "test-token" for c in self.restart.call_args_list))
        self.tick(900)
        self.assertEqual(self.restart.call_count, 2)

    def test_active_jobs_reset_idle_timer_and_rearm_restart(self):
        self.tick(0)
        self.tick(300)
        self.restart.reset_mock()
        job_id = self.store.exec(
            "INSERT INTO jobs (created_at,total,chunk_size,status) VALUES (?,?,?,?)",
            (0, 1, 1, "creating"),
        )
        for seconds, status in ((301, "creating"), (700, "open"), (1000, "stopping")):
            self.store.exec("UPDATE jobs SET status=? WHERE id=?", (status, job_id))
            self.tick(seconds)
        self.restart.assert_not_called()
        self.store.exec("UPDATE jobs SET status='done' WHERE id=?", (job_id,))
        self.tick(1100)
        self.tick(1399)
        self.restart.assert_not_called()
        self.tick(1400)
        self.assertEqual(self.restart.call_count, 2)

    def test_failed_target_does_not_block_other_targets_or_repeat_restart(self):
        def restart(target, token):
            if target["url"] == "https://normal.example":
                raise RuntimeError("offline")
            return {"ok": True}
        self.restart.side_effect = restart
        self.tick(0)
        self.tick(300)
        self.tick(600)
        self.assertEqual(self.restart.call_count, 2)

    def test_missing_control_token_sends_nothing(self):
        self.server.master_token = ""
        self.tick(0)
        self.tick(300)
        self.restart.assert_not_called()

    def test_kientuong_404_marks_service_down(self):
        with mock.patch.object(master, "run_kientuong_probe", return_value={
            "probe_succeeded": True,
            "http_status": 404,
            "available": False,
        }) as probe:
            self.assertTrue(self.server.refresh_kientuong_status())

        status = self.server.kientuong_status()
        self.assertEqual(status["state"], "down")
        self.assertFalse(status["available"])
        self.assertEqual(status["http_status"], 404)
        self.assertEqual(probe.call_args.args, ("regcsuc1", "Zocl00zonx."))
        self.assertEqual(status["satellite"], "master")

    def test_kientuong_normal_response_marks_service_ready(self):
        with mock.patch.object(master, "run_kientuong_probe", return_value={
            "probe_succeeded": True,
            "http_status": 200,
            "available": True,
        }):
            self.assertTrue(self.server.refresh_kientuong_status())

        status = self.server.kientuong_status()
        self.assertEqual(status["state"], "ready")
        self.assertTrue(status["available"])
        self.assertEqual(status["http_status"], 200)

    def test_probe_failure_keeps_last_confirmed_state(self):
        with mock.patch.object(master, "run_kientuong_probe", return_value={
            "probe_succeeded": True,
            "http_status": 200,
            "available": True,
        }):
            self.assertTrue(self.server.refresh_kientuong_status())

        with mock.patch.object(
            master, "run_kientuong_probe", side_effect=RuntimeError("temporary offline")
        ):
            self.assertFalse(self.server.refresh_kientuong_status())

        status = self.server.kientuong_status()
        self.assertEqual(status["state"], "ready")
        self.assertTrue(status["available"])
        self.assertIn("temporary offline", status["error"])


if __name__ == "__main__":
    unittest.main()

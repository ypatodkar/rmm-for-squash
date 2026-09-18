"""Upgrading reinstalls the agent over its own connection. The script is the
server's, not the caller's, and it goes through the same dispatch checks as
everything else."""

import re
import unittest

from fastapi import HTTPException

import main
import protocol
from test_result_handling import Harness


class UpgradeScriptTests(unittest.TestCase):
    def test_it_fits_through_the_command_line(self):
        self.assertLess(protocol.script_length(protocol.UPGRADE_SCRIPT), protocol.MAX_SCRIPT_CHARS)

    def test_it_reinstalls_from_the_server_the_endpoint_is_enrolled_with(self):
        """Read from the endpoint's own configuration, so neither a caller nor
        a Host header can point it somewhere else."""
        script = protocol.UPGRADE_SCRIPT
        self.assertIn("appsettings.json", script)
        self.assertIn("$settings.Server.Url", script)
        self.assertIn("-Server $server", script)

    def test_values_read_from_the_endpoint_are_checked_before_use(self):
        script = protocol.UPGRADE_SCRIPT
        url_check = script.index("unexpected server URL")
        dir_check = script.index("unexpected install directory")
        use = script.index("$inner =")
        self.assertLess(url_check, use)
        self.assertLess(dir_check, use)

    def test_the_url_check_accepts_real_servers_and_refuses_anything_else(self):
        pattern = re.search(r"-notmatch '([^']+)'", protocol.UPGRADE_SCRIPT).group(1)
        for good in ("https://35-173-64-136.sslip.io", "http://10.0.0.5:5200",
                     "https://rmm.example.com/"):
            self.assertRegex(good, pattern)
        for bad in ("https://x.io; Remove-Item C:\\", "https://x.io/$(whoami)",
                    "file:///C:/evil", "https://x.io/'; calc'", "https://a b"):
            self.assertNotRegex(bad, pattern)

    def test_it_keeps_a_custom_install_directory(self):
        self.assertIn("-InstallDir '$dir'", protocol.UPGRADE_SCRIPT)
        self.assertIn("Win32_Service", protocol.UPGRADE_SCRIPT)

    def test_it_runs_detached_so_stopping_the_service_does_not_kill_it(self):
        self.assertIn("Register-ScheduledTask", protocol.UPGRADE_SCRIPT)
        self.assertIn(f"AddSeconds({protocol.UPGRADE_DELAY_SECONDS})", protocol.UPGRADE_SCRIPT)


class UpgradeRouteTests(Harness):
    def upgrade(self, key=None, device="dev"):
        return self.loop.run_until_complete(main.upgrade_device(
            device, main.UpgradeRequest(idempotencyKey=key), operator="operator"))

    def test_it_dispatches_the_servers_script_as_an_ordinary_job(self):
        response = self.upgrade()
        self.assertEqual(response["state"], "Dispatched")
        self.assertEqual(response["startsInSeconds"], protocol.UPGRADE_DELAY_SECONDS)
        job = self.jobs.get(response["jobId"])
        self.assertEqual(job.script, protocol.UPGRADE_SCRIPT)
        self.assertEqual(job.device_id, "dev")

    def test_it_reads_as_itself_in_the_audit_log_and_device_history(self):
        self.upgrade()
        self.assertIn("device.upgrade", [r["action"] for r in self.store.recent_audit(5)])
        self.assertIn("upgrade_requested",
                      [e["event"] for e in self.store.device_events("dev", 5)])

    def test_a_retry_with_the_same_key_upgrades_once(self):
        first = self.upgrade(key="u-1")
        again = self.upgrade(key="u-1")
        self.assertEqual(again["jobId"], first["jobId"])
        self.assertTrue(again["deduplicated"])
        self.assertEqual(
            [e["event"] for e in self.store.device_events("dev", 10)].count("upgrade_requested"), 1)

    def test_an_offline_device_is_refused_not_queued(self):
        self.connection.revoked = True
        with self.assertRaises(HTTPException) as caught:
            self.upgrade()
        self.assertEqual(caught.exception.status_code, 409)

    def test_an_unknown_device_is_refused(self):
        with self.assertRaises(HTTPException) as caught:
            self.upgrade(device="nope")
        self.assertEqual(caught.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()

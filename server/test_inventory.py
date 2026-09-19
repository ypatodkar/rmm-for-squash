"""Device inventory: collected by the control plane, read from the API.

The end-to-end tests run the real collection path -- dispatch, a signed result
from the device, parsing, storage -- against a real in-memory store.
"""

import asyncio
import json
import unittest

from fastapi import HTTPException

import inventory
import main
import protocol
from test_result_handling import Harness

SAMPLE = {
    "os": {"name": "Microsoft Windows Server 2022 Datacenter", "version": "10.0.20348",
           "build": "20348.5622", "displayVersion": "21H2", "architecture": "64-bit",
           "installedAt": "2026-09-17T08:00:22Z", "lastBootAt": "2026-09-18T03:43:23Z"},
    "hardware": {"manufacturer": "Amazon EC2", "model": "t3.medium", "memoryMB": 4036,
                 "processors": [{"name": "Intel Xeon", "cores": 1, "logicalProcessors": 2}],
                 "disks": [{"drive": "C:", "sizeGB": 50, "freeGB": 29.7}],
                 "networkAdapters": [{"name": "ENA", "mac": "0A:FF", "ipv4": ["172.31.27.210"]}]},
    "software": [{"name": "Amazon SSM Agent", "version": "3.3.5226.0", "publisher": "AWS"}],
}


def job(**fields):
    view = {"state": "Completed", "exitCode": 0, "stdout": json.dumps(SAMPLE),
            "stdoutTruncated": False, "stderr": "", "error": None}
    view.update(fields)
    return view


class ParseTests(unittest.TestCase):
    def test_a_complete_answer_is_accepted(self):
        data, error = inventory.parse(job())
        self.assertIsNone(error)
        self.assertEqual(data["os"]["build"], "20348.5622")

    def test_an_incomplete_answer_is_never_stored_as_if_whole(self):
        cases = {
            "truncated": job(stdoutTruncated=True),
            "not json": job(stdout="{\"os\": {"),
            "not an object": job(stdout="[1, 2]"),
            "missing section": job(stdout=json.dumps({"os": {}, "hardware": {}})),
            "wrong section type": job(stdout=json.dumps({**SAMPLE, "software": {}})),
            "failed": job(state="Failed", exitCode=None, error="agent crashed"),
            "timed out": job(state="TimedOut", exitCode=None),
            "nonzero exit": job(exitCode=1, stderr="Get-CimInstance : Access denied"),
            "unreachable": job(state="Unreachable", exitCode=None),
            "nothing": {},
        }
        for name, view in cases.items():
            with self.subTest(case=name):
                data, error = inventory.parse(view)
                self.assertIsNone(data)
                self.assertTrue(error)

    def test_the_reason_for_a_failure_is_kept(self):
        _, error = inventory.parse(job(exitCode=1, stderr="Access denied"))
        self.assertIn("Access denied", error)


class ScheduleTests(unittest.TestCase):
    NOW = 1_000_000.0

    def test_a_device_never_collected_is_due(self):
        self.assertTrue(inventory.due(None, self.NOW))

    def test_a_fresh_inventory_is_not_due(self):
        self.assertFalse(inventory.due({"collected_at": self.NOW - 60}, self.NOW))

    def test_an_old_inventory_is_due(self):
        record = {"collected_at": self.NOW - inventory.MAX_AGE_SECONDS}
        self.assertTrue(inventory.due(record, self.NOW))
        self.assertTrue(inventory.stale(record, self.NOW))

    def test_a_recent_failure_is_not_retried_in_a_loop(self):
        record = {"collected_at": None, "error": "boom", "attempted_at": self.NOW - 60}
        self.assertFalse(inventory.due(record, self.NOW))

    def test_an_old_failure_is_retried(self):
        record = {"collected_at": None, "error": "boom",
                  "attempted_at": self.NOW - inventory.RETRY_AFTER_FAILURE_SECONDS}
        self.assertTrue(inventory.due(record, self.NOW))


class ScriptTests(unittest.TestCase):
    def test_it_fits_through_the_command_line(self):
        self.assertLess(protocol.script_length(inventory.SCRIPT), protocol.MAX_SCRIPT_CHARS)

    def test_it_is_read_only(self):
        for verb in ("Set-", "Remove-", "Stop-", "Start-Service", "New-Item", "Restart-",
                     "Invoke-Expression", "shutdown"):
            self.assertNotIn(verb, inventory.SCRIPT)

    def test_it_never_queries_win32_product(self):
        """Win32_Product makes Windows re-verify, and sometimes repair, every
        installed MSI package."""
        self.assertNotIn("Win32_Product", inventory.SCRIPT)


class CollectionTests(Harness):
    def setUp(self):
        super().setUp()
        main._inventory_in_flight.clear()
        main._background.clear()
        # Runs before the harness closes the loop (cleanups run last-added first).
        self.addCleanup(self.cancel_unfinished)

    def cancel_unfinished(self):
        """Some tests start a collection that never gets an answer."""
        pending = list(main._background)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    def settle(self):
        """Runs background work to completion."""
        while main._background:
            self.loop.run_until_complete(asyncio.gather(*list(main._background)))

    def collect(self, **result):
        dispatched = self.loop.run_until_complete(main.start_inventory("dev"))
        sent = self.jobs.get(dispatched["jobId"])
        main.handle_result(self.signed(sent, **result), self.connection)
        self.settle()
        return sent

    def view(self, **kwargs):
        return self.loop.run_until_complete(
            main.device_inventory("dev", include_software=kwargs.get("software", True),
                                  operator="operator"))

    def test_the_control_plane_sends_the_fixed_script_as_itself(self):
        sent = self.collect(stdout=json.dumps(SAMPLE))
        self.assertEqual(sent.script, inventory.SCRIPT)
        self.assertEqual(sent.created_by, "system")
        self.assertIn("inventory.collect", [r["action"] for r in self.store.recent_audit(10)])

    def test_a_collected_inventory_is_served_without_running_anything(self):
        self.collect(stdout=json.dumps(SAMPLE))
        dispatched_before = len(self.jobs._jobs)
        view = self.view()
        self.assertEqual(len(self.jobs._jobs), dispatched_before)
        self.assertEqual(view["inventory"]["hardware"]["model"], "t3.medium")
        self.assertEqual(view["inventory"]["softwareCount"], 1)
        self.assertIsNotNone(view["collectedAt"])
        self.assertFalse(view["stale"])
        self.assertFalse(view["collecting"])
        self.assertIsNone(view["lastError"])

    def test_the_software_list_can_be_left_out(self):
        self.collect(stdout=json.dumps(SAMPLE))
        view = self.view(software=False)
        self.assertNotIn("software", view["inventory"])
        self.assertEqual(view["inventory"]["softwareCount"], 1)

    def test_a_failed_collection_keeps_the_last_good_inventory(self):
        self.collect(stdout=json.dumps(SAMPLE))
        self.collect(exitCode=1, stdout="", stderr="Access denied")
        view = self.view()
        self.assertEqual(view["inventory"]["os"]["build"], "20348.5622")
        self.assertIn("Access denied", view["lastError"])

    def test_a_truncated_inventory_is_not_stored(self):
        self.collect(stdout=json.dumps(SAMPLE), stdoutTruncated=True)
        view = self.view()
        self.assertIsNone(view["inventory"])
        self.assertIn("cut off", view["lastError"])

    def test_every_device_is_listed_even_before_collection(self):
        listed = self.loop.run_until_complete(main.list_inventory(include_software=True,
                                                                  operator="operator"))
        self.assertEqual([d["deviceId"] for d in listed], ["dev"])
        self.assertIsNone(listed[0]["inventory"])
        self.assertTrue(listed[0]["stale"])

    def test_refreshing_an_unknown_device_is_404(self):
        with self.assertRaises(HTTPException) as caught:
            self.loop.run_until_complete(main.refresh_inventory("nope", operator="operator"))
        self.assertEqual(caught.exception.status_code, 404)

    def test_refreshing_an_offline_device_is_409_and_nothing_is_left_in_flight(self):
        self.connection.revoked = True
        with self.assertRaises(HTTPException) as caught:
            self.loop.run_until_complete(main.refresh_inventory("dev", operator="operator"))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertNotIn("dev", main._inventory_in_flight)

    def test_a_second_refresh_while_collecting_sends_nothing_new(self):
        first = self.loop.run_until_complete(main.refresh_inventory("dev", operator="operator"))
        second = self.loop.run_until_complete(main.refresh_inventory("dev", operator="operator"))
        self.assertIsNotNone(first["jobId"])
        self.assertIsNone(second["jobId"])
        self.assertTrue(second["collecting"])

    def test_a_fresh_inventory_is_not_collected_again_unless_forced(self):
        self.collect(stdout=json.dumps(SAMPLE))
        jobs_before = len(self.jobs._jobs)
        self.loop.run_until_complete(main.refresh_inventory_if_due("dev"))
        self.assertEqual(len(self.jobs._jobs), jobs_before)
        self.loop.run_until_complete(main.refresh_inventory_if_due("dev", force=True))
        self.assertEqual(len(self.jobs._jobs), jobs_before + 1)


if __name__ == "__main__":
    unittest.main()

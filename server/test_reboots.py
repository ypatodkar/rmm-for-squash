"""Tracked restarts: requested, scheduled, offline, back -- and whether Windows
was already waiting on a pending reboot."""

import asyncio
import json
import unittest

from fastapi import HTTPException

import main
import protocol
import reboots
from test_result_handling import Harness

PENDING = {"pending": True, "reasons": [{"code": "windows_update",
                                         "description": "Windows Update has installed updates that need a restart"}]}
CLEAR = {"pending": False, "reasons": []}


def record(**fields):
    base = {"restart_id": "r", "device_id": "d", "requested_at": 100.0, "delay_seconds": 15,
            "status": "scheduling", "scheduled_at": None, "went_offline_at": None}
    base.update(fields)
    return base


class PendingCheckTests(unittest.TestCase):
    def job(self, **fields):
        view = {"state": "Completed", "exitCode": 0, "stdout": json.dumps(PENDING)}
        view.update(fields)
        return view

    def test_an_answer_is_read(self):
        self.assertEqual(reboots.parse_pending(self.job()), (PENDING, None))
        self.assertEqual(reboots.parse_pending(self.job(stdout=json.dumps(CLEAR)))[0], CLEAR)

    def test_a_failed_check_is_never_nothing_pending(self):
        for view in (self.job(state="Failed", exitCode=1), self.job(stdout="{"),
                     self.job(stdout='{"pending": "yes", "reasons": []}'),
                     self.job(stdoutTruncated=True), {}):
            result, error = reboots.parse_pending(view)
            self.assertIsNone(result)
            self.assertTrue(error)

    def test_the_check_looks_everywhere_windows_records_it_and_changes_nothing(self):
        script = reboots.PENDING_SCRIPT
        for place in ("Component Based Servicing\\RebootPending",
                      "WindowsUpdate\\Auto Update\\RebootRequired",
                      "PendingFileRenameOperations", "UpdateExeVolatile", "ActiveComputerName"):
            self.assertIn(place, script)
        for verb in ("Set-", "New-ItemProperty", "Remove-", "Restart-", "shutdown"):
            self.assertNotIn(verb, script)
        self.assertLess(protocol.script_length(script), protocol.MAX_SCRIPT_CHARS)


class LifecycleTests(unittest.TestCase):
    def test_the_machine_confirms_the_restart_is_booked(self):
        self.assertEqual(reboots.restart_command_finished(record(), {"state": "Completed", "exitCode": 0}, 101),
                         {"scheduled_at": 101, "status": "scheduled"})

    def test_a_failed_restart_command_fails_the_restart(self):
        changes = reboots.restart_command_finished(record(), {"state": "Failed", "exitCode": 1,
                                                              "stderr": "Access is denied"}, 101)
        self.assertEqual(changes["status"], "failed")
        self.assertIn("Access is denied", changes["error"])

    def test_a_confirmation_arriving_after_it_went_offline_keeps_offline(self):
        changes = reboots.restart_command_finished(record(status="offline"),
                                                   {"state": "Completed", "exitCode": 0}, 101)
        self.assertEqual(changes, {"scheduled_at": 101})

    def test_going_offline_then_back_with_a_new_boot_completes(self):
        offline = reboots.went_offline(record(status="scheduled"), 120)
        self.assertEqual(offline, {"status": "offline", "went_offline_at": 120})
        back = reboots.came_back(record(status="offline"), True, 180)
        self.assertEqual(back, {"status": "completed", "came_back_at": 180, "boot_confirmed": 1})

    def test_back_without_a_new_boot_is_not_restarted(self):
        """Someone ran shutdown /a on the machine, or it was only a network drop."""
        back = reboots.came_back(record(status="offline"), False, 180)
        self.assertEqual(back["status"], "not_restarted")
        self.assertEqual(back["boot_confirmed"], 0)

    def test_a_reconnect_before_going_down_changes_nothing(self):
        """A network blip or a control plane restart during the delay."""
        self.assertEqual(reboots.came_back(record(status="scheduled"), False, 105), {})
        self.assertEqual(reboots.came_back(record(status="scheduled"), None, 105), {})

    def test_a_new_boot_seen_without_the_offline_moment_still_completes(self):
        """The control plane may have restarted while the machine was down."""
        self.assertEqual(reboots.came_back(record(status="scheduled"), True, 180)["status"],
                         "completed")

    def test_an_unconfirmable_boot_is_completed_but_says_so(self):
        back = reboots.came_back(record(status="offline"), None, 180)
        self.assertEqual(back["status"], "completed")
        self.assertIsNone(back["boot_confirmed"])
        self.assertIn("could not be confirmed", back["error"])

    def test_a_finished_restart_is_never_reopened(self):
        for status in ("completed", "not_restarted", "failed"):
            self.assertEqual(reboots.went_offline(record(status=status), 200), {})
            self.assertEqual(reboots.came_back(record(status=status), True, 200), {})

    def test_overdue_restarts_are_closed(self):
        never_down = record(status="scheduled", scheduled_at=100.0)
        self.assertEqual(reboots.overdue(never_down, 100 + 15 + 60), {})
        self.assertEqual(reboots.overdue(never_down, 100 + 15 + reboots.NEVER_WENT_OFFLINE_AFTER_SECONDS + 1)
                         ["status"], "failed")
        never_back = record(status="offline", went_offline_at=200.0)
        self.assertEqual(reboots.overdue(never_back, 200 + 60), {})
        self.assertIn("did not come back",
                      reboots.overdue(never_back, 200 + reboots.DID_NOT_RETURN_AFTER_SECONDS + 1)["error"])


class TrackedRestartTests(Harness):
    def setUp(self):
        super().setUp()
        main._background.clear()
        self.addCleanup(self.cancel_unfinished)

    def cancel_unfinished(self):
        pending = list(main._background)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    def step(self, times=20):
        for _ in range(times):
            self.loop.run_until_complete(asyncio.sleep(0))

    def answer(self, script, **result):
        """Answers the in-flight job running `script`, as the device would."""
        self.step()
        job = next(j for j in self.jobs.active() if j.script == script)
        main.handle_result(self.signed(job, **result), self.connection)
        self.step()
        return job

    def restart(self, pending_answer, key=None):
        request = main.RestartRequest(delaySeconds=15, idempotencyKey=key)
        task = self.loop.create_task(main.restart_device("dev", request, operator="operator"))
        if pending_answer is not None:
            self.answer(reboots.PENDING_SCRIPT, **pending_answer)
        return self.loop.run_until_complete(task)

    def test_a_restart_tracked_from_request_to_a_new_boot(self):
        response = self.restart({"stdout": json.dumps(PENDING)})
        restart_id = response["restartId"]
        self.assertEqual(response["pendingRebootBefore"], PENDING)

        restart_script = protocol.restart_script(15, protocol.DEFAULT_RESTART_REASON)
        self.answer(restart_script, stdout="restart scheduled in 15s")
        self.assertEqual(main.restart_view(self.store.get_restart(restart_id))["status"], "scheduled")

        main.advance_restarts_on_disconnect("dev")
        self.assertEqual(self.store.get_restart(restart_id)["status"], "offline")

        # Called from the connection handler in production, so inside the loop.
        async def reconnect():
            main.advance_restarts_on_return("dev", rebooted=True)
        self.loop.run_until_complete(reconnect())
        self.answer(reboots.PENDING_SCRIPT, stdout=json.dumps(CLEAR))   # the check after
        view = self.loop.run_until_complete(main.get_restart(restart_id, operator="operator"))
        self.assertEqual(view["status"], "completed")
        self.assertTrue(view["bootConfirmed"])
        self.assertEqual(view["pendingRebootBefore"]["pending"], True)
        self.assertEqual(view["pendingRebootAfter"], CLEAR)
        for moment in ("requestedAt", "scheduledAt", "wentOfflineAt", "cameBackAt"):
            self.assertIsNotNone(view[moment], moment)

    def test_a_failed_pending_check_does_not_stop_the_restart(self):
        response = self.restart({"exitCode": 1, "stdout": "", "stderr": "Access is denied"})
        self.assertIsNone(response["pendingRebootBefore"])
        self.assertIn("Access is denied", response["pendingCheckError"])
        self.assertEqual(self.store.get_restart(response["restartId"])["status"], "scheduling")

    def test_an_offline_device_is_refused_and_nothing_is_recorded(self):
        self.connection.revoked = True
        with self.assertRaises(HTTPException) as caught:
            self.restart(None)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.store.restarts_for_device("dev"), [])

    def test_a_retry_returns_the_same_restart_without_checking_again(self):
        first = self.restart({"stdout": json.dumps(CLEAR)}, key="restart-1")
        jobs_before = len(self.store.recent_jobs(50))
        again = self.restart(None, key="restart-1")
        self.assertEqual(again["restartId"], first["restartId"])
        self.assertTrue(again["deduplicated"])
        self.assertEqual(len(self.store.recent_jobs(50)), jobs_before)

    def test_restarts_are_listed_per_device(self):
        self.restart({"stdout": json.dumps(CLEAR)})
        listed = self.loop.run_until_complete(main.list_restarts("dev", limit=20, operator="operator"))
        self.assertEqual(len(listed), 1)
        with self.assertRaises(HTTPException):
            self.loop.run_until_complete(main.list_restarts("nope", limit=20, operator="operator"))
        with self.assertRaises(HTTPException):
            self.loop.run_until_complete(main.get_restart("rst-nope", operator="operator"))

    def test_the_live_check_endpoint(self):
        task = self.loop.create_task(main.pending_reboot("dev", operator="operator"))
        self.answer(reboots.PENDING_SCRIPT, stdout=json.dumps(PENDING))
        result = self.loop.run_until_complete(task)
        self.assertTrue(result["pending"])
        self.assertEqual(result["reasons"][0]["code"], "windows_update")

    def test_the_live_check_reports_a_failure_as_502(self):
        task = self.loop.create_task(main.pending_reboot("dev", operator="operator"))
        self.answer(reboots.PENDING_SCRIPT, exitCode=1, stdout="", stderr="boom")
        with self.assertRaises(HTTPException) as caught:
            self.loop.run_until_complete(task)
        self.assertEqual(caught.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()

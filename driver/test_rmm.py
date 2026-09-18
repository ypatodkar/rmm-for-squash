"""Failure paths a live endpoint will not reliably produce on demand.

These use a fake transport rather than a fake control plane: the contract under
test is what this client concludes from each response, not the server's
behaviour, which has its own tests.
"""

import json
import time
import unittest
import urllib.error
from unittest import mock

import rmm
from rmm import DeviceUnavailable, RmmClient, RmmError

BASE = "https://control.example"
KEY = "op_test"


def http_error(code: int, detail: str) -> urllib.error.HTTPError:
    body = json.dumps({"detail": detail}).encode()
    return urllib.error.HTTPError(BASE, code, detail, {}, mock.Mock(read=lambda: body))


class TransportTests(unittest.TestCase):
    def test_plaintext_control_plane_is_refused(self):
        with self.assertRaises(ValueError):
            RmmClient("http://control.example", KEY)
        RmmClient("http://localhost:5200", KEY)  # allowed for local testing

    def test_a_hostname_that_merely_contains_localhost_is_refused(self):
        """A substring test would accept these and send the key to a stranger."""
        for hostile in ("http://localhost.example.invalid",
                        "http://localhost.attacker.com/api",
                        "http://notlocalhost",
                        "http://evil.com/?x=localhost",
                        "http://user@localhost.evil.com"):
            with self.assertRaises(ValueError, msg=hostile):
                RmmClient(hostile, KEY)

    def test_loopback_addresses_are_accepted_over_plaintext(self):
        for allowed in ("http://localhost:5200", "http://127.0.0.1:5200"):
            RmmClient(allowed, KEY)

    def test_a_redirect_is_refused_rather_than_followed(self):
        """urllib carries headers across redirects, so following one could
        hand the operator key to another host, or downgrade to http."""
        client = RmmClient(BASE, KEY)
        redirect = urllib.error.HTTPError(
            BASE, 302, "Found", {"Location": "http://elsewhere.example/api"}, None)
        with mock.patch.object(client._opener, "open", side_effect=redirect):
            with self.assertRaises(RmmError):
                client.list_devices()

    def test_unreachable_control_plane_is_reported_clearly(self):
        client = RmmClient(BASE, KEY)
        with mock.patch.object(rmm.urllib.request, "urlopen",
                               side_effect=urllib.error.URLError("connection refused")):
            with self.assertRaises(RmmError) as caught:
                client.list_devices()
        self.assertIn("unreachable", str(caught.exception))

    def test_authentication_failure_is_not_mistaken_for_an_unavailable_device(self):
        client = RmmClient(BASE, KEY)
        with mock.patch.object(rmm.RmmClient, "_request",
                               side_effect=http_error(401, "Valid X-API-Key required.")):
            pass  # covered below via _request directly

        with mock.patch.object(rmm.urllib.request, "urlopen",
                               side_effect=http_error(401, "Valid X-API-Key required.")):
            with self.assertRaises(RmmError) as caught:
                client.list_devices()
        self.assertNotIsInstance(caught.exception, DeviceUnavailable)


class TerminalStateTests(unittest.TestCase):
    """Every dispatch must end somewhere the caller can act on."""

    def setUp(self):
        self.client = RmmClient(BASE, KEY)

    def run_with(self, job: dict):
        responses = [{"jobId": "job-1", "state": "Dispatched"}, job]
        with mock.patch.object(RmmClient, "_request", side_effect=responses):
            return self.client.run_diagnostic("dev-1", "disk_usage", {})

    def test_timed_out_job_is_surfaced_not_raised(self):
        result = self.run_with({"state": "TimedOut", "stdout": "", "stderr": "",
                                "exitCode": None, "durationMs": None,
                                "error": "No result within 30s."})
        self.assertEqual(result.state, "TimedOut")
        self.assertFalse(result.succeeded)

    def test_unreachable_job_is_surfaced_not_raised(self):
        result = self.run_with({"state": "Unreachable", "stdout": "", "stderr": "",
                                "exitCode": None, "durationMs": None})
        self.assertEqual(result.state, "Unreachable")
        self.assertFalse(result.succeeded)

    def test_non_zero_exit_is_not_treated_as_success(self):
        result = self.run_with({"state": "Completed", "stdout": "", "stderr": "not found",
                                "exitCode": 1, "durationMs": 120})
        self.assertEqual(result.state, "Completed")
        self.assertFalse(result.succeeded)
        self.assertEqual(result.stderr, "not found")

    def test_output_that_is_not_json_is_preserved_rather_than_discarded(self):
        result = self.run_with({"state": "Completed", "stdout": "totally not json",
                                "stderr": "", "exitCode": 0, "durationMs": 10})
        self.assertIsNone(result.data)
        self.assertEqual(result.raw_stdout, "totally not json")
        self.assertTrue(result.succeeded)

    def test_truncated_output_is_never_parsed_even_when_still_valid_json(self):
        """The dangerous case is truncation that leaves valid syntax: '12345'
        cut to '123' parses cleanly and is simply wrong. Flagging truncation is
        not enough; the value must not be offered as data at all."""
        result = self.run_with({"state": "Completed", "stdout": "123", "stderr": "",
                                "exitCode": 0, "durationMs": 10, "stdoutTruncated": True})
        self.assertTrue(result.truncated)
        self.assertIsNone(result.data)
        self.assertEqual(result.raw_stdout, "123", "raw output must remain inspectable")

    def test_truncated_stderr_also_suppresses_parsing(self):
        result = self.run_with({"state": "Completed", "stdout": '{"a":1}', "stderr": "x",
                                "exitCode": 0, "durationMs": 10, "stderrTruncated": True})
        self.assertTrue(result.truncated)
        self.assertIsNone(result.data)

    def test_the_control_plane_explanation_is_preserved(self):
        """'No result within 30s' and 'Device is not reachable' call for
        different responses, so the reason must survive."""
        result = self.run_with({"state": "TimedOut", "stdout": "", "stderr": "",
                                "exitCode": None, "durationMs": None,
                                "error": "No result within 30s."})
        self.assertEqual(result.error, "No result within 30s.")
        self.assertIn("No result within 30s.", result.summary())

    def test_waiting_gives_up_rather_than_blocking_forever(self):
        """If the control plane never reports a terminal state, the worker must
        stop rather than occupy a slot indefinitely."""
        calls = {"n": 0}

        def never_finishes(method, path, body=None, timeout=None):
            calls["n"] += 1
            if method == "POST":
                return {"jobId": "job-1", "state": "Dispatched"}
            return {"state": "Running"}

        with mock.patch.object(RmmClient, "_request", side_effect=never_finishes):
            with self.assertRaises(RmmError) as caught:
                self.client.run_diagnostic("dev-1", "disk_usage", {}, deadline_seconds=0.8)
        self.assertIn("terminal state", str(caught.exception))

    def test_the_deadline_bounds_each_request_not_just_the_loop(self):
        """A per-request timeout independent of the deadline lets a single slow
        call run far past what the caller allowed."""
        seen = []

        def record_timeout(request, timeout=None):
            seen.append(timeout)
            raise urllib.error.URLError("too slow")

        client = RmmClient(BASE, KEY)
        with mock.patch.object(client._opener, "open", side_effect=record_timeout):
            with self.assertRaises(RmmError):
                client.run_diagnostic("dev-1", "disk_usage", {}, deadline_seconds=0.01)

        self.assertTrue(seen, "no request was attempted")
        self.assertLessEqual(max(seen), 0.01 + 0.001,
                             f"request timeout {max(seen)} exceeded the 0.01s deadline")

    def test_dispatch_time_counts_against_the_deadline(self):
        def slow_dispatch(method, path, body=None, timeout=None):
            if method == "POST":
                time.sleep(0.15)
                return {"jobId": "job-1", "state": "Dispatched"}
            raise AssertionError("waiting should not begin; the deadline is spent")

        client = RmmClient(BASE, KEY)
        with mock.patch.object(RmmClient, "_request", side_effect=slow_dispatch):
            with self.assertRaises(RmmError) as caught:
                client.run_diagnostic("dev-1", "disk_usage", {}, deadline_seconds=0.1)
        # Never began waiting: slow_dispatch asserts if a GET is attempted.
        self.assertIn("0.10s", str(caught.exception))

    def test_a_server_that_ignores_the_long_poll_does_not_cause_a_hot_loop(self):
        """The wait relies on the server holding the request. If it answers
        instantly, polling must still be paced locally."""
        calls = {"n": 0}

        def answers_instantly(method, path, body=None, timeout=None):
            calls["n"] += 1
            if method == "POST":
                return {"jobId": "job-1", "state": "Dispatched"}
            return {"state": "Running"}

        with mock.patch.object(RmmClient, "_request", side_effect=answers_instantly):
            with self.assertRaises(RmmError):
                self.client.run_diagnostic("dev-1", "disk_usage", {}, deadline_seconds=0.8)

        # Without pacing this would run thousands of times in 0.8s.
        self.assertLess(calls["n"], 12, f"polled {calls['n']} times in 0.8s")


class GuardrailTests(unittest.TestCase):
    """Nothing outside the catalogue may reach the control plane."""

    def setUp(self):
        self.client = RmmClient(BASE, KEY)

    def test_an_unknown_diagnostic_never_dispatches(self):
        with mock.patch.object(RmmClient, "_request") as request:
            with self.assertRaises(Exception):
                self.client.run_diagnostic("dev-1", "Remove-Item C:\\ -Recurse", {})
        request.assert_not_called()

    def test_an_invalid_argument_never_dispatches(self):
        with mock.patch.object(RmmClient, "_request") as request:
            with self.assertRaises(Exception):
                self.client.run_diagnostic("dev-1", "service_status",
                                           {"service_name": "a'; Stop-Service b; '"})
        request.assert_not_called()

    def test_the_dispatched_script_is_the_catalogue_script(self):
        captured = {}

        def record(method, path, body=None, timeout=None):
            if method == "POST":
                captured.update(body)
                return {"jobId": "job-1", "state": "Dispatched"}
            return {"state": "Completed", "stdout": "{}", "stderr": "",
                    "exitCode": 0, "durationMs": 5}

        with mock.patch.object(RmmClient, "_request", side_effect=record):
            self.client.run_diagnostic("dev-1", "service_status", {"service_name": "Spooler"})

        self.assertIn("Get-Service -Name 'Spooler'", captured["script"])
        self.assertIn("idempotencyKey", captured)
        self.assertTrue(captured["timeoutSeconds"] > 0)


if __name__ == "__main__":
    unittest.main()

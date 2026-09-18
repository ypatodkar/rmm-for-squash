"""What the control plane accepts from an endpoint, and what it dispatches.

A result is untrusted even when it is correctly signed: the device holds its
own key and can sign anything. These run the real handler against a real
in-memory store, so what is asserted is what a caller would read back.
"""

import asyncio
import base64
import time
import unittest
from unittest import mock

import pydantic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException

import main
import protocol
from jobs import JobStore
from registry import DeviceConnection, DeviceRegistry
from store import Store

HOSTILE = "<img src=x onerror=alert(localStorage.getItem('apiKey'))>"


class Harness(unittest.TestCase):
    """A real store, job table and registry, patched into main."""

    def setUp(self):
        # JobRecord creates its completion future on the current loop, as it
        # does under uvicorn; each test gets its own.
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.addCleanup(self.loop.close)

        self.store = Store(":memory:")
        self.jobs = JobStore(self.store)
        self.registry = DeviceRegistry()
        for name, value in (("store", self.store), ("jobs", self.jobs),
                            ("registry", self.registry)):
            patcher = mock.patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.store._db.close)

        self.key = ec.generate_private_key(ec.SECP256R1())
        public = base64.b64encode(self.key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()
        self.store.insert_device("dev", public, "HOST-1", "Windows", "0.4.0")
        self.connection = self.registry.register(
            DeviceConnection(device_id="dev", hostname="HOST-1",
                             os_version="Windows", agent_version="0.4.0"))

    def dispatch(self, script="hostname", max_output_bytes=1_048_576):
        job = self.jobs.create("dev", script, 30, max_output_bytes, "operator")
        self.jobs.mark_dispatched(job)
        return job

    def signed(self, job, **fields):
        """A result exactly as a device holding the enrolled key would send it.
        The signature is computed over whatever values are given, hostile or
        not -- that is the point."""
        result = {"jobId": job.job_id, "state": "Completed", "exitCode": 0,
                  "durationMs": 7, "stdout": "ok", "stderr": "",
                  "stdoutTruncated": False, "stderrTruncated": False}
        result.update(fields)
        sha = protocol.sha256_hex(job.script)
        attestation = protocol.result_attestation(
            job.job_id, sha, result["exitCode"], result["durationMs"],
            result["stdout"], result["stderr"])
        result["scriptSha256"] = sha
        result["signature"] = base64.b64encode(
            self.key.sign(attestation, ec.ECDSA(hashes.SHA256()))).decode()
        return result

    def stored(self, job):
        """What GET /api/jobs/{id} returns once the job leaves memory."""
        self.jobs._jobs.pop(job.job_id, None)
        return self.jobs.view(job.job_id)


class HostileResultTests(Harness):
    def test_markup_in_a_signed_exit_code_never_reaches_storage(self):
        """The dashboard once rendered exitCode unescaped. A device could sign
        HTML as its exit code and run script in the operator's browser, where
        the operator key lives."""
        job = self.dispatch()
        main.handle_result(self.signed(job, exitCode=HOSTILE), self.connection)
        view = self.stored(job)
        self.assertEqual(view["state"], "Failed")
        self.assertIn("malformed result", view["error"])
        self.assertIsNone(view["exitCode"])
        self.assertNotIn("<img", str(view))

    def test_markup_in_a_signed_duration_never_reaches_storage(self):
        job = self.dispatch()
        main.handle_result(self.signed(job, durationMs=HOSTILE), self.connection)
        self.assertEqual(self.stored(job)["state"], "Failed")
        self.assertNotIn("<img", str(self.stored(job)))

    def test_every_malformed_field_is_refused(self):
        cases = {
            "exitCode": ["0", 1.5, True, 2**31, -2**31 - 1, [], {}],
            "durationMs": ["7", -1, 1.5, False, protocol.MAX_DURATION_MS + 1],
            "stdout": [1, [], {}],
            "stdoutTruncated": ["false", 0, 1, None],
            "state": ["Running", "Queued", "Dispatched", 0, 1, 2, -1, 99, "done", True],
            "error": [5, ["x"]],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(protocol.MalformedResult):
                        protocol.parse_result({"jobId": "j", field: value})

    def test_a_result_that_is_not_an_object_does_not_raise(self):
        """An exception here would drop the device's socket."""
        for payload in (None, [], "text", 5):
            main.handle_result(payload, self.connection)

    def test_a_result_for_another_devices_job_is_ignored(self):
        other = self.jobs.create("someone-else", "hostname", 30, 1024, "operator")
        main.handle_result(self.signed(other), self.connection)
        self.assertEqual(self.jobs.get(other.job_id).state.value, "Queued")


class GenuineResultTests(Harness):
    def test_an_ordinary_result_is_stored_unchanged(self):
        job = self.dispatch()
        main.handle_result(self.signed(job, exitCode=3, stdout="hello\n"), self.connection)
        view = self.stored(job)
        self.assertEqual((view["state"], view["exitCode"], view["stdout"]),
                         ("Completed", 3, "hello\n"))
        self.assertFalse(view["stdoutTruncated"])

    def test_states_arrive_as_names_or_ordinals(self):
        """System.Text.Json may send the enum either way."""
        for sent, expected in (("TimedOut", "TimedOut"), (4, "TimedOut"),
                               (3, "Completed"), ("Failed", "Failed")):
            with self.subTest(sent=sent):
                job = self.dispatch()
                main.handle_result(self.signed(job, state=sent, exitCode=None),
                                   self.connection)
                self.assertEqual(self.stored(job)["state"], expected)

    def test_a_missing_state_still_means_completed(self):
        job = self.dispatch()
        result = self.signed(job)
        del result["state"]
        main.handle_result(result, self.connection)
        self.assertEqual(self.stored(job)["state"], "Completed")

    def test_an_unpaired_surrogate_is_hashed_the_way_dotnet_hashes_it(self):
        """.NET signs U+FFFD where Python would raise. The two must agree or a
        genuine result is rejected, or worse, the handler crashes."""
        job = self.dispatch()
        dotnet_view = "a�b"
        result = self.signed(job, stdout=dotnet_view)
        result["stdout"] = "a\ud800b"      # what arrives after JSON decoding
        main.handle_result(result, self.connection)
        view = self.stored(job)
        self.assertEqual(view["state"], "Completed", view["error"])
        self.assertEqual(view["stdout"], dotnet_view)


class OutputLimitTests(Harness):
    def test_output_over_the_dispatched_limit_is_cut_and_flagged(self):
        """The agent is meant to enforce this; the server holds it to it."""
        job = self.dispatch(max_output_bytes=1024)
        main.handle_result(self.signed(job, stdout="x" * 4096), self.connection)
        view = self.stored(job)
        self.assertEqual(view["state"], "Completed")
        self.assertEqual(len(view["stdout"].encode()), 1024)
        self.assertTrue(view["stdoutTruncated"])

    def test_a_multibyte_character_is_never_split(self):
        cut = protocol.limit_output(
            {"stdout": "é" * 1024, "stderr": "", "stdoutTruncated": False,
             "stderrTruncated": False}, 1025)
        self.assertEqual(cut["stdout"], "é" * 512)       # 1024 bytes, not 1025
        self.assertTrue(cut["stdoutTruncated"])

    def test_output_within_the_limit_is_untouched(self):
        result = {"stdout": "é" * 512, "stderr": "ok", "stdoutTruncated": False,
                  "stderrTruncated": True}
        self.assertEqual(protocol.limit_output(result, 1024), result)


class DispatchLimitTests(unittest.TestCase):
    def test_a_script_windows_cannot_start_is_refused(self):
        main.DispatchRequest(script="x" * protocol.MAX_SCRIPT_CHARS)
        with self.assertRaises(pydantic.ValidationError):
            main.DispatchRequest(script="x" * (protocol.MAX_SCRIPT_CHARS + 1))

    def test_script_length_counts_what_powershell_receives(self):
        """An emoji is one character to Python and two to UTF-16."""
        self.assertEqual(protocol.script_length("\U0001F600"), 2)
        with self.assertRaises(pydantic.ValidationError):
            main.DispatchRequest(script="\U0001F600" * (protocol.MAX_SCRIPT_CHARS // 2 + 1))

    def test_output_limit_has_a_ceiling(self):
        main.DispatchRequest(script="x", maxOutputBytes=protocol.MAX_OUTPUT_BYTES)
        with self.assertRaises(pydantic.ValidationError):
            main.DispatchRequest(script="x", maxOutputBytes=protocol.MAX_OUTPUT_BYTES + 1)

    def test_every_built_in_script_fits(self):
        """The limit must not remove anything that works today: the longest
        restart, and every diagnostic and repair at its widest arguments."""
        restart = protocol.restart_script(protocol.MAX_RESTART_DELAY_SECONDS, "x" * 200)
        self.assertLess(protocol.script_length(restart), protocol.MAX_SCRIPT_CHARS)

        import investigations  # noqa: F401  (puts the driver on sys.path)
        import diagnostics
        import repairs
        for entry in [*diagnostics.CATALOG.values(), *repairs.CATALOG.values()]:
            with self.subTest(entry=entry.name):
                # The template plus 64-character arguments is an upper bound.
                self.assertLess(protocol.script_length(entry.script) + 256,
                                protocol.MAX_SCRIPT_CHARS)


class IdempotencyTests(Harness):
    def send(self, *, key, script="hostname", device="dev", operator="operator", timeout=30):
        return self.loop.run_until_complete(main.send_to_device(
            device, script, timeout_seconds=timeout, max_output_bytes=1024,
            operator=operator, idempotency_key=key, action="job.dispatch", detail={}))

    def test_a_retry_returns_the_original_job(self):
        first = self.send(key="k1")
        again = self.send(key="k1")
        self.assertEqual(again, {"jobId": first["jobId"], "state": "Duplicate",
                                 "deduplicated": True})

    def test_a_key_reused_for_a_different_request_is_a_conflict(self):
        """It used to return the earlier job -- possibly another device's."""
        self.store.insert_device("dev-2", "k", "HOST-2", "Windows", "0.4.0")
        self.registry.register(DeviceConnection(device_id="dev-2", hostname="HOST-2",
                                                os_version="Windows", agent_version="0.4.0"))
        self.send(key="k1")
        for change in ({"script": "Get-Date"}, {"device": "dev-2"},
                       {"operator": "someone-else"}, {"timeout": 60}):
            with self.subTest(change=change):
                with self.assertRaises(HTTPException) as caught:
                    self.send(key="k1", **change)
                self.assertEqual(caught.exception.status_code, 409)

    def test_no_key_still_dispatches(self):
        """Keys stay optional; callers that omit one behave as before."""
        a, b = self.send(key=None), self.send(key=None)
        self.assertNotEqual(a["jobId"], b["jobId"])

    def test_a_refused_dispatch_leaves_an_audit_record(self):
        self.connection.revoked = True     # unreachable
        with self.assertRaises(HTTPException) as caught:
            self.send(key=None)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(caught.exception.detail, "Device 'dev' is not reachable.")
        actions = [row["action"] for row in self.store.recent_audit(5)]
        self.assertIn("job.refused", actions)


class EvictionTests(Harness):
    def test_finished_jobs_leave_memory_but_not_history(self):
        job = self.dispatch()
        running = self.dispatch()
        main.handle_result(self.signed(job), self.connection)
        job.completed_at = time.time() - 120

        self.assertEqual(self.jobs.evict_finished(60), 1)
        self.assertIsNone(self.jobs.get(job.job_id))
        self.assertIsNotNone(self.jobs.get(running.job_id))
        self.assertEqual(self.jobs.view(job.job_id)["state"], "Completed")

    def test_a_just_finished_job_is_kept_briefly(self):
        job = self.dispatch()
        main.handle_result(self.signed(job), self.connection)
        self.assertEqual(self.jobs.evict_finished(60), 0)


class StoredSecretTests(unittest.TestCase):
    """Investigation text is written from many places; the store is the one
    place all of it passes."""

    def test_the_running_control_plane_installs_the_filter(self):
        import investigations
        import redaction
        self.assertTrue(investigations.DRIVER_AVAILABLE)
        self.assertIs(main.store.redact_text, redaction.redact)

    def test_every_investigation_text_field_is_filtered(self):
        import redaction
        store = Store(":memory:")
        self.addCleanup(store._db.close)
        store.redact_text = redaction.redact
        store.insert_device("dev", "k", "HOST", "Windows", "0.4.0")
        store.create_investigation("inv-1", "dev", "printing is broken", "operator", "req-1")

        leak = "provider said: Incorrect API key provided: sk-proj-****abcd1234"
        store.set_investigation_error("inv-1", leak)
        store.append_investigation_event("inv-1", leak)
        store.set_investigation_finding("inv-1", leak, "low")
        store.set_investigation_outcome("inv-1", {"detail": leak})
        store.insert_investigation_evidence("inv-1", "system_overview", {}, False, None, leak)

        row = store.get_investigation("inv-1")
        texts = [row["error"], row["finding"], row["outcome"],
                 *[e["message"] for e in store.get_investigation_events("inv-1")],
                 *[e["note"] for e in store.get_investigation_evidence("inv-1")]]
        for text in texts:
            self.assertNotIn("sk-proj", text)
            self.assertIn(redaction.REDACTED, text)


if __name__ == "__main__":
    unittest.main()

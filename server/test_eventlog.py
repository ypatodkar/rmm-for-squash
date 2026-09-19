"""Event log queries: filters become a fixed script, entries come back
structured. Nothing a caller sends may become script text."""

import asyncio
import datetime as dt
import json
import unittest

from fastapi import HTTPException

import eventlog
import main
import protocol
from test_result_handling import Harness

NOW = dt.datetime(2026, 9, 19, 12, 0, tzinfo=dt.timezone.utc)
ENTRY = {"timeCreated": "2026-09-19T11:00:00.0000000Z", "level": "error", "levelNumber": 2,
         "eventId": 7031, "provider": "Service Control Manager", "log": "System",
         "recordId": 1234, "message": "The Print Spooler service terminated unexpectedly.",
         "messageTruncated": False}


def query(**kwargs):
    return eventlog.make_query(now=NOW, **kwargs)


class FilterTests(unittest.TestCase):
    def test_defaults_are_the_last_day_of_problems_in_the_system_log(self):
        q = query()
        self.assertEqual(q.log, "System")
        self.assertEqual(q.levels, ("critical", "error", "warning"))
        self.assertEqual(q.until - q.since, dt.timedelta(hours=24))
        self.assertEqual(q.max_events, 50)

    def test_log_names_come_from_a_fixed_list(self):
        self.assertEqual(query(log="security").log, "Security")
        for bad in ("Microsoft-Windows-Sysmon/Operational", "System'; Remove-Item C:\\", "", "Foo"):
            with self.subTest(log=bad), self.assertRaises(eventlog.QueryError):
                query(log=bad)

    def test_levels_are_named_normalised_and_deduplicated(self):
        self.assertEqual(query(levels=" Warning,error,ERROR ").levels, ("error", "warning"))
        for bad in ("fatal", "error;calc", ",", "1,2"):
            with self.subTest(levels=bad), self.assertRaises(eventlog.QueryError):
                query(levels=bad)

    def test_times_need_a_timezone_and_an_order(self):
        with self.assertRaises(eventlog.QueryError):
            query(since=dt.datetime(2026, 9, 18))
        with self.assertRaises(eventlog.QueryError):
            query(since=NOW, until=NOW - dt.timedelta(hours=1))

    def test_limits(self):
        for bad in (0, -1, 501, True):
            with self.subTest(max_events=bad), self.assertRaises(eventlog.QueryError):
                query(max_events=bad)
        for bad in (-1, 65536):
            with self.subTest(event_id=bad), self.assertRaises(eventlog.QueryError):
                query(event_id=bad)

    def test_a_provider_cannot_carry_script_text(self):
        self.assertEqual(query(provider="Service Control Manager").provider,
                         "Service Control Manager")
        for hostile in ("x'; Remove-Item C:\\ -Recurse; '", "$(whoami)", "a`b", "a|b",
                        "a;b", 'a"b', "x" * 129, ""):
            with self.subTest(provider=hostile), self.assertRaises(eventlog.QueryError):
                query(provider=hostile)


class ScriptTests(unittest.TestCase):
    def test_information_includes_level_zero(self):
        """Security audit events are level 0; without it that log looks empty."""
        script = eventlog.build_script(query(log="Security", levels="information"))
        self.assertIn("Level     = @(0,4)", script)

    def test_only_canonical_values_reach_the_script(self):
        q = query(log="system", levels="error", provider="Service Control Manager", event_id=7031,
                  since=dt.datetime(2026, 9, 18, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=5))))
        script = eventlog.build_script(q)
        self.assertIn("LogName   = 'System'", script)
        self.assertIn("'2026-09-17T19:00:00Z'", script)       # converted to UTC by us
        self.assertIn("$filter.ProviderName = 'Service Control Manager'", script)
        self.assertIn("$filter.Id = 7031", script)
        self.assertNotIn("__", script)                        # every marker replaced

    def test_optional_filters_are_absent_unless_given(self):
        script = eventlog.build_script(query())
        self.assertNotIn("$filter.ProviderName", script)
        self.assertNotIn("$filter.Id", script)

    def test_nothing_found_is_an_empty_answer_not_a_failure(self):
        script = eventlog.build_script(query())
        self.assertIn("NoMatchingEventsFound", script)
        self.assertIn("else { throw }", script)

    def test_it_is_read_only_and_fits(self):
        script = eventlog.build_script(query(provider="x" * 128, event_id=65535))
        for verb in ("Clear-EventLog", "Remove-", "Set-", "Limit-EventLog", "wevtutil", "Stop-"):
            self.assertNotIn(verb, script)
        self.assertLess(protocol.script_length(script), protocol.MAX_SCRIPT_CHARS)


class ParseTests(unittest.TestCase):
    def job(self, **fields):
        view = {"state": "Completed", "exitCode": 0, "stdout": json.dumps([ENTRY]),
                "stdoutTruncated": False}
        view.update(fields)
        return view

    def test_entries_and_empty_lists_are_answers(self):
        self.assertEqual(eventlog.parse(self.job())[0], [ENTRY])
        self.assertEqual(eventlog.parse(self.job(stdout="[]")), ([], None))

    def test_anything_incomplete_is_a_failed_query(self):
        for name, view in {
            "truncated": self.job(stdoutTruncated=True),
            "not json": self.job(stdout="[{"),
            "not a list": self.job(stdout=json.dumps(ENTRY)),
            "failed": self.job(state="Failed", exitCode=1, stderr="Access denied"),
            "timed out": self.job(state="TimedOut", exitCode=None),
        }.items():
            with self.subTest(case=name):
                entries, error = eventlog.parse(view)
                self.assertIsNone(entries)
                self.assertTrue(error)


class EndpointTests(Harness):
    def ask(self, answer=None, **filters):
        """Calls the endpoint and, once it has dispatched, answers as the device."""
        task = self.loop.create_task(main.query_event_log(
            "dev", log=filters.get("log", "System"), levels=filters.get("levels"),
            since=None, until=None, max_events=filters.get("max_events", 50),
            provider=None, event_id=None, operator="operator"))
        for _ in range(20):
            self.loop.run_until_complete(asyncio.sleep(0))
            if self.jobs.active() or task.done():
                break
        if answer is not None and self.jobs.active():
            main.handle_result(self.signed(self.jobs.active()[0], **answer), self.connection)
        return self.loop.run_until_complete(task)

    def test_structured_entries_come_back(self):
        result = self.ask({"stdout": json.dumps([ENTRY])}, levels="error")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["entries"][0]["eventId"], 7031)
        self.assertEqual(result["query"]["levels"], ["error"])
        self.assertIn("eventlog.query", [r["action"] for r in self.store.recent_audit(5)])

    def test_the_query_runs_under_the_callers_name(self):
        self.ask({"stdout": "[]"})
        job = self.jobs.recent(1)[0]
        self.assertEqual(self.store.get_job(job["jobId"])["created_by"], "operator")

    def test_a_bad_filter_is_refused_before_anything_is_sent(self):
        with self.assertRaises(HTTPException) as caught:
            self.ask(log="Nonsense")
        self.assertEqual(caught.exception.status_code, 400)
        self.assertEqual(self.jobs.recent(5), [])

    def test_an_offline_device_is_409(self):
        self.connection.revoked = True
        with self.assertRaises(HTTPException) as caught:
            self.ask()
        self.assertEqual(caught.exception.status_code, 409)

    def test_a_failure_on_the_device_is_502_with_the_reason(self):
        with self.assertRaises(HTTPException) as caught:
            self.ask({"exitCode": 1, "stdout": "", "stderr": "Access is denied"})
        self.assertEqual(caught.exception.status_code, 502)
        self.assertIn("Access is denied", caught.exception.detail)


if __name__ == "__main__":
    unittest.main()

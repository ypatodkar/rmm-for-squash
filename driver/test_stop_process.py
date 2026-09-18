"""Stopping a process is the most destructive thing in the catalogue, and the
only one whose target can change identity between proposing and executing."""

import unittest

import repairs
from diagnostics import ArgumentError


def top_memory(*processes) -> list[dict]:
    return [{"name": n, "pid": p, "memoryMB": m} for n, p, m in processes]


class ProtectedProcessTests(unittest.TestCase):
    def test_processes_windows_needs_are_refused(self):
        repair = repairs.get("stop_process")
        for name in ("lsass", "csrss", "wininit", "services", "smss", "winlogon",
                     "System", "svchost", "explorer", "LSASS", "lsass.exe"):
            with self.assertRaises(ArgumentError, msg=name):
                repair.build({"process_name": name, "pid": 1234})

    def test_the_agent_cannot_be_told_to_stop_itself(self):
        """Stopping it would strand the endpoint with no way to be told anything."""
        repair = repairs.get("stop_process")
        for name in ("SquashRmm.Agent", "squashrmm.agent", "SquashRmm.Agent.exe"):
            with self.assertRaises(ArgumentError, msg=name):
                repair.build({"process_name": name, "pid": 2544})

    def test_defender_is_refused(self):
        with self.assertRaises(ArgumentError):
            repairs.get("stop_process").build({"process_name": "MsMpEng", "pid": 2576})

    def test_an_ordinary_application_is_allowed(self):
        script = repairs.get("stop_process").build(
            {"process_name": "ReportBuilder", "pid": 4321})
        self.assertIn("Get-Process -Id 4321", script)
        self.assertIn("ReportBuilder", script)

    def test_a_process_name_cannot_carry_script_text(self):
        repair = repairs.get("stop_process")
        for hostile in ("a'; Stop-Process -Name lsass; '", "a$(whoami)", "a|b", "a`b", ""):
            with self.assertRaises(ArgumentError, msg=repr(hostile)):
                repair.build({"process_name": hostile, "pid": 1234})

    def test_system_and_idle_pids_are_refused(self):
        repair = repairs.get("stop_process")
        for pid in (0, 4, -1, "1234", None, True, 1.5):
            with self.assertRaises(ArgumentError, msg=repr(pid)):
                repair.build({"process_name": "ReportBuilder", "pid": pid})


class PidReuseTests(unittest.TestCase):
    def test_the_script_rechecks_the_pid_on_the_endpoint(self):
        """A pid is reused the moment it is freed, so a check made here or at
        precondition time can be stale by the time the command lands."""
        script = repairs.get("stop_process").build(
            {"process_name": "ReportBuilder", "pid": 4321})
        self.assertIn("$p.ProcessName -ne 'ReportBuilder'", script)
        self.assertIn("refusing", script)
        # The guard must come before the stop, not after.
        self.assertLess(script.index("refusing"), script.index("Stop-Process"))


class ConditionTests(unittest.TestCase):
    def setUp(self):
        self.repair = repairs.get("stop_process")
        self.arguments = {"process_name": "ReportBuilder", "pid": 4321}

    def test_applies_when_the_named_process_is_using_significant_memory(self):
        data = top_memory(("ReportBuilder", 4321, 1500), ("Registry", 96, 64))
        self.assertTrue(self.repair.precondition.evaluate(data, self.arguments))

    def test_does_not_apply_to_a_different_pid_with_the_same_name(self):
        data = top_memory(("ReportBuilder", 9999, 1500))
        self.assertFalse(self.repair.precondition.evaluate(data, self.arguments))

    def test_does_not_apply_to_a_different_name_with_the_same_pid(self):
        data = top_memory(("SomethingElse", 4321, 1500))
        self.assertFalse(self.repair.precondition.evaluate(data, self.arguments))

    def test_does_not_apply_to_a_process_using_little_memory(self):
        data = top_memory(("ReportBuilder", 4321, 12))
        self.assertFalse(self.repair.precondition.evaluate(data, self.arguments))

    def test_verified_only_once_the_process_is_gone(self):
        gone = top_memory(("Registry", 96, 64))
        still_there = top_memory(("ReportBuilder", 4321, 1500))
        self.assertTrue(self.repair.verification.evaluate(gone, self.arguments))
        self.assertFalse(self.repair.verification.evaluate(still_there, self.arguments))

    def test_an_unusable_result_satisfies_neither_condition(self):
        for data in (None, {}, "not a list", [{"unexpected": True}]):
            self.assertFalse(self.repair.precondition.evaluate(data, self.arguments), repr(data))


if __name__ == "__main__":
    unittest.main()

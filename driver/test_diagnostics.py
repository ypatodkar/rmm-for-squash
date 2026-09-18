"""The catalogue is the boundary between a caller's intent and script text.
These cover what must never cross it."""

import unittest

import diagnostics
from diagnostics import ArgumentError


class CatalogTests(unittest.TestCase):
    def test_unknown_diagnostic_is_refused(self):
        with self.assertRaises(ArgumentError):
            diagnostics.get("delete_everything")

    def test_every_catalogue_entry_builds_with_no_placeholder_left_behind(self):
        defaults = {"top_n": 5, "hours": 1, "max_events": 5, "service_name": "Spooler"}
        for name, diagnostic in diagnostics.CATALOG.items():
            arguments = {k: defaults[k] for k in diagnostic.parameters}
            script = diagnostic.build(arguments)
            self.assertTrue(script.strip(), name)
            for parameter in diagnostic.parameters:
                self.assertNotIn("{" + parameter + "}", script,
                                 f"{name} left {parameter} unsubstituted")

    def test_scripts_are_read_only(self):
        """A mutating verb in this catalogue would defeat the point of it."""
        forbidden = ("Remove-", "Stop-Service", "Stop-Process", "Set-", "New-Item",
                     "shutdown", "Restart-", "Start-Service", "Invoke-Expression")
        defaults = {"top_n": 5, "hours": 1, "max_events": 5, "service_name": "Spooler"}
        for name, diagnostic in diagnostics.CATALOG.items():
            script = diagnostic.build({k: defaults[k] for k in diagnostic.parameters})
            for verb in forbidden:
                self.assertNotIn(verb, script, f"{name} contains {verb}")


class ArgumentValidationTests(unittest.TestCase):
    def test_arguments_outside_the_declared_range_are_refused(self):
        top = diagnostics.get("top_processes_by_memory")
        for value in (0, -1, 26, 10_000):
            with self.assertRaises(ArgumentError, msg=value):
                top.build({"top_n": value})

    def test_arguments_of_the_wrong_type_are_refused(self):
        top = diagnostics.get("top_processes_by_memory")
        for value in ("5", 5.5, None, True, [5], {"n": 5}):
            with self.assertRaises(ArgumentError, msg=repr(value)):
                top.build({"top_n": value})

    def test_missing_and_unexpected_arguments_are_refused(self):
        top = diagnostics.get("top_processes_by_memory")
        with self.assertRaises(ArgumentError):
            top.build({})
        with self.assertRaises(ArgumentError):
            top.build({"top_n": 5, "extra": 1})

    def test_a_name_cannot_carry_script_text(self):
        """The decisive case: a service name is substituted into a script, so
        anything that could close the quote or start a new statement is refused
        outright rather than escaped."""
        service = diagnostics.get("service_status")
        hostile = [
            "Spooler'; Remove-Item C:\\ -Recurse; '",
            "Spooler`; whoami",
            "Spooler$(whoami)",
            "Spooler | Stop-Service",
            "Spooler\nStop-Service Spooler",
            "Spooler&whoami",
            "'",
            '"',
            "a" * 65,
            "",
        ]
        for value in hostile:
            with self.assertRaises(ArgumentError, msg=repr(value)):
                service.build({"service_name": value})

    def test_a_legitimate_service_name_is_accepted(self):
        script = diagnostics.get("service_status").build({"service_name": "Spooler"})
        self.assertIn("Get-Service -Name 'Spooler'", script)


if __name__ == "__main__":
    unittest.main()

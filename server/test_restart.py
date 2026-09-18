"""Restarting is the only route that deliberately takes a machine down, and the
only place an operator's free text reaches a command line."""

import unittest

import protocol


class RestartScriptTests(unittest.TestCase):
    def test_builds_the_expected_command(self):
        script = protocol.restart_script(15, protocol.DEFAULT_RESTART_REASON)
        self.assertIn("shutdown.exe /r /t 15", script)
        self.assertIn(protocol.DEFAULT_RESTART_REASON, script)

    def test_a_reason_cannot_carry_script_text(self):
        hostile = [
            'a"; Remove-Item C:\\ -Recurse -Force; "',
            "a$(whoami)",
            "a`nb",
            "a|b", "a;b", "a&b", "a>b",
            "$env:USERNAME",
            "",
            "x" * 201,
        ]
        for reason in hostile:
            with self.assertRaises(protocol.RestartError, msg=repr(reason)):
                protocol.restart_script(15, reason)

    def test_a_reason_is_not_silently_escaped(self):
        """Refusing is the whole point: an escaped reason would still reach the
        command line, and escaping is a thing you can get subtly wrong."""
        with self.assertRaises(protocol.RestartError):
            protocol.restart_script(15, 'patch window"')

    def test_ordinary_reasons_are_allowed(self):
        for reason in ("Monthly patch window", "IT restart (ticket 4821)",
                       "Applying updates - please save your work",
                       "Restarting now! OK?", "Tonight's maintenance"):
            script = protocol.restart_script(30, reason)
            self.assertIn(reason, script)

    def test_a_restart_cannot_be_immediate(self):
        """Below the floor the machine goes down before it can report the
        result, and a succeeded restart is shown to the operator as a failure."""
        for delay in (0, 1, 4, -60):
            with self.assertRaises(protocol.RestartError, msg=delay):
                protocol.restart_script(delay, "ok")

    def test_delay_must_be_a_whole_number_of_seconds(self):
        for delay in (True, "15", 15.0, None, 3601):
            with self.assertRaises(protocol.RestartError, msg=repr(delay)):
                protocol.restart_script(delay, "ok")

    def test_the_delay_is_reported_back_in_the_output(self):
        """The operator sees confirmation from the machine itself, not only
        from the control plane that asked."""
        self.assertIn('"restart scheduled in 45s"', protocol.restart_script(45, "ok"))


if __name__ == "__main__":
    unittest.main()

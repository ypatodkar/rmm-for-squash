"""The network checks take a hostname and a port from the model and put them
into a script. Only real hostnames, IPv4 addresses and port numbers may pass."""

import json
import unittest

import diagnostics
import investigator
from diagnostics import ArgumentError

NETWORK = ("network_adapters", "ping_host", "resolve_name", "test_tcp_port",
           "outbound_firewall_blocks")


class HostArgumentTests(unittest.TestCase):
    def test_real_hosts_are_accepted(self):
        ping = diagnostics.get("ping_host")
        for host in ("fileserver", "fileserver.corp.local", "172.31.16.1", "example.com",
                     "one.one.one.one", "ip-172-31-27-210.ec2.internal", "a.b.", "x" * 63):
            with self.subTest(host=host):
                self.assertIn(f"'{host}'", ping.build({"host": host}))

    def test_a_host_cannot_carry_script_text(self):
        ping = diagnostics.get("ping_host")
        for hostile in ("a'; Remove-Item C:\\ -Recurse; '", "a b", "$(whoami)", "a`b",
                        "a|b", "a;b", "a&b", "'a'", '"a"', "a\nb", "-leading", "trailing-",
                        "a..b", ".a", "", "x" * 64, "a." * 127 + "a", "http://a.b",
                        "::1", "a/b", "a\\b", "a@b", "a:445"):
            with self.subTest(host=hostile):
                with self.assertRaises(ArgumentError):
                    ping.build({"host": hostile})

    def test_a_host_must_be_text(self):
        for value in (None, 1, 1.5, True, ["a"], {"h": "a"}):
            with self.assertRaises(ArgumentError, msg=repr(value)):
                diagnostics.get("resolve_name").build({"name": value})

    def test_ports_are_bounded_whole_numbers(self):
        tcp = diagnostics.get("test_tcp_port")
        self.assertIn("445", tcp.build({"host": "fs", "port": 445}))
        for port in (0, -1, 65536, "445", 445.0, True, None):
            with self.subTest(port=port):
                with self.assertRaises(ArgumentError):
                    tcp.build({"host": "fs", "port": port})


class ScriptTests(unittest.TestCase):
    def build(self, name):
        sample = {"host": "fileserver.corp.local", "name": "fileserver.corp.local", "port": 445}
        entry = diagnostics.get(name)
        return entry.build({k: sample[k] for k in entry.parameters})

    def test_every_parameter_is_substituted(self):
        for name in NETWORK:
            with self.subTest(name=name):
                script = self.build(name)
                self.assertNotIn("<<", script)
                self.assertNotIn("{host}", script)
                self.assertNotIn("{port}", script)

    def test_powershell_braces_survive_formatting_intact(self):
        """The failure _ps exists to prevent: doubled or collapsed braces."""
        for name in NETWORK:
            with self.subTest(name=name):
                script = self.build(name)
                self.assertEqual(script.count("{"), script.count("}"))
                self.assertNotIn("{{", script)
                self.assertNotIn("}}", script)

    def test_they_emit_json(self):
        for name in NETWORK:
            with self.subTest(name=name):
                self.assertIn("ConvertTo-Json", self.build(name))

    def test_timeouts_are_short(self):
        """A dead end should cost seconds, not the whole job timeout."""
        self.assertIn("Send('fileserver.corp.local', 1000)", self.build("ping_host"))
        self.assertIn(".Wait(2000)", self.build("test_tcp_port"))
        self.assertIn("-QuickTimeout", self.build("resolve_name"))


class ToolDefinitionTests(unittest.TestCase):
    def test_the_model_is_offered_each_check_with_a_strict_schema(self):
        tools = {t["function"]["name"]: t["function"] for t in investigator.tool_definitions()}
        for name in NETWORK:
            self.assertIn(name, tools)
            self.assertFalse(tools[name]["parameters"]["additionalProperties"])
        port = tools["test_tcp_port"]["parameters"]["properties"]["port"]
        self.assertEqual((port["minimum"], port["maximum"]), (1, 65535))
        self.assertEqual(sorted(tools["test_tcp_port"]["parameters"]["required"]),
                         ["host", "port"])
        json.dumps(tools)   # must be serialisable as sent to the provider


if __name__ == "__main__":
    unittest.main()

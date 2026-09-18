"""Boot time is reported by the endpoint, so it is a claim, not a fact. These
cover what the control plane concludes from it -- and what it refuses to."""

import time
import unittest

import main
from store import Store


class BootTimeParsingTests(unittest.TestCase):
    def test_plausible_value_is_accepted(self):
        now_ms = time.time() * 1000
        self.assertAlmostEqual(main.parse_reported_boot_time(now_ms), now_ms / 1000, places=3)

    def test_missing_or_non_numeric_is_rejected(self):
        for value in (None, "yesterday", {}, [], True, False):
            self.assertIsNone(main.parse_reported_boot_time(value), repr(value))

    def test_far_future_is_rejected(self):
        # Would otherwise poison every later comparison: nothing could ever
        # look like a newer boot again.
        self.assertIsNone(main.parse_reported_boot_time((time.time() + 86_400) * 1000))

    def test_implausibly_old_is_rejected(self):
        self.assertIsNone(main.parse_reported_boot_time(0))
        self.assertIsNone(main.parse_reported_boot_time(-1))


class ConnectionEventTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(setattr, main, "store", main.store)
        main.store = self.store
        self.store.insert_device("dev", "key", "host", "Windows", "0.3.0")

    def latest(self):
        return self.store.device_events("dev", limit=1)[0]

    def hello(self, boot_at):
        return {"bootTimeUnixMs": boot_at * 1000} if boot_at is not None else {}

    def device(self):
        return self.store.get_device("dev")

    def test_first_connection_records_online_not_reboot(self):
        main.record_connection(self.device(), self.hello(time.time() - 3600))
        self.assertEqual(self.latest()["event"], "online")

    def test_same_boot_time_is_not_reported_as_a_reboot(self):
        boot = time.time() - 3600
        main.record_connection(self.device(), self.hello(boot))
        main.record_connection(self.device(), self.hello(boot + 5))
        event = self.latest()
        self.assertEqual(event["event"], "online")
        self.assertIn('"newBootObserved": false', event["detail"])

    def test_later_boot_time_is_reported_as_a_reboot(self):
        main.record_connection(self.device(), self.hello(time.time() - 7200))
        main.record_connection(self.device(), self.hello(time.time() - 30))
        self.assertEqual(self.latest()["event"], "rebooted")

    def test_boot_time_moving_backwards_is_flagged_not_treated_as_normal(self):
        main.record_connection(self.device(), self.hello(time.time() - 60))
        main.record_connection(self.device(), self.hello(time.time() - 7200))
        self.assertEqual(self.latest()["event"], "boot_time_regressed")

    def test_absent_boot_time_is_recorded_honestly(self):
        main.record_connection(self.device(), self.hello(None))
        event = self.latest()
        self.assertEqual(event["event"], "online")
        self.assertIn('"bootTimeReported": false', event["detail"])

    def test_implausible_boot_time_does_not_become_stored_state(self):
        main.record_connection(self.device(), {"bootTimeUnixMs": (time.time() + 86_400) * 1000})
        self.assertIsNone(self.device()["last_boot_at"])
        self.assertIn('"bootTimeReported": false', self.latest()["detail"])

    def test_unreachable_interval_is_measured_from_the_disconnect(self):
        main.record_connection(self.device(), self.hello(time.time() - 3600))
        self.store.set_disconnected("dev")
        main.record_connection(self.device(), self.hello(time.time() - 10))
        event = self.latest()
        self.assertEqual(event["event"], "rebooted")
        self.assertIn("secondsUnreachable", event["detail"])


if __name__ == "__main__":
    unittest.main()

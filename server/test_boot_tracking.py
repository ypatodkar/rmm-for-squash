"""Reboot detection reasons about an endpoint's clock and counters, both of
which can be wrong or hostile. These cover the cases where a naive reading
would invent a restart or miss one."""

import time
import unittest

import main
from store import Store


class NumericValidationTests(unittest.TestCase):
    def test_uptime_rejects_values_that_are_not_real_numbers(self):
        for value in (None, "an hour", {}, [], True, False,
                      float("nan"), float("inf"), float("-inf"), 10 ** 400):
            self.assertIsNone(main.parse_reported_uptime(value), repr(value))

    def test_uptime_rejects_negative_and_absurd_durations(self):
        self.assertIsNone(main.parse_reported_uptime(-1))
        self.assertIsNone(main.parse_reported_uptime(main.MAX_PLAUSIBLE_UPTIME_SECONDS + 1))
        self.assertEqual(main.parse_reported_uptime(3600), 3600)

    def test_boot_time_rejects_non_finite_and_oversized_values(self):
        for value in (float("nan"), float("inf"), 10 ** 400, None, True):
            self.assertIsNone(main.parse_reported_boot_time(value), repr(value))

    def test_boot_time_rejects_future_and_prehistoric_values(self):
        self.assertIsNone(main.parse_reported_boot_time((time.time() + 86_400) * 1000))
        self.assertIsNone(main.parse_reported_boot_time(0))


class RebootDetectionTests(unittest.TestCase):
    """Detection uses uptime, which comes from a monotonic counter, so neither
    the endpoint's clock nor the control plane's can influence the outcome."""

    def test_restart_is_detected_when_uptime_falls_back(self):
        self.assertTrue(main.detect_reboot(
            previous_uptime=7200, reported_uptime=30, elapsed_seconds=60))

    def test_restart_of_a_briefly_running_machine_is_detected(self):
        # The shortfall here is only 90s, inside the tolerance, so the shortfall
        # rule alone would miss it. Uptime fell from 60 to 20, which cannot
        # happen within one boot.
        self.assertTrue(main.detect_reboot(
            previous_uptime=60, reported_uptime=20, elapsed_seconds=50))

    def test_restart_after_a_long_absence_is_detected_though_uptime_grew(self):
        # Uptime is higher than before, so only the shortfall rule can catch it.
        self.assertTrue(main.detect_reboot(
            previous_uptime=100, reported_uptime=600, elapsed_seconds=86_400))

    def test_endpoint_clock_correction_does_not_look_like_a_restart(self):
        self.assertFalse(main.detect_reboot(
            previous_uptime=3600, reported_uptime=3900, elapsed_seconds=300))

    def test_control_plane_clock_correction_does_not_look_like_a_restart(self):
        # Sixty seconds of normal operation. A wall clock adjusted forward by
        # three minutes would report 240s elapsed and manufacture a restart;
        # the monotonic reading still reports 60.
        self.assertFalse(main.detect_reboot(
            previous_uptime=1000, reported_uptime=1060, elapsed_seconds=60))

    def test_continuous_uptime_is_not_a_restart(self):
        self.assertFalse(main.detect_reboot(
            previous_uptime=1000, reported_uptime=1500, elapsed_seconds=500))

    def test_unreliable_elapsed_time_still_catches_a_decrease(self):
        self.assertTrue(main.detect_reboot(
            previous_uptime=5000, reported_uptime=30,
            elapsed_seconds=120, elapsed_is_reliable=False))

    def test_unreliable_elapsed_time_does_not_invent_a_restart_from_a_small_gap(self):
        # After a control plane restart the elapsed figure comes from a wall
        # clock that may have moved; a modest shortfall is not enough.
        self.assertFalse(main.detect_reboot(
            previous_uptime=1000, reported_uptime=1100,
            elapsed_seconds=400, elapsed_is_reliable=False))

    def test_undeterminable_without_a_previous_observation_or_uptime(self):
        self.assertIsNone(main.detect_reboot(None, 100, 10))
        self.assertIsNone(main.detect_reboot(100, None, 10))

    def test_without_elapsed_time_only_a_decrease_can_be_concluded(self):
        self.assertTrue(main.detect_reboot(1000, 10, None))
        self.assertFalse(main.detect_reboot(1000, 1200, None))


class ElapsedMeasurementTests(unittest.TestCase):
    def test_monotonic_reading_from_this_process_is_trusted(self):
        device = {"last_uptime_observer_epoch": main.OBSERVER_EPOCH,
                  "last_uptime_observed_monotonic": 100.0,
                  "last_uptime_observed_at": time.time() - 9999}
        elapsed, reliable = main.elapsed_since_observation(device, monotonic_now=160.0)
        self.assertEqual(elapsed, 60.0)
        self.assertTrue(reliable)

    def test_reading_from_a_previous_process_falls_back_and_is_marked_unreliable(self):
        device = {"last_uptime_observer_epoch": "a-previous-process",
                  "last_uptime_observed_monotonic": 100.0,
                  "last_uptime_observed_at": time.time() - 60}
        elapsed, reliable = main.elapsed_since_observation(device, monotonic_now=1_000_000.0)
        self.assertAlmostEqual(elapsed, 60, delta=2)
        self.assertFalse(reliable)

    def test_no_observation_yields_no_elapsed_time(self):
        elapsed, reliable = main.elapsed_since_observation({}, monotonic_now=10.0)
        self.assertIsNone(elapsed)
        self.assertFalse(reliable)


class ConnectionEventTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(setattr, main, "store", main.store)
        main.store = self.store
        self.store.insert_device("dev", "key", "host", "Windows", "0.3.0")

    def device(self):
        return self.store.get_device("dev")

    def latest(self):
        return self.store.device_events("dev", limit=1)[0]

    def connect(self, uptime):
        main.record_connection(self.device(), {"uptimeSeconds": uptime})

    def test_first_contact_cannot_determine_a_restart(self):
        self.connect(3600)
        event = self.latest()
        self.assertEqual(event["event"], "online")
        self.assertIn('"rebootDetermined": false', event["detail"])

    def test_restart_is_recorded_between_connections(self):
        self.connect(7200)
        self.connect(20)
        self.assertEqual(self.latest()["event"], "rebooted")

    def test_steady_uptime_is_not_recorded_as_a_restart(self):
        self.connect(7200)
        self.connect(7260)
        self.assertEqual(self.latest()["event"], "online")

    def test_missing_uptime_is_recorded_honestly(self):
        main.record_connection(self.device(), {})
        self.assertIn("endpoint did not report uptime", self.latest()["detail"])

    def test_implausible_uptime_does_not_become_stored_state(self):
        main.record_connection(self.device(), {"uptimeSeconds": float("nan")})
        self.assertIsNone(self.device()["last_uptime_seconds"])

    def test_outage_is_closed_on_reconnect_so_it_is_not_counted_twice(self):
        self.connect(3600)
        self.store.set_disconnected("dev")
        self.connect(3700)
        self.assertIsNone(self.device()["last_disconnect_at"])

        # A later reconnection must not reuse the previous outage.
        self.connect(3800)
        self.assertIn('"secondsUnreachable": null', self.latest()["detail"])


class UptimeReportingTests(unittest.TestCase):
    def test_uptime_advances_only_while_the_device_is_visible(self):
        row = {"last_uptime_seconds": 1000, "last_uptime_observed_at": time.time() - 500}
        online = main.uptime_view(row, online=True)
        offline = main.uptime_view(row, online=False)

        self.assertAlmostEqual(online["uptimeSeconds"], 1500, delta=2)
        self.assertFalse(online["uptimeIsLastKnown"])

        # The machine may be powered off; extrapolating would be a fiction.
        self.assertEqual(offline["uptimeSeconds"], 1000)
        self.assertTrue(offline["uptimeIsLastKnown"])

    def test_uptime_is_unknown_without_an_observation(self):
        view = main.uptime_view({"last_uptime_seconds": None,
                                 "last_uptime_observed_at": None}, online=True)
        self.assertIsNone(view["uptimeSeconds"])


if __name__ == "__main__":
    unittest.main()

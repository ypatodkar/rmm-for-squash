"""An investigation must end. These cover each way it is made to."""

import time
import unittest

from limits import Budget, BudgetExceeded


class BudgetTests(unittest.TestCase):
    def test_a_fresh_budget_permits_work(self):
        Budget().check("disk_usage")

    def test_the_diagnostic_count_is_capped(self):
        budget = Budget(max_diagnostics=2, max_repeats_per_diagnostic=99)
        for _ in range(2):
            budget.check("disk_usage")
            budget.record("disk_usage", None, 100)
        with self.assertRaises(BudgetExceeded):
            budget.check("disk_usage")

    def test_elapsed_time_is_capped(self):
        budget = Budget(max_wall_clock_seconds=0.05)
        time.sleep(0.06)
        with self.assertRaises(BudgetExceeded):
            budget.check("disk_usage")

    def test_collected_output_is_capped(self):
        budget = Budget(max_total_output_bytes=500, max_repeats_per_diagnostic=99)
        budget.check("disk_usage")
        budget.record("disk_usage", None, 600)
        with self.assertRaises(BudgetExceeded):
            budget.check("disk_usage")

    def test_repeating_an_identical_check_is_stopped(self):
        """A loop asking the same question is stuck, not investigating."""
        budget = Budget(max_repeats_per_diagnostic=2)
        for _ in range(2):
            budget.check("top_processes_by_memory", {"top_n": 5})
            budget.record("top_processes_by_memory", {"top_n": 5}, 100)
        with self.assertRaises(BudgetExceeded):
            budget.check("top_processes_by_memory", {"top_n": 5})

    def test_different_arguments_are_a_different_check(self):
        budget = Budget(max_repeats_per_diagnostic=1)
        budget.check("top_processes_by_memory", {"top_n": 5})
        budget.record("top_processes_by_memory", {"top_n": 5}, 100)
        budget.check("top_processes_by_memory", {"top_n": 10})

    def test_argument_order_does_not_create_a_new_signature(self):
        budget = Budget(max_repeats_per_diagnostic=1)
        budget.check("recent_system_errors", {"hours": 24, "max_events": 5})
        budget.record("recent_system_errors", {"hours": 24, "max_events": 5}, 10)
        with self.assertRaises(BudgetExceeded):
            budget.check("recent_system_errors", {"max_events": 5, "hours": 24})

    def test_limits_are_checked_before_work_not_after(self):
        """The bound must reject the dispatch that would exceed it, so nothing
        beyond the limit ever reaches an endpoint."""
        budget = Budget(max_diagnostics=1, max_repeats_per_diagnostic=99)
        budget.check("disk_usage")
        budget.record("disk_usage", None, 10)
        with self.assertRaises(BudgetExceeded):
            budget.check("disk_usage")
        self.assertEqual(budget.diagnostics_run, 1)

    def test_summary_reports_what_is_left(self):
        budget = Budget(max_diagnostics=5)
        budget.record("disk_usage", None, 250)
        summary = budget.summary()
        self.assertEqual(summary["diagnosticsRun"], 1)
        self.assertEqual(summary["diagnosticsRemaining"], 4)
        self.assertEqual(summary["outputBytes"], 250)


if __name__ == "__main__":
    unittest.main()

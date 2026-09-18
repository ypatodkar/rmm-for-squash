"""Bounds on a single investigation.

An investigation is a loop whose length will later be decided by a model, so it
needs the same discipline the control plane applies to a job: a definite end,
enforced by code rather than by asking nicely. These bounds are checked before
each dispatch, so exceeding one stops the investigation instead of being noticed
afterwards.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    """An investigation reached one of its limits and must stop."""


@dataclass
class Budget:
    max_diagnostics: int = 12
    max_wall_clock_seconds: float = 300.0
    max_total_output_bytes: int = 512_000
    # Repeating the same check with the same arguments adds no evidence; a loop
    # doing so is stuck, and should stop rather than burn the whole budget.
    max_repeats_per_diagnostic: int = 2
    # Attempts that never produced a result -- an offline device, a refused
    # argument -- consume real time and dispatches. Counting only successes
    # would let a failing loop run until the wall clock alone stopped it.
    max_attempts: int = 20
    max_failed_attempts: int = 6

    diagnostics_run: int = 0
    attempts: int = 0
    failed_attempts: int = 0
    output_bytes: int = 0
    started_at: float = field(default_factory=time.monotonic)
    _signatures: dict[str, int] = field(default_factory=dict)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_wall_clock_seconds - self.elapsed_seconds)

    def check(self, diagnostic: str, arguments: dict | None = None) -> None:
        """Raises if this dispatch would exceed a bound. Called before the
        dispatch, so a rejected call never reaches an endpoint."""
        if self.diagnostics_run >= self.max_diagnostics:
            raise BudgetExceeded(
                f"reached the limit of {self.max_diagnostics} diagnostics")

        if self.attempts >= self.max_attempts:
            raise BudgetExceeded(f"reached the limit of {self.max_attempts} attempts")

        if self.failed_attempts >= self.max_failed_attempts:
            raise BudgetExceeded(
                f"{self.failed_attempts} checks failed; stopping rather than retrying further")

        if self.elapsed_seconds >= self.max_wall_clock_seconds:
            raise BudgetExceeded(
                f"investigation exceeded {self.max_wall_clock_seconds:.0f}s")

        if self.output_bytes >= self.max_total_output_bytes:
            raise BudgetExceeded(
                f"collected output exceeded {self.max_total_output_bytes} bytes")

        signature = _signature(diagnostic, arguments)
        if self._signatures.get(signature, 0) >= self.max_repeats_per_diagnostic:
            raise BudgetExceeded(
                f"'{diagnostic}' has already been run "
                f"{self.max_repeats_per_diagnostic} times with these arguments")

    def record_attempt(self, diagnostic: str, arguments: dict | None, *,
                       succeeded: bool, output_bytes: int = 0) -> None:
        """Counts every attempt, whether or not it produced data. An attempt
        that failed still cost a dispatch and still moves the loop forward."""
        self.attempts += 1
        signature = _signature(diagnostic, arguments)
        self._signatures[signature] = self._signatures.get(signature, 0) + 1
        if succeeded:
            self.diagnostics_run += 1
            self.output_bytes += max(0, output_bytes)
        else:
            self.failed_attempts += 1

    def record(self, diagnostic: str, arguments: dict | None, output_bytes: int) -> None:
        self.record_attempt(diagnostic, arguments, succeeded=True, output_bytes=output_bytes)

    def summary(self) -> dict:
        return {
            "diagnosticsRun": self.diagnostics_run,
            "diagnosticsRemaining": max(0, self.max_diagnostics - self.diagnostics_run),
            "outputBytes": self.output_bytes,
            "elapsedSeconds": round(self.elapsed_seconds, 1),
            "remainingSeconds": round(self.remaining_seconds, 1),
        }


def _signature(diagnostic: str, arguments: dict | None) -> str:
    items = sorted((arguments or {}).items())
    return diagnostic + "|" + ",".join(f"{k}={v}" for k, v in items)

"""Run one investigation against a real endpoint.

    python diagnose.py <hostname> "why is this machine slow?"
"""

from __future__ import annotations

import os
import sys
import time

import model as model_module
from investigator import Investigator
from rmm import DeviceUnavailable, RmmClient, RmmError

START = time.monotonic()


def show(event: str, detail: dict) -> None:
    elapsed = time.monotonic() - START
    if event == "collecting":
        args = detail.get("arguments") or {}
        suffix = f" {args}" if args else ""
        print(f"  [{elapsed:5.1f}s] running {detail['diagnostic']}{suffix}")
    elif event == "collected":
        mark = "ok" if detail.get("ok") else "failed"
        print(f"  [{elapsed:5.1f}s]   {mark} in {detail.get('durationMs')}ms "
              f"(round-trip {detail.get('roundTripMs')}ms, job {str(detail.get('jobId'))[:8]})")
    elif event == "refused":
        print(f"  [{elapsed:5.1f}s] refused {detail['diagnostic']}: {detail['reason']}")
    elif event == "analyzing":
        print(f"  [{elapsed:5.1f}s] deciding what to check next")


def main(argv: list[str]) -> int:
    model_module.load_dotenv()
    base_url = os.environ.get("SQUASH_SERVER")
    api_key = os.environ.get("SQUASH_DRIVER_KEY")
    if not base_url or not api_key:
        print("set SQUASH_SERVER and SQUASH_DRIVER_KEY", file=sys.stderr)
        return 2

    target = argv[1] if len(argv) > 1 else None
    problem = argv[2] if len(argv) > 2 else "This machine is running slowly."

    client = RmmClient(base_url, api_key)
    try:
        device = client.resolve_device(target) if target else \
            next(d for d in client.list_devices() if d.online)
    except (RmmError, DeviceUnavailable, StopIteration) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        llm = model_module.from_environment()
    except model_module.ModelError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"device   {device.hostname}")
    print(f"problem  {problem}")
    print(f"model    {llm.name}")
    print()

    result = Investigator(client, llm, on_progress=show).investigate(
        device.device_id, device.hostname, problem)

    print()
    print("=" * 68)
    print(result.finding or "(no finding produced)")
    print("=" * 68)
    summary = result.summary()
    print(f"diagnostics {summary['diagnosticsRun']}   model calls {summary['modelCalls']}   "
          f"tokens {summary['tokens']['input']}/{summary['tokens']['output']}   "
          f"elapsed {summary['elapsedSeconds']}s")
    print(f"stopped because: {summary['stoppedBecause']}")
    print()
    for index, step in enumerate(result.steps, 1):
        print(f"  {index}. {step.diagnostic}{step.arguments or ''} -> {step.detail}")
    return 0 if result.concluded else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

"""Milestone 1 demonstration: one real round trip, no model involved.

    SQUASH_SERVER=https://…  SQUASH_DRIVER_KEY=op_…  python probe.py <hostname>
"""

from __future__ import annotations

import json
import os
import sys

from diagnostics import CATALOG
from rmm import DeviceUnavailable, RmmClient, RmmError


def main(argv: list[str]) -> int:
    base_url = os.environ.get("SQUASH_SERVER")
    api_key = os.environ.get("SQUASH_DRIVER_KEY")
    if not base_url or not api_key:
        print("set SQUASH_SERVER and SQUASH_DRIVER_KEY", file=sys.stderr)
        return 2

    client = RmmClient(base_url, api_key)
    target = argv[1] if len(argv) > 1 else None

    try:
        if target:
            device = client.resolve_device(target)
        else:
            online = [d for d in client.list_devices() if d.online]
            if not online:
                print("no device is currently online", file=sys.stderr)
                return 1
            device = online[0]
    except (RmmError, DeviceUnavailable) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"device   {device.hostname}  ({device.device_id[:12]}…)")
    print(f"online   {device.online}   uptime {device.uptime_seconds}s")
    print()

    plan = [
        ("system_overview", {}),
        ("top_processes_by_memory", {"top_n": 5}),
        ("disk_usage", {}),
    ]

    failures = 0
    for name, arguments in plan:
        try:
            result = client.run_diagnostic(device.device_id, name, arguments)
        except (RmmError, DeviceUnavailable) as error:
            print(f"{name}: {error}")
            failures += 1
            continue

        status = "ok" if result.succeeded else result.state
        print(f"--- {name} [{status}] "
              f"exec {result.duration_ms}ms  round-trip {result.round_trip_ms}ms  "
              f"job {result.job_id[:8]}…")
        if result.data is not None:
            print(json.dumps(result.data, indent=2)[:900])
        elif result.raw_stdout:
            print("  (not JSON) " + result.raw_stdout[:200])
        if result.stderr:
            print("  stderr:", result.stderr[:200])
        if not result.succeeded:
            failures += 1
        print()

    print(f"catalog: {', '.join(sorted(CATALOG))}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

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


def clean(value: object, limit: int = 60) -> str:
    """Endpoint text goes to a terminal, where control characters could move
    the cursor or rewrite what was printed. Only printable text survives."""
    text = "".join(c for c in str(value) if c.isprintable())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def summarize(diagnostic: str, data: object) -> str:
    """One line saying what a check found, so the narrowing is visible as it
    happens. Reads only fields each check is known to return."""
    def rows(value):
        return value if isinstance(value, list) else [value] if isinstance(value, dict) else []

    try:
        if diagnostic == "network_adapters":
            parts = [f"{clean(a.get('name'))} {clean(a.get('status'))}, "
                     f"ip {clean(', '.join(a.get('ipv4') or []) or 'none')}, "
                     f"gateway {clean(', '.join(a.get('gateways') or []) or 'none')}"
                     for a in rows(data)]
            return "; ".join(parts) or "no adapters"
        if diagnostic == "ping_host":
            statuses = {clean(r.get("status")) for r in rows(data.get("replies"))}
            return (f"{data.get('received')}/{data.get('sent')} replies"
                    + ("" if data.get("received") else f" ({', '.join(sorted(statuses))})"))
        if diagnostic == "resolve_name":
            dns = ", ".join(data.get("dnsServerAnswer") or []) or clean(data.get("dnsServerError") or "none")
            system = ", ".join(data.get("systemAnswer") or []) or clean(data.get("systemError") or "none")
            hosts = len(data.get("hostsFileEntries") or [])
            return (f"DNS server says {clean(dns)}; this machine uses {clean(system)}"
                    + (f"; {hosts} hosts-file entr{'y' if hosts == 1 else 'ies'}" if hosts else ""))
        if diagnostic == "test_tcp_port":
            return f"port {data.get('port')}: {clean(data.get('result'))}"
        if diagnostic == "outbound_firewall_blocks":
            names = [clean(r.get("name"), 40) for r in rows(data)]
            return f"{len(names)} blocking rule(s): {', '.join(names)}" if names else "no blocking rules"
    except (AttributeError, TypeError):
        pass
    count = len(data) if isinstance(data, list) else 1 if data is not None else 0
    return f"{count} result{'s' if count != 1 else ''}"


def show(event: str, detail: dict) -> None:
    elapsed = time.monotonic() - START
    if event == "collecting":
        args = detail.get("arguments") or {}
        suffix = f" {args}" if args else ""
        print(f"  [{elapsed:5.1f}s] running {detail['diagnostic']}{suffix}")
    elif event == "collected":
        # "check failed" means the check itself could not run. What it found --
        # including that a host did not answer -- is the line's result.
        found = summarize(detail["diagnostic"], detail.get("data")) if detail.get("ok") \
            else "check failed"
        print(f"  [{elapsed:5.1f}s]   -> {found}")
        print(f"            {detail.get('durationMs')}ms on the endpoint, "
              f"{detail.get('roundTripMs')}ms round-trip")
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
        found = summarize(step.diagnostic, step.data) if step.ok else step.detail
        print(f"  {index}. {step.diagnostic}{step.arguments or ''} -> {found}")
    return 0 if result.concluded else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

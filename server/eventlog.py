"""Windows event log queries: structured entries, filtered by log, severity and
time, without the caller writing PowerShell.

Unlike the inventory, event logs change by the second, so nothing is stored:
each query runs a fixed, read-only script on the device and returns what it
found. Every filter is validated and turned into a canonical value here, before
it reaches the script, so nothing a caller sends can become script text.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass

LOGS = ("System", "Application", "Security", "Setup")

# Windows level numbers. Level 0 ("LogAlways") is what Event Viewer shows as
# Information, and it is the level of every Security audit event, so a filter
# for information has to include it or the Security log looks empty.
LEVELS = {"critical": (1,), "error": (2,), "warning": (3,),
          "information": (0, 4), "verbose": (5,)}
DEFAULT_LEVELS = ("critical", "error", "warning")
DEFAULT_WINDOW = dt.timedelta(hours=24)
MAX_EVENTS = 500
DEFAULT_EVENTS = 50
MESSAGE_CHARS = 2000
TIMEOUT_SECONDS = 60
# 500 events of up to 2,000 characters, plus their fields, fit comfortably.
MAX_OUTPUT_BYTES = 2 * 1024 * 1024

_PROVIDER = re.compile(r"^[A-Za-z0-9 ._\-]{1,128}$")


class QueryError(ValueError):
    """The filters do not describe a query we will run."""


@dataclass(frozen=True)
class Query:
    log: str
    levels: tuple[str, ...]
    since: dt.datetime
    until: dt.datetime
    max_events: int
    provider: str | None = None
    event_id: int | None = None

    def view(self) -> dict:
        return {"log": self.log, "levels": list(self.levels),
                "since": _iso(self.since), "until": _iso(self.until),
                "maxEvents": self.max_events, "provider": self.provider,
                "eventId": self.event_id}


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_query(*, log: str = "System", levels: str | None = None,
               since: dt.datetime | None = None, until: dt.datetime | None = None,
               max_events: int = DEFAULT_EVENTS, provider: str | None = None,
               event_id: int | None = None, now: dt.datetime | None = None) -> Query:
    """Validates the filters and fills in defaults: the last 24 hours, and
    critical, error and warning."""
    now = now or dt.datetime.now(dt.timezone.utc)

    matched = [name for name in LOGS if name.lower() == (log or "").lower()]
    if not matched:
        raise QueryError(f"log must be one of: {', '.join(LOGS)}")

    names = DEFAULT_LEVELS if not levels else tuple(
        part.strip().lower() for part in levels.split(",") if part.strip())
    unknown = [name for name in names if name not in LEVELS]
    if unknown or not names:
        raise QueryError(f"levels must be a comma-separated list of: {', '.join(LEVELS)}")
    names = tuple(sorted(set(names), key=list(LEVELS).index))

    for label, moment in (("since", since), ("until", until)):
        if moment is not None and moment.tzinfo is None:
            raise QueryError(f"{label} needs a timezone, e.g. 2026-09-18T00:00:00Z")
    until = until or now
    since = since or until - DEFAULT_WINDOW
    if since >= until:
        raise QueryError("since must be earlier than until")

    if isinstance(max_events, bool) or not 1 <= max_events <= MAX_EVENTS:
        raise QueryError(f"maxEvents must be between 1 and {MAX_EVENTS}")
    if provider is not None and not _PROVIDER.match(provider):
        raise QueryError("provider may contain only letters, digits, spaces, dots, "
                         "hyphens and underscores (up to 128)")
    if event_id is not None and not 0 <= event_id <= 65535:
        raise QueryError("eventId must be between 0 and 65535")

    return Query(log=matched[0], levels=names, since=since, until=until,
                 max_events=max_events, provider=provider, event_id=event_id)


_TEMPLATE = r"""$filter = @{
  LogName   = '__LOG__'
  Level     = @(__LEVELS__)
  StartTime = [datetime]::Parse('__SINCE__', [Globalization.CultureInfo]::InvariantCulture).ToLocalTime()
  EndTime   = [datetime]::Parse('__UNTIL__', [Globalization.CultureInfo]::InvariantCulture).ToLocalTime()
}
__PROVIDER____EVENT_ID__try {
  $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents __MAX__ -ErrorAction Stop)
} catch {
  # Windows reports "nothing matched" as an error. That is an answer, not a
  # failure; anything else is a real failure and is raised.
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() } else { throw }
}
$names = @{ 0 = 'information'; 1 = 'critical'; 2 = 'error'; 3 = 'warning'; 4 = 'information'; 5 = 'verbose' }
$rows = @($events | ForEach-Object {
  $message = if ($_.Message) { $_.Message } else { '' }
  [pscustomobject]@{
    timeCreated      = $_.TimeCreated.ToUniversalTime().ToString('o')
    level            = $names[[int]$_.Level]
    levelNumber      = [int]$_.Level
    eventId          = $_.Id
    provider         = $_.ProviderName
    log              = $_.LogName
    recordId         = $_.RecordId
    message          = $message.Substring(0, [Math]::Min(__MESSAGE__, $message.Length))
    messageTruncated = ($message.Length -gt __MESSAGE__)
  }
})
ConvertTo-Json -InputObject $rows -Depth 3 -Compress
"""


def build_script(query: Query) -> str:
    """Every value substituted here came out of make_query: a name from a fixed
    list, integers, timestamps this module formatted, or a provider name that
    matched a narrow pattern."""
    numbers = sorted({n for name in query.levels for n in LEVELS[name]})
    replacements = {
        "__LOG__": query.log,
        "__LEVELS__": ",".join(str(n) for n in numbers),
        "__SINCE__": _iso(query.since),
        "__UNTIL__": _iso(query.until),
        "__PROVIDER__": f"$filter.ProviderName = '{query.provider}'\n" if query.provider else "",
        "__EVENT_ID__": f"$filter.Id = {query.event_id}\n" if query.event_id is not None else "",
        "__MAX__": str(query.max_events),
        "__MESSAGE__": str(MESSAGE_CHARS),
    }
    script = _TEMPLATE
    for marker, value in replacements.items():
        script = script.replace(marker, value)
    return script


def parse(job: dict) -> tuple[list | None, str | None]:
    """(entries, None) or (None, reason). A cut-off or malformed answer is a
    failed query, never a shorter list of events."""
    if job.get("state") != "Completed" or job.get("exitCode") != 0:
        detail = job.get("error") or (job.get("stderr") or "").strip()[:300]
        return None, (f"the query ended {job.get('state')}, exit {job.get('exitCode')}"
                      + (f": {detail}" if detail else ""))
    if job.get("stdoutTruncated"):
        return None, "the result was too large and was cut off; narrow the query"
    try:
        entries = json.loads(job.get("stdout") or "")
    except ValueError:
        return None, "the result was not valid JSON"
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        return None, "the result had an unexpected shape"
    return entries, None

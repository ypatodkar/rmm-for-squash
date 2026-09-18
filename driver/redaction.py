"""Removes credentials from text before it is stored or shown.

Error messages are the usual leak: an upstream service echoes part of the key
it rejected, an exception carries a URL or a header, and the text ends up in
the database and on the dashboard. The brief allows no secrets in logs, stored
output or error messages, so anything that stores upstream text runs it
through here first.

Two layers, because neither alone is enough. Known credential shapes catch
keys this process has never been told about, including a provider's masked
echo of one. Exact configured values catch a secret in any shape, as long as
it is one this process holds.
"""

from __future__ import annotations

import os
import re

REDACTED = "[redacted]"

_PATTERNS = [
    # OpenAI keys, including the masked form a 401 echoes back
    # ("sk-proj-****...abcd").
    re.compile(r"\bsk-[A-Za-z0-9_\-\*\.]{6,}"),
    # This system's own operator keys and enrolment tokens.
    re.compile(r"\bop_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\benr_[A-Za-z0-9_\-]{8,}"),
    # Credentials in headers, however they were quoted.
    re.compile(r"(?i)\b(bearer|x-api-key[\"']?\s*[:=])\s*[\"']?[A-Za-z0-9_\-\.=]{8,}"),
]

# Environment variables whose values are secrets. SQUASH_OPERATOR_KEYS holds
# name:key pairs; only the key half is secret.
_SECRET_VARIABLES = ("OPENAI_API_KEY", "OPEN_AI_API_KEY", "SQUASH_DRIVER_KEY")
# Shorter values would redact ordinary words.
_MIN_SECRET_LENGTH = 8


def configured_secrets() -> list[str]:
    values = [os.environ.get(name, "") for name in _SECRET_VARIABLES]
    for pair in os.environ.get("SQUASH_OPERATOR_KEYS", "").split(","):
        values.append(pair.partition(":")[2])
    # Longest first, so a secret that contains another is removed whole.
    return sorted({v.strip() for v in values if len(v.strip()) >= _MIN_SECRET_LENGTH},
                  key=len, reverse=True)


def redact(text: str | None) -> str | None:
    if not text:
        return text
    for secret in configured_secrets():
        text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text

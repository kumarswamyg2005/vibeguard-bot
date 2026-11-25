"""Public-safe logging (invariants 6 and 7).

Actions logs on a public repo are public. The only things allowed in a log
line are counts, durations and opaque numeric IDs. Two layers enforce that:

- ``public_log`` emits a single line built from whitelisted fields only.
- ``SecretRedactionFilter`` is attached to the root logger and scrubs any
  secret-shaped string that slips through any other logging call.
"""

from __future__ import annotations

import logging
import re
import sys

SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWTs
    re.compile(r"sb_secret_[A-Za-z0-9_\-]+"),
    re.compile(r"sb_publishable_[A-Za-z0-9_\-]+"),
    re.compile(r"sbp_[A-Za-z0-9]+"),
    re.compile(r"postgres(?:ql)?://\S+"),
    re.compile(r"x-access-token:[^@\s]+@"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]*-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"gho_[A-Za-z0-9]+"),
    re.compile(r"ghs_[A-Za-z0-9]+"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
]

REDACTED = "[redacted]"


def redact(text: str) -> str:
    for pat in SECRET_PATTERNS:
        text = pat.sub(REDACTED, text)
    return text


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
            if record.args:
                record.args = tuple(
                    redact(str(a)) if isinstance(a, str) else a for a in record.args
                )
        except Exception:  # noqa: BLE001 - logging must never crash the app
            record.msg = REDACTED
            record.args = ()
        return True


class PublicLogFormatter(logging.Formatter):
    """Invariant 7: only counts, timings and opaque IDs may appear.

    Any message that is not already tagged safe gets collapsed to a generic
    shape. ``public_log`` marks its lines via the ``pub`` extra key.
    """

    def format(self, record: logging.LogRecord) -> str:
        if getattr(record, "pub", False):
            return f"{record.getMessage()}"
        # Untagged logging calls degrade to level + logger name only.
        return f"{record.levelname} {record.name} event"


def configure_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(PublicLogFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    filt = SecretRedactionFilter()
    root.addFilter(filt)
    handler.addFilter(filt)
    return logging.getLogger("vibeguard")


def public_log(logger: logging.Logger, **fields: object) -> None:
    """Emit one public-safe line. Only numeric/simple-whitelisted values."""
    parts = []
    for key, value in fields.items():
        if isinstance(value, bool):
            parts.append(f"{key}={int(value)}")
        elif isinstance(value, int | float) or (
            isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", value)
        ):
            parts.append(f"{key}={value}")
        else:
            parts.append(f"{key}=?")
    logger.info(" ".join(parts), extra={"pub": True})

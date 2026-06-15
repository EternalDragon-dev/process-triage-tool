from __future__ import annotations

import json
from typing import NoReturn

from validation import InputValidationError


def _report(error: dict) -> dict:
    return {"report_type": "sentinel_loop.error.v1", "error": error}


def emit_cli_error(
    *,
    domain: str,
    pretty: bool,
    path: str | None = None,
    exc: Exception | None = None,
) -> NoReturn:
    if isinstance(exc, InputValidationError):
        payload = _report(exc.to_dict())
    elif isinstance(exc, FileNotFoundError):
        path_value = str(exc.filename) if getattr(exc, "filename", None) else path or "unknown"
        payload = _report(
            {
                "code": "INPUT_FILE_NOT_FOUND",
                "domain": domain,
                "message": "Input file was not found.",
                "details": {"path": path_value},
            }
        )
    else:
        payload = _report(
            {
                "code": "UNHANDLED_ERROR",
                "domain": domain,
                "message": str(exc) if exc else "Unknown error.",
            }
        )

    print(json.dumps(payload, indent=2 if pretty else None))
    raise SystemExit(2)

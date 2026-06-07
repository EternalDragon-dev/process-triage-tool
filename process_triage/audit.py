from __future__ import annotations
from collections.abc import Callable
from functools import wraps

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _sanitize_value(value: Any, max_str_len: int = 280, max_items: int = 20) -> Any:
    if isinstance(value, (str, bytes)):
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        if len(text) > max_str_len:
            return f"{text[:max_str_len]}...<truncated:{len(text) - max_str_len}>"
        return text
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for idx, (key, item) in enumerate(value.items()):
            if idx >= max_items:
                sanitized["__truncated_keys__"] = len(value) - max_items
                break
            sanitized[str(key)] = _sanitize_value(item, max_str_len=max_str_len, max_items=max_items)
        return sanitized
    if isinstance(value, list):
        items = [_sanitize_value(v, max_str_len=max_str_len, max_items=max_items) for v in value[:max_items]]
        if len(value) > max_items:
            items.append({"__truncated_items__": len(value) - max_items})
        return items
    if isinstance(value, tuple):
        return _sanitize_value(list(value), max_str_len=max_str_len, max_items=max_items)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def _extract_revised_confidence(result: Any) -> float | None:
    if not isinstance(result, dict):
        return None
    if "confidence_factor" in result and isinstance(result.get("confidence_factor"), (int, float)):
        return round(float(result["confidence_factor"]), 3)
    correction_summary = result.get("correction_summary")
    if isinstance(correction_summary, dict):
        # The loop itself stores the revised average confidence at top-level
        cf = result.get("confidence_factor")
        if isinstance(cf, (int, float)):
            return round(float(cf), 3)
    return None


def _summarize_output(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"output_type": type(result).__name__}
    summary: dict[str, Any] = {"output_type": "dict"}
    if isinstance(result.get("report_type"), str):
        summary["report_type"] = result["report_type"]
    if isinstance(result.get("summary"), dict):
        summary["summary"] = _sanitize_value(result["summary"])
    if isinstance(result.get("triage_summary"), dict):
        summary["triage_summary"] = _sanitize_value(result["triage_summary"])
    if isinstance(result.get("correction_summary"), dict):
        summary["correction_summary"] = _sanitize_value(result["correction_summary"])
    if isinstance(result.get("integrity"), dict):
        summary["integrity"] = _sanitize_value(result["integrity"])
    if isinstance(result.get("confidence_factor"), (int, float)):
        summary["confidence_factor"] = round(float(result["confidence_factor"]), 3)
    return summary


def audit_tool(tool_name: str, reasoning: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger = kwargs.get("audit_logger")
            audit_log_path = kwargs.get("audit_log_path")
            if logger and isinstance(logger, AuditLogger):
                logger.log(
                    "audit_tool_invocation_started",
                    tool=tool_name,
                    reasoning=reasoning,
                    inputs=_sanitize_value(kwargs),
                    started_at_utc=_utc_now_iso(),
                )
            result = func(*args, **kwargs)
            if logger and isinstance(logger, AuditLogger):
                logger.log(
                    "audit_tool_invocation_completed",
                    tool=tool_name,
                    reasoning=reasoning,
                    completed_at_utc=_utc_now_iso(),
                    revised_confidence=_extract_revised_confidence(result),
                    output_summary=_summarize_output(result),
                )
                if isinstance(audit_log_path, str) and audit_log_path:
                    logger.write_jsonl(audit_log_path)
            return result

        return wrapper

    return decorator


class AuditLogger:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.events: list[dict[str, Any]] = []

    def log(self, event_type: str, **details: Any) -> None:
        if not self.enabled:
            return
        self.events.append(
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_utc": _utc_now_iso(),
                "event_type": event_type,
                "details": details,
            }
        )

    def write_jsonl(self, output_path: str) -> None:
        if not self.enabled:
            return
        with open(output_path, "w", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(event))
                handle.write("\n")

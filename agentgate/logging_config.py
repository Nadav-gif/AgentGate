"""
Shared logging configuration for all AgentGate components.

Produces structured JSON logs so they're easy to query in the audit log DB
and readable in the console during development.

Usage in any module:
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Permission check", extra={"user_arn": arn, "action": action})
"""

import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include any extra fields passed via logger.info(..., extra={...})
        for key in ("user_arn", "action", "resource", "decision", "reason", "agent_id", "tool_name"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(level: str = "INFO", json_output: bool = False) -> None:
    """
    Configure logging for the entire application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        json_output: If True, output structured JSON. If False, use readable console format.
    """
    root_logger = logging.getLogger("agentgate")
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers to avoid duplicates on repeated calls
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        ))

    root_logger.addHandler(handler)

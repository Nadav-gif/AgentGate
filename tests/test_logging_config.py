"""Smoke tests for the shared logging configuration."""

import json
import logging

from agentgate.logging_config import setup_logging


def test_setup_logging_console_format(capsys):
    """Console logging produces readable output."""
    setup_logging(level="DEBUG", json_output=False)
    logger = logging.getLogger("agentgate.test")
    logger.info("hello")

    captured = capsys.readouterr()
    assert "hello" in captured.out
    assert "INFO" in captured.out


def test_setup_logging_json_format(capsys):
    """JSON logging produces parseable structured output with extra fields."""
    setup_logging(level="DEBUG", json_output=True)
    logger = logging.getLogger("agentgate.test")
    logger.info("permission check", extra={"user_arn": "arn:aws:iam::123:user/alice", "action": "s3:GetObject"})

    captured = capsys.readouterr()
    log_entry = json.loads(captured.out.strip())

    assert log_entry["message"] == "permission check"
    assert log_entry["user_arn"] == "arn:aws:iam::123:user/alice"
    assert log_entry["action"] == "s3:GetObject"
    assert "timestamp" in log_entry


def test_setup_logging_does_not_duplicate_handlers():
    """Calling setup_logging twice should not create duplicate handlers."""
    setup_logging()
    setup_logging()
    logger = logging.getLogger("agentgate")
    assert len(logger.handlers) == 1

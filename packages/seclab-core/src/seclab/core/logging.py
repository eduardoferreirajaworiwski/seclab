import json
import logging
from datetime import UTC, datetime

_REDACT_KEYS = {
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
    "webhook",
    "authorization",
    "pepper",
    "openai_api_key",
    "discord_webhook_url",
}

_STDLIB_RECORD_KEYS = {
    "args",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


def _redact(key: str, value: object) -> object:
    if any(marker in key.lower() for marker in _REDACT_KEYS):
        return "***REDACTED***"
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _STDLIB_RECORD_KEYS:
                continue
            payload[key] = _redact(key, value)
        return json.dumps(payload, ensure_ascii=True, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())
    root.addHandler(handler)

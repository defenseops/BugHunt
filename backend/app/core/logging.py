"""
Structured logging configuration — Phase 14.3.
Uses structlog with JSON output in production, colored console in dev.
Error logs written to /app/logs/errors.log.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import structlog


def configure_logging() -> None:
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    app_env   = os.getenv("APP_ENV", "development")
    log_dir   = Path(os.getenv("LOG_DIR", "/app/logs"))

    # Ensure log directory exists
    log_dir.mkdir(parents=True, exist_ok=True)

    # Shared processors
    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if app_env == "production":
        # JSON for log aggregators (ELK, Loki, CloudWatch)
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Error file handler
    error_handler = logging.FileHandler(str(log_dir / "errors.log"))
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=shared_processors,
        )
    )

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(error_handler)
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

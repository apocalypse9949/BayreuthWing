"""
BAYREUTHWING — Structured Logger

Configures structured logging with Rich formatting for console output
and optional file logging for audit trails.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class BayreuthWingFormatter(logging.Formatter):
    """Custom formatter with severity-based prefixes."""

    FORMATS = {
        logging.DEBUG: "  [DEB] %(message)s",
        logging.INFO: "  [INF] %(message)s",
        logging.WARNING: "  [WRN] %(message)s",
        logging.ERROR: "  [ERR] %(message)s",
        logging.CRITICAL: "  [CRT] %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


def setup_logger(
    name: str = "bayreuthwing",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Set up a configured logger instance.
    
    Args:
        name: Logger name.
        level: Logging level.
        log_file: Optional file path for log output.
        
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(BayreuthWingFormatter())
    logger.addHandler(console_handler)

    # File handler (if requested)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

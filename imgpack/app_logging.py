"""
Application logging.
"""

import logging
import logging.config
import logging.handlers
import time

import dotsi  # type: ignore

def setup_logging(log_name, settings) -> None:
    """
    Sets up the logging handle.

    Args:
        log_name:   Name for logger
    """

    # Create logger.
    log = logging.getLogger(log_name)
    # Use default logging level from settings.
    log.setLevel(settings.log.DEF_LEVEL)
    # Setup log handler for rotating files.
    handler = logging.handlers.RotatingFileHandler(
        settings.app.APP_NAME + ".log", maxBytes=settings.log.MAX_SIZE,
        backupCount=settings.log.MAX_FILES,
        delay=True
    )
    # Assign formatter to the log handler.
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d [%(name)s] [%(levelname)-s] %(message)s",
            datefmt="%Y%m%d-%H:%M:%S",
            style="%",
        )
    )
    logging.Formatter.converter = time.localtime
    # Add log handler to logger.
    log.addHandler(handler)
    # Set propagate attribute to True to ensure log messages are propagated to the root logger.
    log.propagate = True

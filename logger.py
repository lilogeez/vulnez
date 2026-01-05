import logging
import logging.handlers
import os
from pathlib import Path

LOG_DIR = Path(os.environ.get("VULNEZ_OUTPUT_DIR", "outputs")) / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "vulnez.log"

LEVEL = os.environ.get("VULNEZ_LOG_LEVEL", "INFO").upper()

def get_logger(name: str = "vulnez"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(getattr(logging, LEVEL, logging.INFO))
    fmt = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s')
    sh = logging.StreamHandler()
    sh.setLevel(getattr(logging, LEVEL, logging.INFO))
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = logging.handlers.RotatingFileHandler(str(LOG_FILE), maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    fh.setLevel(getattr(logging, LEVEL, logging.INFO))
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.propagate = False
    return logger

logger = get_logger()

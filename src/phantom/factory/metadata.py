"""
Антифорензик-утилита: подделка временных меток файлов (Time Stomping).
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional

# NEW-L1 fix: имя логгера по конвенции проекта
logger = logging.getLogger("phantom.factory.metadata")

DEFAULT_MIN_DAYS = 10
DEFAULT_MAX_DAYS = 300
DEFAULT_ATIME_OFFSET_MIN = 5
DEFAULT_ATIME_OFFSET_MAX = 300
_MAX_DAYS_CAP = 10000  # NEW-H2 fix: верхняя граница для защиты от overflow


def stomp_timestamp(
    filepath: str,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Применяет технику Anti-Forensics: Time Stomping (подделка временных меток).

    Изменяет время последнего доступа (atime) и модификации (mtime) файла,
    сдвигая их в прошлое.

    Args:
        filepath: Полный или относительный путь к целевому файлу.
        config: Словарь конфигурации с параметрами:
            - min_days_ago (int): Минимальный "возраст" файла в днях.
            - max_days_ago (int): Максимальный "возраст" файла в днях.
            - atime_offset_min (int): Мин. смещение atime от mtime (сек).
            - atime_offset_max (int): Макс. смещение atime от mtime (сек).
    """
    # NEW-L2 fix: Path API вместо os.path
    if not Path(filepath).exists():
        # NEW-H2 fix: %-formatting вместо f-string
        logger.debug("File not found for stomping: %s", filepath)
        return

    cfg = config or {}
    min_days = int(cfg.get("min_days_ago", DEFAULT_MIN_DAYS))
    max_days = int(cfg.get("max_days_ago", DEFAULT_MAX_DAYS))
    atime_min = int(cfg.get("atime_offset_min", DEFAULT_ATIME_OFFSET_MIN))
    atime_max = int(cfg.get("atime_offset_max", DEFAULT_ATIME_OFFSET_MAX))

    # NEW-H2 fix: валидация границ
    min_days = max(0, min(min_days, _MAX_DAYS_CAP))
    max_days = max(min_days, min(max_days, _MAX_DAYS_CAP))
    atime_min = max(0, atime_min)
    atime_max = max(atime_min, atime_max)

    try:
        # NEW-M1 fix: secrets вместо random для непредсказуемости timestomping
        seconds_in_day = 86400
        days_ago = min_days + secrets.randbelow(max_days - min_days + 1)
        noise = secrets.randbelow(seconds_in_day)

        current_time = time.time()
        mtime = current_time - (days_ago * seconds_in_day) - noise

        atime_offset = atime_min + secrets.randbelow(atime_max - atime_min + 1)
        atime = mtime + atime_offset

        os.utime(filepath, (atime, mtime))

        logger.debug("Time stomped: %s -> %d days ago", Path(filepath).name, days_ago)

    except OSError as exc:
        logger.warning("Failed to stomp time for %s: %s", filepath, exc)
    except (ValueError, OverflowError) as exc:
        logger.error("Invalid timestomping parameters for %s: %s", filepath, exc)

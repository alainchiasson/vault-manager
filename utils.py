#!/usr/bin/env python3

import datetime
from typing import Optional


def format_datetime(dt: Optional[datetime.datetime]) -> str:
    """
    Format datetime for display.
    
    Args:
        dt: Datetime object to format
        
    Returns:
        Formatted string or 'Unknown' if None
    """
    if dt is None:
        return "Unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

"""
A lightweight webpage change detection tool using SHA256 hashing.

* `WebhashMonitor`:
    1. Fetch webpage content via HTTP GET
    2. Compute SHA256(content) -> hex digest
    3. Generate database entry: SHA256(url).hash
    4. Compare current hash with stored hash:
    - Match    → [UNCHANGED]
    - Diverge  → [CHANGED]
    - No file  → [FIRST RUN]
    5. Update database entry with current digest and timestamp
* `send_pushbullet_note`, `send_telegram_msg`:
    6. Executes callback (optional)

Author: NenshaM
License: GPL v3
"""

from .WebhashMonitor import WebhashMonitor
from .callbacks import send_pushbullet_note, send_telegram_msg

__all__ = [
    "WebhashMonitor", 
    
    "send_pushbullet_note", "send_telegram_msg"
]

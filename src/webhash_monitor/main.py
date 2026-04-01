#!/usr/bin/env python3
"""
main.py

A secure, lightweight webpage change detection tool using SHA256 hashing.

The application workflow:
    1. Downloads webpage content securely via HTTP(S).
    2. Computes a SHA256 hash of the response body.
    3. Stores the hash locally in a SQLite database.
    4. Detects changes between runs and logs them for auditing.

Configuration is managed using Hydra, supporting flexible CLI and YAML overrides.

Usage Examples:
    python main.py url=http://example.com
    python main.py urls='["http://example.com", "http://example.org"]'

Author: NenshaM
License: GPL v3
"""

from pathlib import Path

import hydra
from omegaconf import DictConfig
from WebhashMonitor import WebhashMonitor


# -----------------------------------------------------------------------------
# Hydra Entry Point
# -----------------------------------------------------------------------------
@hydra.main(
    version_base=None, config_path=str(Path(__file__).parent), config_name="config"
)
def main(cfg: DictConfig) -> None:
    """
    WebHash Monitor CLI entry point.

    Supports monitoring single or multiple URLs with Hydra configuration.
    Instantiates :class:`WebHashMonitor` and delegates to it.

    Config keys:
        options.timeout_seconds  : int
        options.db_path          : str
        options.max_urls         : int
        options.max_retries      : int
        options.max_content_size : int
        request_headers          : dict
        url                      : str (single URL, optional)
        urls                     : list[str] (optional)
    """
    db_path = Path(cfg.options.db_path)
    timeout = cfg.options.timeout_seconds
    headers = cfg.get("request_headers", {})

    monitor = WebhashMonitor(
        db_path=db_path,
        timeout=timeout,
        headers=headers,
        max_urls=cfg.options.max_urls,
        retries=cfg.options.max_retries,
        max_content_size=cfg.options.max_content_size,
    )

    # process callback option
    callback = cfg.get("callback")
    if callback:
        if str(cfg.callback).lower() == "pushbullet":
            from .callbacks import send_pushbullet_note

            callback = send_pushbullet_note
        elif str(cfg.callback).lower() == "telegram":
            from .callbacks import send_telegram_msg

            callback = send_telegram_msg
        else:
            print("Invalid callback: try `pushbullet` or `telegram`")

    # process url(s) and check respective webpage(s) for changes
    if cfg.get("url"):
        monitor.check_website_change(cfg.url, callback=callback)
    elif cfg.get("urls"):
        for u in cfg.urls:
            monitor.check_website_change(url=u, callback=callback)
    else:
        print("No URL provided. Use 'url=' or 'urls=' argument.")


# -----------------------------------------------------------------------------
# Program Execution
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()

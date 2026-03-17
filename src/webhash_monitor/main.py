#!/usr/bin/env python3
"""
main.py

WebHash Monitor v1.2.0

A secure, lightweight webpage change detection tool using SHA256 hashing.

The application workflow:
    1. Downloads webpage content securely via HTTP(S).
    2. Computes a SHA256 hash of the response body.
    3. Stores the hash locally in a configurable directory.
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
from WebhashMonitor import WebHashMonitor


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
        options.hash_dir         : str
        options.max_dir_size     : int
        options.max_urls         : int
        options.max_retries      : int
        options.max_content_size : int
        request_headers          : dict
        url                      : str (single URL, optional)
        urls                     : list[str] (optional)
    """
    hash_dir = Path(cfg.options.hash_dir)
    timeout = cfg.options.timeout_seconds
    headers = cfg.get("request_headers", {})

    monitor = WebHashMonitor(
        hash_dir=hash_dir,
        timeout=timeout,
        headers=headers,
        max_dir_size=cfg.options.max_dir_size,
        max_urls=cfg.options.max_urls,
        retries=cfg.options.max_retries,
        max_content_size=cfg.options.max_content_size,
    )

    if cfg.get("url"):
        monitor.check_website_change(cfg.url)
    elif cfg.get("urls"):
        for u in cfg.urls:
            monitor.check_website_change(u)
    else:
        print("No URL provided. Use 'url=' or 'urls=' argument.")


# -----------------------------------------------------------------------------
# Program Execution
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()

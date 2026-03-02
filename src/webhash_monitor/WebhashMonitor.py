#!/usr/bin/env python3
"""
main.py

WebHash Monitor v1.1.0

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

import hashlib
import logging
from pathlib import Path

import requests

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# WebHashMonitor Class
# -----------------------------------------------------------------------------


class WebHashMonitor:
    """Encapsulates all functionality for monitoring webpage changes.

    The class methods mirror the previous module-level utilities but
    operate against instance configuration (hash directory, timeout,
    headers).  By returning statuses instead of only logging, the
    behaviour is easier to exercise from pytest.
    """

    def __init__(
        self,
        hash_dir: Path,
        timeout: int = 10,
        headers: dict[str, str] | None = None,
    ):
        self.hash_dir = hash_dir
        self.timeout = timeout
        self.headers = headers or {}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def compute_sha256(content: bytes) -> str:
        """Return the SHA256 hex digest of ``content``."""
        return hashlib.sha256(content).hexdigest()

    def generate_hash_path(self, url: str) -> Path:
        """Create a filesystem-safe hash file path for ``url``."""
        url_digest = hashlib.md5(url.encode("utf-8")).hexdigest()
        return self.hash_dir / f"{url_digest}.hash"

    # ------------------------------------------------------------------
    # network
    # ------------------------------------------------------------------
    def fetch_webpage(self, url: str) -> bytes | None:
        """Perform a GET request and return response content or ``None`` on error."""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.content
        except requests.RequestException as e:
            logger.error("Failed to fetch %s: %s", url, e)
            return None

    # ------------------------------------------------------------------
    # high-level monitoring
    # ------------------------------------------------------------------
    def check_website_change(self, url: str) -> str:
        """Check a single ``url`` for changes, update hash file, and return status.

        Possible return values:
            * ``"first_run"``   - no previous hash existed
            * ``"unchanged"``   - hash matches stored value
            * ``"changed"``     - hash differs from stored value
            * ``"fetch_error"`` - the page could not be retrieved
        """
        content = self.fetch_webpage(url)
        if content is None:
            return "fetch_error"

        current_hash = self.compute_sha256(content)
        hash_path = self.generate_hash_path(url)

        self.hash_dir.mkdir(parents=True, exist_ok=True)

        if hash_path.exists():
            stored_hash = hash_path.read_text().strip()
            if stored_hash == current_hash:
                logger.info("[UNCHANGED] %s", url)
                status = "unchanged"
            else:
                logger.warning("[CHANGED] %s", url)
                status = "changed"
        else:
            logger.info("[FIRST RUN] %s", url)
            status = "first_run"

        hash_path.write_text(current_hash)
        return status

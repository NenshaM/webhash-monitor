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

import hashlib
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

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
    """
    Monitor webpages for changes using SHA256 hashing with resource controls.

    The WebHashMonitor class provides a secure, lightweight mechanism to track
    changes to webpages over time. It fetches content, computes a SHA256 hash,
    and stores it locally. On subsequent runs, it compares the current hash to
    the stored one to determine whether a page has changed.

    Usage
    -----
    Initialize the monitor:

        monitor = WebHashMonitor(
            hash_dir=Path("/path/to/hashes"),
            timeout=10,
            headers={"User-Agent": "WebHashMonitor/1.2.0"},
            max_dir_size=50*1024*1024,
            max_urls=1000,
            retries=3,
            max_content_size=50*1024*1024
        )

    Check a single URL:

        status = monitor.check_website_change("https://example.com")
        # status is one of: "first_run", "unchanged", "changed", "fetch_error"

    Check multiple URLs (looping):

        for url in ["https://example.com", "https://example.org"]:
            status = monitor.check_website_change(url)

    Methods
    -------
    - compute_sha256(content: bytes) -> str
        Compute SHA256 hash of given content.
    - generate_hash_path(url: str) -> Path
        Determine the hash file path for a URL.
    - fetch_webpage(url: str) -> bytes | None
        Download a webpage with streaming, retries, and size limits.
    - enforce_url_limit() -> None
        Ensure the number of tracked URLs does not exceed `max_urls`.
    - cleanup_oldest_files() -> None
        Delete oldest hash files to maintain directory size limits.
    - check_website_change(url: str) -> str
        Determine whether a webpage has changed and update stored hash.
    """

    def __init__(
        self,
        hash_dir: Path,
        timeout: int = 10,
        headers: dict[str, str] | None = None,
        max_dir_size: int = 50 * 1024 * 1024,  # 50 MB
        max_urls: int = 1000,
        retries: int = 3,
        max_content_size: int = 50 * 1024 * 1024,  # 50 MB
    ):
        self.hash_dir = hash_dir
        self.timeout = timeout
        self.headers = headers or {}

        self.max_dir_size = max_dir_size
        self.max_urls = max_urls
        self.retries = retries
        self.max_content_size = max_content_size

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def compute_sha256(content: bytes) -> str:
        """
        Compute the SHA256 hash of the given content.

        Parameters
        ----------
        content : bytes
            The raw content to hash.

        Returns
        -------
        str
            Hexadecimal SHA256 digest of the content.

        Notes
        -----
        - The content is fully buffered in memory before hashing.
        - For very large content, consider streaming-based hashing.
        """
        return hashlib.sha256(content).hexdigest()

    def generate_hash_path(self, url: str) -> Path:
        """
        Generate a filesystem-safe path for storing a hash for a URL.

        Parameters
        ----------
        url : str
            The URL for which to generate the hash file path.

        Returns
        -------
        Path
            The path within `hash_dir` where the SHA256 hash of the URL is stored.

        Notes
        -----
        - Uses SHA256(url) as the filename to avoid unsafe characters.
        - Ensures deterministic mapping: same URL - same path.
        """
        url_digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.hash_dir / f"{url_digest}.hash"

    # ------------------------------------------------------------------
    # network
    # ------------------------------------------------------------------
    def fetch_webpage(self, url: str) -> bytes | None:
        """
        Fetch the content of a webpage with retries and resource limits.

        Parameters
        ----------
        url : str
            The webpage URL to fetch.

        Returns
        -------
        bytes | None
            The full content of the page, or None if the fetch failed.

        Raises
        ------
        ValueError
            If the response exceeds `max_content_size`.

        Notes
        -----
        - Enforces a maximum content size to prevent memory exhaustion.
        - Retries requests up to `self.retries` times with incremental backoff.
        - Logs a warning for non-HTTPS URLs.
        - Sanitizes the URL to prevent log injection (\n, \r removed).
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            logger.warning("Non-HTTPS URL: %s", url)

        # prohibit logging injection
        url = url.replace("\n", "").replace("\r", "").strip()
        try:
            for attempt in range(1, self.retries + 1):
                try:
                    response = requests.get(
                        url, headers=self.headers, timeout=self.timeout, stream=True
                    )
                    response.raise_for_status()

                    content = b""
                    for chunk in response.iter_content(4096):
                        content += chunk
                        if len(content) > self.max_content_size:
                            raise ValueError("Response too large")

                        return content

                except (requests.RequestException, ValueError):
                    if attempt == self.retries:
                        raise
                    else:
                        time.sleep(0.5 * attempt)

        except (requests.RequestException, ValueError) as e:
            logger.error("Failed to fetch %s: %s", url, e)
            return None

    # ------------------------------------------------------------------
    # high-level monitoring
    # ------------------------------------------------------------------
    def enforce_url_limit(self):
        """
        Ensure the number of tracked URLs does not exceed `max_urls`.

        Raises
        ------
        RuntimeError
            If the current number of hash files is >= `max_urls`.

        Notes
        -----
        - Only counts `.hash` files in `hash_dir`.
        """
        existing_files = list(self.hash_dir.glob("*.hash"))
        if len(existing_files) >= self.max_urls:
            raise RuntimeError("Maximum number of tracked URLs reached")

    def cleanup_oldest_files(self):
        """
        Remove oldest hash files to ensure `hash_dir` does not exceed `max_dir_size`.

        Notes
        -----
        - Oldest files are determined by filesystem modification time (mtime).
        - Deletes files until total directory size <= `max_dir_size`.
        - Logs a warning if cleanup is triggered.
        - Updates total size decrementally to avoid repeated rescans.
        """
        files = sorted(self.hash_dir.glob("*.hash"), key=lambda f: f.stat().st_mtime)

        total_size = sum(f.stat().st_size for f in files)

        if total_size > self.max_dir_size and files:
            logger.warning("Maximal directory size reached. Cleaning up old files")

        while total_size > self.max_dir_size and files:
            oldest = files.pop(0)
            logger.warning(f"Cleaning up {oldest}")
            size = oldest.stat().st_size
            oldest.unlink()
            total_size -= size

    def check_website_change(self, url: str) -> str:
        """
        Check if a webpage has changed since the last run and update its hash.

        Parameters
        ----------
        url : str
            The webpage URL to monitor.

        Returns
        -------
        str
            Status of the page after comparison:
            - "first_run"   → URL was not previously tracked.
            - "unchanged"   → Content has not changed since last run.
            - "changed"     → Content has changed since last run.
            - "fetch_error" → Page could not be retrieved.

        Notes
        -----
        - Fetches the page content with `fetch_webpage()`.
        - Computes SHA256 hash of the page.
        - Cleans up old hash files if directory exceeds `max_dir_size`.
        - Enforces `max_urls` before creating a new hash file.
        - Logs changes (first run, changed, unchanged) for auditing.
        """
        content = self.fetch_webpage(url)
        if content is None:
            return "fetch_error"

        current_hash = self.compute_sha256(content)
        hash_path = self.generate_hash_path(url)

        self.hash_dir.mkdir(parents=True, exist_ok=True)

        self.cleanup_oldest_files()
        self.enforce_url_limit()

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

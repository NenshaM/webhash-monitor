#!/usr/bin/env python3
"""
WbhashMonitor.py

WebHash Monitor v1.3.0

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

import hashlib
import logging
import sqlite3
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
            db_path=Path("/path/to/database"),
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
    - fetch_webpage(url: str) -> bytes | None
        Download a webpage with streaming, retries, and size limits.
    - cleanup_oldest_entries() -> None
        Ensure the number of tracked URLs does not exceed `max_urls`.
    - check_website_change(url: str) -> str
        Determine whether a webpage has changed and update stored hash.
    """

    def __init__(
        self,
        db_path: Path,
        timeout: int = 10,
        headers: dict[str, str] | None = None,
        max_urls: int = 1000,
        retries: int = 3,
        max_content_size: int = 50 * 1024 * 1024,  # 50 MB
    ):
        self.db_path = db_path
        self.timeout = timeout
        self.headers = headers or {}

        self.max_urls = max_urls
        self.retries = retries
        self.max_content_size = max_content_size

        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                    CREATE TABLE IF NOT EXISTS hashes (
                    url_hash PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def compute_sha256(content: bytes | str) -> str:
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
        if isinstance(content, str):
            return hashlib.sha256(content.encode("utf-8")).hexdigest()

        return hashlib.sha256(content).hexdigest()

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
    def cleanup_oldest_entries(self, conn: sqlite3.Connection) -> None:
        """
        Remove oldest hash files to ensure a maximum number of `max_urls`.

        Parameters
        ----------
        conn : Connection
            SQLite database connection

        """
        cur = conn.execute("SELECT COUNT(*) FROM hashes")
        count = cur.fetchone()[0]

        if count <= self.max_urls:
            return

        to_delete = count - self.max_urls

        logger.warning("Cleaning up %d old entries", to_delete)

        conn.execute(
            """
                DELETE FROM hashes
                WHERE url_hash IN (
                    SELECT url_hash FROM hashes
                    ORDER BY last_updated ASC
                    LIMIT ?
                )
            """,
            (to_delete,),
        )

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
        """
        content = self.fetch_webpage(url)
        if content is None:
            return "fetch_error"

        current_hash = self.compute_sha256(content)
        url_hash = self.compute_sha256(url)

        with sqlite3.connect(self.db_path) as conn:
            self.cleanup_oldest_entries(conn)

            cur = conn.execute(
                """
                    SELECT content_hash FROM hashes WHERE url_hash = ? LIMIT 1
                """,
                (url_hash,),
            )
            row = cur.fetchone()

            if row:
                if row[0] == current_hash:
                    logger.info("[UNCHANGED] %s", url)
                    status = "unchanged"
                else:
                    logger.warning("[CHANGED] %s", url)
                    status = "changed"

                conn.execute(
                    """
                        UPDATE hashes
                        SET content_hash = ?, last_updated = CURRENT_TIMESTAMP
                        WHERE url_hash = ?
                    """,
                    (current_hash, url_hash),
                )

            else:
                logger.info("[FIRST RUN] %s", url)
                status = "first_run"

                conn.execute(
                    """
                        INSERT INTO hashes (url_hash, content_hash)
                        VALUES (?, ?)
                    """,
                    (url_hash, current_hash),
                )

        return status

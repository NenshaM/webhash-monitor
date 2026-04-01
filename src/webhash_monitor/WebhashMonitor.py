#!/usr/bin/env python3
"""
WebhashMonitor.py

A lightweight webpage change detection tool using SHA256 hashing.

The workflow:
    1. Fetch webpage content via HTTP GET
    2. Compute SHA256(content) -> hex digest
    3. Generate database entry: SHA256(url).hash
    4. Compare current hash with stored hash:
        - Match    → [UNCHANGED]
        - Diverge  → [CHANGED]
        - No file  → [FIRST RUN]
    5. Update database entry with current digest and timestamp

Author: NenshaM
License: GPL v3
"""

import hashlib
import logging
import sqlite3
import time
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

import requests


# -----------------------------------------------------------------------------
# WebHashMonitor Webpage Status
# -----------------------------------------------------------------------------
class Status(Enum):
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    FIRST_RUN = "first_run"
    FETCH_ERROR = "fetch_error"


# -----------------------------------------------------------------------------
# WebHashMonitor Class
# -----------------------------------------------------------------------------
class WebhashMonitor:
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

        self.logger = self._init_logger()
        self._init_db()

    def _init_logger(self) -> logging.Logger:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
        return logging.getLogger(self.__class__.__name__)

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
            self.logger.warning("Non-HTTPS URL: %s", url)

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
            self.logger.error("Failed to fetch %s: %s", url, e)
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

        self.logger.warning("Cleaning up %d old entries", to_delete)

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

    def check_website_change(
        self, url: str, callback: Callable | None = None
    ) -> Status:
        """
        Check if a webpage has changed since the last run and update its hash.

        Parameters
        ----------
        url : str
            The webpage URL to monitor.
        callback: Callable, optional
            Callback function which gets executed if status is `Status.CHANGED`

        Returns
        -------
        Status
            Status of the page after comparison:
            - Status.FIRST_RUN   → URL was not previously tracked.
            - Status.UNCHANGED   → Content has not changed since last run.
            - Status.CHANGED     → Content has changed since last run.
            - Status.FETCH_ERROR → Page could not be retrieved.
        """
        content = self.fetch_webpage(url)
        if content is None:
            return Status.FETCH_ERROR

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
                    self.logger.info("[UNCHANGED] %s", url)
                    status = Status.UNCHANGED
                else:
                    self.logger.warning("[CHANGED] %s", url)
                    status = Status.CHANGED

                conn.execute(
                    """
                        UPDATE hashes
                        SET content_hash = ?, last_updated = CURRENT_TIMESTAMP
                        WHERE url_hash = ?
                    """,
                    (current_hash, url_hash),
                )

            else:
                self.logger.info("[FIRST RUN] %s", url)
                status = Status.FIRST_RUN

                conn.execute(
                    """
                        INSERT INTO hashes (url_hash, content_hash)
                        VALUES (?, ?)
                    """,
                    (url_hash, current_hash),
                )

        if status == Status.CHANGED and isinstance(callback, Callable):
            try:
                callback(url)
            except Exception as e:
                self.logger.error(f"Callback failed ({e})")

        return status

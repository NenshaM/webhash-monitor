#!/usr/bin/env python3
"""
main.py

WebHash Monitor v1.0.0

A secure, lightweight webpage change detection tool using SHA256 hashing.

The application workflow:
    1. Downloads webpage content securely via HTTP(S).
    2. Computes a SHA256 hash of the response body.
    3. Stores the hash locally in a configurable directory.
    4. Detects changes between runs and logs them for auditing.

Configuration is managed using Hydra, supporting flexible CLI and YAML overrides.

Usage Examples:
    python main.py url=https://example.com
    python main.py urls='["https://example.com", "https://example.org"]'

Author: NenshaM
License: GPL v3
"""

import hashlib
import logging
from pathlib import Path

import requests
import hydra
from omegaconf import DictConfig

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def compute_sha256(content: bytes) -> str:
    """
    Compute the SHA256 hash of raw bytes.

    Args:
        content: Raw byte content of the webpage.

    Returns:
        Hexadecimal SHA256 digest string.
    """
    return hashlib.sha256(content).hexdigest()


def generate_hash_path(url: str, hash_dir: Path) -> Path:
    """
    Generate a filesystem-safe path to store a hash for a URL.

    Uses MD5 digest of the URL to create a unique, reproducible filename.

    Args:
        url: Webpage URL.
        hash_dir: Directory in which to store hash files.

    Returns:
        Path object pointing to the hash file.
    """
    url_digest = hashlib.md5(url.encode("utf-8")).hexdigest()
    return hash_dir / f"{url_digest}.hash"


def fetch_webpage(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 10
) -> bytes | None:
    """
    Fetch webpage content using a secure GET request.

    Args:
        url: Webpage URL.
        headers: Optional HTTP headers to use.
        timeout: Request timeout in seconds.

    Returns:
        Raw response bytes if successful, None if an error occurs.
    """
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        logger.error("Failed to fetch %s: %s", url, e)
        return None


def check_website_change(
    url: str,
    hash_dir: Path,
    headers: dict[str, str] | None = None,
    timeout: int = 10
) -> None:
    """
    Detect whether a webpage has changed since the last run.

    This function:
        - Fetches the page content.
        - Computes its SHA256 hash.
        - Compares it against the stored hash.
        - Logs whether the page is unchanged, changed, or a first run.
        - Updates the stored hash.

    Args:
        url: Webpage URL to monitor.
        hash_dir: Directory for storing hashes.
        headers: Optional HTTP headers for the request.
        timeout: HTTP request timeout in seconds.
    """
    content = fetch_webpage(url, headers=headers, timeout=timeout)
    if content is None:
        return

    current_hash = compute_sha256(content)
    hash_path = generate_hash_path(url, hash_dir)

    hash_dir.mkdir(parents=True, exist_ok=True)

    if hash_path.exists():
        stored_hash = hash_path.read_text().strip()
        if stored_hash == current_hash:
            logger.info("[UNCHANGED] %s", url)
        else:
            logger.warning("[CHANGED] %s", url)
    else:
        logger.info("[FIRST RUN] %s", url)

    hash_path.write_text(current_hash)


# -----------------------------------------------------------------------------
# Hydra Entry Point
# -----------------------------------------------------------------------------
@hydra.main(
    version_base=None,
    config_path=str(Path(__file__).parent),
    config_name="config"
)
def main(cfg: DictConfig) -> None:
    """
    WebHash Monitor CLI entry point.

    Supports monitoring single or multiple URLs with Hydra configuration.

    Config keys:
        options.timeout_seconds : int
        options.hash_dir        : str
        request_headers         : dict
        url                     : str (single URL, optional)
        urls                    : list[str] (optional)

    CLI Examples:
        python main.py url=https://example.com
        python main.py urls='["https://a.com", "https://b.com"]'
    """
    hash_dir = Path(cfg.options.hash_dir)
    timeout = cfg.options.timeout_seconds
    headers = cfg.get("request_headers", {})

    if cfg.get("url"):
        check_website_change(
            cfg.url,
            hash_dir=hash_dir,
            headers=headers,
            timeout=timeout
        )
    elif cfg.get("urls"):
        for u in cfg.urls:
            check_website_change(
                u,
                hash_dir=hash_dir,
                headers=headers,
                timeout=timeout
            )
    else:
        logger.error("No URL provided. Use 'url=' or 'urls=' argument.")


# -----------------------------------------------------------------------------
# Program Execution
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
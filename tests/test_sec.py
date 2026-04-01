import sqlite3
import time

import pytest

from webhash_monitor.WebhashMonitor import WebhashMonitor


@pytest.fixture
def tmp_hash_db(tmp_path):
    """Provide a temporary directory used as the hash storage."""
    return tmp_path / "hashes.db"


def test_cleanup_oldest_entries(tmp_hash_db):
    monitor = WebhashMonitor(tmp_hash_db, max_urls=2)

    # insert 3 entries with increasing timestamps
    with sqlite3.connect(tmp_hash_db) as conn:
        monitor._init_db()

        for i in range(3):
            conn.execute(
                "INSERT INTO hashes (url_hash, content_hash, last_updated) "
                "VALUES (?, ?, CURRENT_TIMESTAMP)",
                (f"hash{i}", f"content{i}"),
            )
            time.sleep(1)  # ensure ordering

        monitor.cleanup_oldest_entries(conn)

        rows = conn.execute("SELECT url_hash FROM hashes").fetchall()

    urls = {row[0] for row in rows}

    # only 2 entries should remain
    assert len(urls) == 2

    # oldest (http://0) should be gone
    assert "http://0" not in urls

import time

import pytest

from webhash_monitor.WebhashMonitor import WebHashMonitor


@pytest.fixture
def tmp_hash_dir(tmp_path):
    """Provide a temporary directory used as the hash storage."""
    return tmp_path / "hashes"


def test_cleanup_oldest_files(tmp_hash_dir):
    monitor = WebHashMonitor(tmp_hash_dir, max_dir_size=15)
    tmp_hash_dir.mkdir(parents=True)
    # create three files of 10 bytes each
    for i in range(3):
        p = tmp_hash_dir / f"{i}.hash"
        p.write_text("1234567890")
        time.sleep(1)

    monitor.cleanup_oldest_files()
    remaining = list(tmp_hash_dir.glob("*.hash"))
    total_size = sum(f.stat().st_size for f in remaining)
    assert total_size <= 15
    # oldest file should be deleted
    assert (tmp_hash_dir / "0.hash").exists() is False


def test_enforce_url_limit(tmp_hash_dir):
    monitor = WebHashMonitor(tmp_hash_dir, max_urls=2)
    tmp_hash_dir.mkdir(parents=True)
    # create two dummy hash files
    for i in range(2):
        (tmp_hash_dir / f"{i}.hash").write_text("abc")

    with pytest.raises(RuntimeError):
        monitor.enforce_url_limit()

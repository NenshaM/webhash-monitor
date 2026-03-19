import hashlib
import sqlite3

import pytest
import requests

from webhash_monitor.WebhashMonitor import Status, WebHashMonitor


class DummyResponse:
    def __init__(self, content: bytes, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code != 200:
            raise requests.HTTPError("bad status")

    def iter_content(self, chunk_size: int = 4096):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i : i + chunk_size]


@pytest.fixture
def tmp_hash_db(tmp_path):
    """Provide a temporary directory used as the hash storage."""
    return tmp_path / "hashes.db"


def test_compute_sha256():
    data = b"hello"
    expected = hashlib.sha256(data).hexdigest()
    assert WebHashMonitor.compute_sha256(data) == expected


def test_fetch_webpage_success(monkeypatch, tmp_hash_db):
    monitor = WebHashMonitor(tmp_hash_db)
    content = b"abc"

    def fake_get(url, headers, timeout, stream):
        return DummyResponse(content)

    monkeypatch.setattr(requests, "get", fake_get)
    assert monitor.fetch_webpage("http://foo") == content


def test_fetch_webpage_failure(monkeypatch, caplog, tmp_hash_db):
    monitor = WebHashMonitor(tmp_hash_db)

    def fake_get(url, headers, timeout, stream):
        raise requests.RequestException("fail")

    monkeypatch.setattr(requests, "get", fake_get)
    caplog.set_level("ERROR")
    assert monitor.fetch_webpage("http://foo") is None
    assert "Failed to fetch" in caplog.text


def test_check_website_change_first_run(tmp_hash_db, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_db)
    content = b"first content"
    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: content)

    url = "http://a"
    url_hash = monitor.compute_sha256(url)
    status = monitor.check_website_change(url)
    assert status == Status.FIRST_RUN

    # verify DB entry
    with sqlite3.connect(tmp_hash_db) as conn:
        row = conn.execute(
            "SELECT content_hash FROM hashes WHERE url_hash = ?", (url_hash,)
        ).fetchone()

    assert row is not None
    assert row[0] == WebHashMonitor.compute_sha256(content)


def test_check_website_change_unchanged(tmp_hash_db, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_db)

    content = b"same"
    url = "http://a"

    # pre-insert existing hash
    with sqlite3.connect(tmp_hash_db) as conn:
        monitor._init_db()
        conn.execute(
            "INSERT INTO hashes (url_hash, content_hash) VALUES (?, ?)",
            (monitor.compute_sha256(url), WebHashMonitor.compute_sha256(content)),
        )

    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: content)

    status = monitor.check_website_change(url)
    assert status == Status.UNCHANGED


def test_check_website_change_changed(tmp_hash_db, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_db)

    old = b"old"
    new = b"new"
    url = "http://a"

    # pre-insert old hash
    with sqlite3.connect(tmp_hash_db) as conn:
        monitor._init_db()
        conn.execute(
            "INSERT INTO hashes (url_hash, content_hash) VALUES (?, ?)",
            (monitor.compute_sha256(url), WebHashMonitor.compute_sha256(old)),
        )

    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: new)

    status = monitor.check_website_change(url)
    url_hash = monitor.compute_sha256(url)
    assert status == Status.CHANGED

    # verify DB updated
    with sqlite3.connect(tmp_hash_db) as conn:
        row = conn.execute(
            "SELECT content_hash FROM hashes WHERE url_hash = ?", (url_hash,)
        ).fetchone()

    assert row[0] == WebHashMonitor.compute_sha256(new)


def test_check_website_change_fetch_error(tmp_hash_db, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_db)
    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: None)
    status = monitor.check_website_change("http://a")
    assert status == Status.FETCH_ERROR


def test_check_website_onchange_callback(tmp_hash_db, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_db)

    old = b"old"
    new = b"new"
    url = "http://a"

    # pre-insert old hash
    with sqlite3.connect(tmp_hash_db) as conn:
        monitor._init_db()
        conn.execute(
            "INSERT INTO hashes (url_hash, content_hash) VALUES (?, ?)",
            (monitor.compute_sha256(url), WebHashMonitor.compute_sha256(old)),
        )

    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: new)

    cb_successful = False

    def callback(url: str):
        nonlocal cb_successful
        cb_successful = True

    status = monitor.check_website_change(url=url, callback=callback)
    assert status == Status.CHANGED
    assert cb_successful

    cb_successful = False
    status = monitor.check_website_change(url=url, callback=callback)
    assert status == Status.UNCHANGED
    assert not cb_successful

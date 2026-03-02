import hashlib
from pathlib import Path

import pytest
import requests

from webhash_monitor.WebhashMonitor import WebHashMonitor


class DummyResponse:
    def __init__(self, content: bytes, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code != 200:
            raise requests.HTTPError("bad status")


@pytest.fixture
def tmp_hash_dir(tmp_path):
    """Provide a temporary directory used as the hash storage."""
    return tmp_path / "hashes"


def test_compute_sha256():
    data = b"hello"
    expected = hashlib.sha256(data).hexdigest()
    assert WebHashMonitor.compute_sha256(data) == expected


def test_generate_hash_path(tmp_hash_dir):
    monitor = WebHashMonitor(tmp_hash_dir)
    url = "http://example.com"
    p = monitor.generate_hash_path(url)
    assert p.parent == tmp_hash_dir
    assert p.suffix == ".hash"
    assert len(p.name) > len(".hash")


def test_fetch_webpage_success(monkeypatch):
    monitor = WebHashMonitor(Path("/does/not/matter"))
    content = b"abc"

    def fake_get(url, headers, timeout):
        return DummyResponse(content)

    monkeypatch.setattr(requests, "get", fake_get)
    assert monitor.fetch_webpage("http://foo") == content


def test_fetch_webpage_failure(monkeypatch, caplog):
    monitor = WebHashMonitor(Path("/tmp"))

    def fake_get(url, headers, timeout):
        raise requests.RequestException("fail")

    monkeypatch.setattr(requests, "get", fake_get)
    caplog.set_level("ERROR")
    assert monitor.fetch_webpage("http://foo") is None
    assert "Failed to fetch" in caplog.text


def test_check_website_change_first_run(tmp_hash_dir, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_dir)
    content = b"first content"
    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: content)

    status = monitor.check_website_change("http://a")
    assert status == "first_run"
    # hash file created correctly
    path = monitor.generate_hash_path("http://a")
    assert path.exists()
    assert path.read_text() == WebHashMonitor.compute_sha256(content)


def test_check_website_change_unchanged(tmp_hash_dir, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_dir)
    content = b"same"
    # prepare existing hash file
    path = monitor.generate_hash_path("http://a")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(WebHashMonitor.compute_sha256(content))

    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: content)
    status = monitor.check_website_change("http://a")
    assert status == "unchanged"


def test_check_website_change_changed(tmp_hash_dir, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_dir)
    old = b"old"
    new = b"new"
    path = monitor.generate_hash_path("http://a")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(WebHashMonitor.compute_sha256(old))

    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: new)
    status = monitor.check_website_change("http://a")
    assert status == "changed"


def test_check_website_change_fetch_error(tmp_hash_dir, monkeypatch):
    monitor = WebHashMonitor(tmp_hash_dir)
    monkeypatch.setattr(monitor, "fetch_webpage", lambda url: None)
    status = monitor.check_website_change("http://a")
    assert status == "fetch_error"

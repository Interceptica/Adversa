"""Tests for ArtifactStore — write/read roundtrip, existence, isolation."""
from __future__ import annotations

import pytest

from src.artifacts.store import ArtifactStore


def test_write_read_roundtrip(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    data = {"key": "value", "nested": {"a": 1}}

    path = store.write("TEST_ARTIFACT", data)

    assert path.exists()
    assert store.read("TEST_ARTIFACT") == data


def test_exists_returns_false_when_missing(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    assert store.exists("NONEXISTENT") is False


def test_exists_returns_true_after_write(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    store.write("MY_ARTIFACT", {"x": 1})
    assert store.exists("MY_ARTIFACT") is True


def test_read_missing_raises_file_not_found(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    with pytest.raises(FileNotFoundError):
        store.read("MISSING")


def test_creates_directories_on_write(tmp_path):
    store = ArtifactStore("eng-deep/nested", base_dir=str(tmp_path))
    store.write("DATA", {"ok": True})
    assert store.read("DATA") == {"ok": True}


def test_engagement_isolation(tmp_path):
    store_a = ArtifactStore("eng-a", base_dir=str(tmp_path))
    store_b = ArtifactStore("eng-b", base_dir=str(tmp_path))

    store_a.write("SHARED_NAME", {"from": "a"})
    store_b.write("SHARED_NAME", {"from": "b"})

    assert store_a.read("SHARED_NAME") == {"from": "a"}
    assert store_b.read("SHARED_NAME") == {"from": "b"}


def test_overwrite_existing_artifact(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    store.write("DATA", {"version": 1})
    store.write("DATA", {"version": 2})
    assert store.read("DATA") == {"version": 2}

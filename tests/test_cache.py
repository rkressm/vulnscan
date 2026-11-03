"""Offline cache persistence and expiry tests using a controllable clock."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depscan.cache import LookupCache
from depscan.models import Advisory, FailedLookup, PackageVersion, SuccessfulLookup
from depscan.osv import lookup_packages

NOW = datetime(2026, 11, 3, tzinfo=UTC)
PACKAGE = PackageVersion(name="demo-pkg", version="1")


def success(*, vulnerable: bool = False) -> SuccessfulLookup:
    advisories = (
        (Advisory(identifier="TEST-1", severity="HIGH", url="https://osv.dev/TEST-1"),)
        if vulnerable
        else ()
    )
    return SuccessfulLookup(package=PACKAGE, advisories=advisories, looked_up_at=NOW)


@pytest.mark.parametrize("vulnerable", [False, True])
def test_persist_successes(tmp_path: Path, vulnerable: bool) -> None:
    path = tmp_path / "nested" / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW)
    result = success(vulnerable=vulnerable)
    cache.put(result)
    cache.save()

    reloaded = LookupCache(path, clock=lambda: NOW + timedelta(hours=23))
    assert reloaded.get(PACKAGE) == result
    assert reloaded.get(PackageVersion(name="Demo_Pkg", version="1")) is not None
    assert reloaded.get(PackageVersion(name="demo-pkg", version="2")) is None
    data = json.loads(path.read_text(encoding="utf-8"))
    key = next(iter(data["entries"]))
    assert json.loads(key) == ["PyPI", "demo-pkg", "1"]


@pytest.mark.parametrize(
    ("age", "fresh"),
    [
        (timedelta(0), True),
        (timedelta(hours=24, microseconds=-1), True),
        (timedelta(hours=24), False),
        (timedelta(days=2), False),
        (timedelta(seconds=-1), False),
    ],
)
def test_expiry(tmp_path: Path, age: timedelta, fresh: bool) -> None:
    cache = LookupCache(tmp_path / "osv.json", clock=lambda: NOW + age)
    cache.put(success())
    assert (cache.get(PACKAGE) is not None) is fresh


@pytest.mark.parametrize(
    "contents",
    [
        "not JSON",
        "[]",
        '{"schema_version": 99, "entries": {}}',
        '{"entries": {"bad": {"status": "failed"}}}',
        "\xff",
    ],
)
def test_corrupt_file_recovers(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "osv.json"
    path.write_bytes(contents.encode("latin-1"))
    cache = LookupCache(path, clock=lambda: NOW)
    assert cache.get(PACKAGE) is None
    cache.put(success())
    cache.save()
    assert LookupCache(path, clock=lambda: NOW).get(PACKAGE) == success()


def test_mismatched_key_and_missing_or_naive_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW)
    cache.put(success())
    cache.save()
    original = json.loads(path.read_text(encoding="utf-8"))
    key = next(iter(original["entries"]))
    for timestamp in [None, "2026-11-03T00:00:00"]:
        original["entries"][key]["looked_up_at"] = timestamp
        path.write_text(json.dumps(original), encoding="utf-8")
        assert LookupCache(path, clock=lambda: NOW).get(PACKAGE) is None
    original["entries"][key] = success().model_dump(mode="json")
    original["entries"][key]["package"]["version"] = "2"
    path.write_text(json.dumps(original), encoding="utf-8")
    assert LookupCache(path, clock=lambda: NOW).get(PACKAGE) is None


def test_atomic_write_failure_preserves_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW)
    cache.put(success())
    cache.save()
    previous = path.read_bytes()
    cache.put(success(vulnerable=True))

    def fail_replace(source: Path, destination: Path) -> None:
        assert json.loads(source.read_text(encoding="utf-8"))["entries"]
        assert destination.read_bytes() == previous
        raise OSError("disk failure")

    monkeypatch.setattr("depscan.cache.os.replace", fail_replace)
    cache.save()
    assert path.read_bytes() == previous
    assert list(tmp_path.iterdir()) == [path]


def test_unusable_cache_directory_is_optional(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("blocked", encoding="utf-8")
    cache = LookupCache(parent / "osv.json", clock=lambda: NOW)
    assert cache.get(PACKAGE) is None
    cache.put(success())
    cache.save()
    assert parent.read_text(encoding="utf-8") == "blocked"


def test_hits_skip_network_and_expired_failures_never_use_stale_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = NOW
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: now)
    cache.put(success(vulnerable=True))
    cache.save()
    post = MagicMock()
    post.return_value.__enter__.return_value = post.return_value
    post.return_value.status_code = 503
    monkeypatch.setattr("depscan.osv.requests.post", post)

    assert lookup_packages([PACKAGE, PACKAGE], cache=cache) == [
        success(vulnerable=True)
    ]
    post.assert_not_called()
    now += timedelta(hours=24)
    assert isinstance(lookup_packages([PACKAGE], cache=cache)[0], FailedLookup)
    assert isinstance(lookup_packages([PACKAGE], cache=cache)[0], FailedLookup)
    assert post.call_count == 2
    assert LookupCache(path, clock=lambda: NOW).get(PACKAGE) == success(vulnerable=True)


def test_expired_success_is_refreshed_and_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW + timedelta(hours=24))
    cache.put(success(vulnerable=True))
    cache.save()
    post = MagicMock()
    post.return_value.__enter__.return_value = post.return_value
    post.return_value.status_code = 200
    post.return_value.json.return_value = {}
    monkeypatch.setattr("depscan.osv.requests.post", post)
    clock = MagicMock()
    clock.now.return_value = NOW + timedelta(hours=24)
    monkeypatch.setattr("depscan.osv.datetime", clock)

    results = lookup_packages([PACKAGE, PACKAGE], cache=cache)
    post.assert_called_once()
    result = results[0]
    assert isinstance(result, SuccessfulLookup)
    assert result.advisories == ()
    assert result.looked_up_at is not None
    assert result.looked_up_at == NOW + timedelta(hours=24)
    assert (
        LookupCache(path, clock=lambda: result.looked_up_at or NOW).get(PACKAGE)
        == result
    )

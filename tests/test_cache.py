"""Offline cache persistence and expiry tests using a controllable clock."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depscan.cache import LookupCache
from depscan.cli import main
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
    assert data["schema_version"] == 2
    key = next(iter(data["entries"]))
    assert json.loads(key) == ["PyPI", "demo-pkg", "1"]


def test_ecosystems_have_independent_persisted_entries(tmp_path: Path) -> None:
    path = tmp_path / "osv.json"
    python = PackageVersion(name="demo", version="1.2.3")
    javascript = PackageVersion(ecosystem="npm", name="demo", version="1.2.3")
    python_result = success(vulnerable=True).model_copy(update={"package": python})
    javascript_result = success().model_copy(update={"package": javascript})
    cache = LookupCache(path, clock=lambda: NOW)
    cache.put(python_result)
    assert cache.get(javascript) is None
    cache.put(javascript_result)
    cache.save()

    reloaded = LookupCache(path, clock=lambda: NOW)
    assert reloaded.get(python) == python_result
    assert reloaded.get(javascript) == javascript_result
    assert len(json.loads(path.read_text(encoding="utf-8"))["entries"]) == 2


def test_npm_punctuation_scopes_and_case_remain_distinct(tmp_path: Path) -> None:
    path = tmp_path / "osv.json"
    names = ["demo.pkg", "demo_pkg", "demo-pkg", "@scope/demo.pkg", "Demo.pkg"]
    cache = LookupCache(path, clock=lambda: NOW)
    results = []
    for name in names:
        package = PackageVersion(ecosystem="npm", name=name, version="1.2.3")
        result = SuccessfulLookup(
            package=package,
            advisories=(
                Advisory(identifier=name, severity="UNKNOWN", url="https://osv.dev/"),
            ),
            looked_up_at=NOW,
        )
        results.append(result)
        cache.put(result)
    cache.save()

    reloaded = LookupCache(path, clock=lambda: NOW)
    for result in results:
        assert reloaded.get(result.package) == result
    keys = json.loads(path.read_text(encoding="utf-8"))["entries"]
    assert sorted(json.loads(key) for key in keys) == sorted(
        ["npm", name, "1.2.3"] for name in names
    )


@pytest.mark.parametrize("schema_version", [None, 1, 99])
def test_legacy_and_unversioned_caches_are_invalidated(
    tmp_path: Path, schema_version: int | None
) -> None:
    path = tmp_path / "osv.json"
    python = PackageVersion(name="demo", version="1.2.3")
    javascript = PackageVersion(ecosystem="npm", name="demo", version="1.2.3")
    old_result = success(vulnerable=True).model_copy(update={"package": python})
    entry = old_result.model_dump(mode="json")
    del entry["package"]["ecosystem"]
    entries = {json.dumps(python.identity): entry}
    payload: dict[str, object] = {"entries": entries}
    if schema_version is not None:
        payload["schema_version"] = schema_version
    path.write_text(json.dumps(payload), encoding="utf-8")
    previous = path.read_bytes()

    cache = LookupCache(path, clock=lambda: NOW)
    assert cache.get(python) is None
    assert cache.get(javascript) is None
    cache.save()
    assert path.read_bytes() == previous

    result = success().model_copy(update={"package": javascript})
    cache.put(result)
    cache.save()
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 2
    reloaded = LookupCache(path, clock=lambda: NOW)
    assert reloaded.get(python) is None
    assert reloaded.get(javascript) == result


@pytest.mark.parametrize("field", ["ecosystem", "name", "version", "missing_ecosystem"])
def test_npm_cached_payload_identity_must_match_key(tmp_path: Path, field: str) -> None:
    path = tmp_path / "osv.json"
    package = PackageVersion(ecosystem="npm", name="demo.pkg", version="1.2.3")
    entry = success(vulnerable=True).model_copy(update={"package": package})
    payload = entry.model_dump(mode="json")
    if field == "missing_ecosystem":
        del payload["package"]["ecosystem"]
    else:
        payload["package"][field] = {
            "ecosystem": "PyPI",
            "name": "demo-pkg",
            "version": "2.0.0",
        }[field]
    path.write_text(
        json.dumps(
            {"schema_version": 2, "entries": {json.dumps(package.identity): payload}}
        ),
        encoding="utf-8",
    )
    assert LookupCache(path, clock=lambda: NOW).get(package) is None


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


@pytest.mark.parametrize("existing_cache", [False, True])
def test_no_cache_bypasses_reads_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_cache: bool
) -> None:
    path = tmp_path / "cache" / "osv.json"
    if existing_cache:
        cache = LookupCache(path, clock=lambda: NOW)
        cache.put(success(vulnerable=True))
        cache.save()
    previous = path.read_bytes() if existing_cache else None
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo-pkg==1\n", encoding="utf-8")
    post = MagicMock()
    post.return_value.__enter__.return_value = post.return_value
    post.return_value.status_code = 200
    post.return_value.json.return_value = {}
    monkeypatch.setattr("depscan.osv.requests.post", post)
    monkeypatch.setattr("depscan.cache.user_cache_path", lambda app: path.parent)
    cache_constructor = MagicMock(side_effect=AssertionError("cache must be bypassed"))
    monkeypatch.setattr("depscan.cli.LookupCache", cache_constructor)

    assert main([str(requirements), "--no-cache"]) == 0
    post.assert_called_once()
    cache_constructor.assert_not_called()
    if existing_cache:
        assert path.read_bytes() == previous
    else:
        assert not path.parent.exists()


def test_atomic_write_can_retry_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW)
    cache.put(success())
    with monkeypatch.context() as patch:
        patch.setattr(
            "depscan.cache.os.replace", MagicMock(side_effect=OSError("disk"))
        )
        cache.save()
    assert not path.exists()
    assert not list(tmp_path.iterdir())
    cache.save()
    assert LookupCache(path, clock=lambda: NOW).get(PACKAGE) == success()


def test_missing_timestamp_is_not_persisted(tmp_path: Path) -> None:
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW)
    cache.put(success().model_copy(update={"looked_up_at": None}))
    assert cache.get(PACKAGE) is None
    cache.save()
    assert not path.exists()


def test_failed_lookups_never_create_cache_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "osv.json"
    cache = LookupCache(path, clock=lambda: NOW)
    post = MagicMock()
    post.return_value.__enter__.return_value = post.return_value
    post.return_value.status_code = 503
    monkeypatch.setattr("depscan.osv.requests.post", post)

    for _ in range(2):
        assert isinstance(lookup_packages([PACKAGE], cache=cache)[0], FailedLookup)
        assert cache.get(PACKAGE) is None
        assert not path.exists()
    assert post.call_count == 2

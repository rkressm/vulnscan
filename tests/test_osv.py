"""Offline OSV contract, failure handling, and per-scan deduplication tests."""

from unittest.mock import Mock

import pytest
import requests
from pydantic import TypeAdapter

from depscan.models import FailedLookup, LookupResult, PackageVersion, SuccessfulLookup
from depscan.osv import lookup_packages

PACKAGE = PackageVersion(name="requests", version="2.31.0")


@pytest.fixture
def post(monkeypatch: pytest.MonkeyPatch) -> Mock:
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = {}
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    post = Mock(return_value=response)
    monkeypatch.setattr(requests, "post", post)
    return post


def test_request_contract_and_empty_response(post: Mock) -> None:
    result = lookup_packages([PACKAGE])

    assert isinstance(result[0], SuccessfulLookup)
    assert result[0].package == PACKAGE
    assert result[0].advisories == ()
    assert result[0].looked_up_at is not None
    post.assert_called_once_with(
        "https://api.osv.dev/v1/query",
        json={
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "version": "2.31.0",
        },
        timeout=(5.0, 30.0),
        allow_redirects=False,
    )
    post.return_value.__exit__.assert_called_once()


def test_multiple_advisories(post: Mock) -> None:
    post.return_value.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-example",
                "database_specific": {"severity": " high "},
                "summary": "Extra OSV fields are allowed",
            },
            {"id": "PYSEC-example"},
        ]
    }

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, SuccessfulLookup)
    assert [item.identifier for item in result.advisories] == [
        "GHSA-example",
        "PYSEC-example",
    ]
    assert [item.severity for item in result.advisories] == ["HIGH", "UNKNOWN"]
    assert result.advisories[0].url == "https://osv.dev/vulnerability/GHSA-example"


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("LOW", "LOW"),
        ("MODERATE", "MODERATE"),
        ("medium", "MEDIUM"),
        ("CRITICAL", "CRITICAL"),
        ("unexpected", "UNKNOWN"),
        (9.8, "UNKNOWN"),
        (None, "UNKNOWN"),
    ],
)
def test_severity_labels(post: Mock, label: object, expected: str) -> None:
    post.return_value.json.return_value = {
        "vulns": [{"id": "TEST-1", "database_specific": {"severity": label}}]
    }

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, SuccessfulLookup)
    assert result.advisories[0].severity == expected


def test_cvss_vector_does_not_invent_severity(post: Mock) -> None:
    post.return_value.json.return_value = {
        "vulns": [
            {
                "id": "TEST/1",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
            }
        ]
    }

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, SuccessfulLookup)
    assert result.advisories[0].severity == "UNKNOWN"
    assert result.advisories[0].url.endswith("TEST%2F1")


def test_explicit_empty_vulns(post: Mock) -> None:
    post.return_value.json.return_value = {"vulns": []}

    result = lookup_packages([PACKAGE])[0]
    assert isinstance(result, SuccessfulLookup)
    assert result.package == PACKAGE
    assert result.advisories == ()


@pytest.mark.parametrize("status", [301, 400, 404, 429, 500, 503])
def test_http_failure(post: Mock, status: int) -> None:
    post.return_value.status_code = status

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, FailedLookup)
    assert result.package == PACKAGE
    assert result.reason == f"OSV returned HTTP {status}."
    post.return_value.json.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectTimeout("connect"),
        requests.ReadTimeout("read"),
        requests.ConnectionError("offline"),
        requests.RequestException("transport failure"),
    ],
)
def test_transport_failure(post: Mock, error: requests.RequestException) -> None:
    post.side_effect = error

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, FailedLookup)
    assert result.package == PACKAGE
    if isinstance(error, requests.Timeout):
        assert result.reason == "OSV request timed out."
    else:
        assert str(error) in result.reason


def test_invalid_json(post: Mock) -> None:
    post.return_value.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "not json", 0
    )

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, FailedLookup)
    assert "malformed response" in result.reason


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        "unexpected",
        {"vulns": None},
        {"vulns": {}},
        {"vulns": [None]},
        {"vulns": [{}]},
        {"vulns": [{"id": " "}]},
        {"vulns": [{"id": 123}]},
        {"vulns": [{"id": "TEST-1"}, {"summary": "Missing ID"}]},
        {"vulns": [{"id": "TEST-1", "database_specific": []}]},
    ],
)
def test_malformed_response(post: Mock, payload: object) -> None:
    post.return_value.json.return_value = payload

    result = lookup_packages([PACKAGE])[0]

    assert isinstance(result, FailedLookup)
    assert "malformed response" in result.reason


def test_unique_normalized_package_version_queries(post: Mock) -> None:
    packages = [
        PackageVersion(name="My_Package.Name", version="1.0"),
        PackageVersion(name="my-package-name", version="1.0"),
        PackageVersion(name="my.package_name", version="2.0"),
        PACKAGE,
        PACKAGE,
    ]

    results = lookup_packages(iter(packages))

    assert post.call_count == 3
    assert [(item.package.name, item.package.version) for item in results] == [
        ("my-package-name", "1.0"),
        ("my-package-name", "2.0"),
        ("requests", "2.31.0"),
    ]


def test_failure_is_deduplicated_and_later_packages_are_queried(post: Mock) -> None:
    post.side_effect = [requests.ConnectionError("offline"), post.return_value]
    other = PackageVersion(name="other", version="1.0")

    results = lookup_packages([PACKAGE, PACKAGE, other])

    assert post.call_count == 2
    assert isinstance(results[0], FailedLookup)
    assert isinstance(results[1], SuccessfulLookup)
    assert results[1].package == other


def test_separate_scans_do_not_reuse_results(post: Mock) -> None:
    lookup_packages([PACKAGE])
    lookup_packages([PACKAGE])

    assert post.call_count == 2


def test_empty_scan_makes_no_requests(post: Mock) -> None:
    assert lookup_packages([]) == []
    post.assert_not_called()


def test_lookup_results_json_round_trip(post: Mock) -> None:
    results = lookup_packages([PACKAGE])
    post.side_effect = requests.ConnectionError("offline")
    results.extend(lookup_packages([PACKAGE]))
    adapter = TypeAdapter(list[LookupResult])

    assert adapter.validate_json(adapter.dump_json(results)) == results

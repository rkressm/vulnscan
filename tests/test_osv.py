"""Offline OSV contract, failure handling, and per-scan deduplication tests."""

from pathlib import Path
from unittest.mock import Mock, call

import pytest
import requests
from pydantic import TypeAdapter

from depscan.cache import LookupCache
from depscan.models import FailedLookup, LookupResult, PackageVersion, SuccessfulLookup
from depscan.osv import lookup_packages

PACKAGE = PackageVersion(name="requests", version="2.31.0")
NPM_PACKAGE = PackageVersion(ecosystem="npm", name="@scope/my.package", version="1.2.3")


@pytest.fixture(params=[PACKAGE, NPM_PACKAGE], ids=["PyPI", "npm"])
def package(request: pytest.FixtureRequest) -> PackageVersion:
    assert isinstance(request.param, PackageVersion)
    return request.param


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


def test_request_contract_and_empty_response(
    post: Mock, package: PackageVersion
) -> None:
    result = lookup_packages([package])

    assert isinstance(result[0], SuccessfulLookup)
    assert result[0].package == package
    assert result[0].advisories == ()
    assert result[0].looked_up_at is not None
    post.assert_called_once_with(
        "https://api.osv.dev/v1/query",
        json={
            "package": {"ecosystem": package.ecosystem, "name": package.name},
            "version": package.version,
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
def test_http_failure(post: Mock, package: PackageVersion, status: int) -> None:
    post.return_value.status_code = status

    result = lookup_packages([package])[0]

    assert isinstance(result, FailedLookup)
    assert result.package == package
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
def test_transport_failure(
    post: Mock, package: PackageVersion, error: requests.RequestException
) -> None:
    post.side_effect = error

    result = lookup_packages([package])[0]

    assert isinstance(result, FailedLookup)
    assert result.package == package
    if isinstance(error, requests.Timeout):
        assert result.reason == "OSV request timed out."
    else:
        assert str(error) in result.reason


def test_invalid_json(post: Mock, package: PackageVersion) -> None:
    post.return_value.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "not json", 0
    )

    result = lookup_packages([package])[0]

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
def test_malformed_response(
    post: Mock, package: PackageVersion, payload: object
) -> None:
    post.return_value.json.return_value = payload

    result = lookup_packages([package])[0]

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


def test_ecosystems_and_npm_punctuation_are_distinct(post: Mock) -> None:
    packages = [
        PackageVersion(name="My_Package.Name", version="1.2.3"),
        PackageVersion(ecosystem="npm", name="my-package-name", version="1.2.3"),
        PackageVersion(ecosystem="npm", name="my.package_name", version="1.2.3"),
        PackageVersion(ecosystem="npm", name="my_package.name", version="1.2.3"),
        NPM_PACKAGE,
        PackageVersion(ecosystem="npm", name="@other/my.package", version="1.2.3"),
    ]
    post.return_value.json.side_effect = [
        {"vulns": [{"id": f"TEST-{index}"}]} for index in range(len(packages))
    ]

    results = lookup_packages(packages)

    assert [result.package for result in results] == packages
    assert post.call_count == len(packages)
    for index, (result, request) in enumerate(
        zip(results, post.call_args_list, strict=True)
    ):
        assert isinstance(result, SuccessfulLookup)
        assert result.advisories[0].identifier == f"TEST-{index}"
        ecosystem, name, version = packages[index].identity
        assert request.kwargs["json"] == {
            "package": {"ecosystem": ecosystem, "name": name},
            "version": version,
        }


def test_npm_duplicates_and_exact_versions(post: Mock) -> None:
    packages = [
        NPM_PACKAGE,
        PackageVersion(ecosystem="npm", name="@scope/my.package", version="v1.2.3"),
        PackageVersion(ecosystem="npm", name="@scope/my.package", version="2.0.0"),
        PackageVersion(
            ecosystem="npm", name="@scope/my.package", version="2.0.0-beta.1+build.2"
        ),
        NPM_PACKAGE,
    ]

    results = lookup_packages(iter(packages))

    assert [result.package for result in results] == [packages[i] for i in (0, 2, 3)]
    assert post.call_count == 3
    assert [request.kwargs["json"]["version"] for request in post.call_args_list] == [
        "1.2.3",
        "2.0.0",
        "2.0.0-beta.1+build.2",
    ]


def test_cache_receives_canonical_ecosystem_identities(post: Mock) -> None:
    # Cache key isolation/transition belongs to T04; isolate its legacy keys here.
    cache = Mock(spec=LookupCache)
    cache.get.return_value = None
    packages = [
        PackageVersion(name="My_Package", version="1.2.3"),
        PackageVersion(ecosystem="npm", name="my-package", version="1.2.3"),
        NPM_PACKAGE,
    ]

    results = lookup_packages([*packages, *packages], cache=cache)

    assert cache.get.call_args_list == [call(package) for package in packages]
    assert cache.put.call_args_list == [call(result) for result in results]
    cache.save.assert_called_once_with()
    assert post.call_count == 3

    cache.reset_mock()
    cache.get.side_effect = results
    assert lookup_packages([*packages, *packages], cache=cache) == results
    assert cache.get.call_args_list == [call(package) for package in packages]
    cache.put.assert_not_called()
    cache.save.assert_called_once_with()
    assert post.call_count == 3


@pytest.mark.parametrize("failed_package", [PACKAGE, NPM_PACKAGE])
def test_cross_ecosystem_failure_does_not_stop_other_lookup(
    post: Mock, failed_package: PackageVersion
) -> None:
    other = NPM_PACKAGE if failed_package == PACKAGE else PACKAGE
    post.side_effect = [requests.ReadTimeout("offline"), post.return_value]
    cache = Mock(spec=LookupCache)
    cache.get.return_value = None

    results = lookup_packages([failed_package, failed_package, other], cache=cache)

    assert post.call_count == 2
    assert isinstance(results[0], FailedLookup)
    assert results[0].package == failed_package
    assert isinstance(results[1], SuccessfulLookup)
    assert results[1].package == other
    cache.put.assert_called_once_with(results[1])


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


def test_token_only_page_is_followed(post: Mock, package: PackageVersion) -> None:
    post.return_value.json.side_effect = [
        {"next_page_token": "page-two"},
        {"vulns": [{"id": "TEST-1"}]},
    ]

    result = lookup_packages([package])[0]

    assert isinstance(result, SuccessfulLookup)
    assert [item.identifier for item in result.advisories] == ["TEST-1"]
    assert post.call_count == 2
    assert post.call_args.kwargs["json"]["page_token"] == "page-two"
    assert "page_token" not in post.call_args_list[0].kwargs["json"]
    for request in post.call_args_list:
        assert request.kwargs["json"]["package"] == {
            "ecosystem": package.ecosystem,
            "name": package.name,
        }
        assert request.kwargs["json"]["version"] == package.version
        assert request.kwargs["timeout"] == (5.0, 30.0)
        assert request.kwargs["allow_redirects"] is False


def test_advisories_accumulate_across_pages(
    post: Mock, package: PackageVersion
) -> None:
    post.return_value.json.side_effect = [
        {"vulns": [{"id": "TEST-1"}], "next_page_token": "page-two"},
        {"vulns": [{"id": "TEST-2"}], "next_page_token": "page-three"},
        {"vulns": [{"id": "TEST-3"}]},
    ]

    result = lookup_packages([package])[0]

    assert isinstance(result, SuccessfulLookup)
    assert [item.identifier for item in result.advisories] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]
    assert post.call_count == 3


def test_repeated_page_token_fails_instead_of_looping(
    post: Mock, package: PackageVersion
) -> None:
    post.return_value.json.return_value = {"next_page_token": "same-page"}

    result = lookup_packages([package])[0]

    assert isinstance(result, FailedLookup)
    assert "pagination" in result.reason.lower()
    assert post.call_count == 2


@pytest.mark.parametrize("failure", ["timeout", "http", "malformed", "limit"])
def test_failed_later_page_is_not_cached(
    post: Mock,
    package: PackageVersion,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    first_page = {"vulns": [{"id": "TEST-1"}], "next_page_token": "page-two"}
    if failure == "timeout":
        post.return_value.json.return_value = first_page
        post.side_effect = [post.return_value, requests.ReadTimeout("later page")]
    elif failure == "http":
        failed_response = Mock(spec=requests.Response)
        failed_response.status_code = 503
        failed_response.__enter__ = Mock(return_value=failed_response)
        failed_response.__exit__ = Mock(return_value=False)
        post.return_value.json.return_value = first_page
        post.side_effect = [post.return_value, failed_response]
    else:
        monkeypatch.setattr("depscan.osv._MAX_PAGES", 2)
        second_page: dict[str, object] = (
            {"vulns": [{}]}
            if failure == "malformed"
            else {"next_page_token": "page-three"}
        )
        post.return_value.json.side_effect = [first_page, second_page]
    path = tmp_path / "cache.json"
    cache = LookupCache(path)

    result = lookup_packages([package], cache=cache)[0]

    assert isinstance(result, FailedLookup)
    assert post.call_count == 2
    assert cache.get(package) is None
    assert not path.exists()


def test_all_pages_are_cached_together(post: Mock, tmp_path: Path) -> None:
    post.return_value.json.side_effect = [
        {"vulns": [{"id": "TEST-1"}], "next_page_token": "page-two"},
        {"vulns": [{"id": "TEST-2"}]},
    ]
    path = tmp_path / "cache.json"
    result = lookup_packages([PACKAGE], cache=LookupCache(path))[0]
    assert isinstance(result, SuccessfulLookup)
    assert len(result.advisories) == 2

    post.side_effect = AssertionError("cached lookups must not make HTTP requests")
    assert lookup_packages([PACKAGE], cache=LookupCache(path)) == [result]


@pytest.mark.parametrize("token", [None, 123, [], {}])
def test_malformed_page_token_is_not_a_clean_result(
    post: Mock, package: PackageVersion, token: object
) -> None:
    post.return_value.json.return_value = {"next_page_token": token}
    assert isinstance(lookup_packages([package])[0], FailedLookup)

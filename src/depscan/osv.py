"""Query OSV without depending on requirements parsing or presentation."""

from collections.abc import Iterable
from urllib.parse import quote

import requests
from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from depscan.models import (
    Advisory,
    FailedLookup,
    LookupResult,
    NonEmptyString,
    PackageVersion,
    SuccessfulLookup,
)

_QUERY_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = (5.0, 30.0)  # Connection timeout, then read timeout (seconds).


class _OSVAdvisory(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    id: NonEmptyString
    database_specific: dict[str, object] = Field(default_factory=dict[str, object])


class _OSVResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    # OSV returns {} when there are no known vulnerabilities.
    vulns: list[_OSVAdvisory] = Field(default_factory=list[_OSVAdvisory])


def lookup_packages(packages: Iterable[PackageVersion]) -> list[LookupResult]:
    """Query each unique normalized name/exact version once, in first-seen order.

    Failures are also deduplicated within this call. Nothing is cached between
    calls; callers can map these results back to duplicate source declarations.
    """
    results: list[LookupResult] = []
    seen: set[PackageVersion] = set()
    for package in packages:
        normalized = PackageVersion(
            name=canonicalize_name(package.name), version=package.version
        )
        if normalized not in seen:
            seen.add(normalized)
            results.append(_lookup_package(normalized))
    return results


def _lookup_package(package: PackageVersion) -> LookupResult:
    try:
        with requests.post(
            _QUERY_URL,
            json={
                "package": {"ecosystem": "PyPI", "name": package.name},
                "version": package.version,
            },
            timeout=_TIMEOUT,
            allow_redirects=False,
        ) as response:
            if not 200 <= response.status_code < 300:
                return FailedLookup(
                    package=package,
                    reason=f"OSV returned HTTP {response.status_code}.",
                )
            try:
                payload = _OSVResponse.model_validate(response.json())
            except ValueError, ValidationError:
                return FailedLookup(
                    package=package, reason="OSV returned a malformed response."
                )
    except requests.Timeout:
        return FailedLookup(package=package, reason="OSV request timed out.")
    except requests.RequestException as exc:
        return FailedLookup(package=package, reason=f"OSV request failed: {exc}")

    return SuccessfulLookup(
        package=package,
        advisories=tuple(_advisory(item) for item in payload.vulns),
    )


def _advisory(item: _OSVAdvisory) -> Advisory:
    # Only copy recognized publisher labels. CVSS vectors are not simple labels;
    # without a scoring implementation, reporting UNKNOWN is more honest.
    label = item.database_specific.get("severity")
    severity = label.strip().upper() if isinstance(label, str) else "UNKNOWN"
    if severity not in {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "UNKNOWN"
    return Advisory.model_validate(
        {
            "identifier": item.id,
            "severity": severity,
            "url": f"https://osv.dev/vulnerability/{quote(item.id, safe='')}",
        }
    )

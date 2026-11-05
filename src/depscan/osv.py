"""Query OSV without depending on requirements parsing or presentation."""

from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import quote

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from depscan.cache import LookupCache
from depscan.models import (
    Advisory,
    Ecosystem,
    FailedLookup,
    LookupResult,
    NonEmptyString,
    PackageVersion,
    SuccessfulLookup,
)

_QUERY_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = (5.0, 30.0)  # Connection timeout, then read timeout (seconds).
_MAX_PAGES = 100


class _OSVAdvisory(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    id: NonEmptyString
    database_specific: dict[str, object] = Field(default_factory=dict[str, object])


class _OSVResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    # OSV returns {} when there are no known vulnerabilities.
    vulns: list[_OSVAdvisory] = Field(default_factory=list[_OSVAdvisory])
    next_page_token: str = ""


def lookup_packages(
    packages: Iterable[PackageVersion], *, cache: LookupCache | None = None
) -> list[LookupResult]:
    """Query each unique ecosystem/name/exact version once, in first-seen order.

    Failures are also deduplicated within this call, but never persisted. Pass a
    cache to reuse fresh successes; without one all requests use live OSV data.
    """
    results: list[LookupResult] = []
    seen: set[tuple[Ecosystem, str, str]] = set()
    for package in packages:
        if package.identity not in seen:
            seen.add(package.identity)
            result = cache.get(package) if cache is not None else None
            if result is None:
                lookup = _lookup_package(package)
                if cache is not None and isinstance(lookup, SuccessfulLookup):
                    cache.put(lookup)
                results.append(lookup)
            else:
                results.append(result)
    if cache is not None:
        cache.save()
    return results


def _lookup_package(package: PackageVersion) -> LookupResult:
    advisories: list[Advisory] = []
    page_token = ""
    seen_tokens: set[str] = set()
    try:
        for _ in range(_MAX_PAGES):
            query: dict[str, object] = {
                "package": {"ecosystem": package.ecosystem, "name": package.name},
                "version": package.version,
            }
            if page_token:
                query["page_token"] = page_token
            with requests.post(
                _QUERY_URL,
                json=query,
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
            advisories.extend(_advisory(item) for item in payload.vulns)
            page_token = payload.next_page_token
            if not page_token:
                break
            if page_token in seen_tokens:
                return FailedLookup(
                    package=package,
                    reason="OSV pagination repeated a token; lookup is incomplete.",
                )
            seen_tokens.add(page_token)
        else:
            return FailedLookup(
                package=package,
                reason=f"OSV pagination exceeded {_MAX_PAGES} pages.",
            )
    except requests.Timeout:
        return FailedLookup(package=package, reason="OSV request timed out.")
    except requests.RequestException as exc:
        return FailedLookup(package=package, reason=f"OSV request failed: {exc}")

    return SuccessfulLookup(
        package=package,
        advisories=tuple(advisories),
        looked_up_at=datetime.now(UTC),
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

"""Runtime validation of the shared package/version model."""

from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from depscan.models import (
    NonApplicableRequirement,
    PackageVersion,
    ReadyRequirement,
    RequirementResult,
    SourceLocation,
    UnscannedRequirement,
)


def test_package_version() -> None:
    package = PackageVersion(name=" requests ", version=" 2.31.0 ")

    assert package.model_dump() == {"name": "requests", "version": "2.31.0"}
    assert PackageVersion.model_validate_json(package.model_dump_json()) == package


@pytest.mark.parametrize(
    "data",
    [
        {"name": "", "version": "2.31.0"},
        {"name": "requests", "version": " "},
        {"name": "requests", "version": 2},
        {"name": "requests"},
        {"name": "requests", "version": "2.31.0", "unexpected": True},
    ],
)
def test_invalid_package_version(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PackageVersion.model_validate(data)


def test_package_version_is_immutable() -> None:
    package = PackageVersion(name="requests", version="2.31.0")

    with pytest.raises(ValidationError):
        package.version = "2.32.0"  # type: ignore[misc]  # Test runtime frozen validation.


def test_requirement_results_json_round_trip() -> None:
    source = SourceLocation(path=Path("requirements.txt"), line=1, text="demo==1.0")
    results: list[RequirementResult] = [
        ReadyRequirement(
            source=source, package=PackageVersion(name="demo", version="1.0")
        ),
        UnscannedRequirement(source=source, reason="Package not installed."),
        NonApplicableRequirement(source=source, name="demo", reason="Marker excluded."),
    ]
    adapter = TypeAdapter(list[RequirementResult])

    assert adapter.validate_json(adapter.dump_json(results)) == results


def test_source_line_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path=Path("requirements.txt"), line=0, text="")

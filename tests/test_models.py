"""Runtime validation of the shared package/version model."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from depscan.models import (
    DependencySource,
    DiscoveryResult,
    NonApplicableRequirement,
    PackageVersion,
    ReadyRequirement,
    RequirementResult,
    ScanError,
    ScannedRequirement,
    ScanReport,
    SourceLocation,
    SourceReadResult,
    SourceSelection,
    SourceSummary,
    UnscannedRequirement,
)


def test_package_version() -> None:
    package = PackageVersion(name=" requests ", version=" 2.31.0 ")

    assert package.model_dump() == {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.31.0",
    }
    assert PackageVersion.model_validate_json(package.model_dump_json()) == package


@pytest.mark.parametrize(
    "data",
    [
        {"name": "", "version": "2.31.0"},
        {"name": "requests", "version": " "},
        {"name": "requests", "version": 2},
        {"name": "requests"},
        {"name": "requests", "version": "2.31.0", "unexpected": True},
        {"name": "requests", "version": "2.31.0", "ecosystem": "NPM"},
        {
            "name": "requests",
            "version": "2.31.0",
            "identity": ("PyPI", "requests", "2.31.0"),
        },
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


def test_canonical_identity_is_ecosystem_aware_and_not_serialized() -> None:
    python = PackageVersion(name="Some_Name.pkg", version="1.2.3")
    npm = PackageVersion(ecosystem="npm", name="Some_Name.pkg", version="v1.2.3")
    assert python == PackageVersion(name="some-name-pkg", version="1.2.3")
    assert hash(python) == hash(PackageVersion(name="SOME.name_pkg", version="1.2.3"))
    assert python.identity == ("PyPI", "some-name-pkg", "1.2.3")
    assert npm.identity == ("npm", "Some_Name.pkg", "1.2.3")
    assert (
        len(
            {
                python,
                npm,
                PackageVersion(ecosystem="npm", name="Some_Name.pkg", version="1.2.4"),
            }
        )
        == 3
    )
    assert PackageVersion(name="same", version="1.2.3") != PackageVersion(
        ecosystem="npm", name="same", version="1.2.3"
    )
    assert "identity" not in npm.model_dump()
    assert PackageVersion.model_validate_json(npm.model_dump_json()) == npm


@pytest.mark.parametrize(
    "name", ["foo.bar", "foo_bar", "foo-bar", "@Scope/foo_bar", "~foo", "a" * 214]
)
@pytest.mark.parametrize(
    "version",
    [
        "0.0.0",
        "v1.2.3",
        "1.2.3-rc.1",
        "1.2.3-0+build.01",
        "1.2.3-A-z.0",
        "9007199254740991.0.0",
    ],
)
def test_valid_raw_npm_identity(name: str, version: str) -> None:
    package = PackageVersion(ecosystem="npm", name=name, version=version)
    assert package.name == name
    assert package.version == version.removeprefix("v")


@pytest.mark.parametrize(
    "name",
    [
        "",
        " foo",
        "foo ",
        "a b",
        ".foo",
        "_foo",
        "@scope",
        "@/foo",
        "@scope/_foo",
        "@.scope/foo",
        "scope/foo",
        "@a/b/c",
        "foo:bar",
        "foo%20",
        "föö",
        "a" * 215,
    ],
)
def test_invalid_raw_npm_name(name: str) -> None:
    with pytest.raises(ValidationError):
        PackageVersion(ecosystem="npm", name=name, version="1.2.3")


@pytest.mark.parametrize(
    "version",
    [
        "1",
        "1.2",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-01",
        "1.2.3-a..b",
        "1.2.3+",
        "1.2.3-",
        "1.2.3-ä",
        "1.2.3+foo_bar",
        "1.2.3\n",
        " 1.2.3",
        "1.2.3 ",
        "=1.2.3",
        "^1.2.3",
        "~1.2.3",
        "latest",
        "1.2.x",
        "npm:foo@1.2.3",
        "https://x/1.2.3",
        "V1.2.3",
        "9007199254740992.0.0",
        "1.2.3+" + "a" * 251,
    ],
)
def test_invalid_raw_npm_version(version: str) -> None:
    with pytest.raises(ValidationError):
        PackageVersion(ecosystem="npm", name="foo", version=version)


def test_npm_semver_length_boundary_and_build_identity() -> None:
    assert (
        len(
            PackageVersion(
                ecosystem="npm", name="foo", version="1.2.3+" + "a" * 250
            ).version
        )
        == 256
    )
    assert PackageVersion(
        ecosystem="npm", name="foo", version="1.2.3+one"
    ) != PackageVersion(ecosystem="npm", name="foo", version="1.2.3+two")
    assert PackageVersion(name="foo", version="01!arbitrary").version == "01!arbitrary"


def test_source_failure_and_empty_success_without_packages() -> None:
    source = DependencySource(ecosystem="npm", path=Path("bun.lock"), kind="bun")
    error = ScanError(ecosystem="npm", reason="Malformed document")
    failed = SourceReadResult(source=source, status="failed", errors=(error,))
    empty = SourceReadResult(source=source, status="success")
    assert failed.requirements == empty.requirements == ()
    assert SourceReadResult.model_validate_json(failed.model_dump_json()) == failed
    assert (
        SourceSelection(ecosystem="npm", status="failed", errors=(error,)).source
        is None
    )
    assert ScanError(reason="Global failure").ecosystem is None


def test_valid_discovery_and_contextual_requirements() -> None:
    source = DependencySource(
        ecosystem="npm", path=Path("package.json"), kind="package_json"
    )
    location = SourceLocation(path=source.path, line=1, text="dependencies.foo")
    ready = ReadyRequirement(
        source=location,
        package=PackageVersion(ecosystem="npm", name="foo", version="1.2.3"),
    )
    unscanned = UnscannedRequirement(ecosystem="npm", source=location, reason="Range")
    skipped = NonApplicableRequirement(
        ecosystem="npm", source=location, name="foo", reason="Excluded"
    )
    parsed = SourceReadResult(
        source=source,
        status="success",
        requirements=(ready, unscanned, skipped),
        errors=(ScanError(ecosystem="npm", reason="Entry error"),),
    )
    assert ready.ecosystem == "npm"
    assert "ecosystem" not in ready.model_dump()
    assert SourceReadResult.model_validate_json(parsed.model_dump_json()) == parsed
    selected = SourceSelection(
        ecosystem="npm", status="selected", source=source, candidates=(source,)
    )
    discovery = DiscoveryResult(
        selections=(SourceSelection(ecosystem="PyPI", status="absent"), selected)
    )
    assert DiscoveryResult.model_validate_json(discovery.model_dump_json()) == discovery
    with pytest.raises(ValidationError):
        DiscoveryResult(selections=(selected, selected))


@pytest.mark.parametrize(
    "kind,ecosystem",
    [("npm", "PyPI"), ("requirements", "npm"), ("unknown", "npm"), ("npm", "RubyGems")],
)
def test_invalid_source_ecosystem(kind: str, ecosystem: str) -> None:
    with pytest.raises(ValidationError):
        DependencySource.model_validate(
            {"kind": kind, "ecosystem": ecosystem, "path": Path("input")}
        )


def test_invalid_selection_states() -> None:
    npm = DependencySource(ecosystem="npm", path=Path("package-lock.json"), kind="npm")
    shrinkwrap = DependencySource(
        ecosystem="npm", path=Path("npm-shrinkwrap.json"), kind="npm"
    )
    yarn = DependencySource(ecosystem="npm", path=Path("yarn.lock"), kind="yarn")
    error = ScanError(ecosystem="npm", reason="Ambiguous")
    SourceSelection(
        ecosystem="npm", status="ambiguous", candidates=(npm, yarn), errors=(error,)
    )
    invalid_states: list[dict[str, object]] = [
        {"status": "selected"},
        {"status": "selected", "source": npm},
        {"status": "selected", "source": npm, "candidates": (npm,), "errors": (error,)},
        {"status": "absent", "candidates": (npm,)},
        {"status": "failed"},
        {"status": "failed", "source": npm, "errors": (error,)},
        {"status": "ambiguous", "candidates": (npm, shrinkwrap), "errors": (error,)},
        {"status": "ambiguous", "candidates": (npm, yarn)},
        {"status": "failed", "errors": (ScanError(reason="Missing context"),)},
    ]
    for data in invalid_states:
        with pytest.raises(ValidationError):
            SourceSelection.model_validate({"ecosystem": "npm", **data})


def test_invalid_read_states_and_context() -> None:
    source = DependencySource(ecosystem="npm", path=Path("bun.lock"), kind="bun")
    location = SourceLocation(path=source.path, line=1, text="entry")
    ready = ReadyRequirement(
        source=location,
        package=PackageVersion(ecosystem="npm", name="foo", version="1.2.3"),
    )
    error = ScanError(ecosystem="npm", reason="Broken")
    invalid_states: list[dict[str, object]] = [
        {"status": "failed"},
        {"status": "failed", "errors": (error,), "requirements": (ready,)},
        {
            "status": "success",
            "errors": (ScanError(ecosystem="PyPI", reason="Wrong context"),),
        },
        {
            "status": "success",
            "requirements": (
                UnscannedRequirement(source=location, reason="Defaults to PyPI"),
            ),
        },
        {
            "status": "success",
            "requirements": (
                ReadyRequirement(
                    source=location, package=PackageVersion(name="foo", version="1")
                ),
            ),
        },
    ]
    for data in invalid_states:
        with pytest.raises(ValidationError):
            SourceReadResult.model_validate({"source": source, **data})


def test_schema_v2_defaults_and_exit_semantics() -> None:
    legacy = ScanReport(scanned_at=datetime.now(UTC), results=(), errors=())
    assert legacy.schema_version == 2
    assert legacy.sources == ()
    assert legacy.detected_ecosystems == ()
    assert legacy.input_paths == ()
    assert legacy.exit_code == 2  # No discovery context is not evidence of success.
    source = DependencySource(ecosystem="npm", path=Path("bun.lock"), kind="bun")
    summary = SourceSummary(
        ecosystem="npm", status="success", source=source, candidates=(source,)
    )
    report = ScanReport(
        scanned_at=datetime.now(UTC),
        results=(),
        errors=(),
        detected_ecosystems=("npm",),
        sources=(summary, SourceSummary(ecosystem="PyPI", status="absent")),
    )
    assert report.exit_code == 0
    location = SourceLocation(path=source.path, line=1, text="foo")
    finding = ScannedRequirement(
        source=location,
        package=PackageVersion(ecosystem="npm", name="foo", version="1.2.3"),
        status="vulnerable",
        advisories=(),
    )
    assert finding.ecosystem == "npm"
    assert "ecosystem" not in finding.model_dump()
    assert legacy.model_copy(update={"results": (finding,)}).exit_code == 2
    assert report.model_copy(update={"results": (finding,)}).exit_code == 1
    assert (
        report.model_copy(
            update={"errors": (ScanError(reason="Global failure"),)}
        ).exit_code
        == 2
    )
    for status in ("failed", "ambiguous"):
        candidates = (
            source,
            DependencySource(ecosystem="npm", path=Path("yarn.lock"), kind="yarn"),
        )
        broken = SourceSummary.model_validate(
            {"ecosystem": "npm", "status": status, "candidates": candidates}
        )
        assert (
            report.model_copy(
                update={"results": (finding,), "sources": (broken,)}
            ).exit_code
            == 2
        )
    assert ScanReport.model_validate_json(report.model_dump_json()) == report
    with pytest.raises(ValidationError):
        ScanReport.model_validate({**legacy.model_dump(), "schema_version": 1})


@pytest.mark.parametrize(
    "data",
    [
        {"status": "success"},
        {
            "status": "absent",
            "candidates": (
                DependencySource(ecosystem="npm", path=Path("bun.lock"), kind="bun"),
            ),
        },
        {"status": "ambiguous"},
        {
            "status": "failed",
            "candidates": (
                DependencySource(
                    ecosystem="PyPI", path=Path("requirements.txt"), kind="requirements"
                ),
            ),
        },
    ],
)
def test_invalid_summary_states(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SourceSummary.model_validate({"ecosystem": "npm", **data})

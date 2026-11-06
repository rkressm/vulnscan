"""Offline rendering and atomic schema-v2 exports of constructed reports."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from depscan.models import (
    Advisory,
    DependencySource,
    NonApplicableRequirement,
    PackageVersion,
    ScanError,
    ScannedRequirement,
    ScanReport,
    SourceLocation,
    SourceSummary,
    UnscannedRequirement,
)
from depscan.report import render_terminal, write_json

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PYTHON = DependencySource(
    ecosystem="PyPI", path=Path("/repo/requirements.txt"), kind="requirements"
)
NPM = DependencySource(
    ecosystem="npm", path=Path("/repo/package.json"), kind="package_json"
)
ADVISORIES = (
    Advisory(identifier="OSV-1", severity="HIGH", url="https://osv.dev/OSV-1"),
    Advisory(identifier="OSV-2", severity="UNKNOWN", url="https://osv.dev/OSV-2"),
)


def location(source: DependencySource, text: str) -> SourceLocation:
    return SourceLocation(path=source.path, line=1, text=text)


def success(source: DependencySource) -> SourceSummary:
    return SourceSummary(
        ecosystem=source.ecosystem,
        status="success",
        source=source,
        candidates=(source,),
    )


def mixed_report() -> ScanReport:
    python = ScannedRequirement(
        status="no_known_vulnerabilities",
        source=location(PYTHON, "Shared_Pkg==1.2.3"),
        package=PackageVersion(name="Shared_Pkg", version="1.2.3"),
        advisories=(),
        looked_up_at=NOW,
    )
    npm = ScannedRequirement(
        status="vulnerable",
        source=location(NPM, "dependencies.first = npm:shared-pkg@1.2.3"),
        package=PackageVersion(ecosystem="npm", name="shared-pkg", version="1.2.3"),
        advisories=ADVISORIES,
        looked_up_at=NOW,
    )
    alias = npm.model_copy(
        update={
            "source": location(NPM, "devDependencies.second = npm:shared-pkg@1.2.3")
        }
    )
    distinct_version = ScannedRequirement(
        status="no_known_vulnerabilities",
        source=location(NPM, "dependencies.third = npm:shared-pkg@2.0.0-beta.1+build"),
        package=PackageVersion(
            ecosystem="npm", name="shared-pkg", version="2.0.0-beta.1+build"
        ),
        advisories=(),
    )
    return ScanReport(
        scanned_at=NOW,
        results=(python, npm, alias, distinct_version),
        errors=(),
        detected_ecosystems=("PyPI", "npm"),
        sources=(success(PYTHON), success(NPM)),
        input_paths=(PYTHON.path, NPM.path),
    )


def test_mixed_terminal_counts_identities_but_preserves_provenance() -> None:
    report = mixed_report()
    output = render_terminal(report)

    assert "Detected dependency ecosystems: PyPI, npm" in output
    assert "ECOSYSTEM" in output
    assert "Source PyPI: success; /repo/requirements.txt (requirements)" in output
    assert "Source npm: success; /repo/package.json (package_json)" in output
    assert (
        "Checked 3 unique package/version pairs: 1 vulnerable, "
        "2 with no known vulnerabilities; 2 advisories."
    ) in output
    assert "PyPI: Checked 1 unique package/version pairs: 0 vulnerable" in output
    assert "npm: Checked 2 unique package/version pairs: 1 vulnerable" in output
    for result in report.results:
        assert result.source.text in output
        assert f"{result.source.path}:1" in output
    for advisory in ADVISORIES:
        assert output.count(advisory.identifier) == 4  # ID and URL for both aliases
        assert advisory.severity in output
    assert "2.0.0-beta.1+build" in output
    assert "safe" not in output.lower()
    assert output.endswith("Scan complete.")
    assert report.exit_code == 1


def test_unscanned_and_non_applicable_context_and_global_errors() -> None:
    report = ScanReport(
        scanned_at=NOW,
        detected_ecosystems=("PyPI", "npm"),
        sources=(success(PYTHON), success(NPM)),
        results=(
            UnscannedRequirement(
                ecosystem="npm",
                source=location(NPM, "dependencies.alias = ^1"),
                name="alias",
                reason="Unresolved range; supply a supported lockfile",
            ),
            UnscannedRequirement(
                source=location(PYTHON, "???"), reason="Invalid requirement"
            ),
            NonApplicableRequirement(
                source=location(PYTHON, "win-only; sys_platform == 'win32'"),
                name="win-only",
                reason="Environment marker does not apply",
            ),
        ),
        errors=(ScanError(reason="JSON export unavailable"),),
    )
    output = render_terminal(report)
    assert "Declarations: 2 unscanned, 1 non-applicable." in output
    for result in report.results:
        assert result.source.text in output
        assert not isinstance(result, ScannedRequirement)
        assert result.reason in output
    assert "(unknown)" in output
    assert "Error [global]: JSON export unavailable" in output
    assert output.endswith("Scan incomplete.")
    assert report.exit_code == 2


@pytest.mark.parametrize("status", ["success", "failed", "absent", "ambiguous"])
def test_empty_sources_are_not_conflated(status: str, tmp_path: Path) -> None:
    yarn = DependencySource(ecosystem="npm", path=Path("/repo/yarn.lock"), kind="yarn")
    if status == "success":
        summary = success(NPM)
    elif status == "failed":
        summary = SourceSummary(
            ecosystem="npm", status="failed", source=NPM, candidates=(NPM,)
        )
    elif status == "absent":
        summary = SourceSummary(ecosystem="npm", status="absent")
    else:
        summary = SourceSummary(
            ecosystem="npm",
            status="ambiguous",
            candidates=(
                NPM,
                yarn,
                DependencySource(
                    ecosystem="npm", path=Path("/repo/bun.lock"), kind="bun"
                ),
            ),
        )
    errors = (
        (
            ScanError(
                ecosystem="npm",
                source=location(NPM, "document"),
                reason="Invalid document",
            ),
        )
        if status == "failed"
        else ()
    )
    report = ScanReport(
        scanned_at=NOW,
        results=(),
        errors=errors,
        detected_ecosystems=("PyPI",) if status == "absent" else ("PyPI", "npm"),
        sources=(success(PYTHON), summary),
        input_paths=(PYTHON.path, NPM.path),
    )
    output = render_terminal(report)
    assert f"Source npm: {status};" in output
    assert "npm: Checked 0 unique package/version pairs" in output
    assert "PyPI: Checked 0 unique package/version pairs" in output
    if status == "failed":
        assert "Error [npm; /repo/package.json:1: document]: Invalid document" in output
    if status == "ambiguous":
        assert "Candidate: /repo/yarn.lock (yarn)" in output
        assert "no selected source" in output
    assert report.exit_code == (2 if status in {"failed", "ambiguous"} else 0)
    assert output.endswith(
        "Scan incomplete." if report.exit_code == 2 else "Scan complete."
    )
    destination = tmp_path / "report.json"
    write_json(report, destination)
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["results"] == []
    assert data["sources"][1]["status"] == status
    assert data["sources"][1]["source"] == (
        NPM.model_dump(mode="json") if status in {"success", "failed"} else None
    )
    assert data["errors"] == [error.model_dump(mode="json") for error in errors]


def test_discovery_failure_and_no_detected_ecosystems() -> None:
    report = ScanReport(
        scanned_at=NOW,
        results=(),
        errors=(),
        sources=(SourceSummary(ecosystem="PyPI", status="absent"),),
    )
    output = render_terminal(report)
    assert "Detected dependency ecosystems: none" in output
    assert "Source PyPI: absent; no selected source" in output
    assert output.endswith("Scan incomplete.")
    failed = ScanReport(
        scanned_at=NOW,
        results=(),
        errors=(ScanError(ecosystem="npm", reason="Cannot read selection manifest"),),
        detected_ecosystems=("npm",),
        sources=(SourceSummary(ecosystem="npm", status="failed", candidates=(NPM,)),),
    )
    output = render_terminal(failed)
    assert "Source npm: failed; no selected source" in output
    assert "Candidate: /repo/package.json (package_json)" in output
    assert "Error [npm]: Cannot read selection manifest" in output
    assert output.endswith("Scan incomplete.")


def test_schema_v2_preserves_timestamp_advisories_and_declarations(
    tmp_path: Path,
) -> None:
    report = mixed_report()
    destination = tmp_path / "report.json"
    write_json(report, destination)
    payload = destination.read_text(encoding="utf-8")
    data = json.loads(payload)

    assert payload.endswith("\n")
    assert data == report.model_dump(mode="json")
    assert data["schema_version"] == 2
    assert data["scanned_at"] == "2026-11-06T12:00:00Z"
    assert data["detected_ecosystems"] == ["PyPI", "npm"]
    assert data["input_paths"] == [str(PYTHON.path), str(NPM.path)]
    assert len(data["results"]) == 4
    assert data["results"][0]["package"]["ecosystem"] == "PyPI"
    assert data["results"][1]["package"]["ecosystem"] == "npm"
    assert data["results"][1]["looked_up_at"] == "2026-11-06T12:00:00Z"
    assert data["results"][1]["advisories"] == [
        advisory.model_dump(mode="json") for advisory in ADVISORIES
    ]
    assert data["results"][1]["source"] != data["results"][2]["source"]
    assert "identity" not in data["results"][1]["package"]


def test_mixed_lookup_failure_retains_findings_and_successful_source(
    tmp_path: Path,
) -> None:
    mixed = mixed_report()
    failed_location = location(NPM, "dependencies.unavailable = 1.0.0")
    report = ScanReport(
        scanned_at=NOW,
        results=(
            *mixed.results,
            UnscannedRequirement(
                ecosystem="npm",
                source=failed_location,
                name="unavailable",
                reason="OSV lookup failed",
            ),
        ),
        errors=(
            ScanError(
                ecosystem="npm", source=failed_location, reason="OSV lookup failed"
            ),
        ),
        detected_ecosystems=mixed.detected_ecosystems,
        sources=mixed.sources,
        input_paths=mixed.input_paths,
    )
    output = render_terminal(report)
    assert "OSV-1" in output
    assert "Source npm: success" in output
    assert "Declarations: 1 unscanned, 0 non-applicable." in output
    assert "Error [npm; /repo/package.json:1:" in output
    assert output.endswith("Scan incomplete.")
    assert report.exit_code == 2
    destination = tmp_path / "report.json"
    write_json(report, destination)
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["results"][-1]["ecosystem"] == "npm"
    assert data["results"][-1]["source"]["text"] == failed_location.text
    assert data["sources"][1]["status"] == "success"
    assert data["errors"][0]["ecosystem"] == "npm"


def test_atomic_report_export(tmp_path: Path) -> None:
    report = ScanReport(scanned_at=datetime.now(UTC), results=(), errors=())
    destination = tmp_path / "report.json"
    destination.write_text("previous report", encoding="utf-8")

    write_json(report, destination)

    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == 2
    assert list(tmp_path.iterdir()) == [destination]


def test_failed_export_preserves_previous_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = ScanReport(scanned_at=datetime.now(UTC), results=(), errors=())
    destination = tmp_path / "report.json"
    destination.write_text("previous report", encoding="utf-8")

    def fail_replace(source: Path, target: Path) -> None:
        raise OSError("simulated replacement failure")

    monkeypatch.setattr("depscan.report.os.replace", fail_replace)
    with pytest.raises(OSError, match="replacement failure"):
        write_json(report, destination)

    assert destination.read_text(encoding="utf-8") == "previous report"
    assert list(tmp_path.iterdir()) == [destination]


def test_failed_flush_preserves_previous_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "report.json"
    destination.write_text("previous report", encoding="utf-8")

    def fail_sync(descriptor: int) -> None:
        raise OSError("simulated sync failure")

    monkeypatch.setattr("depscan.report.os.fsync", fail_sync)
    with pytest.raises(OSError, match="sync failure"):
        write_json(mixed_report(), destination)

    assert destination.read_text(encoding="utf-8") == "previous report"
    assert list(tmp_path.iterdir()) == [destination]

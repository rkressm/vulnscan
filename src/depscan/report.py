"""Plain terminal output and versioned JSON export; no scanning or networking."""

import os
import tempfile
from pathlib import Path

from depscan.models import Ecosystem, ScannedRequirement, ScanReport


def render_terminal(report: ScanReport) -> str:
    """Preserve declaration provenance and count ecosystem/package identities once."""
    lines = [
        "Detected dependency ecosystems: "
        + (", ".join(report.detected_ecosystems) or "none")
    ]
    for summary in report.sources:
        selected = (
            f"{summary.source.path} ({summary.source.kind})"
            if summary.source is not None
            else "no selected source"
        )
        lines.append(f"Source {summary.ecosystem}: {summary.status}; {selected}")
        for candidate in summary.candidates:
            if candidate != summary.source:
                lines.append(f"  Candidate: {candidate.path} ({candidate.kind})")
    lines.append("")
    rows: list[tuple[str, ...]] = []
    for result in report.results:
        location = f"{result.source.path}:{result.source.line}"
        provenance = f"{location}: {result.source.text}"
        if isinstance(result, ScannedRequirement):
            for advisory in result.advisories:
                rows.append(
                    (
                        result.ecosystem,
                        result.package.name,
                        result.package.version,
                        "vulnerable",
                        advisory.identifier,
                        advisory.severity,
                        f"{advisory.url}; {provenance}",
                    )
                )
            if not result.advisories:
                rows.append(
                    (
                        result.ecosystem,
                        result.package.name,
                        result.package.version,
                        "no known vulnerabilities",
                        "-",
                        "-",
                        provenance,
                    )
                )
        else:
            rows.append(
                (
                    result.ecosystem,
                    result.name or "(unknown)",
                    "-",
                    result.status.replace("_", " "),
                    "-",
                    "-",
                    f"{provenance}; {result.reason}",
                )
            )

    headers = (
        "ECOSYSTEM",
        "PACKAGE",
        "VERSION",
        "STATUS",
        "ADVISORY",
        "SEVERITY",
        "DETAILS",
    )
    widths = [max(len(row[i]) for row in [headers, *rows]) for i in range(6)]
    lines.extend(
        "  ".join(
            value.ljust(width) for value, width in zip(row[:6], widths, strict=True)
        )
        + f"  {row[6]}"
        for row in [headers, *rows]
    )
    lines.extend(["", _checked_summary(report)])
    # Include absence rows and contextual failures even when they have no packages.
    ecosystems: tuple[Ecosystem, ...] = ("PyPI", "npm")
    for ecosystem in ecosystems:
        if (
            ecosystem in report.detected_ecosystems
            or any(item.ecosystem == ecosystem for item in report.sources)
            or any(item.ecosystem == ecosystem for item in report.results)
            or any(item.ecosystem == ecosystem for item in report.errors)
        ):
            lines.append(f"{ecosystem}: {_checked_summary(report, ecosystem)}")
    unscanned = sum(result.status == "unscanned" for result in report.results)
    non_applicable = sum(result.status == "non_applicable" for result in report.results)
    lines.append(
        f"Declarations: {unscanned} unscanned, {non_applicable} non-applicable."
    )
    for error in report.errors:
        context: str = error.ecosystem or "global"
        if error.source is not None:
            context += f"; {error.source.path}:{error.source.line}: {error.source.text}"
        lines.append(f"Error [{context}]: {error.reason}")
    lines.append("Scan incomplete." if report.exit_code == 2 else "Scan complete.")
    return "\n".join(lines)


def _checked_summary(report: ScanReport, ecosystem: Ecosystem | None = None) -> str:
    """Deduplicate lookups, not the declarations displayed above."""
    checked = {
        result.package.identity: result
        for result in report.results
        if isinstance(result, ScannedRequirement)
        and (ecosystem is None or result.ecosystem == ecosystem)
    }
    vulnerable = sum(result.status == "vulnerable" for result in checked.values())
    advisory_count = sum(len(result.advisories) for result in checked.values())
    return (
        f"Checked {len(checked)} unique package/version pairs: "
        f"{vulnerable} vulnerable, {len(checked) - vulnerable} with no known "
        f"vulnerabilities; {advisory_count} advisories."
    )


def write_json(report: ScanReport, path: Path) -> None:
    """Atomically replace the report; a failed write preserves an existing report."""
    payload = report.model_dump_json(indent=2) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

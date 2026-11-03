"""Plain terminal output and versioned JSON export; no scanning or networking."""

from pathlib import Path

from depscan.models import ScannedRequirement, ScanReport


def render_terminal(report: ScanReport) -> str:
    """Preserve every declaration, but count checked package/version pairs once."""
    rows: list[tuple[str, ...]] = []
    for result in report.results:
        location = f"{result.source.path}:{result.source.line}"
        if isinstance(result, ScannedRequirement):
            for advisory in result.advisories:
                rows.append(
                    (
                        result.package.name,
                        result.package.version,
                        "vulnerable",
                        advisory.identifier,
                        advisory.severity,
                        advisory.url,
                    )
                )
            if not result.advisories:
                rows.append(
                    (
                        result.package.name,
                        result.package.version,
                        "no known vulnerabilities",
                        "-",
                        "-",
                        "-",
                    )
                )
        else:
            rows.append(
                (
                    result.name or "(unknown)",
                    "-",
                    result.status.replace("_", " "),
                    "-",
                    "-",
                    f"{location}: {result.reason}",
                )
            )

    headers = ("PACKAGE", "VERSION", "STATUS", "ADVISORY", "SEVERITY", "DETAILS")
    widths = [max(len(row[i]) for row in [headers, *rows]) for i in range(5)]
    lines = [
        "  ".join(
            value.ljust(width) for value, width in zip(row[:5], widths, strict=True)
        )
        + f"  {row[5]}"
        for row in [headers, *rows]
    ]
    checked = {
        result.package: result
        for result in report.results
        if isinstance(result, ScannedRequirement)
    }
    vulnerable = sum(result.status == "vulnerable" for result in checked.values())
    advisory_count = sum(len(result.advisories) for result in checked.values())
    unscanned = sum(result.status == "unscanned" for result in report.results)
    non_applicable = sum(result.status == "non_applicable" for result in report.results)
    lines.extend(
        [
            "",
            f"Checked {len(checked)} unique package/version pairs: "
            f"{vulnerable} vulnerable, {len(checked) - vulnerable} with no known "
            f"vulnerabilities; {advisory_count} advisories.",
            f"Declarations: {unscanned} unscanned, {non_applicable} non-applicable.",
            "Scan incomplete." if report.exit_code == 2 else "Scan complete.",
        ]
    )
    return "\n".join(lines)


def write_json(report: ScanReport, path: Path) -> None:
    """Write UTF-8 JSON; filesystem errors are handled by the CLI."""
    path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")

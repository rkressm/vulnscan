"""Arguments, scan orchestration, and predictable process exit codes."""

import argparse
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from depscan.models import (
    FailedLookup,
    ReadyRequirement,
    ScanError,
    ScannedRequirement,
    ScanReport,
    ScanResult,
    UnscannedRequirement,
)
from depscan.osv import lookup_packages
from depscan.report import render_terminal, write_json
from depscan.requirements import read_requirements


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description=(
            "Scan declared Python dependencies for known vulnerabilities using OSV."
        ),
    )
    parser.add_argument("--version", action="version", version=version("depscan"))
    parser.add_argument(
        "requirements", type=Path, help="UTF-8 requirements file to scan"
    )
    parser.add_argument(
        "--json", type=Path, metavar="PATH", help="also export a JSON report"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="bypass caching (all lookups currently use live OSV data)",
    )
    args = parser.parse_args(argv)
    # Protect the root input and source files represented in the results.
    try:
        requirements = read_requirements(args.requirements)
        if args.json is not None:
            try:
                output = args.json.resolve()
                overwrites_input = output == args.requirements.resolve() or any(
                    output == item.source.path.resolve() for item in requirements
                )
            except (OSError, ValueError) as exc:
                print(f"depscan: invalid JSON output path: {exc}", file=sys.stderr)
                return 2
            if overwrites_input:
                print(
                    "depscan: JSON output must not overwrite an input file.",
                    file=sys.stderr,
                )
                return 2

        scanned_at = datetime.now(UTC)
        lookups = {
            result.package: result
            for result in lookup_packages(
                item.package
                for item in requirements
                if isinstance(item, ReadyRequirement)
            )
        }
        results: list[ScanResult] = []
        errors: list[ScanError] = []
        for item in requirements:
            if isinstance(item, ReadyRequirement):
                # OSV uses normalized names; the requirements reader does too.
                package = item.package
                lookup = lookups[package]
                if isinstance(lookup, FailedLookup):
                    results.append(
                        UnscannedRequirement(
                            source=item.source, name=package.name, reason=lookup.reason
                        )
                    )
                    errors.append(ScanError(source=item.source, reason=lookup.reason))
                else:
                    results.append(
                        ScannedRequirement(
                            source=item.source,
                            package=package,
                            status=(
                                "vulnerable"
                                if lookup.advisories
                                else "no_known_vulnerabilities"
                            ),
                            advisories=lookup.advisories,
                        )
                    )
            else:
                results.append(item)
                if isinstance(item, UnscannedRequirement):
                    errors.append(ScanError(source=item.source, reason=item.reason))

        report = ScanReport(
            scanned_at=scanned_at, results=tuple(results), errors=tuple(errors)
        )
        if args.json is not None:
            try:
                write_json(report, args.json)
            except (OSError, UnicodeError, ValueError) as exc:
                error = ScanError(reason=f"Cannot write JSON report {args.json}: {exc}")
                report = report.model_copy(update={"errors": (*report.errors, error)})
                print(f"depscan: {error.reason}", file=sys.stderr)
        print(render_terminal(report))
        return report.exit_code
    except BrokenPipeError:
        return 2
    except KeyboardInterrupt:
        print("depscan: scan interrupted; results are incomplete.", file=sys.stderr)
        return 2

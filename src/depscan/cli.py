"""Arguments, scan orchestration, and predictable process exit codes."""

import argparse
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Literal

from depscan.cache import LookupCache
from depscan.models import (
    FailedLookup,
    ReadyRequirement,
    ScanError,
    ScannedRequirement,
    ScanReport,
    ScanResult,
    SourceSummary,
    UnscannedRequirement,
)
from depscan.osv import lookup_packages
from depscan.project import read_sources
from depscan.report import render_terminal, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description=(
            "Scan declared Python and JavaScript dependencies for known "
            "vulnerabilities using OSV."
        ),
    )
    parser.add_argument("--version", action="version", version=version("depscan"))
    parser.add_argument(
        "requirements",
        type=Path,
        help="Python/JavaScript project directory or dependency file",
    )
    parser.add_argument(
        "--venv",
        type=Path,
        metavar="PATH",
        help="read Python installed versions from this venv without executing its code",
    )
    parser.add_argument(
        "--json", type=Path, metavar="PATH", help="also export a JSON report"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="bypass both cache reads and writes; query live OSV data",
    )
    args = parser.parse_args(argv)
    # Track all inputs, including included files with no declarations.
    try:
        discovery, reads = read_sources(args.requirements, venv=args.venv)
        input_paths = set(discovery.input_paths)
        requirements = [item for read in reads for item in read.requirements]
        errors = [
            error for selection in discovery.selections for error in selection.errors
        ]
        summaries: list[SourceSummary] = []
        read_by_ecosystem = {read.source.ecosystem: read for read in reads}
        for selection in discovery.selections:
            read = read_by_ecosystem.get(selection.ecosystem)
            status: Literal["success", "failed", "absent", "ambiguous"]
            if read is None:
                assert selection.status != "selected"
                status = selection.status
            else:
                status = read.status
            summaries.append(
                SourceSummary(
                    ecosystem=selection.ecosystem,
                    status=status,
                    source=read.source if read else None,
                    candidates=selection.candidates,
                )
            )
            detail = (
                f"selected {read.source.path} ({read.status})"
                if read
                else selection.status
            )
            print(f"{selection.ecosystem} dependency source: {detail}", file=sys.stderr)
            input_paths.update(candidate.path for candidate in selection.candidates)
        for read in reads:
            input_paths.update(read.input_paths)
            input_paths.add(read.source.path)
            errors.extend(read.errors)
        input_paths.update(item.source.path for item in requirements)
        # Include explicit inputs even when discovery could not inspect them.
        if not args.requirements.is_dir():
            input_paths.add(args.requirements.absolute())
        detected = tuple(
            selection.ecosystem
            for selection in discovery.selections
            if selection.status != "absent"
        )
        if not detected:
            errors.append(
                ScanError(
                    reason=(
                        "No supported dependency sources found in "
                        f"{args.requirements}."
                    )
                )
            )
        if args.json is not None:
            try:
                output = args.json.resolve()
                overwrites_input = _overwrites_input(output, input_paths)
            except (OSError, ValueError, RuntimeError) as exc:
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
                (
                    item.package
                    for item in requirements
                    if isinstance(item, ReadyRequirement)
                ),
                cache=None if args.no_cache else LookupCache(),
            )
        }
        results: list[ScanResult] = []
        for item in requirements:
            if isinstance(item, ReadyRequirement):
                # OSV uses normalized names; the requirements reader does too.
                package = item.package
                lookup = lookups[package]
                if isinstance(lookup, FailedLookup):
                    results.append(
                        UnscannedRequirement(
                            ecosystem=package.ecosystem,
                            source=item.source,
                            name=package.name,
                            reason=lookup.reason,
                        )
                    )
                    errors.append(
                        ScanError(
                            ecosystem=package.ecosystem,
                            source=item.source,
                            reason=lookup.reason,
                        )
                    )
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
                            looked_up_at=lookup.looked_up_at,
                        )
                    )
            else:
                results.append(item)
                if isinstance(item, UnscannedRequirement):
                    errors.append(
                        ScanError(
                            ecosystem=item.ecosystem,
                            source=item.source,
                            reason=item.reason,
                        )
                    )

        report = ScanReport(
            scanned_at=scanned_at,
            results=tuple(results),
            errors=tuple(dict.fromkeys(errors)),
            detected_ecosystems=detected,
            sources=tuple(summaries),
            input_paths=tuple(sorted(input_paths)),
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


def _overwrites_input(output: Path, input_paths: set[Path]) -> bool:
    """Fail closed on comparison errors; resolve every input, including aliases."""
    collision = False
    for path in sorted(input_paths):
        resolved = path.resolve()
        if output == resolved:
            collision = True
        # stat rather than exists: permission/IO errors must not authorize writing.
        try:
            path.stat()
        except FileNotFoundError:
            continue
        try:
            output.stat()
        except FileNotFoundError:
            continue
        if output.samefile(path):
            collision = True
    return collision

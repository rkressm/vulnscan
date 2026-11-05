"""Arguments, scan orchestration, and predictable process exit codes."""

import argparse
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from depscan.cache import LookupCache
from depscan.models import (
    DependencySource,
    FailedLookup,
    ReadyRequirement,
    ScanError,
    ScannedRequirement,
    ScanReport,
    ScanResult,
    SourceKind,
    SourceSummary,
    UnscannedRequirement,
)
from depscan.osv import lookup_packages
from depscan.project import read_project
from depscan.report import render_terminal, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description=(
            "Scan declared Python dependencies for known vulnerabilities using OSV."
        ),
    )
    parser.add_argument("--version", action="version", version=version("depscan"))
    parser.add_argument(
        "requirements", type=Path, help="Python project directory or dependency file"
    )
    parser.add_argument(
        "--venv",
        type=Path,
        metavar="PATH",
        help="read installed versions from this venv without executing its code",
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
        input_paths: set[Path] = set()
        source_errors: list[ScanError] = []
        selected, requirements = read_project(
            args.requirements,
            venv=args.venv,
            input_paths=input_paths,
            source_errors=source_errors,
        )
        if args.requirements.is_dir():
            print(f"Dependency source: {selected}", file=sys.stderr)
        if args.json is not None:
            try:
                output = args.json.resolve()
                protected_paths = {
                    args.requirements.resolve(),
                    selected.resolve(),
                    *input_paths,
                    *(item.source.path.resolve() for item in requirements),
                }
                overwrites_input = output in protected_paths or (
                    output.exists()
                    and any(
                        path.exists() and output.samefile(path)
                        for path in protected_paths
                    )
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
                (
                    item.package
                    for item in requirements
                    if isinstance(item, ReadyRequirement)
                ),
                cache=None if args.no_cache else LookupCache(),
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

        kinds: dict[str, SourceKind] = {
            "uv.lock": "uv",
            "poetry.lock": "poetry",
            "Pipfile.lock": "pipfile",
            "pyproject.toml": "pyproject",
        }
        source = (
            None
            if selected.is_dir()
            else DependencySource(
                ecosystem="PyPI",
                path=selected.absolute(),
                kind=kinds.get(selected.name, "requirements"),
            )
        )
        summary = SourceSummary(
            ecosystem="PyPI",
            status="absent"
            if source is None
            else "failed"
            if source_errors
            else "success",
            source=source,
            candidates=(source,) if source else (),
        )
        report = ScanReport(
            scanned_at=scanned_at,
            results=tuple(results),
            errors=tuple(errors),
            detected_ecosystems=("PyPI",) if source else (),
            sources=(summary,),
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

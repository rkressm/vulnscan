"""Command-line entry point. Scanning will be implemented separately."""

import argparse
from importlib.metadata import version


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description=(
            "Scan declared Python dependencies for known vulnerabilities using OSV."
        ),
    )
    parser.add_argument("--version", action="version", version=version("depscan"))
    parser.parse_args()
    parser.exit(2, "depscan: scanning is not implemented yet.\n")

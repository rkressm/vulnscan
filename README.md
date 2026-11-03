# depscan

[![Checks](https://github.com/rkressm/vulnscan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/rkressm/vulnscan/actions/workflows/checks.yml)

Check a Python project's dependencies for known vulnerabilities using [OSV](https://osv.dev/).
Get a readable terminal report, export JSON, and see exactly what couldn't be checked.

## Quick install

Requires **Python 3.14+** and [uv](https://docs.astral.sh/uv/getting-started/installation/).
uv can install Python for you if needed.

```sh
git clone https://github.com/rkressm/vulnscan.git
cd vulnscan
uv sync --locked
```

No need to activate a virtual environment. These commands install from source.

## Usage

From the depscan directory, point it at a Python project or a dependency file:

```sh
uv run depscan .
uv run depscan /path/to/project --json report.json
uv run depscan /path/to/project --no-cache
uv run depscan /path/to/project --venv /path/to/project/.venv
uv run depscan /path/to/requirements.txt
uv run depscan --help
uv run depscan --version
```

Directories are checked in this order: **`uv.lock` → `poetry.lock` → `Pipfile.lock`
→ `pyproject.toml` → `requirements.txt`**. The selected file is printed to stderr.
To override detection, pass the file directly. A broken lockfile is reported,
not silently replaced with another file.

Successful lookups are cached for **24 hours**. Use `--no-cache` to bypass the
cache and fetch current data: cached results may miss newly published advisories.
Failed lookups are never cached, and expired data isn't used when OSV is unavailable.
OSV pagination is followed automatically; a failed page makes the lookup incomplete,
not a clean result. Repeated tokens or more than 100 pages also fail the lookup.

### Reading the results

- **Vulnerable:** known advisories, with identifiers, severity, and links.
- **No known vulnerabilities:** OSV returned no advisories—not a guarantee of safety.
- **Unscanned:** something couldn't be checked; the report explains why.
- **Non applicable:** an environment marker excluded the requirement.

Missing severity is shown as `UNKNOWN`; depscan doesn't infer ratings from CVSS vectors.
The summary counts unique package/version pairs separately from advisory totals.

For scripts and CI, exit codes are **0** for no known vulnerabilities, **1** when
vulnerabilities are found, and **2** for errors or incomplete scans—even if findings
were also reported. Excluded markers don't make a scan incomplete.

JSON reports include a schema version, scan and lookup timestamps, source locations,
results, and errors. The output directory must already exist.
Exports are atomic: a failed write preserves the previous report.

## What it checks

- Exact pins such as `requests==2.31.0` are checked as declared.
- Lockfiles provide exact versions, including transitive dependencies. All recorded
  registry versions are checked, including development, optional, and other-platform
  entries; this is a lockfile audit, not a reconstruction of your active environment.
- `pyproject.toml` supports static `[project].dependencies`, not optional dependencies,
  dependency groups, dynamic declarations, or legacy Poetry declarations.
- Without a lockfile, ranges and unpinned names need **`--venv PATH`** for project
  scans. depscan reads that environment's package metadata without running its code.
  Missing or incompatible versions are reported as unscanned.
- Explicit requirements-file scans still use depscan's installed environment unless
  `--venv` is supplied. Environment markers are evaluated on the Python running
  depscan, so use the target platform and Python when scanning manifests.
- Comments, environment markers, extras, and relative requirements-file includes work.

Without a lockfile, only declared dependencies are checked; extras don't discover
additional dependencies. URLs, editable dependencies, local paths, and pip options
are reported as unscanned. uv's root project and virtual workspace entries are
excluded from registry checks. Registry packages are looked up in OSV's PyPI ecosystem.
Automatic fixes and other language ecosystems aren't supported, and depscan never
installs the packages it scans.

Live lookups require internet access and send package names and versions to public OSV.
Results depend on its coverage and freshness.

The files in [`examples/`](examples/) demonstrate supported and unsupported inputs.
**Don't install those requirements.**

## Development

Run the offline tests and code checks:

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

Normal tests are offline and mock HTTP responses. GitHub Actions runs the same
checks on pushes and pull requests using the locked dependencies.

### Architecture

In `src/depscan/`, `cli.py` orchestrates scanning and exit codes;
`project.py` detects manifests and reads lockfiles; `requirements.py` parses
declarations and selects versions; `osv.py` performs HTTP
lookups and interprets advisories; and `cache.py` handles expiring local storage.
`models.py` defines validated shared data, while `report.py` renders terminal and
JSON output without networking. Corresponding behavior tests live in `tests/`.

## Next steps

- Support optional dependency groups in `pyproject.toml`.
- Batch OSV queries while preserving per-package failure reporting.
- Add Windows and macOS CI coverage.

## License

[MIT](LICENSE).

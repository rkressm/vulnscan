# depscan

[![Checks](https://github.com/rkressm/vulnscan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/rkressm/vulnscan/actions/workflows/checks.yml)

## Goal

depscan aims to check declared Python dependencies for known vulnerabilities using
the public [OSV](https://osv.dev/) database, with clear results for dependencies
that cannot be checked.

**Current status:** CLI scanning, terminal reports, and JSON export are implemented.
Persistent caching is planned for Day 4. See [plan.md](plan.md) for the roadmap.

## Quick install

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run
from the project directory:

```sh
uv sync --locked
```

The project requires Python 3.14 or newer; uv can install Python automatically
if needed. You do not need to activate the virtual environment.

## Usage

Scan a requirements file, optionally saving a JSON report:

```sh
uv run depscan requirements.txt
uv run depscan requirements.txt --json report.json
uv run depscan requirements.txt --no-cache
uv run depscan --help
uv run depscan --version
```

Scanning makes requests to the public OSV API. `--no-cache` is accepted now;
all lookups currently use live data, with no persistent cache.

Terminal output distinguishes **vulnerable**, **no known vulnerabilities**,
**unscanned**, and **non applicable** declarations. Advisory rows include the
identifier, published severity (or `UNKNOWN`), and an OSV details link. Unscanned
and excluded declarations include their source filename, line, and reason.

The summary counts checked package/version pairs once, separately reporting
vulnerable pairs and advisory totals. The same advisory affecting two distinct
pairs counts twice. Duplicate declarations remain visible in terminal and JSON
results but do not inflate these totals. Unscanned and non-applicable counts
are counts of declarations (including file/include errors).

Exit codes:

- `0`: completed scan, no known vulnerabilities.
- `1`: completed scan, vulnerabilities found.
- `2`: invalid input, failed lookup, incomplete scan, or failed report export,
  even when vulnerabilities were also found.

Excluded environment markers do not make a scan incomplete. Empty files complete
with zero checked packages; this is not a claim about undeclared dependencies.

JSON export uses `schema_version: 1`, a UTC scan-start timestamp (`scanned_at`),
`results`, and `errors`. Each result preserves its source location and declaration.
Statuses are `vulnerable`, `no_known_vulnerabilities`, `unscanned`, and
`non_applicable`. Completed lookups include the package/version and advisories;
other results include a reason. `errors` lists failures with their source location
(or `null` for a report-wide failure). A failed lookup is never exported as a
successful empty advisory list. The destination's parent directory must exist.

### Requirements file support

- Exact pins use the declared version. Ranges and unpinned dependencies need a
  matching version installed in the Python environment running depscan.
- Comments, environment markers, extras, and relative `-r` / `--requirement`
  includes are supported. Extras do not discover additional dependencies.
- URLs, editable dependencies, local packages, and pip options are unsupported
  and reported as `unscanned`, along with unreadable files and include cycles.

Do not install the example requirements; they intentionally demonstrate missing,
excluded, and unsupported dependencies.

### OSV lookups (Python API)

The lookup client accepts selected package versions independently of the reader:

```python
from depscan.models import PackageVersion
from depscan.osv import lookup_packages

results = lookup_packages([PackageVersion(name="requests", version="2.31.0")])
for result in results:
    print(result.model_dump_json())
```

This makes real requests to the public OSV API. Each normalized package name and
exact version is queried once per call, with a 5-second connection timeout and a
30-second read timeout. These are not a total scan deadline. No persistent cache
or automatic retries are used yet.

Results have status `success` with an `advisories` list (empty means **no known
vulnerabilities**), or `failed` with a reason. Failed lookups never become empty
successful results. Each advisory includes its identifier, an OSV details link,
and severity. Severity copies recognized `database_specific.severity` labels
(`LOW`, `MODERATE`, `MEDIUM`, `HIGH`, `CRITICAL`, case-insensitive); missing or
unrecognized labels, including CVSS-only data, produce `UNKNOWN`. CVSS vectors
are not scored and ratings are not inferred.

## Development

Run the offline tests and code checks:

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

Source code is in `src/depscan/`, and tests are in `tests/`.

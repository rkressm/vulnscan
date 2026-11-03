# depscan

## Goal

depscan aims to check declared Python dependencies for known vulnerabilities using
the public [OSV](https://osv.dev/) database, with clear results for dependencies
that cannot be checked.

**Current status:** reading requirements files and selecting package versions work.
Vulnerability lookups and CLI scanning are not implemented yet. See
[plan.md](plan.md) for the roadmap.

## Quick install

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run
from the project directory:

```sh
uv sync --locked
```

The project requires Python 3.14 or newer; uv can install Python automatically
if needed. You do not need to activate the virtual environment.

## Usage

Show the available CLI options or package version:

```sh
uv run depscan --help
uv run depscan --version
```

Running `uv run depscan` currently exits with an error explaining that scanning is
not implemented. To try the requirements reader, run this Python example from
the project directory:

```sh
uv run python - <<'PY'
from depscan.models import ReadyRequirement
from depscan.requirements import read_requirements

for result in read_requirements("examples/requirements.txt"):
    location = f"{result.source.path}:{result.source.line}"
    if isinstance(result, ReadyRequirement):
        detail = f"{result.package.name}=={result.package.version}"
    else:
        detail = result.reason
    print(f"{location}: {result.status}: {detail}")
PY
```

Replace `examples/requirements.txt` with your own file to read its dependencies.
The reader does not install packages or make network requests.

Results are `ready` (a version was selected), `non_applicable` (excluded by an
environment marker), or `unscanned` (unsupported or unresolved). **`ready` does
not mean vulnerability-free.**

### Requirements file support

- Exact pins use the declared version. Ranges and unpinned dependencies need a
  matching version installed in the Python environment running depscan.
- Comments, environment markers, extras, and relative `-r` / `--requirement`
  includes are supported. Extras do not discover additional dependencies.
- URLs, editable dependencies, local packages, and pip options are unsupported
  and reported as `unscanned`, along with unreadable files and include cycles.

Do not install the example requirements; they intentionally demonstrate missing,
excluded, and unsupported dependencies.

## Development

Run the offline tests and code checks:

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

Source code is in `src/depscan/`, and tests are in `tests/`.

# Python and JavaScript scanning validation

## Scope

The v2 implementation extends depscan's existing Python scanner with npm, Yarn,
pnpm, and Bun text-lock readers. Package version remains `0.1.0`; JSON reports
and cache files use schema version 2. The supported-format list and user-facing
limitations are maintained in `README.md`.

## Release gate

T12 and T13 were independently reviewed and merged. At final implementation
checkpoint `cc83e28`, all **1,462 offline tests** passed, along with Ruff lint,
Ruff format checks, mypy, and diff whitespace checks. No v2 acceptance blockers
remain. The dependency lockfile is unchanged from the session baseline `6b96272`.

The final wheel was rebuilt, installed into a disposable Python environment,
and passed all **1,462 tests** against that installed package. The separate
17-format/file smoke harness also passed, covering help/version, mixed exits
0/1/2, binary Bun diagnostics, and empty sources with real network, subprocess,
and cache access forbidden. The installed CLI entry point's help/version work.

Validation commands (cached Python dependencies; no project dependency install):

Local tools: Python 3.14.4, uv 0.12.22, pytest 9.2.0, Ruff 0.17.3, and mypy 2.4.1.

```sh
uv run --offline --frozen pytest -q
uv run --offline --frozen ruff check .
uv run --offline --frozen ruff format --check .
uv run --offline --frozen mypy
git diff --check
uv build --offline
```

## Earlier source validation

- At `bbccc2e`, all 1,246 offline tests, Ruff lint/format checks, mypy, and diff
  whitespace checks passed. Independent standards and specification audits of
  `6b96272...bbccc2e` reported no findings.
- The installed wheel passed the same 1,246 tests and a separate smoke harness:
  17 supported-format/file cases, help/version, mixed exits 0/1/2, unsupported
  binary Bun, and successful empty sources. HTTP was mocked; real network,
  subprocess, and cache access were forbidden, with an empty executable `PATH`.
- Full upstream npm, Bun, Yarn Classic/modern metadata 4/6/8/10, and pnpm 6/9
  lockfiles parsed successfully without entry errors. Unsupported records stayed
  explicitly unscanned. Fixture provenance and exact source revisions are in
  `tests/fixtures/` and the historical implementation contract.
- Packaging checks confirmed that the existing ignored
  `src/depscan/report.json` is preserved locally and excluded from the source
  archive, source-derived wheel, and direct wheel.

## Documentation and artifact checkpoint

T12 was independently reviewed and merged at `4698a0d`. All 1,250 tests passed
both in the source environment and against the installed wheel, as did the
17-case smoke harness. GitHub Checks passed for that commit.

The source archive and both wheel build paths were independently inspected:
all 15 Python modules match the source, wheel RECORD hashes/sizes validate,
and direct/source-derived wheels are byte-identical. Version, Python requirement,
dependencies, description, README, license, and entry point match configuration.
No local report, planning files, or virtual environment files are shipped.

## Coverage boundaries

- Discovery is root-only, not a complete recursive workspace audit.
- Unknown lock versions and binary `bun.lockb` remain unsupported.
- Unresolved declarations, unverifiable registry identities, workspace/local
  records, and applied patches retain explicit incomplete-coverage diagnostics.
- Live vulnerability scans require OSV connectivity. Offline tests use mocked
  responses; validation does not certify dependencies as vulnerability-free.
- No project packages, package-manager commands, or lifecycle scripts are run.

## Regression evidence

- Discovery/selection and Python compatibility: `tests/test_discovery.py`,
  `tests/test_project.py`, `tests/test_requirements.py`, and `tests/test_cli.py`.
- Advertised JavaScript formats and malformed/non-registry records:
  `tests/test_npm.py`, `tests/test_yarn.py`, `tests/test_pnpm.py`, and
  `tests/test_bun.py`, with provenance notes in their fixture directories.
- Ecosystem identity, query/cache isolation, and schema-v2 output:
  `tests/test_models.py`, `tests/test_osv.py`, `tests/test_cache.py`, and
  `tests/test_report.py`.
- Inert documentation examples: `tests/test_v2_examples.py`.
- Independent cross-component regressions: `tests/test_v2_integration.py`
  (**212 cases**). These cover mixed failures, ecosystem/cache separation,
  input protection, environment selection, empty/ambiguous states, and parsing
  without package-manager executables. Independent review findings were fixed;
  four in-memory mutation probes demonstrated that the tested faults are caught.
- Local-report packaging exclusion: `tests/test_build_config.py`.

# Offline cross-component fixtures (T13)

`tests/test_v2_integration.py` creates minimal **synthetic**, inert documents in
pytest temporary directories. They are not package-manager-generated evidence or
installable examples. Names such as demo, integrity `synthetic`, example.invalid
URLs, lifecycle/code sentinels and fake environment metadata are deliberate test
data. No project packages, scripts, managers or network resources are executed.

Accepted-format cases exercise the integrated CLI for npm package-lock and
shrinkwrap 1/2/3, Classic Yarn v1, modern Yarn metadata 4/6/8/10, pnpm 6.0/9.0
(documented numeric/string spellings), Bun text v1 JSONC, and package.json.
Manager executables are absent from PATH; subprocesses and real HTTP/socket
connections fail the tests. Only mocked OSV POST responses are allowed.

Two existing synthetic fixtures are copied byte-for-byte into temporary roots:

- `../yarn/wrappers.lock`: grouped alias descriptors, virtual/patch wrappers and
  workspace limits. See `../yarn/README.md` for pinned grammar authority and the
  distinction between real upstream patch identity and synthetic wrapper cases.
- `../pnpm/contexts.yaml`: importer aliases, peer variants, distinct versions,
  patches and non-registry/workspace coverage. See `../pnpm/README.md` for grammar
  authority and fixture provenance.

These intentionally incomplete inventories must exit 2 while preserving usable
registry lookups. Reader-specific suites retain exhaustive syntax/version tests;
T13 checks the discovery/read/lookup/cache/report and export-protection boundaries.

Manager-hint success cases include competing managers and stale same-manager
siblings, proving selection reaches the intended reader and OSV identity. A small
unsupported-format matrix (including selected binary Bun) proves these inputs
remain source failures while Python findings survive. Detailed rejection syntax
stays in reader unit tests.

The HTTP timeout tuple, PyPI-then-npm source ordering, and document-level line 1
are deliberately asserted as the current implementation contract, not inferred
from terminal snapshots. Isolated metadata tests stub only the CLI's own version
string; dependency metadata discovery uses real temporary distributions/archives.

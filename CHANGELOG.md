# Changelog

## Unreleased

- Scan Python and JavaScript dependency ecosystems independently at a supplied
  project root, with combined/per-ecosystem results and isolated source failures.
- Add exact-pin `package.json`, npm lock/shrinkwrap v1/v2/v3, Yarn Classic v1,
  modern Yarn metadata 4/6/8/10, pnpm 6.0/9.0 and Bun text v1 readers. Binary
  `bun.lockb` remains unsupported, with external migration guidance.
- Preserve Python version-selection behavior; `--venv` applies only to Python.
  Parsing never installs dependencies or invokes project code/package managers.
- **Breaking report change:** JSON schema 2 adds ecosystem-aware identities,
  detected ecosystems, source statuses/candidates, contextual failures and input
  paths. Update schema-1 consumers; package version remains **0.1.0**.
- **Cache transition:** schema 2 isolates ecosystems. Legacy/unversioned caches
  are ignored rather than migrated, then atomically replaced on a saved successful
  lookup. Preserve 24-hour expiry and `--no-cache` read/write bypass.
- Protect detected/read inputs, includes and version-selection metadata against
  JSON overwrite, including symlink/hardlink aliases.
- Add inert JavaScript-only and mixed examples with offline mocked-OSV smoke tests.
  Discovery remains root-only; incomplete workspace, unresolved declarations and
  upstream-only patch coverage remain visible, not clean-scan claims.

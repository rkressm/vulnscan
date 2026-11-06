# depscan

[![Checks](https://github.com/rkressm/vulnscan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/rkressm/vulnscan/actions/workflows/checks.yml)

Check Python and JavaScript dependencies for known vulnerabilities using [OSV](https://osv.dev/).
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

From the depscan directory, point it at a project or a dependency file:

```sh
uv run depscan .
uv run depscan /path/to/project --json report.json
uv run depscan /path/to/project --no-cache
uv run depscan /path/to/project --venv /path/to/project/.venv
uv run depscan /path/to/requirements.txt
uv run depscan /path/to/package.json
uv run depscan /path/to/package-lock.json
uv run depscan /path/to/yarn.lock
uv run depscan /path/to/pnpm-lock.yaml
uv run depscan /path/to/bun.lock
uv run depscan --help
uv run depscan --version
```

### Detection and source selection

- Directory scans inspect **only the supplied root**, selecting Python and
  JavaScript independently and scanning both when present. This detects dependency
  ecosystems, not proof of every language used; TypeScript also uses OSV's `npm`.
- Python precedence: **`uv.lock` → `poetry.lock` → `Pipfile.lock`
  → `pyproject.toml` → `requirements.txt`**.
- JavaScript prefers a lockfile over `package.json`; `npm-shrinkwrap.json` beats
  `package-lock.json`, and text `bun.lock` beats binary `bun.lockb`.
- With locks from multiple managers, a valid `package.json#packageManager` hint
  such as `pnpm@9.15.9` selects a matching available manager. Recognized managers
  are npm, yarn, pnpm and bun, with an exact version and optional SHA-224/256/384/512
  hex metadata. Absent, invalid, unsupported or conflicting hints cause ambiguity:
  pass a lockfile explicitly. A malformed manifest needed for selection is an error.
  With just one lock manager, its lock wins regardless of the hint.
- Detected ecosystem/source statuses are printed to stderr, including empty sources.
  A selected broken lock never falls back to another file. One ecosystem failing
  does not prevent results for the other, but the overall scan is incomplete.
  No supported source is an error (exit 2), not a clean empty scan.
- Explicit file inputs scan only that file; lockfiles work without `package.json`.
  Other filenames retain the Python requirements-file fallback.
- Nested projects and workspace member manifests are **not discovered recursively**.
  Pass each nested project's directory/file explicitly. Workspace containers/links
  are excluded from registry queries; available external lock inventory is checked,
  but missing workspace coverage is reported. This is not a complete workspace audit.

### Cache

Successful lookups are cached for **24 hours**. Use `--no-cache` to bypass
cache reads **and writes** and fetch current data: cached results may miss newly
published advisories.
Failed lookups are never cached, and expired data isn't used when OSV is unavailable.
OSV pagination is followed automatically; a failed page makes the lookup incomplete,
not a clean result. Repeated tokens or more than 100 pages also fail the lookup.

Cache schema 2 separates `(ecosystem, canonical package name, exact version)`
identities. Legacy/unversioned caches are ignored, not migrated; the next saved
successful lookup atomically replaces them. No manual deletion is needed.
Successful empty results are cached too. The default file is `depscan/osv.json`
under the platform's user cache directory; cache IO failures do not block scanning.

### Reading the results

- **Vulnerable:** known advisories, with identifiers, severity, and links.
- **No known vulnerabilities:** OSV returned no advisories—not a guarantee of safety.
- **Unscanned:** something couldn't be checked; the report explains why.
- **Non applicable:** an environment marker excluded the requirement.

Missing severity is shown as `UNKNOWN`; depscan doesn't infer ratings from CVSS vectors.
Combined and per-ecosystem summaries count unique ecosystem/name/version identities
separately from advisory totals. Repeated declarations retain source provenance.

For scripts and CI, exit codes are **0** for no known vulnerabilities, **1** when
vulnerabilities are found, and **2** for errors or incomplete scans—even if findings
were also reported. Excluded markers don't make a scan incomplete.

### JSON schema 2

JSON exports now use **`schema_version: 2`**, a breaking change for schema-1 consumers
(not a package version bump). They retain scan/lookup timestamps, advisory details,
source locations, results and errors, and add:

- `detected_ecosystems` (`PyPI`, `npm`), including failed/ambiguous detection.
- `sources`: ecosystem, status (`success`, `failed`, `absent`, `ambiguous`), selected
  `source` and `candidates`. Directory scans include absent ecosystems; explicit
  files describe only their ecosystem. Selection failures may have a null source.
- `input_paths`: detected inputs and files read or attempted, including includes
  and Python version-selection metadata.
- `package.ecosystem` on checked results; ecosystem context on unscanned results
  and source/lookup errors. Global errors can have a null ecosystem.

Source `success` means the document was read, not that every entry or lookup was
covered. A valid empty inventory can complete with exit 0; failed/unsupported
sources cannot masquerade as empty clean scans. Source errors are recorded at
report level. Document parsers use line 1 plus entry descriptions when exact lines
are unavailable.

The output directory must already exist. Exports are atomic: a failed write
preserves the previous report. Output cannot overwrite detected/read inputs,
including unselected manifests, includes and environment metadata, even through
symlink or hardlink aliases.

## What it checks

Lock scans audit recorded registry inventory, not an active installation: all
recorded development, optional, transitive and other-platform entries are included.
Distinct versions survive; identical identities are queried once. depscan does not
verify downloaded artifacts or integrity hashes, or prove a lock is up to date.

### Python

- Exact pins such as `requests==2.31.0` are checked as declared.
- `uv.lock`, `poetry.lock` and `Pipfile.lock` provide recorded exact versions.
- `pyproject.toml` supports static `[project].dependencies`, not optional dependencies,
  dependency groups, dynamic declarations, or legacy Poetry declarations.
- Without a lockfile, ranges and unpinned names need **`--venv PATH`** for project
  scans. depscan reads that environment's package metadata without running its code.
  Missing or incompatible versions are reported as unscanned.
- Explicit requirements-file scans still use depscan's installed environment unless
  `--venv` is supplied. Environment markers are evaluated on the Python running
  depscan, so use the target platform and Python when scanning manifests.
- Explicit `pyproject.toml` scans, like directory manifest scans, need `--venv`
  for unresolved versions; they do not use depscan's installed packages.
- `--venv` is **Python-only** and ignored for JavaScript-only inputs. When a Python
  source is scanned, a supplied venv must be valid (with `pyvenv.cfg` and a
  site-packages location), even for a lockfile, exact pins or an empty inventory.
  Invalid environments fail Python coverage, not the other ecosystem's scan.
- Comments, environment markers, extras, and relative requirements-file includes work.

Without a lockfile, only declared dependencies are checked; extras don't discover
additional dependencies. URLs, editable dependencies, local paths, and pip options
are reported as unscanned. uv's root project and virtual workspace entries are
excluded from registry checks. Registry packages are looked up in OSV's PyPI ecosystem.

### JavaScript / TypeScript

Supported formats are pinned to these identifiers, not every release of a manager:

- `package.json`: the four groups `dependencies`, `devDependencies`,
  `optionalDependencies` and `peerDependencies`, as objects with string values.
  Checks **exact npm SemVer pins** such as `1.2.3`, scoped names and prereleases;
  optional leading `v` is stripped and build metadata retained. Exact aliases such
  as `npm:@scope/real@1.2.3` query the real target, retaining alias provenance.
- npm `package-lock.json` / `npm-shrinkwrap.json`: integer `lockfileVersion`
  **1, 2, 3**. v1 walks nested entries; v2/v3 use `packages` without scanning the
  duplicate v2 legacy tree. v2/v3 require a `packages` object.
- Yarn Classic `yarn.lock`: mandatory **`# yarn lockfile v1`** preamble, grouped
  selectors and scoped packages. Scoped/digit-leading keys must be double-quoted.
  No headerless dialect, merge-conflict repair or general YAML syntax fallback.
- Modern Yarn `yarn.lock`: integer **`__metadata.version` 4, 6, 8, 10**;
  `cacheKey` is not the format version. Exact npm resolutions supply real identity.
  Virtual/patch wrappers are recovered only when unambiguous (maximum 16 layers).
  Binding-bearing npm locators and malformed alias resolutions remain unscanned.
- pnpm `pnpm-lock.yaml`: **`6.0`, `9.0`** as exact YAML strings or numeric values
  equal to 6/9 (integer 6/9 included), never booleans. Strings `"6"`/`"9"` and
  other minor versions are unsupported. Importers/packages/snapshots are joined;
  recognized exact peer contexts do not become separate package versions.
- Bun text `bun.lock`: integer **`lockfileVersion: 1`** only. JSONC comments and
  trailing commas are supported, along with JSON5 lexical extensions (single
  quotes/unquoted keys); no code evaluation. Registry tuple locators, not install
  keys, supply identity. Binary `bun.lockb` is detected but **not decoded**.

Unknown/missing versions fail explicitly. npm/Bun version identifiers must be
integers, not strings/floats/booleans; the same applies to modern Yarn metadata.
Duplicate keys and malformed documents fail contextually. Entry-local problems
preserve usable siblings while marking coverage incomplete. Detailed grammar,
fixture provenance and edge-case limits are in
[`npm`](tests/fixtures/npm/README.md), [`Yarn`](tests/fixtures/yarn/README.md),
[`pnpm`](tests/fixtures/pnpm/README.md) and [`Bun`](tests/fixtures/bun/README.md).

Important limits:

- Manifest ranges (`^1.2.3`, `~1.2.3`), tags (`latest`), unresolved aliases and
  git/URL/local/workspace declarations are unscanned. Generate a supported lockfile
  **externally**, then supply it. JavaScript never uses `--venv`, depscan's installed
  environment or `node_modules` as a fallback; no network range resolution occurs.
- npm names preserve scopes, dots, underscores and legacy case, unlike PyPI name
  normalization. Alias selectors, paths and peer suffixes are not package names.
- npm/Yarn Classic recognize public npm/Yarn tarball hosts
  (`registry.npmjs.org`, `registry.yarnpkg.com`); custom-host/arbitrary tarballs
  remain unscanned when registry identity cannot be established offline. npm v1
  also accepts recognized registry-relative paths; conflicting identity evidence
  remains unscanned. No resolution URL is fetched.
- pnpm requires exact registry-keyed metadata with nonempty integrity and no
  explicit git/directory/tarball source. Opaque hashed peer contexts, unknown
  suffixes, orphan references and catalog declarations stay visibly unscanned;
  separately recorded trustworthy registry inventory can still be queried.
- Bun's registry tuple shape permits custom registry strings and empty integrity;
  this does not verify their contents. Missing root install keys are unscanned,
  not inferred from a target name or nested key. This presence check does not
  reconstruct the dependency graph or check range satisfaction.
- Recognized registry patches are checked against **upstream** advisories and also
  produce an unscanned diagnostic (exit 2): advisories do not assess the patch.
  Patch files are not read. Local/workspace coverage is never silently assumed.

### Legacy Bun migration (external/manual)

depscan never runs Bun. If you choose to migrate `bun.lockb` yourself, use a Bun
release that writes text lockfile version 1 (text v1 was verified with **1.2.22**).
Upstream's [migration guidance](https://bun.com/docs/pm/lockfile) gives:

```sh
bun install --save-text-lockfile --frozen-lockfile --lockfile-only
```

This is an external package-manager operation and **may populate Bun's cache**;
it is not guaranteed side-effect-free or offline. Inspect the generated `bun.lock`,
confirm `lockfileVersion: 1`, and verify it before manually removing the binary.
Not every Bun release emits a supported format; v0 is unsupported.

### Safety and advisory coverage

depscan never installs scanned dependencies, executes project code/lifecycle
scripts or invokes Node/package managers. Supported parsing needs no Node.js,
npm, Yarn, pnpm or Bun installation. Automatic fixes and ecosystems other than
PyPI/npm are outside its scope. These guarantees do not apply to commands you
choose to run externally.

Live lookups require internet access and send package names and versions to public OSV.
Results depend on its coverage and freshness.

The files in [`examples/`](examples/) demonstrate supported and unsupported inputs.
**Don't install example dependencies or run project scripts.**

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
`discovery.py` selects root sources; `project.py` dispatches readers, with
JavaScript parsers in `javascript/`; `requirements.py` parses Python
declarations and selects versions; `osv.py` performs HTTP
lookups and interprets advisories; and `cache.py` handles expiring local storage.
`models.py` defines validated shared data, while `report.py` renders terminal and
JSON output without networking. Corresponding behavior tests live in `tests/`.

## Next steps

- Support optional dependency groups in `pyproject.toml`.
- Recursive nested-project discovery and complete workspace-aware coverage.
- Batch OSV queries while preserving per-package failure reporting.
- Add Windows and macOS CI coverage.

## License

[MIT](LICENSE).

# v2 implementation contract (T01 → T02)

This is a preparation contract, not a claim that JavaScript readers exist yet.
T02 implements and tests the types below before the parallel wave. Subsequent
interface changes require the coordinator's decision. `plan-v2.md` sections 1–4
and 7 remain the acceptance criteria.

## Baseline and isolation

- Base: `746a87677e54f928bea3ed83ca5f639910505e24` (resolved from `746a876`).
- Branch: `agent/T01`; worktree:
  `/home/remi/Développement/smallprojects/vulnscanner-T01-20261105`.
- Initial tracked and nonignored untracked changes: none. Main checkout ignored
  state included `.venv`, tool caches, `dist`, Python bytecode, `plan.md`,
  `plan-v2.md`, and `src/depscan/report.json`; all preserved. `AGENT.md` was read
  in the main checkout along with the entire plan before creating the worktree.
- Actual UTC environment time at start: `2026-11-05T11:39:51+00:00`.
- Baseline commands, all in the worktree, using cached Python dependencies only:
  `uv run --offline --frozen pytest`: **210 passed**;
  `uv run --offline --frozen ruff check .`: **passed**;
  `uv run --offline --frozen ruff format --check .`: **17 files formatted**;
  `uv run --offline --frozen mypy`: **15 source files, no issues**.
  No pre-existing check failures.

## Parser dependencies and release evidence

Stdlib `json`/`tomllib` remain the choices for JSON/TOML. Stdlib has neither YAML
nor JSONC. Regex comment removal corrupts strings such as URLs and is unsuitable.

Selected, explained in commentary before editing dependencies:

- `ruamel.yaml==0.19.1`: safe YAML 1.2 loader, rejects duplicate keys by default,
  typed Python package, pure-Python operation without optional C extensions.
  Use `YAML(typ="safe", pure=True)` and `allow_duplicate_keys = False`. Validate
  loaded shapes explicitly. Never use the unsafe loader. Safe loading still
  needs malformed/recursive input handling; convert parser exceptions and
  `RecursionError` to a contextual failed read, never a clean empty result.
- `json5==0.17.3` (distribution `json5`, import `json5`, repository
  `dpranke/pyjson5`, **not** the separate `pyjson5` distribution): handles comments,
  escaped strings and trailing commas. Use
  `json5.loads(text, allow_duplicate_keys=False)`, then validate Bun shapes and
  exact format identifier. This accepts a JSON5 lexical superset of JSONC, not
  arbitrary JavaScript; document that permissiveness. It is slower than stdlib
  JSON and can raise `RecursionError`. No execution/eval is involved.

Alternatives inspected through registry metadata: PyYAML 6.0.3 is mature and has
no runtime dependencies, but its YAML 1.1 implicit scalar conversions need care
and it requires separate type stubs under strict mypy. `types-PyYAML` latest
6.0.12.20261103 was too young on this date; it was not selected. Ruamel provides
the desired YAML 1.2 and duplicate-key behavior directly. `jsonc-parser` 1.1.5
last released in 2021 is less attractive than the actively released `json5`.
Neither YAML parser parses Yarn Classic's distinct non-YAML grammar: T09 needs
a small format-specific tokenizer/parser, not a partial general YAML parser.

Primary dependency references:

- <https://yaml.dev/doc/ruamel.yaml/>
- <https://pyyaml.org/wiki/PyYAMLDocumentation>
- <https://github.com/dpranke/pyjson5/blob/v0.17.3/README.md>
- <https://pypi.org/pypi/jsonc-parser/json>
- <https://pypi.org/pypi/types-PyYAML/json>

Registry verification at `2026-11-05T11:44:09.982229+00:00`, cutoff
`2026-10-29T11:44:09.982229+00:00` (seven full days):

- <https://pypi.org/pypi/json5/0.17.3/json>:
  wheel `2026-10-09T21:19:27.357259Z`, sdist
  `2026-10-09T21:19:28.335106Z`; `requires_dist: null`.
- <https://pypi.org/pypi/ruamel-yaml/0.19.1/json>:
  wheel `2026-01-02T16:50:29.201949Z`, sdist
  `2026-01-02T16:50:31.840645Z`. Requirements are extras only
  (`oldlibyaml`, `libyaml`, `jinja2`, `docs`); none enabled.
- Every published artifact of each selected version was checked against the
  cutoff. Both pass. Lock artifact SHA-256 values match those registry records.
  There are **no newly selected transitive packages**.
- `uv lock --exclude-newer 2026-10-29T11:39:51Z` initially failed because the
  existing `platformdirs>=4.14.3` constraint has no eligible version. No change
  resulted. A normal `uv lock` retained every existing package/version and added
  only the two exact pins. Review: 22 lock lines added, no existing lines removed;
  no dependency upgrades/downgrades. Existing dependency age is not re-certified.

## Verified formats and fixture evidence

The lockfile evidence below was retrieved on 2026-11-05; additional supporting
documentation links are provided alongside it. These are real upstream committed
lockfiles, read as inert text, never generated locally. JSON, YAML and Bun inputs
were decoded with the chosen Python parsers; Classic tokens were inspected
against its upstream grammar. Excerpts below are sanitized structural reductions:
omitted unrelated entries/checksums, retained real names/versions and key shapes.
They are evidence, **not yet offline parser tests**. Reader owners must commit
their fixtures and support notes, including unsupported-version tests, in their
owned fixture directories. No npm/Yarn/pnpm/Bun executable was run.

### npm

Primary specification:
<https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json> and
<https://docs.npmjs.com/cli/v11/configuring-npm/npm-shrinkwrap-json>.
Accept only integer `lockfileVersion` **1, 2, 3** (not bool, missing or unknown).
Shrinkwrap has the same format. v1 walks nested `dependencies`; v2/v3 use
`packages`, skipping `""` and workspace containers/links. In v2 the legacy tree
duplicates the inventory: do not scan both representations.

Verified raw URLs and SHA-256 of original bytes:

- <https://raw.githubusercontent.com/npm/cli/v6.14.18/package-lock.json>
  `ff4faf16cf362d766b28f708e5f71f912a87ad698a572d867048852587f81bb4`
- <https://raw.githubusercontent.com/npm/cli/v8.19.4/workspaces/arborist/test/fixtures/dedupe-lockfile/package-lock.json>
  `626c70cfe98ad5b513609bb8d6059890812379192dec92ffc17d36fbae2afd71`
- <https://raw.githubusercontent.com/npm/cli/v10.9.0/package-lock.json>
  `deb2e887500fa99469c5ba586fb6c017c9b63c3a2638e8fd473847cc95ef1249`

v1 real nested identity example (fields reduced):

```json
{"lockfileVersion":1,"dependencies":{"@babel/core":{"version":"7.12.9","dependencies":{"@babel/code-frame":{"version":"7.18.6"}}}}}
```

v2 verified fixture has root `""`, `node_modules/@isaacs/dedupe-tests-a`
version `1.0.1`, its nested `node_modules/@isaacs/dedupe-tests-b` version
`1.0.0`, and top-level b version `2.0.0`, plus the duplicate legacy tree.
All three distinct identities must survive. v3 real root additionally contains
workspace `docs` (`@npmcli/docs`) and registry installation-path records; a
workspace's own version is not evidence of a registry dependency. npm 8.19.4's
own root lock is version 3, not 2: the fixture above is the verified v2 evidence.

### Yarn

Classic documentation: <https://classic.yarnpkg.com/lang/en/docs/yarn-lock/>;
grammar: <https://github.com/yarnpkg/yarn/blob/v1.22.22/src/lockfile/parse.js>.
Accept Classic **`# yarn lockfile v1`**, no `__metadata`; unknown explicit Classic
header versions fail. Grouped selectors, quotes/escapes, indentation and comments
need token-aware handling. Missing header is not an additional supported format.

<https://raw.githubusercontent.com/yarnpkg/yarn/v1.22.22/yarn.lock>
SHA-256 `80653a1a393d3747fc6aefe19d3feafc2a9f8249ba843d25c26273020b721cd9`:

```text
# yarn lockfile v1
acorn@5.X, acorn@^5.0.0, acorn@^5.0.3, acorn@^5.5.0, acorn@^5.5.3:
  version "5.7.1"
  resolved "https://registry.yarnpkg.com/acorn/-/acorn-5.7.1.tgz#f095829297706a7c9776958c0afc8930a9b9d9d8"
"@babel/code-frame@^7.0.0-beta.35":
  version "7.0.0-beta.55"
```

Modern terminology: <https://yarnpkg.com/advanced/lexicon>.
Serialization/metadata implementation:
<https://github.com/yarnpkg/berry/blob/8f638c0806ec8f3758adb13d93567fc782f9c903/packages/yarnpkg-core/sources/Project.ts>.
Accept only integer **`__metadata.version` 4, 6, 8, 10**. `cacheKey` is not a
format version. Verified raw files:

- <https://raw.githubusercontent.com/yarnpkg/berry/@yarnpkg/cli/2.4.3/yarn.lock>
  version 4/cacheKey 7;
  `0269b8c62da771c9009ce696d11d95968625203c90568d7ca49bedafd6b9eda3`.
- <https://raw.githubusercontent.com/yarnpkg/berry/@yarnpkg/cli/3.8.7/yarn.lock>
  version 6/cacheKey 8;
  `52a79f6fd8398c5a6328de3282e0be12ddc2ba6248541607986ce1cb481f2470`.
- <https://raw.githubusercontent.com/yarnpkg/berry/@yarnpkg/cli/4.9.2/yarn.lock>
  version 8/cacheKey 10;
  `38ed16896134c2ae127528285776e10d3c12421988096065bcae677ddc048141`.
- <https://raw.githubusercontent.com/yarnpkg/berry/8f638c0806ec8f3758adb13d93567fc782f9c903/yarn.lock>
  version 10/cacheKey 10;
  `9b6da38cc7b4796bef968c0a06677b3846c82707098d67455cd5fd6d5ef57eaa`.

```yaml
__metadata:
  version: 6
  cacheKey: 8
"@actions/core@npm:^1.2.6":
  version: 1.2.6
  resolution: "@actions/core@npm:1.2.6"
  languageName: node
  linkType: hard
```

v4 has `@algolia/cache-browser-local-storage@npm:4.2.0`; v8/v10 have
`@aashutoshrathi/word-wrap@npm:1.2.6`. Those versions and npm locator shapes
were checked in decoded documents. Real v4/v6 patch resolution:
`@strictsoftware/typedoc-plugin-monorepo@patch:@strictsoftware/typedoc-plugin-monorepo@npm%3A0.2.2#./.patches/@strictsoftware/typedoc-plugin-monorepo.patch::version=0.2.2&hash=3cb6af&locator=%40yarnpkg%2Fgatsby%40workspace%3Apackages%2Fgatsby`
(v6 hash differs). v8/v10 likewise contain patched npm resolutions. Recover
the percent-encoded inner locator, not the outer selector or patch version;
report upstream-only coverage. Virtual wrappers are a grammar-level requirement,
not evidence that these particular lockfiles contain serialized virtual records;
T09 must supply a separate provenance-documented virtual fixture. Decode only
the wrapper component prescribed by Yarn, with bounded nesting; ambiguous inner
identities stay unscanned.

### pnpm

Primary v6 specification:
<https://github.com/pnpm/spec/blob/master/lockfile/6.0.md>.
Its `lockfileVersion` paragraph still says major 4; that stale prose is not the
accepted-version authority. Actual serialized v6 and v9 files and v9 definitions:

- <https://raw.githubusercontent.com/pnpm/pnpm/v8.0.0/pnpm-lock.yaml>
  `4004d9c289ca5c1a51050ec76905535d0da8974c48c2f493350a73e2905f0e37`.
- <https://raw.githubusercontent.com/pnpm/pnpm/v9.15.9/pnpm-lock.yaml>
  `8faf3dc0f279200ec7daec6478eb04b379c988b1f4707625fbb8bb95586e04cd`.
- <https://github.com/pnpm/pnpm/blob/v9.15.9/lockfile/types/src/index.ts>
- <https://github.com/pnpm/pnpm/blob/v9.15.9/lockfile/types/src/lockfileFileTypes.ts>

Accept exactly **`6.0` and `9.0`**, as YAML strings or numeric values equal to
6.0/9.0 (including integer 6/9), explicitly excluding bool. Reject other minors,
missing versions, and coercible but differently spelled strings such as `"6"`.

```yaml
lockfileVersion: '6.0'
importers:
  .:
    devDependencies:
      '@babel/plugin-proposal-dynamic-import':
        specifier: ^7.18.6
        version: 7.18.6(@babel/core@7.21.0)
packages:
  /@ampproject/remapping@2.2.0:
    resolution: {integrity: sha512-qRmjj8nj9qmLTQXXmaR1cck3UXSRMPrbsLJAasZpF+t3riI71BXed5ebIOYwQntykeZuhjsdweEc9BxH5Jc26w==}
    dev: true
```

```yaml
lockfileVersion: '9.0'
packages:
  '@ampproject/remapping@2.3.0':
    resolution: {integrity: sha512-30iZtAPgz+LTIYoeivqYo853f02jBYSd5uGnGpkFV0M3xOt9aN73erkgYAmZU43x4VfqcnLxW9Kpg3R5LC4YYw==}
snapshots:
  '@ampproject/remapping@2.3.0':
    dependencies:
      '@jridgewell/gen-mapping': 0.3.8
      '@jridgewell/trace-mapping': 0.3.25
```

v9 also has importers with `{specifier, version}` and peer suffixes. Join
snapshots to package metadata, never query snapshots/importer aliases as names.
v6 records include leading `/`; v9 package keys do not. Keep platform/dev/optional
inventory, strip only recognized peer/patch context, preserve distinct versions.
The pnpm v8.15.9 repository root already uses 9.0 and some old fixtures use 5.1;
neither is substituted for verified v6 evidence.

### Bun

Primary docs retrieved from
<https://raw.githubusercontent.com/oven-sh/bun/main/docs/pm/lockfile.mdx>
(public page <https://bun.com/docs/pm/lockfile> returned 403 to this client).
Format introduction: <https://bun.com/blog/bun-lock-text-lockfile>.
Version and tuple authority:
<https://github.com/oven-sh/bun/blob/bun-v1.2.22/src/install/lockfile/bun.lock.zig>.
The source enum explicitly defines v0 and v1, with current v1.

Accept integer **`lockfileVersion: 1` only**. Verified actual file:
<https://raw.githubusercontent.com/oven-sh/bun/bun-v1.2.22/bun.lock>
SHA-256 `5c23e1735e8d5cd76ae7cc94f1ea0e9b58cefe690eeee3ee9306fa27f6a49030`.

```jsonc
{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "bun" } },
  "packages": {
    "@esbuild/aix-ppc64": ["@esbuild/aix-ppc64@0.21.5", "", { "os": "aix", "cpu": "ppc64" }, "sha512-1SDgH6ZSPTlggy1yI6+Dbkiz8xzpHJEVAlF/AM1tHPLsf5STom9rwtjE4hKAF20FfXXNTFqEYXyJNWh1GiZedQ=="],
    "@types/bun": ["@types/bun@workspace:packages/@types/bun"],
  },
}
```

The first tuple element, not map key, supplies resolved identity; different
source types have different tuple lengths. Registry tuples carry resolution
string, metadata object, integrity; validate before extracting. The real document
contains trailing commas and short workspace tuples. Bun's parser permits absent
`packages` for an empty inventory; validate remaining document/workspaces rather
than requiring a fake package. Bun 1.2.0's text root has version 0 and is outside
this target. `bun.lockb` is detection-only unsupported input: recommend the
documented **external** command
`bun install --save-text-lockfile --frozen-lockfile --lockfile-only`, then manual
verification/removal of binary lock. Warn this external operation can populate
Bun's cache; depscan never invokes it.

## Shared Python types for T02

Keep Pydantic strict/extra-forbid/frozen configuration and tuple collections used
by current `models.py`. Names below are the exact public internal names. They
are concrete records, not a plugin protocol. All paths are `pathlib.Path` in
Python and strings in JSON. No synthetic line numbers beyond document line 1.

```python
type Ecosystem = Literal["PyPI", "npm"]
type SourceKind = Literal[
    "requirements",
    "pyproject",
    "uv",
    "poetry",
    "pipfile",
    "package_json",
    "npm",
    "yarn",
    "pnpm",
    "bun",
    "bun_binary",
]


class DependencySource(BaseModel):
    ecosystem: Ecosystem
    path: Path
    kind: SourceKind


class SourceSelection(BaseModel):
    ecosystem: Ecosystem
    status: Literal["selected", "absent", "ambiguous", "failed"]
    source: DependencySource | None = None
    candidates: tuple[DependencySource, ...] = ()
    errors: tuple[ScanError, ...] = ()


class DiscoveryResult(BaseModel):
    selections: tuple[SourceSelection, ...]
    input_paths: tuple[Path, ...] = ()


class SourceReadResult(BaseModel):
    source: DependencySource
    status: Literal["success", "failed"]
    requirements: tuple[RequirementResult, ...] = ()
    errors: tuple[ScanError, ...] = ()
    input_paths: tuple[Path, ...] = ()


class SourceSummary(BaseModel):
    ecosystem: Ecosystem
    status: Literal["success", "failed", "absent", "ambiguous"]
    source: DependencySource | None = None
    candidates: tuple[DependencySource, ...] = ()
```

Use model validators for these invariants:

- `DependencySource.kind` matches ecosystem: first five kinds PyPI, rest npm.
- Selection `selected`: source present and in candidates, no errors. `absent`:
  no source/candidates/errors. `ambiguous`: no source, at least two surviving
  cross-manager candidates, contextual error. `failed`: no source, nonempty
  errors; candidates may exist (e.g. unreadable selection-only package.json).
- A successful read may be empty, contain unscanned entries or contain recoverable
  entry errors. A failed read has nonempty errors and no requirements: document
  unreadable, syntax/overall-shape invalid, unknown format, or binary Bun. Preserve
  usable siblings for entry-local failures in a structurally valid document.
- Summary success/failed from a read retains source; discovery failure has failed
  summary with source null. Ambiguous/absent have null source. Errors live once at
  report top level, not duplicated inside summary. Candidates always preserve
  discovery evidence. Explicit files have just their own candidate.
- Every read/selection error has matching ecosystem, even if no package exists.
  Requirements' ecosystem matches the enclosing source. Ready/scanned requirements
  derive ecosystem from `package.ecosystem`, rather than a second mutable copy.

Modify existing models as follows; retain their other fields/unions:

- `PackageVersion.ecosystem: Ecosystem = "PyPI"`. Keep frozen/hashable. Normalize
  PyPI names using `packaging.utils.canonicalize_name`; npm names preserve scopes,
  dots, underscores, hyphens and case (validate, never PyPI-normalize). Expose
  `identity: tuple[Ecosystem, str, str]` as a **property**, not serialized field.
  Canonical normalized model fields participate in equality/hash. Version stays
  exact selected string for Python (preserve existing selection behavior).
- For npm, shared `PackageVersion` validation accepts exact SemVer core X.Y.Z
  with optional prerelease/build, optional leading `v` stripped; no leading zeros
  in core/numeric prerelease, ASCII alphanumeric/hyphen identifiers, no empty
  identifiers, integer core components <= `2**53-1`, total input <=256 chars.
  Preserve build metadata; do not translate to PEP 440. Ranges, `=`, tags, URLs,
  aliases and wrappers are not raw package versions. T06 extracts alias/wrapper
  targets before constructing a model. Names must be nonempty unscoped or
  `@scope/name`, <=214 chars, no whitespace/URL delimiters/extra slash, npm-safe
  ASCII `[A-Za-z0-9._~-]+` segments, no segment starting `.` or `_`.
  Allow legacy uppercase names unchanged. Root/workspace exclusion belongs in
  readers, not name validation. T02 tests these npm rules; T08 can use this model
  without importing T06 helpers. This is exact-pin validation, not a range solver.
- `UnscannedRequirement.ecosystem: Ecosystem = "PyPI"` and
  `NonApplicableRequirement.ecosystem: Ecosystem = "PyPI"`.
- `ScanError.ecosystem: Ecosystem | None = None`. None means a genuinely global
  failure (e.g. JSON export/no supported sources). Every source/lookup failure
  must set ecosystem explicitly. Existing Python adapters/CLI error construction
  sites must set PyPI, including failures before package creation.
- Leave `SourceLocation(path, line, text)` unchanged. Its path identifies the
  declaration/include, not necessarily the selected root input. Document parsers
  use line 1 and text like `dependencies.alias = npm:@scope/real@1.2.3` or
  `packages["node_modules/foo"]`; requirements retain actual lines/raw text.

Defaults on package/unscanned/non-applicable models preserve legacy Python
construction sites; **all npm construction sites explicitly pass `"npm"`**.
Preserve Python markers, pinned version choice, installed version selection,
includes/depth handling and unsupported declaration behavior.

## Functions and module boundaries

```python
# discovery.py (T05); no reader imports
def discover_sources(path: Path) -> DiscoveryResult: ...


# javascript/npm.py (T06)
def read_package_json(path: Path) -> SourceReadResult: ...
def read_npm_lock(path: Path) -> SourceReadResult: ...
# javascript/yarn.py (T09), pnpm.py (T10), bun.py (T08)
def read_yarn_lock(path: Path) -> SourceReadResult: ...
def read_pnpm_lock(path: Path) -> SourceReadResult: ...
def read_bun_lock(path: Path) -> SourceReadResult: ...


# javascript/identity.py (T06); raw exact values validated by PackageVersion
def exact_npm_version(value: str) -> str | None: ...
def resolve_npm_declaration(
    name: str, declaration: str, source: SourceLocation
) -> RequirementResult: ...


# project.py (T11), discovery plus dispatch/adaptation
def read_sources(
    path: Path, *, venv: Path | None = None
) -> tuple[DiscoveryResult, tuple[SourceReadResult, ...]]: ...
```

`exact_npm_version` implements the same npm version validation as the model,
using the model rather than diverging regexes. `resolve_npm_declaration` handles
`npm:target@exact`, including scoped targets, and otherwise returns contextual
unscanned outcomes for invalid names, ranges/tags/non-registry specs. Shape errors
are the file reader's responsibility. Both helpers are pure/offline. Minimal
`javascript/__init__.py`; no imports of unfinished siblings. No registry of
parsers/plugin base class. Format modules keep private syntax helpers local.

Keep current `read_requirements(path, *, installed_versions=None,
input_paths=None) -> list[RequirementResult]` and existing `read_project`
signature during T02 compatibility work. T11 adapts them behind `read_sources`;
it can keep `read_project` for callers/tests. Read adapters must distinguish a
failed document from a valid empty list: an IO/syntax/overall-shape failure in
the legacy reader is not a successful source. Entry-level Python unresolved
requirements remain unscanned. `--venv` failure affects Python only.

### Selection and every-input protection

Directory discovery returns exactly two selections, PyPI then npm, including
absent ecosystems; explicit file discovery returns only that file's ecosystem.
Recognize all JS names before arbitrary requirements filename fallback. Absolute
paths preserve their input spelling for source display. Candidate ordering is
deterministic: Python precedence; JS shrinkwrap, package-lock, yarn, pnpm, bun
text, bun binary, manifest. All detected candidates remain in `candidates`, even
if same-manager precedence discards one for selection. Ambiguity validation
counts surviving managers, not raw candidates.

Select within each ecosystem using plan precedence, root only. Only read a
`package.json#packageManager` hint when multiple surviving JS lock managers
need disambiguation. Valid hint grammar: recognized `npm|yarn|pnpm|bun`, `@`, an
exact npm version as defined above, optionally `+sha224.<hex>`/`+sha256.<hex>`/
`+sha384.<hex>`/`+sha512.<hex>` with respectively 56/64/96/128 hex digits.
The hash suffix follows Corepack metadata, not part of the manager version; require
nonempty exact version before it. A supported hint selects a present matching
manager; absent/invalid/conflicting hints produce ambiguity with explicit-file
guidance. Malformed/unreadable selection manifest produces failed npm discovery,
not silent choice. With one surviving manager the lock wins regardless of hint;
parsing a selected broken lock never falls back to the manifest.

Hint reference: <https://github.com/nodejs/corepack/blob/main/README.md> documents
exact versions with optional SHA-224 metadata and npm/Yarn/pnpm names. Accepting
Bun and the listed SHA algorithms is depscan's explicit hint policy, not a claim
that Corepack manages Bun. URL-based Corepack hints remain unsupported here.

Each `input_paths` tuple is sorted/deduplicated absolute paths of files whose
contents were read **or attempted**, registered before open/decode. Discovery
also registers every detected manifest/lock candidate (conservative protection),
including unselected/selection-only package.json. Reader paths include empty
files, failed includes, recursive requirements includes, selected root, and any
Python environment metadata files actually read for version selection. Binary
Bun diagnostics register the selected path even without decoding it. No reader
opens nested workspace manifests; produce visible missing-coverage outcomes.
Directory enumeration alone is not a content read. Retain attempted absolute
paths if resolving a symlink raises; that error is contextual scan failure.

T11 unions discovery/read paths plus explicit/selected paths before any export.
Compare output resolved path and existing-file `samefile` for every protected
path, catching symlink **and hardlink** aliases. Included empty files and
selection-only files are protected too. Path comparison errors block output
with exit 2, not permission to overwrite. Existing atomic `write_json` stays in
`report.py`; collision decisions stay in CLI. No scanner invokes Node, package
managers, lifecycle scripts, installs, range resolution, or node_modules fallback.

## Schema v2, outcomes and concrete examples

`ScanReport` retains `scanned_at`, `results`, `errors`; changes
`schema_version: Literal[2] = 2`, adds
`detected_ecosystems: tuple[Ecosystem, ...] = ()`,
`sources: tuple[SourceSummary, ...] = ()`, and
`input_paths: tuple[Path, ...] = ()`. Defaults enable transitional Python tests;
T02 updates CLI construction to populate truthful Python source context before
parallel reporting tests depend on it. New reports constructed in v2 code always
populate these fields. `detected_ecosystems` includes any non-absent ecosystem,
in PyPI/npm order (including failed/ambiguous discovery). Explicit input is
detected even if unreadable. `sources` includes absent rows for directory scans.
No schema-1 JSON compatibility promise; timestamps/advisory fields unchanged.

Exit code: 2 for any error, unscanned requirement, failed/ambiguous source, or
no detected ecosystems; otherwise 1 if any vulnerable result, otherwise 0.
An absent ecosystem beside a successful one is not incomplete. A success status
means the document was read, not that every declaration/lookup was covered.
Lookup failure leaves source success, creates ecosystem-aware unscanned result
and contextual ScanError; source read failure has failed summary even with zero
package results. Summaries count unique `(ecosystem, canonical name, version)`
checked identities combined and per ecosystem; declarations/provenance remain
visible, including repeated aliases and distinct versions. Never say “safe”.

Examples (constructor arguments; defaults above omitted):

```python
src = DependencySource(
    ecosystem="npm", path=Path("/repo/package.json"), kind="package_json"
)
loc = SourceLocation(
    path=src.path, line=1, text="dependencies.alias = npm:@scope/real@1.2.3"
)
ready = ReadyRequirement(
    source=loc,
    package=PackageVersion(ecosystem="npm", name="@scope/real", version="1.2.3"),
)
parsed = SourceReadResult(
    source=src, status="success", requirements=(ready,), input_paths=(src.path,)
)
empty = SourceReadResult(source=src, status="success", input_paths=(src.path,))
broken = SourceReadResult(
    source=src,
    status="failed",
    input_paths=(src.path,),
    errors=(ScanError(ecosystem="npm", source=loc, reason="Invalid JSON object"),),
)
absent = SourceSelection(ecosystem="PyPI", status="absent")
```

`empty` produces a success summary and no package results, exit 0 if alone;
`broken` produces a failed summary and top-level error, exit 2. An ambiguity
contains candidate sources and a contextual npm ScanError but no read result.
If Python succeeded meanwhile, retain its lookups/findings and still exit 2.
`PackageVersion(name="a_b", version="1.2.3")` identifies PyPI `a-b`;
the explicit npm equivalent identifies npm `a_b`, not the same cache/OSV key.
`UnscannedRequirement(ecosystem="npm", source=loc, name="alias",
reason="Unresolved range; supply a supported lockfile")` preserves declaration
context without inventing an identity.

Patched registry entries with a trustworthy upstream identity yield a ready
upstream declaration **and** an unscanned declaration at the same location
explaining that advisories do not assess the applied patch (exit 2). Workspace
containers/links are never queried; emit unscanned coverage diagnostics when
external workspace coverage is unavailable. Already recorded external registry
inventory remains queryable. Untrustworthy/non-registry records yield unscanned
results, not guessed names/versions. Do not collapse source provenance during
reader deduplication; lookup/cache/report unique counts alone deduplicate identity.

## Remaining work and evidence limits

T01 adds dependencies and this contract only. It does not implement readers,
discovery, cache/schema migration, OSV routing, tests or executable fixtures.
The inspected files prove the accepted versions and representative structures,
not every alias/wrapper/non-registry edge case; those need offline fixtures and
grammar checks in their owning reader tasks. Unknown versions fail explicitly.
No package-manager release-version-to-lock-version inference is authorized.
No dependency vulnerability audit was performed; release age is not such an audit.

## T01 validation

After dependency synchronization, offline pytest again passed all 210 tests;
Ruff lint and mypy passed unchanged. The first final format check found only new
Python examples in this document; formatted this owned document only, then
re-ran the format check successfully. Parser smoke assertions passed for YAML
1.2 `on` as string, duplicate-key rejection, unsafe tag rejection, JSONC comments,
trailing commas, URL strings containing `//`, and JSON5 duplicate-key rejection.
Registry and upstream-file inspection used read-only HTTP through Python; no
project JavaScript dependencies were installed or executed. `uv sync --frozen`
installed only the scanner's approved Python parser dependencies in this worktree.

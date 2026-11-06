# npm reader evidence and support (T06)

Only inert JSON/text was inspected. No Node, npm, package installation, lifecycle
script, registry resolution, or project script was executed. Tests are offline.

## Verified sources, retrieved 2026-11-05 before reader implementation

- Format documentation:
  <https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json>
  and <https://docs.npmjs.com/cli/v11/configuring-npm/npm-shrinkwrap-json>.
  Shrinkwrap and package-lock share a format. The docs identify v1's nested
  dependencies, v2's duplicate legacy tree, package-path records, links,
  optional/dev/platform fields, and non-registry version/resolution forms.
- Manifest/declaration documentation:
  <https://docs.npmjs.com/cli/v11/configuring-npm/package-json#dependencies>
  and <https://docs.npmjs.com/cli/v11/using-npm/package-spec#aliases>.
- `upstream-v1.json`: structural reduction of
  <https://raw.githubusercontent.com/npm/cli/v6.14.18/package-lock.json>.
  Original SHA-256:
  `ff4faf16cf362d766b28f708e5f71f912a87ad698a572d867048852587f81bb4`.
  Retains real nested `@babel/core` / `@babel/code-frame` names and versions;
  removes unrelated entries and resolution/checksum metadata.
- `upstream-v2.json`: structural reduction of
  <https://raw.githubusercontent.com/npm/cli/v8.19.4/workspaces/arborist/test/fixtures/dedupe-lockfile/package-lock.json>.
  Original SHA-256:
  `626c70cfe98ad5b513609bb8d6059890812379192dec92ffc17d36fbae2afd71`.
  Preserves three distinct real inventory identities and duplicate legacy entries;
  removes unrelated metadata and some resolution/checksum fields.
- `upstream-v3.json`: structural reduction of
  <https://raw.githubusercontent.com/npm/cli/v10.9.0/package-lock.json>.
  Original SHA-256:
  `deb2e887500fa99469c5ba586fb6c017c9b63c3a2638e8fd473847cc95ef1249`.
  Preserves real root/workspace containers and the real `string-width-cjs` alias
  with explicit target `name: string-width`, version and registry resolution.
  Reduces the workspace list and omits unrelated entries/metadata/checksums.

Original byte hashes were rechecked against these upstream URLs. Synthetic edge
cases are explicitly constructed in `test_npm.py` and
`test_javascript_identity.py`, not represented as upstream captures. They include
scoped aliases, declaration-only alias hints, prereleases, duplicate inventory,
unknown versions, malformed shapes, local/git/workspace and unverifiable tarballs.

## Exact accepted formats and behavior

- `package.json`: JSON object; four dependency groups are objects, with string
  values. Invalid group shapes fail the document; bad individual values yield
  contextual errors while preserving usable siblings. Workspaces are arrays of
  strings; no nested member manifests are opened.
- npm lock/shrinkwrap: **integer** `lockfileVersion` **1, 2, 3** only, excluding
  bool, float and string values. v1 permits absent dependencies for an empty
  inventory; if present they must be an object. v2/v3 require a `packages` object.
  v2's legacy dependencies are never inventoried or used as fallback.
- Strict JSON: duplicate keys, NaN/Infinity, malformed/recursive inputs and invalid
  UTF-8 fail contextually. Unknown versions never produce an empty success.
- All recorded versions/dev/optional/platform entries are inventoried, regardless
  of current environment. Distinct versions survive; identical identities at
  different locations also survive for provenance. Only downstream lookups dedup.
- Root records are excluded. Workspace/local containers and links yield explicit
  unscanned diagnostics; recorded external workspace registry inventory still
  scans. Root workspace declarations also signal incomplete member coverage.
- Identity comes from explicit real names, exact `npm:target@version` aliases,
  recognized registry URL package paths, or ordinary package installation names.
  A parent's npm alias declaration can supply the target for an exact locked
  version even if the declared range itself is unresolved. Conflicting evidence
  stays unscanned. The installation alias never overrides a known real target.
  Requester declarations (including v1 `requires`) join to their nearest recorded
  installation along the requester's ancestor paths, so hoisted alias evidence
  is retained without leaking across shadowing nested records. Conflicting alias
  targets or alias-versus-ordinary requests for the same record stay unscanned.
  This is a lexical inventory join, not dependency range/installation resolution.
  Root/workspace declarations with no matching recorded installation yield
  contextual unscanned outcomes, including exact pins, ranges and URL requests.
  A matching install is not checked for range satisfaction; missing transitive
  peers are not treated as evidence of a broken inventory. Declaration groups
  and values in package records are validated with recoverable contextual errors.
  v1 `dependencies` remain record trees, and root `requires` remains a boolean.
  Alias version, explicit name, requester and public-registry URL evidence are
  reconciled before validating a registry-relative source against the real target.
  Ordinary registry requests assert the installation name independently of whether
  any `npm:` alias request exists; conflicting explicit names/registry URLs also
  stay unscanned. URL/protocol/path and local archive declarations do not assert
  a registry name. This syntactic distinction does not parse or resolve ranges.
- Recognized public tarball URL hosts: `registry.npmjs.org`,
  `registry.yarnpkg.com`; their `/<package>/-/<artifact>` paths identify packages.
  v1 registry-relative `<package>/-/<artifact>` resolutions are also accepted.
  HTTP(S) custom hosts cannot reliably distinguish registry versus arbitrary
  tarballs offline; they remain **unscanned**, as do git/file/link/URL versions and
  sources. No URL is fetched by the reader. Missing resolved fields are allowed
  for otherwise exact lock inventory (e.g. bundled entries).
  Without a recorded resolution or independent registry/alias request, affirmative
  non-registry declarations prevent a bare version/name from becoming a registry
  identity. Mixed hoisted registry/alias and non-registry requests preserve the
  registry inventory but expose the separate non-registry declaration as unscanned.
  Explicit recognized registry resolutions continue to supply registry evidence.
- Sources register just the attempted selected file as an absolute path, preserving
  symlink spelling. No environment, package manager, node_modules or member file
  is read. Locations use document line 1 and group/key/path descriptions.
- IO/decode/syntax/overall-shape failures return failed `SourceReadResult` with
  contextual npm errors, no requirements and the attempted input path. Entry-local
  defects preserve usable siblings under success plus errors/unscanned outcomes.
  Success means read successfully, not complete coverage. Empty valid sources
  return success with no requirements/errors.

## Stable interfaces for T09/T10/T11

```python
from depscan.javascript.identity import exact_npm_version, resolve_npm_declaration
from depscan.javascript.npm import read_npm_lock, read_package_json


def exact_npm_version(value: str) -> str | None: ...
def resolve_npm_declaration(
    name: str, declaration: str, source: SourceLocation
) -> RequirementResult: ...
def read_package_json(path: Path) -> SourceReadResult: ...
def read_npm_lock(path: Path) -> SourceReadResult: ...
```

`exact_npm_version` reuses `PackageVersion` validation and strips a leading `v`
exactly as the shared model does; preserves prerelease/build strings. It is not a
range solver. `resolve_npm_declaration` validates the declared name and extracts
unscoped/scoped exact alias targets, preserving the supplied source verbatim.
It returns `ReadyRequirement` or npm `UnscannedRequirement`, never raises for
unresolved/invalid string declarations, and does not resolve alias ranges/tags.
All npm model construction is explicit about ecosystem; Python defaults are not
used. No public helper/interface was added beyond the shared contract.

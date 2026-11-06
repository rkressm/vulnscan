# Yarn reader support and fixture provenance

Accepted identifiers: Classic `# yarn lockfile v1` (mandatory; no metadata),
or modern integer `__metadata.version` **4, 6, 8, 10**. `cacheKey` is not a
format identifier. Missing, unknown, boolean, float and quoted versions fail.
Unknown explicit Classic versions fail, even beside modern metadata.
Classic markers are recognized only in the leading blank/comment preamble;
header-like comments in a modern mapping do not change its format.

The following original inert upstream files were re-fetched on 2026-11-06.
Their SHA-256 values agree with T01's contract. No JavaScript/package-manager
executable was invoked. Committed fixtures are structural reductions, not byte
copies; checksums below identify originals, not these reductions.

- `classic.lock`: <https://raw.githubusercontent.com/yarnpkg/yarn/v1.22.22/yarn.lock>
  SHA-256 `80653a1a393d3747fc6aefe19d3feafc2a9f8249ba843d25c26273020b721cd9`.
  Real acorn grouped selectors (three retained), scoped Babel prerelease and
  acorn registry URL retained. Nested `example`, alias and second acorn version
  are synthetic grammar/identity regression cases, not claimed upstream records.
- `modern-4.lock`: <https://raw.githubusercontent.com/yarnpkg/berry/@yarnpkg/cli/2.4.3/yarn.lock>
  SHA-256 `0269b8c62da771c9009ce696d11d95968625203c90568d7ca49bedafd6b9eda3`.
  Actual Algolia descriptor, version, npm resolution and metadata retained.
- `modern-6.lock`: <https://raw.githubusercontent.com/yarnpkg/berry/@yarnpkg/cli/3.8.7/yarn.lock>
  SHA-256 `52a79f6fd8398c5a6328de3282e0be12ddc2ba6248541607986ce1cb481f2470`.
  Actual Actions descriptor, version, resolution, metadata and two ancillary fields.
- `modern-8.lock`: <https://raw.githubusercontent.com/yarnpkg/berry/@yarnpkg/cli/4.9.2/yarn.lock>
  SHA-256 `38ed16896134c2ae127528285776e10d3c12421988096065bcae677ddc048141`.
- `modern-10.lock`: <https://raw.githubusercontent.com/yarnpkg/berry/8f638c0806ec8f3758adb13d93567fc782f9c903/yarn.lock>
  SHA-256 `9b6da38cc7b4796bef968c0a06677b3846c82707098d67455cd5fd6d5ef57eaa`.
  Both word-wrap reductions retain actual descriptor/version/resolution/metadata.

## Grammar and wrappers

Classic grammar authority:
<https://github.com/yarnpkg/yarn/blob/v1.22.22/src/lockfile/parse.js>.
The format-specific tokenizer recognizes JSON double-quoted strings/escapes,
bare strings, integer/boolean values, colons, commas, comments and pairs-of-space
indentation. Nested maps/grouped properties are supported. There is no general
YAML fallback, merge-conflict repair, duplicate-key overwrite, single-quoted
string syntax, flow mapping, tag or anchor handling. These stricter failure
policies intentionally avoid ambiguous or silently repaired inventories. Normal
Classic serialized records are line-oriented. The complete original Classic
file was parsed successfully during fixture verification (1,355 selectors).
The cited tokenizer starts bare strings with `[a-zA-Z/.-]`, and parses a leading
digit as a number: scoped and digit-leading package keys **must be double-quoted**
in Classic. We reject bare `@scope/name@...` / `123@...`, rather than inventing
a more permissive dialect; their quoted equivalents are supported.

`wrappers.lock` is **synthetic**, except the patch's package, upstream version and
encoded npm source derive from T01's verified v4/v6 typedoc patch. Patch paths,
selector and context are shortened. Virtual, alias, nested wrapper and workspace
records are deliberately constructed, not evidence of serialized virtual records
in the upstream lockfiles above. Grammar authority (pinned modern revision):

- <https://github.com/yarnpkg/berry/blob/8f638c0806ec8f3758adb13d93567fc782f9c903/packages/yarnpkg-core/sources/structUtils.ts>
  `virtualizePackage` / `devirtualizeLocator`: preserve ident, wrap the reference
  in `virtual:<entropy>#<reference>`; do not percent-decode the virtual component.
  `makeRange` / `parseRange`: percent-encode/decode the patch source exactly once.
- <https://github.com/yarnpkg/berry/blob/8f638c0806ec8f3758adb13d93567fc782f9c903/packages/plugin-patch/sources/patchUtils.ts>
  `parseSpec` / `makeSpec`: source is a full locator before `#`; patch paths and
  `::version=...&hash=...&locator=...` are not the registry identity.

## Coverage and deliberate limits

- Modern `resolution` supplies identity, not alias/group selector names. Classic
  aliases supply their target; public npm/Yarn tarball identity must agree when
  present. Custom tarball hosts remain unscanned rather than guessed.
  Modern aliases are remapped from descriptors to real-target locators by
  <https://github.com/yarnpkg/berry/blob/8f638c0806ec8f3758adb13d93567fc782f9c903/packages/plugin-npm/sources/NpmRemapResolver.ts>:
  `supportsLocator` explicitly returns false, while candidates come from the
  remapped target descriptor. Its sibling `NpmSemverResolver.ts` emits
  `<real-ident>@npm:<exact-version>`. Thus `alias@npm:real@1.2.3` is **not** a
  supported resolved locator; it remains unscanned instead of interpreting a
  malformed resolution as a descriptor. `wrappers.lock` covers the real-target
  resolution shape while retaining grouped alias descriptor provenance.
- Npm locator versions must be exact shared-model SemVer and agree with the
  record version. Binding-bearing npm locators are conservatively unscanned.
- Virtual/patch nesting is bounded to 16 wrappers. Patch source ident must match
  outer ident. Only a recovered exact npm locator is queryable. Patches also emit
  an unscanned diagnostic: upstream advisories do not assess the applied patch.
- Workspace/root links and other non-registry resolutions are never queried.
  Missing external workspace coverage is visible; nested manifests are not read.
- Grouped Classic selectors retain individual locations; modern groups retain
  their complete original selector text. Readers do not deduplicate provenance.
- Only the selected file is read/registered, including unsuccessful read attempts.
  Document line 1 is used, not fabricated parser line numbers.
- Document IO/syntax/version failures produce a failed source with no packages.
  Bad records in a valid document preserve usable siblings via contextual entry
  errors/unscanned outcomes. Safe YAML rejects duplicate keys and unsafe tags.
  Loader `TypeError` (including complex unhashable mapping keys) and excessive
  nesting/recursion become contextual failed reads, never raw tracebacks.
  Malformed and unsupported-version test cases are synthetic inline test inputs;
  the test suite makes no HTTP calls and needs no Node/Yarn installation.

# Bun reader support and fixture provenance

Accepted format: integer `lockfileVersion: 1` only. v0, unknown, missing,
boolean, string and float identifiers fail. `bun.lockb` is detection-only.
`read_bun_lock(path: Path) -> SourceReadResult` accepts either filename;
only the exact filename `bun.lockb` selects the binary diagnostic.

## Verified evidence

Retrieved as inert text on 2026-11-06:

- https://raw.githubusercontent.com/oven-sh/bun/bun-v1.2.22/bun.lock
  Original SHA-256 (T01, independently rechecked 2026-11-06):
  `5c23e1735e8d5cd76ae7cc94f1ea0e9b58cefe690eeee3ee9306fa27f6a49030`.
- Tuple/version/patch serialization authority:
  https://github.com/oven-sh/bun/blob/bun-v1.2.22/src/install/lockfile/bun.lock.zig
  (`Stringifier.saveFromBinary`, `parseIntoBinaryLockfile`).
- Migration documentation:
  https://raw.githubusercontent.com/oven-sh/bun/main/docs/pm/lockfile.mdx
  and https://bun.com/blog/bun-lock-text-lockfile.

`upstream-v1.lock` is a sanitized structural reduction, not a complete installable
project: kept real names, versions, installation keys and tuple forms; removed
unrelated records/dependency metadata, shortened the github metadata to `{}`, and
replaced the three Octokit integrities with empty strings (Bun serializes absent
integrity as a string too). Other retained integrity strings are unchanged. It
proves scoped names, alias targets, platform metadata, short workspace tuples,
github sources, distinct versions and repeated provenance. `-patch.1` in the real
alias target is a normal prerelease, not evidence of an applied Bun patch.

`coverage-v1.lock` is **synthetic**, built from the pinned serializer's grammar;
it adds `patchedDependencies` (resolved `name@version` to path), local/link/root,
git/URL, escaped/comment-marker strings, prerelease/build, optional inventory and
an intentionally malformed sibling. Parametrized Python tests synthesize further
malformed documents and tuples; these are not claimed to be Bun-generated files.

## Behavior and limitations

- Uses approved `json5` with duplicate-key rejection: JSONC comments/trailing
  commas are handled token-aware, including comment markers inside strings.
  JSON5 lexical extensions (single quotes, unquoted keys, etc.) are also accepted;
  this is intentionally not a strict JSONC lexer. No code evaluation occurs.
- Registry tuples are `[resolved-name@exact-version, registry-string,
  metadata-object, integrity-string]`. The first element is authoritative, not the
  install key or a declaration's alias. No registry access or integrity
  verification occurs; custom registries are accepted, and integrity may be empty.
- Inventory includes development, optional and other-platform tuples. Repeated
  identities retain all provenance; downstream lookup deduplicates them.
- Root and workspace/local tuples are never queried. Non-root workspaces yield
  visible missing external coverage; nested manifests are never opened.
- Registry patches yield both upstream ready and unscanned patch-coverage results
  at the same location. Patch files are never opened or assessed. Non-registry,
  invalid or ambiguous locators are unscanned, never guessed.
- A valid empty root workspace with absent/empty `packages` is successful;
  declarations without any inventory yield missing-coverage diagnostics.
- IO/decode/syntax/overall-shape/version failures are failed sources with no
  requirements. Malformed tuples yield contextual entry errors, preserving usable
  siblings. All source locations use document line 1 and every input is registered
  before any open; binary diagnostics register the path without decoding it.
- Legacy guidance is external only:
  `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`.
  Manually verify the text lockfile before removing the binary lock; the external
  operation may populate Bun's cache. depscan never invokes Bun, Node, installs,
  lifecycle scripts, environment fallback or range resolution.

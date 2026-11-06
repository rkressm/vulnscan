# pnpm reader fixtures and support

Accepted format identifiers are exactly YAML strings `6.0` / `9.0`, or numeric
values equal to 6 / 9, never booleans. Other versions fail explicitly. YAML is
loaded using approved ruamel.yaml safe/pure mode, duplicate keys disallowed;
recursive aliases and unsafe tags fail. No package manager is required or run.

## Provenance

T01 inspected these committed upstream lockfiles on 2026-11-05:

- https://raw.githubusercontent.com/pnpm/pnpm/v8.0.0/pnpm-lock.yaml
  SHA-256 `4004d9c289ca5c1a51050ec76905535d0da8974c48c2f493350a73e2905f0e37`
- https://raw.githubusercontent.com/pnpm/pnpm/v9.15.9/pnpm-lock.yaml
  SHA-256 `8faf3dc0f279200ec7daec6478eb04b379c988b1f4707625fbb8bb95586e04cd`

`v6.yaml` retains the real remapping record and importer peer reference from the
contract's v6 excerpt. Babel inventory records are **synthetic additions** to make
the excerpt self-contained. `v9.yaml` retains the real remapping package and
snapshot excerpt; referenced jridgewell package records/snapshots are synthetic
additions. Integrity strings marked synthetic are intentionally not checksums.
These files are structural reductions, not byte-identical upstream artifacts;
the hashes above refer only to upstream originals.

`contexts.yaml` and parametrized test documents are synthetic, grammar-directed
cases, not claims of package-manager-generated evidence. Context and importer
grammar references:

- https://github.com/pnpm/spec/blob/master/lockfile/6.0.md
- https://github.com/pnpm/pnpm/blob/v9.15.9/lockfile/types/src/lockfileFileTypes.ts
- https://github.com/pnpm/pnpm/blob/v9.15.9/packages/dependency-path/src/index.ts

## Behavior and limitations

Inventory includes dev, optional and other-platform packages, regardless of
reachability. v6 package dependencies and v9 snapshots/importers join to the
package metadata. Every retained declaration keeps document-line-1 provenance;
peer variants share npm identities rather than becoming fake version strings.
Lookups/counts deduplicate identities downstream, not by deleting provenance.

Only exact registry-keyed packages with nonempty integrity and no explicit
git/directory/tarball resolution are trusted. Arbitrary tarballs (including ones
claiming a registry-looking name/version) remain unscanned; integrity is not
cryptographically verified. Missing/malformed metadata, orphan references and
unknown suffixes remain visible. Recognized suffixes are balanced exact peer
locators (including nested peers) and `patch_hash=...`; opaque hashed peer
contexts are not guessed. Peer suffixes identify contexts, not additional locked
peer packages: only actual package metadata is inventoried.

Aliases use resolved target references, never the importer alias as a package.
Patched packages produce upstream ready results plus explicit patch-coverage
diagnostics. Workspace members/links are not queried; member importer dependency
records remain usable, but nested manifests are never opened and incomplete
workspace coverage is explicit. A valid version-only/empty inventory succeeds;
invalid document/container shapes fail, while malformed entries preserve siblings
with npm-contextual errors. No network resolution or active-install reconstruction.

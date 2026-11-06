# Demonstration files

**Do not install these dependencies or run project scripts.** These are inert
scanner inputs, not applications or installation instructions. Some versions may
have known vulnerabilities. No example has lifecycle scripts.

From the depscan repository directory:

```sh
uv run depscan examples/javascript --no-cache
uv run depscan examples/javascript/package.json --no-cache
uv run depscan examples/mixed --no-cache
```

- `javascript/`: manifest-only exact pin, scoped prerelease alias and development
  pin. The `latest` peer and `^1.0.0` optional range deliberately remain unscanned,
  so this example exits **2** regardless of advisory findings. Generate a supported
  lock externally for unresolved declarations; the scanner never resolves them.
- `mixed/`: Python exact requirement plus a minimal npm v3 lock. The manifest's
  `^4.17.0` declaration is not resolved by depscan: the selected lock supplies
  `lodash@4.17.21`. Both ecosystems are queried. Exit **0** means no known
  advisories, **1** means findings, and **2** means incomplete coverage/errors.
- Existing `requirements.txt` and `requirements/` demonstrate Python includes,
  missing, excluded and unsupported declarations. Explicit requirements scans can
  depend on depscan's installed environment unless `--venv` is supplied.

These commands perform live OSV requests; results depend on advisory coverage and
freshness. The examples' smoke tests (`tests/test_v2_examples.py`) instead mock
HTTP, check JSON/source context and never install dependencies or execute scripts.

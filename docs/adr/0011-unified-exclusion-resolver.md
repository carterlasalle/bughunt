<!-- trace:exempt reason=design-record-no-product-behavior -->
# ADR-011: One exclusion resolver for every engine and the report

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Context

What a scan excludes was defined four times over, in four different forms:

- `technology.IGNORED_DIRS`, the canonical name set the walkers filtered on;
- `configurator.EXCLUDE_DIRS`, a copy of it for the generated analyzer configs;
- **three divergent private copies** inside `policy_scan`, `metrics_scan`, and
  `evidence_scan` (`EXCLUDED` / `IGNORED`), each a different subset — so the
  same file could be excluded by one engine and scanned by another;
- the per-tool configs, several of which hardcoded their own smaller list
  (`bandit.yaml` `exclude_dirs`, `pylintrc` `ignore=`, the `mypy.ini` exclude
  regex, `coverage.ini` `source`).

Nothing let a repository exclude a tree from the scan. `[project]` accepted
`python_paths` / `source_paths` / `test_paths`, which can only *narrow* a
scope, so a vendored directory listed in `source_paths` was scanned by every
engine, and the only lever that reached some engines was Ruff's
`extend-exclude`.

`.gitignore` was honoured by Ruff alone (its generated config sets
`respect-gitignore`) while BugHunt's own scanners walked straight into the same
trees — measured 2026-10-06: a gitignored `vendored/` produced ten Ruff-silent
findings from the native engines.

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Decision

1. `technology.resolve_exclusions(root)` is the single resolver. It merges the
   built-in artifact directories, the repository's `[project] exclude`, and
   `.gitignore`, resolved once per walk. A bare entry matches any path
   component (`vendored`); an entry containing a slash matches a
   repository-relative prefix (`third_party/legacy`).
2. `.gitignore` is applied through one batched `git check-ignore`, and only
   inside a git work tree. Exit 1 (nothing matched) and exit 128 (not a
   repository) are normal; without git, or outside a repository, the built-in
   and configured excludes still apply. BugHunt never fails a scan because git
   is absent.
3. `technology.scope_files` is the single traversal for BugHunt's native
   scanners, so the built-in, configured, and gitignored sets are applied once
   instead of once per scanner. The three private copies are deleted.
4. Generated configs carry the resolved set in each tool's own format
   (`extend-exclude`, `exclude` regex, `ignore`/`ignore-paths`, `exclude_dirs`,
   coverage `omit`), and the scope roots handed to engines are filtered, since
   mypy and pylint apply their own excludes only to paths they discover.
5. `canonicalize_findings` drops findings on excluded paths. Whole-repository
   engines cannot take per-path excludes — CodeQL builds a database of the tree
   — so the boundary is enforced once, where every engine's findings pass.
6. Helper scanners run as `python -m bughunt.*` and receive only a root, so an
   explicit `--config` is exported as `BUGHUNT_CONFIG` for them.

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Alternatives

- Keep per-engine lists (rejected: the three private copies had already
  drifted, and the drift is invisible until a finding appears in a tree the
  user believes is excluded).
- A new `[project] exclude` implemented only in the generated configs
  (rejected: it would not reach BugHunt's own scanners, and CodeQL would still
  report on the tree).
- Implement `.gitignore` with a hand-written matcher (rejected: negation,
  anchoring, and nested ignore files are subtle; `git check-ignore` is exact
  and git is already assumed for the baseline and `git_path_exists`).

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Consequences

One key excludes a tree from every engine, and `git status`-level intent is
respected: what git ignores, BugHunt does not analyse or report. Measured on
this repository, the newly excluded existing paths are generated artifacts
only (`.hypothesis/`, `brag-output/`, `.bugcorpus/generated/`, `.DS_Store`),
and no first-party file is dropped (57 `src/` modules and 39 test modules are
still walked).

Accepted nuance: `git check-ignore` matches patterns regardless of tracking,
so a tracked file that also matches an ignore pattern is excluded, exactly as
Ruff treats it. Tracked-but-ignored is a repository inconsistency worth
fixing rather than special-casing.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt Technology-Aware Correctness Engines (0.5.2+, extended in 0.6.0)

BugHunt's primary objective is finding **bugs and correctness regressions**. The technology layer is not a generic quality/security catalog: an engine is enabled only when the repository contains a surface where it adds a distinct correctness signal.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Applicability contract

`configure --auto` writes `.bughunt/generated/capabilities.json` from repository evidence. `doctor` shows that inventory. A defense whose technology is absent is **N/A** and does not reduce defense health. A defense whose technology is present but whose analyzer cannot run is **SKIPPED/MISSING** and is a real coverage gap.

`all`, `full`, and `skipmutmut` refresh capability discovery before installation, then install only applicable technology-specific engines. The existing Python stack remains the primary Python defense layer.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Engines

| Capability | Engine(s) | BugHunt use |
|---|---|---|
| GitHub Actions | actionlint | Workflow syntax, expression/property typing, jobs/needs/action-interface mistakes; uses ShellCheck for embedded shell when available. |
| Shell | ShellCheck | Quoting, word-splitting, condition, pipeline, variable, command-substitution and portability bugs. |
| Environment files/access | dotenv-linter | `.env` syntax/duplicates plus `.env` ↔ `.env.example` key-contract drift when both exist. |
| OpenAPI/Swagger | oasdiff | Validate current specs and compare them with a local Git baseline for breaking contract changes. |
| Protocol Buffers | Buf | `STANDARD` lint plus `FILE` compatibility checks against a local Git baseline. |
| SQL | SQLFluff | Correctness-only rule subset: AL04, AL08, AM04, AM07, AM08, AM09, RF01, RF02. Formatting/capitalization rules are intentionally excluded. |
| PostgreSQL migrations | Squawk | Migration patterns that can break or block production PostgreSQL deployments. |
| Dockerfiles | Hadolint | Dockerfile/build correctness, including shell-related build failure hazards. |
| Terraform | TFLint | Terraform language/provider correctness via the bundled recommended Terraform plugin preset. |
| Go | golangci-lint | Curated bug set: errcheck, govet, staticcheck, ineffassign, unused, bodyclose, durationcheck, errorlint, exhaustive, makezero, rowserrcheck, sqlclosecheck. |
| Rust | Clippy | `correctness` + `suspicious` as errors, `complexity` + `perf` as warnings. The full `restriction` group is deliberately not enabled. |
| C/C++ | Cppcheck | Independent compiler-adjacent warning/performance/portability analysis. |
| C/C++ + compile database | clang-tidy | `clang-analyzer-*`, `bugprone-*`, and `concurrency-*`. |
| C/C++ + compile database | Infer | Whole-program native analysis when Infer is already provisioned. BugHunt does not pipe an unverified installer into the shell. |
| PHP | PHPStan | Maximum static-analysis level on first-party PHP paths. |
| JavaScript/TypeScript | Oxlint | correctness+suspicious errors; pedantic/perf/restriction/nursery warnings; style disabled. |
| JavaScript | ESLint | Generated correctness-first fallback using `@eslint/js`; project-owned configs are also supported. TypeScript is primarily covered by Oxlint unless the project owns a richer ESLint TS setup. |
| React | React Doctor | React-specific correctness analysis with supply-chain/security scanning disabled in the default correctness profile. |

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Temporal correctness

Two defenses explicitly compare revisions rather than only inspecting HEAD:

- **oasdiff**: `baseline:spec -> working-tree spec`
- **Buf**: current module/schema -> local Git baseline

The baseline selection prefers the merge-base with an existing main/master ref. If HEAD itself is main/master, BugHunt uses `HEAD^` so a committed change is not compared against itself.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Installation policy

BugHunt never installs an ecosystem merely because the engine exists in the catalog. Capability discovery comes first. On macOS, verified Homebrew formulas/taps are used for supported native CLIs. SQLFluff/Squawk can be added with `uv`; JS tools use the repository's available bun/pnpm/yarn/npm; PHPStan uses Composer. Infer is supported when installed but has no automatic installer because BugHunt will not run an unverified download script merely to make `doctor` green.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Security

Security remains additive. Checkov, Trivy, OSV-Scanner, TruffleHog, Presidio, Betterleaks and similar tools are intentionally not part of the primary correctness-health denominator in the primary profile. Security-oriented Semgrep packs remain opt-in.

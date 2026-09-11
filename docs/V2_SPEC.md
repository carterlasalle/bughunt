<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt V2 — Autonomous Correctness Campaign

Status: design specification

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 1. Goal

V1 answers:

> What do all of our existing bug-finding defenses say about this repository?

V2 must answer a harder question:

> After the existing defenses finish, where could important bugs still be hiding, and what new deterministic analyses/tests can we invent to attack those gaps?

The target is not a claim of mathematically perfect software. The target is to continuously reduce the **undefended behavior surface** of a repository until additional compute produces diminishing new evidence.

V2 is an autonomous bug-search campaign manager layered on top of the deterministic V1 runner.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 2. Core operating loop

```text
Repository
   │
   ├── code / types / tests / configs / schemas
   ├── existing analyzer output
   ├── coverage + mutation survivors
   ├── Bug Corpus history
   └── architecture / call graph / dataflow facts
              │
              ▼
         RISK MODEL
              │
              ▼
     bug hypotheses / gaps
              │
       ┌──────┴─────────┐
       │                │
       ▼                ▼
 existing detector   synthesize new searcher
       │                │
       └──────┬─────────┘
              ▼
        run deterministically
              │
              ▼
     adversarially challenge
              │
       ┌──────┴───────────┐
       │                  │
       ▼                  ▼
    evidence            weak rule
       │                  │
       ▼                  └→ refine / retire
   triage + reproduce
       │
       ▼
 confirmed real defect
       │
       ├→ fix
       ├→ regression/property/fuzzer target
       ├→ Bug Corpus BugCase/family
       └→ permanent detector
              │
              └──────────────→ next campaign iteration
```

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 3. Required V2 command surface

```bash
uv run bughunt hunt
uv run bughunt hunt --budget standard
uv run bughunt hunt --budget deep
uv run bughunt hunt --budget insane
uv run bughunt hunt --focus src/router
uv run bughunt hunt --family async-state
uv run bughunt hunt --resume CAMPAIGN_ID

uv run bughunt risk
uv run bughunt hypotheses
uv run bughunt hypothesis show HYP-000123
uv run bughunt hypothesis run HYP-000123

uv run bughunt synthesize-detector HYP-000123
uv run bughunt challenge-detector DET-000044

uv run bughunt campaign show CAMPAIGN_ID
uv run bughunt campaign report CAMPAIGN_ID
```

`bughunt all` remains deterministic V1-style execution. `bughunt hunt` is the agentic V2 campaign.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 4. Campaign state

Campaigns are durable and resumable:

```text
.bughunt/campaigns/CMP-20260910-001/
├── campaign.json
├── risk-map.json
├── hypotheses.jsonl
├── evidence/
├── experiments/
├── candidate-detectors/
├── challenges/
├── decisions.jsonl
└── report/
```

Every agent decision must have inspectable evidence. The model's prose is never the only source of truth.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 5. Risk map

V2 builds a scored map of repository behavior. A unit may be a function, method, class, module, endpoint, CLI command, state machine transition, job handler, or important cross-component flow.

Candidate features include:

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Change / history risk

- churn frequency
- bug-fix density
- recent large diffs
- frequently reverted areas
- repeated Bug Corpus families

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Static complexity

- cyclomatic/cognitive complexity
- deep nesting
- large functions
- dynamic typing / Any / Unknown
- reflection / monkey patching
- broad exception handling
- mutable global state
- async/concurrency boundaries
- resource/transaction boundaries

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Defense weakness

- no tests
- low mutation kill rate
- low type coverage
- analyzer suppressions
- skipped whole-program analysis
- no contracts/invariants
- no fuzz target on complex external input
- no state-machine property for lifecycle-heavy code

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Boundary risk

- parser/deserializer
- network input
- filesystem
- database writes
- auth decisions
- serialization
- subprocess/shell
- model/LLM output
- time/randomness
- concurrency/locks
- external APIs

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Blast radius

- high fan-in
- high fan-out
- shared infrastructure
- security-sensitive sink
- persistence mutation
- irreversible side effect

The risk score must be explainable; agents should be able to answer why something ranked high.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 6. Behavior-defense matrix

V2 maintains a matrix showing how each important unit is defended:

```text
UNIT                   TYPE STATIC FLOW CONTRACT SYMBOLIC PROPERTY FUZZ MUTATION BUGCORPUS
parse_message()         yes   yes   yes    no       no      yes      yes    yes      yes
commit_job()            yes   yes   yes    yes      no      yes      no     yes      yes
retry_request()         yes   yes   no     yes      no      yes      yes    yes      no
world_model_update()    yes   yes   yes    no       no      no       no     yes      yes
```

The blanks are attack opportunities.

This matrix is not a vanity score. V2 should generate hypotheses specifically from meaningful missing defenses.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 7. Hypothesis generation

A hypothesis is a concrete falsifiable statement, not "there may be bugs here."

Good examples:

```text
HYP-0142
Snapshot instances acquired before an `await` can be reused afterward without refresh.

HYP-0201
A parser accepts a negative count that later reaches an allocation boundary.

HYP-0314
One transaction path can commit before audit-log persistence.

HYP-0419
Two semantically equivalent normalization routes disagree for non-ASCII IDs.
```

Each hypothesis records:

- target scope
- why it is plausible
- evidence/risk signals
- intended falsification strategy
- cheapest suitable analysis engine
- estimated cost
- expected false-positive modes
- current state

States:

```text
proposed
queued
running
supported
falsified
inconclusive
converted-to-detector
confirmed-bug
retired
```

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 8. Detector synthesis ladder

V2 uses the cheapest representation capable of expressing the hypothesis:

```text
existing analyzer/config
→ literal/grep query
→ ast-grep
→ Semgrep structural
→ Semgrep dataflow/taint
→ CodeQL
→ Pysa
→ custom AST / CST analyzer
→ custom local call/data-flow engine
→ purpose-built repository searcher
```

An agent must justify moving to a more expensive layer.

Generated analyzers become source-controlled deterministic artifacts if promoted.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 9. Purpose-built searchers

V2 may write code specifically to search for a suspected bug family.

Examples:

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### stale-state-after-await

Required model:

- identify acquisition calls
- local def/use identity
- `await` boundaries
- rebinding/refresh
- uses after final invalidation

Do not build a full points-to engine if function-local analysis is enough.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### transaction ordering

Required model:

- transaction entry/exit
- commit paths
- audit-write paths
- CFG ordering
- exceptional exits

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### parser length propagation

Required model:

- parse source
- integer propagation
- validation predicates
- allocation/loop sinks

The generated searcher must include fixtures and a normalized Finding adapter.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 10. Detector adversarial challenge

A detector is not trusted because it catches the original example.

Challenge transforms should include:

- identifier renaming
- temporary variables
- helper extraction/inlining
- import aliases
- equivalent control-flow forms
- early returns
- exception wrappers
- cross-module movement
- subclass/protocol implementations
- async boundary insertion
- safe refresh/revalidation
- dead/unreachable lookalikes

Required fixture classes:

```text
historical positive
minimal positive
adversarial positives
minimal negative
near-miss negatives
historical fixed revision
```

Promotion thresholds are configurable. Known positives should normally require 100% recall and known negatives 0% false positives.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 11. Fuzz target synthesis

V2 generalizes V1's conservative Atheris discovery.

It should infer richer input strategies from:

- annotations
- Pydantic/dataclass models
- enums/Literals
- parser grammar clues
- serializers
- tests and fixture literals
- OpenAPI / JSON Schema

For structured formats, V2 may synthesize Atheris custom mutators rather than relying only on raw byte mutation.

Every generated target records:

- why the target matters
- input model
- expected exceptions
- seed corpus sources
- coverage signal
- run budget
- crash artifacts

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 12. Property synthesis

V2 searches for metamorphic/differential properties, for example:

```text
serialize(deserialize(x)) == canonical(x)
normalize(normalize(x)) == normalize(x)
optimized(x) == reference(x)
distance(a,b) == distance(b,a)
encode/decode round-trip
cache-on == cache-off
parallel result == sequential result
```

Properties are first run in shadow mode. If they produce stable high-value counterexamples, they become normal tests.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 13. State-machine synthesis

For lifecycle APIs/classes V2 should infer candidate states and transitions from:

- status enums
- method names
- guards/assertions
- database state columns
- tests
- endpoint operations
- Bug Corpus history

It then builds Hypothesis RuleBasedStateMachine or Schemathesis state-machine tests to search operation sequences.

Target bug classes:

- invalid transition
- repeated operation / idempotency
- delete/restore
- retry semantics
- out-of-order operations
- double commit
- stale handles

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 14. Fault injection synthesis

V2 identifies infrastructure boundaries and generates failure campaigns:

- timeout
- connection reset
- partial read/write
- DB rollback/commit failure
- disk errors
- duplicated messages
- reordered messages
- clock jumps
- dependency malformed response

It must assert invariants after each injected failure, not merely check "did not crash."

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 15. Mutation-driven search

Mutation survivors are direct evidence of undefended semantics.

V2 should cluster survivors by operator and code region, then choose one of:

- generate missing property
- strengthen ordinary tests
- add invariant/contract
- mark equivalent mutant with evidence

A surviving boundary mutation such as `<` ↔ `<=` should rank higher than a low-value logging-string mutant.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 16. Differential oracles

When multiple implementations exist, V2 automatically looks for pairs:

- optimized vs reference
- sync vs async
- cached vs uncached
- old vs new implementation
- CPU vs accelerator backend
- parser vs serializer inverse

It generates randomized differential tests and minimizes disagreements.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 17. Agent architecture

V2's deterministic core remains tool-agnostic.

```text
BugHunt core
   ├── CLI
   ├── campaign store
   ├── analyzer adapters
   ├── experiment sandbox
   └── report schema
          ↑
       optional MCP
          ↑
   OMP / Claude / Codex / others
```

Harness-specific plugins/skills only expose the same campaign operations.

No campaign state should live solely inside chat history.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 18. Agent roles

A deep campaign may use specialized agents:

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Mapper

Builds risk/architecture understanding.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Hypothesis generator

Produces falsifiable bug theories from gaps.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Searcher builder

Writes static/dataflow/custom detectors.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Fuzzer/property engineer

Builds dynamic search experiments.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Adversary

Attempts to defeat candidate detectors/tests.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Triage agent

Validates evidence and minimizes reproducers.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Reviewer

Challenges whether claimed fixes/detectors really close the class.

Agents may run in parallel, but the campaign store resolves their evidence into a single state machine.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 19. Compute budgets

Suggested profiles:

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### standard

- V1 all scan
- risk map
- top ~20 hypotheses
- cheap static synthesis
- bounded property/fuzz search

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### deep

- top ~100 hypotheses
- CodeQL/Pysa custom work
- broader mutation review
- state-machine/fault campaigns
- adversarial detector tests

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### insane

- repeatedly regenerate hypotheses
- multiple independent agents per high-risk region
- large fuzz/property budgets
- historical commit mining
- mutation-driven property synthesis
- continue until stopping criteria fire

Budgets must be expressed in actual limits: wall time, number of experiments, model calls, fuzz iterations, and analyzer CPU/time.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 20. Stopping criteria

A campaign stops when any configured combination is reached:

- time/compute budget exhausted
- no high-confidence hypotheses remain
- N consecutive hypothesis batches produce no confirmed bugs
- all high-risk units meet minimum defense requirements
- mutation survivor threshold reached
- user-requested scope cleared

"No more hypotheses" means only that the current campaign exhausted its search strategy, not proof of zero bugs.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 21. Bug Corpus integration

Every confirmed V2 bug goes through the Bug Corpus workflow:

```text
confirmed evidence
→ minimized bad/fixed examples
→ root cause
→ violated invariant
→ family match/create
→ detector/property selection
→ adversarial verification
→ shadow/warning/blocking promotion
```

V2 should query Bug Corpus *before* synthesizing a new family so it strengthens existing detectors when possible.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 22. Repair loop

When a real bug is confirmed, V2 can hand it to the same V1 agent repair queue format:

```text
BH/CMP finding ID
location
reproducer
root-cause hypothesis
minimal failing test
suggested verification commands
related Bug Corpus family
```

After repair, the search experiment must be re-run against the fixed code.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 23. Safety against self-deception

V2 must explicitly prevent these failure modes:

- generated rule catches only exact historical text
- model says "clean" without a deterministic scan
- tool crash interpreted as zero findings
- generated fuzz harness never reaches target code
- fuzzer treats documented invalid input as a bug
- property encodes the current implementation rather than intended behavior
- differential test compares two implementations sharing the same defect
- suppressions erase evidence
- huge raw finding count mistaken for high-quality bug discovery

Campaign reports must disclose blind spots and inconclusive experiments.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 24. Experiment observability

Long experiments need the same live heartbeat as V1, plus:

```text
campaign phase
hypothesis ID
engine
elapsed
budget consumed
coverage delta
new paths / findings
last meaningful progress timestamp
```

A stage with no coverage/path progress for a configurable interval should be marked `STALLED`, not merely `RUNNING`.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 25. Data schemas

Add versioned schemas for:

```text
Campaign
RiskUnit
DefenseCoverage
Hypothesis
Experiment
Counterexample
CandidateDetector
DetectorChallenge
BugEvidence
CampaignDecision
```

All agent-readable Markdown is generated from these structured records.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 26. V2 report

The report should answer, in order:

1. What confirmed bugs were found?
2. What high-frequency bug families appeared?
3. What new detectors/properties were created?
4. Which detector candidates failed adversarial testing?
5. Which repository areas remain high-risk?
6. Which defenses are still missing?
7. What experiments were inconclusive?
8. What should the next campaign spend compute on?

Machine output remains JSON/JSONL first-class.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 27. MVP implementation order

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Phase A — campaign substrate

- campaign IDs/state
- risk-unit schema
- risk scoring
- V1 result ingestion
- hypothesis store

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Phase B — static hypothesis synthesis

- agent prompt/skill
- ast-grep/Semgrep candidate generation
- fixtures
- challenge runner

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Phase C — dynamic synthesis

- richer Atheris targets
- Hypothesis property templates
- differential pair discovery
- mutation-survivor ingestion

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Phase D — whole-program synthesis

- custom CodeQL
- Pysa model generation
- reusable custom-searcher SDK

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Phase E — autonomous loop

- budget controller
- parallel agents
- evidence reconciliation
- stopping criteria
- Bug Corpus automatic handoff

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 28. V2 acceptance criteria

V2 is not complete until:

1. `bughunt hunt` creates a durable campaign.
2. A campaign can resume after process exit.
3. Risk ranking is explainable.
4. At least three independent hypothesis sources exist.
5. A candidate static detector can be synthesized and executed.
6. Candidate detectors have positive + negative + adversarial fixtures.
7. A detector can fail challenge and remain unpromoted.
8. A fuzz/property experiment can produce a minimized counterexample.
9. Mutation survivors can generate hypotheses.
10. Confirmed defects can become Bug Corpus entries.
11. No LLM is required to execute promoted detectors/tests later.
12. Tool/agent failure cannot be reported as clean.
13. Live status exposes stalled experiments.
14. The final report clearly separates confirmed bug, probable signal, false positive, inconclusive experiment, and missing defense.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 29. Long-term destination

The end state is a repository-specific **Correctness Compiler**.

Each project accumulates machine-readable knowledge of:

```text
types
contracts
invariants
state machines
taint rules
architectural rules
bug families
properties
fuzz targets
reference implementations
static detectors
fault models
```

BugHunt then continuously asks:

> What important behavior is still defended by too few independent mechanisms?

and spends compute attacking those gaps.

That is the path from "run every linter" toward genuinely driving escaped defect probability as low as practical.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Appendix A — V1.3 strict-analysis baseline

V1.3 establishes the configuration floor that V2 inherits. `bughunt configure --auto` now generates max-recall analyzer overlays, not only fuzz targets. Ruff runs ALL + preview, all four type-checking engines are configured at their strongest practical settings, Pylint loads installed bundled extensions, generic architecture/AST/Pysa/Hypothesis/Schemathesis scaffolding is generated, and broad scanners exclude BugHunt runtimes/vendor artifacts. See `STRICT_CONFIGS.md` for the exact baseline.

V2 must never silently relax this baseline. It may add project-specific suppressions only when they are structured, justified, and visible in the coverage model. The V2 synthesis loop should preferentially fill the remaining semantic gaps: application Pysa models, project Semgrep/ast-grep/CodeQL rules, contracts, properties, differential/metamorphic oracles, fault injection, and durable Bug Corpus families.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Implemented ahead of V2 in v0.4.0

The following pieces originally described as V2 foundations now exist in the deterministic v0.4.0 core:

- evidence-tiered semantic target discovery,
- automatic differential reference-vs-optimized Hypothesis campaigns,
- automatic typed round-trip properties,
- automatic high-confidence idempotence/metamorphic properties,
- external fault-boundary coverage campaigns,
- managed generated `[[custom.checks]]` entries,
- direct Pysa source/sink wrapper model inference with evidence records,
- safe parser/decoder Atheris discovery including static/class methods and test-call type evidence,
- FastAPI ASGI and evidence-backed Flask WSGI Schemathesis discovery,
- first-party source-root inference for non-`src/` layouts,
- deterministic safe/unsafe/review autofix accounting in reports.

V2 still owns the harder semantic layer: agent-generated hypotheses, arbitrary project-specific invariants, detector synthesis and adversarial evaluation, Bug Corpus learning, state-machine/model inference beyond explicit contracts, custom CodeQL/Pysa/Semgrep generation, and iterative search campaigns.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## v0.5 foundation carried into V2

V2 should treat the shipped default policy/complexity pack as seed invariants rather than a closed rule list. Historical bugs and repository semantics may promote a warning/note into a stronger project-specific detector, generate new Semgrep/CodeQL/Pysa/custom rules, or create executable properties. Complexity refactors should be evaluated on call-graph/state complexity as well as local metric deltas so agents cannot "fix" a budget merely by moving the same branching behind meaningless indirection.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Implemented ahead of V2 in v0.5.2

The deterministic core now has technology-capability discovery and applicability-aware defense health. Non-Python correctness engines are selected from repository evidence rather than installed globally. OpenAPI/Protobuf comparisons introduce temporal contract checks against a local Git baseline. V2 should consume `.bughunt/generated/capabilities.json` as another hypothesis source and should generate project-specific rules/campaigns within each applicable technology rather than broadening the catalog blindly.



<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Implemented ahead of V2 in v0.6.0

The deterministic core now contains branch-coverage findings, coverage-aware mutation, runtime type verification, randomized/environment/interpreter matrices, HypoFuzz, packaging checks, API/history compatibility checks, native seam drift rules, cross-type-checker disagreement, non-destructive logical deduplication, ODC-like classification, and a coverage-weighted risk map.

V2 should consume these signals as hypothesis sources. In particular:

- uncovered exception/branch regions receive elevated search budget;
- mutation survivors are hypotheses about weak assertions, not reachability;
- cross-tool type disagreement is a high-signal ambiguity source;
- BHSEAM findings seed custom dataflow queries and boundary validators;
- version-differential failures seed backward-compatibility Bug Corpus families;
- ODC/taxonomy gaps guide detector synthesis toward under-defended bug classes.

The remaining major V2 ring is deterministic simulation. See `DETERMINISTIC_SIMULATION.md`: project adapters inject clock, scheduler, network, RNG, filesystem/persistence and external-service behavior from a single replayable seed, then execute generated histories while checking repository-specific invariants. The system must never claim simulation coverage when no valid adapter/invariant exists.

Rule synthesis should mine `BUG_TAXONOMY.md` and promote only detectors that survive positive, negative and adversarial fixtures.

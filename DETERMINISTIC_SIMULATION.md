# Deterministic Simulation Ring

Deterministic simulation is the V2 answer to bugs that only appear across histories: retries, timeouts, reordered events, partial writes, duplicate delivery, cancellation, races, delayed messages, and state-machine interactions.

## Core model

A repository opts in through a project adapter that exposes controllable seams:

- clock / timers
- RNG / UUID generation
- scheduler / task interleavings
- network send/receive/drop/delay/duplicate
- filesystem and persistence operations
- external model/API calls

One recorded seed drives every pseudo-random choice. Every event is appended to a replay trace. A failure must be reproducible from `{seed, initial state, event trace}`.

## Campaign

1. Construct a valid initial state.
2. Generate an operation history with Hypothesis stateful testing or an equivalent deterministic generator.
3. Inject a deterministic fault schedule and scheduler decisions from the same seed.
4. Check invariants after every meaningful transition, not only at the end.
5. Shrink/minimize the history when possible.
6. Write a replay artifact under `.bughunt/simulation/replays/`.
7. Promote a confirmed escaped defect into a deterministic regression and Bug Corpus family.

## Generic invariants BugHunt may suggest

BugHunt may infer candidates such as no impossible state, no duplicate stable identifier, no resource leak, no unbounded retry, and round-trip/monotonicity properties. It must not invent business invariants and report them as facts.

## Adapter contract (V2 target)

A future `.bughunt/simulation.py` adapter should expose roughly:

```python
class SimulationAdapter(Protocol):
    def initial_state(self, seed: int) -> object: ...
    def operations(self) -> Sequence[Operation]: ...
    def inject_fault(self, fault: Fault) -> None: ...
    def invariants(self) -> Sequence[Invariant]: ...
    def snapshot(self) -> object: ...
```

The exact API may evolve; replayability and explicit invariants are non-negotiable.

## CI profiles

- PR: replay known failing seeds and a small deterministic history budget.
- Nightly/deep: many fresh seeds and interleavings.
- Weekly/insane: long histories, exhaustive fault combinations, free-threaded interpreters where applicable.

A timeout or crash in the simulator is not clean. Use the `ci-fix-dont-freeze` skill to diagnose infrastructure or hangs before weakening the campaign.

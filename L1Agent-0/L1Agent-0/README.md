# An L1 SOC agent

A SOC triage agent built to be **read**, not deployed. Every external
dependency — threat intelligence, the LLM — is simulated deterministically, so
the whole thing runs offline, instantly, and gives the same answer every time.

Zero dependencies. Python 3.10+.

```bash
python -m socedu.lessons          # 12 runnable lessons
python -m socedu.cli compare      # all scenarios side by side
python -m socedu.cli run breach --explain
python -m socedu.cli run-file sample.log
```

## What this is for

Production agents are black boxes: logs in, alert out. That is fine
operationally and useless for learning, because everything interesting happens
in between.

Here, every stage records **what it decided and why**, including the
alternatives it rejected. The same pipeline now also accepts a real log file
via the file-based command path, which makes the project usable for live
SOC-style triage experiments rather than only built-in scenarios:

```python
from socedu import SOCAgent, SCENARIOS

agent = SOCAgent()
result = agent.analyze(SCENARIOS["breach"].log)

print(result.alert.title)              # what it concluded
print(result.explain())                # every decision, in order
print(result.why("185.220.101.34"))    # every decision touching one value
print(result.prompt.render())          # the exact context the model received
```

## The pipeline

```
ingest   raw text        →  structured events
detect   events          →  findings + a reduced event set
extract  events          →  indicators
enrich   indicators      →  indicators with external verdicts
recall   incident shape  →  similar past incidents
reason   everything      →  correlation, severity, narrative
report   assessment      →  the alert
feedback analyst verdict →  memory
```

The ordering is the architecture. Cheap, deterministic, reliable work runs
first; the expensive non-deterministic step runs last, on a small curated
slice. Handing raw logs straight to a model is the most common way these
systems get built badly.

## Nine ideas, one per problem

**1. Stages narrow.** 109 log lines become 24 events reaching the reasoner.
Every stage exists to reduce what the next one must consider.

**2. Deterministic first.** "Four failures then a success from one address" is
a counter, not a judgement. Code gets it right every time, names the rule that
fired, and costs nothing. Save the model for correlation, which is real
judgement.

**3. Restraint is a capability.** An agent tuned only on attacks finds an
attack in a backup script. Two scenarios here are entirely benign, and the
agent reports 80% confidence that nothing happened — a stronger claim than most
of its attack verdicts.

**4. Context assembly is the engineering.** Choosing what enters the prompt
determines answer quality more than prompt wording does. `PromptBundle` keeps
context as structured data and renders to text last, so the selection stays
visible as a decision.

**5. Unknown is not clean.** The most common way an agent misses a novel
attack. Freshly registered attacker infrastructure has no reputation. The agent
keeps severity HIGH on behaviour alone, lowers confidence, and says why.

**6. Enrichment must precede reasoning.** The `breach` and `maintenance`
scenarios fire overlapping detectors — download, staged script, new cron job.
Only the source verdicts differ. A pattern matcher cannot separate them.

**7. Log data is attacker-controlled.** Usernames and filenames are chosen by
whoever is attacking you. Three defenses, none sufficient alone, plus the
architectural one: the agent recommends, a human decides.

**8. Memory makes it an agent.** A pipeline repeats its mistakes forever.
Recording an analyst verdict against the incident's *shape* — which detectors
fired, which techniques — means a new attack from a different address still
matches a structurally similar past case.

**9. Degrade, never fail.** Providers go down, models return prose instead of
JSON, rate limits bite. Every external call lowers confidence on failure rather
than raising an exception.

## Scenarios

| Scenario | Verdict | Teaches |
|---|---|---|
| `breach` | CRITICAL 96% | Weak signals correlating into one narrative |
| `injection` | CRITICAL 95% | Attacker text reaching the AI analyst |
| `failed_attack` | HIGH 70% | Attempt vs compromise |
| `novel` | HIGH 50% | Reasoning without threat intelligence |
| `ambiguous` | MEDIUM 50% | Calibrated uncertainty |
| `maintenance` | LOW 55% | Same shape, opposite conclusion |
| `benign` | LOW 80% | Restraint |
| `quiet` | LOW 80% | Saying nothing happened |

The non-attacks matter most. An agent that flags everything is as useless as
one that flags nothing.

## Lessons

```bash
python -m socedu.lessons --list
python -m socedu.lessons 6        # same shape, opposite conclusions
```

1. The shape of an agent
2. Why detection runs before the model
3. Restraint
4. Context assembly
5. Unknown is not clean
6. Same shape, opposite conclusions
7. Log data is attacker-controlled
8. Memory makes it an agent
9. Calibrated uncertainty
10. Degradation, not failure
11. Reading the agent's mind
12. Tuning changes the answer

Each runs real code. Where a lesson shows the agent being wrong, it is actually
wrong.

## Reading order

1. `agent.py` — the whole architecture in one readable function
2. `stages.py` — the seven steps, in pipeline order
3. `trace.py` — how decisions get recorded
4. `simulation.py` — what is faked, and what is preserved about it
5. `scenarios.py` — the test cases, including the traps

## What the simulation preserves

The fakes are honest about being fakes. They do not model an LLM's ability to
generalise — the simulated reasoner follows a fixed decision tree where a real
model handles shapes nobody wrote a branch for. That gap is the argument for
paying for a real model.

What they *do* preserve is every failure mode the architecture must handle:
rate limits, caching, providers disagreeing, providers having no data,
transient failures, malformed model output, prompt injection, and tool
approval boundaries. Those are the things worth learning, and they are
identical whether the provider is real.

Swapping in reality is a constructor argument:

```python
agent = SOCAgent(providers=[RealVirusTotal(key)], reasoner=RealClaude(key))
```

`socedu/groq_reasoner.py` does exactly this against Groq's hosted models — no
SDK, one stdlib HTTP call, same `.reason(bundle) -> dict` interface as
`SimulatedReasoner`. A lightweight tool layer in `socedu/tools.py` adds real
SOC-style adapters for reading log files, querying a SIEM endpoint, and
executing EDR containment actions behind a simple approval guard. It is wired
into the CLI:

```bash
# put GROQ_API_KEY=... in .env (repo root) or export it
python -m socedu.cli run breach --reasoner groq
python -m socedu.cli run breach --reasoner groq --model llama-3.3-70b-versatile
python -m socedu.cli run-file sample.log --reasoner groq
```

A missing key, a network failure, or a non-JSON response all degrade to the
rule-derived fallback rather than raising — see idea #9 above.

## Testing

```bash
python run_tests.py        # no dependencies
python -m pytest tests/    # if available
```

64 tests. Several assert claims the lessons make out loud — if a lesson says
"unknown is not clean", a test proves it. Teaching material that drifts from
its code is worse than none.

## What this is not

Not production software. No log shipping, no file watching, no persistence, no
deployment tooling, no alert delivery. Those are solved problems and they
obscure the architecture.

If you want the production version, the pieces are: a watcher that handles log
rotation and offset persistence, a real vector store, real API clients with
retry logic, and systemd or container packaging. None of it changes the
pipeline shape above.

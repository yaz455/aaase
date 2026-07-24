"""The trace — how this package teaches.

A production agent is a black box: logs go in, an alert comes out. That is fine
operationally and useless pedagogically, because the interesting part is the
*reasoning between* those two points.

Every stage in this package writes to a shared Trace. Each entry records what
the stage saw, what it decided, and — most importantly — *why*, including the
alternatives it rejected. You can then replay the agent's thinking:

    trace.explain()                  # full narrative
    trace.explain(stage="enrich")    # one stage
    trace.decisions_about("10.0.0.5")  # every decision touching one value

This is deliberately more machinery than a working agent needs. It exists so
that when the agent gets something wrong — and it will — you can see exactly
which decision was responsible instead of guessing.

Design note: the Trace is passed *into* stages rather than stages returning it.
That keeps stage signatures honest (they return their actual output, not a
tuple of output-plus-metadata) and lets a stage record decisions from deep
inside a helper function without threading return values back up.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Stage(str, Enum):
    """The seven stages an agent moves through. Ordered."""
    INGEST = "ingest"
    DETECT = "detect"
    EXTRACT = "extract"
    ENRICH = "enrich"
    RECALL = "recall"
    REASON = "reason"
    REPORT = "report"
    FEEDBACK = "feedback"


STAGE_ORDER = {s: i for i, s in enumerate(Stage)}


class Confidence(str, Enum):
    """How sure the agent is about a single decision.

    Deliberately coarse. A decision function that claims 0.73 confidence is
    usually inventing precision it does not have; four buckets are honest
    about what these heuristics actually know.
    """
    CERTAIN = "certain"       # deterministic, no judgement involved
    STRONG = "strong"         # clear evidence, benign explanation unlikely
    MODERATE = "moderate"     # fits the pattern, alternatives remain open
    WEAK = "weak"             # suggestive only, would not stand alone


@dataclass
class Decision:
    """One choice the agent made, with its justification.

    `alternatives` is the field that makes this educational rather than
    decorative. Recording what was *rejected* and why is how a reader learns
    the decision boundary, not just the outcome.
    """
    stage: Stage
    subject: str                     # what was being decided about
    verdict: str                     # what was decided
    because: str                     # why
    confidence: Confidence = Confidence.MODERATE
    alternatives: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def render(self, indent: int = 0, width: int = 78) -> str:
        pad = " " * indent
        body = f"{pad}{self.subject} → {self.verdict}  [{self.confidence.value}]"
        lines = [body]
        for line in textwrap.wrap(f"because {self.because}", width - indent - 4):
            lines.append(f"{pad}    {line}")
        for item in self.evidence:
            for j, line in enumerate(textwrap.wrap(item, width - indent - 8)):
                prefix = f"{pad}    · " if j == 0 else f"{pad}      "
                lines.append(prefix + line)
        for alt in self.alternatives:
            for j, line in enumerate(textwrap.wrap(f"rejected: {alt}",
                                                   width - indent - 8)):
                prefix = f"{pad}    ✗ " if j == 0 else f"{pad}      "
                lines.append(prefix + line)
        return "\n".join(lines)


@dataclass
class StageRecord:
    """What one stage did overall."""
    stage: Stage
    summary: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0


class Trace:
    """Collects every decision the agent makes during one analysis."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.records: dict[Stage, StageRecord] = {}
        self._order: list[Stage] = []

    # -- recording ---------------------------------------------------------

    def stage(self, stage: Stage, summary: str = "", **inputs: Any) -> StageRecord:
        """Open (or reopen) a stage record."""
        record = self.records.get(stage)
        if record is None:
            record = StageRecord(stage=stage, summary=summary, inputs=inputs)
            self.records[stage] = record
            self._order.append(stage)
        else:
            if summary:
                record.summary = summary
            record.inputs.update(inputs)
        return record

    def decide(self, stage: Stage, subject: str, verdict: str, because: str,
               confidence: Confidence = Confidence.MODERATE,
               alternatives: list[str] | None = None,
               evidence: list[str] | None = None) -> Decision:
        """Record a single decision. Returns it so callers can chain."""
        decision = Decision(
            stage=stage, subject=subject, verdict=verdict, because=because,
            confidence=confidence,
            alternatives=alternatives or [], evidence=evidence or [])
        if self.enabled:
            self.stage(stage).decisions.append(decision)
        return decision

    def note(self, stage: Stage, text: str) -> None:
        if self.enabled:
            self.stage(stage).notes.append(text)

    def finish(self, stage: Stage, summary: str = "",
               elapsed_ms: float = 0.0, **outputs: Any) -> None:
        record = self.stage(stage)
        if summary:
            record.summary = summary
        record.elapsed_ms = elapsed_ms
        record.outputs.update(outputs)

    # -- querying ----------------------------------------------------------

    def all_decisions(self) -> list[Decision]:
        out: list[Decision] = []
        for stage in sorted(self._order, key=lambda s: STAGE_ORDER[s]):
            out.extend(self.records[stage].decisions)
        return out

    def decisions_about(self, needle: str) -> list[Decision]:
        """Every decision mentioning a value — trace one IP through the agent."""
        needle = needle.lower()
        return [d for d in self.all_decisions()
                if needle in d.subject.lower()
                or needle in d.verdict.lower()
                or needle in d.because.lower()
                or any(needle in e.lower() for e in d.evidence)]

    def explain(self, stage: Stage | str | None = None,
                show_evidence: bool = True) -> str:
        """Render the trace as a readable narrative."""
        if isinstance(stage, str):
            stage = Stage(stage)
        stages = ([stage] if stage
                  else sorted(self._order, key=lambda s: STAGE_ORDER[s]))

        out: list[str] = []
        for st in stages:
            record = self.records.get(st)
            if record is None:
                continue
            header = f"── {st.value.upper()} "
            out.append(header + "─" * max(0, 74 - len(header)))
            if record.summary:
                out.extend(textwrap.wrap(record.summary, 76))
            if record.elapsed_ms:
                out.append(f"   ({record.elapsed_ms:.1f} ms)")
            for note in record.notes:
                for line in textwrap.wrap(note, 74):
                    out.append(f"  ▸ {line}")
            if record.decisions:
                out.append("")
                for decision in record.decisions:
                    if not show_evidence:
                        decision = Decision(
                            stage=decision.stage, subject=decision.subject,
                            verdict=decision.verdict, because=decision.because,
                            confidence=decision.confidence)
                    out.append(decision.render(indent=2))
                    out.append("")
            out.append("")
        return "\n".join(out).rstrip()

    def summary_table(self) -> str:
        rows = ["stage      decisions  elapsed",
                "─────────  ─────────  ───────"]
        for st in sorted(self._order, key=lambda s: STAGE_ORDER[s]):
            r = self.records[st]
            rows.append(f"{st.value:<9}  {len(r.decisions):>9}  "
                        f"{r.elapsed_ms:>6.1f}ms")
        return "\n".join(rows)

    def to_dict(self) -> dict[str, Any]:
        return {
            st.value: {
                "summary": r.summary,
                "inputs": r.inputs,
                "outputs": r.outputs,
                "elapsed_ms": round(r.elapsed_ms, 2),
                "notes": r.notes,
                "decisions": [
                    {"subject": d.subject, "verdict": d.verdict,
                     "because": d.because, "confidence": d.confidence.value,
                     "evidence": d.evidence, "alternatives": d.alternatives}
                    for d in r.decisions
                ],
            }
            for st, r in (
                (s, self.records[s])
                for s in sorted(self._order, key=lambda x: STAGE_ORDER[x])
            )
        }

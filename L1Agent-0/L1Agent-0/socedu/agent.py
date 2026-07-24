"""The agent.

Deliberately thin. If the orchestrator needed a lot of code, the stage
boundaries would be wrong.

Read `analyze` top to bottom and you have the whole architecture. Everything
interesting happens inside the stages; this file just shows the order and the
handful of decisions that only make sense at the seam between stages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .simulation import (
    PromptBundle, SimulatedIntelProvider, SimulatedReasoner,
    default_providers, scan_for_injection,
)
from .tools import FileLogReaderTool, SOCTool
from .trace import Confidence, Stage, Trace
from .types import Alert, Event, Intel, Memory, Severity
from . import stages


@dataclass
class AgentConfig:
    """Every tunable in one place, with the reasoning behind each default."""

    # Detection sensitivity. Too low floods the analyst with scanner noise;
    # too high misses slow attacks. There is no correct value, only a value
    # tuned to one environment.
    brute_threshold: int = 4
    window_seconds: int = 300
    beacon_min_events: int = 5
    beacon_jitter: float = 0.15

    # Context budget. The single biggest cost lever in a real deployment.
    context_events: int = 2
    max_events_to_reasoner: int = 60

    # Recall
    recall_threshold: float = 0.3
    recall_top_k: int = 3

    # Simulation controls, for teaching
    reasoner_seed: int = 7
    malformed_rate: float = 0.0
    provider_seed: int = 11

    trace_enabled: bool = True


@dataclass
class Result:
    """What one analysis produced, including how it got there."""
    alert: Alert
    trace: Trace
    events: list[Event]
    prompt: PromptBundle
    elapsed_ms: float = 0.0

    def explain(self, stage: str | None = None) -> str:
        return self.trace.explain(stage)

    def why(self, value: str) -> str:
        """Every decision that touched one value. Trace an IP end to end."""
        decisions = self.trace.decisions_about(value)
        if not decisions:
            return f"No decision mentioned {value!r}."
        parts = [f"Decisions involving {value!r}:", ""]
        for decision in decisions:
            parts.append(f"[{decision.stage.value}]")
            parts.append(decision.render(indent=2))
            parts.append("")
        return "\n".join(parts)


class SOCAgent:
    """A SOC triage agent, built for reading rather than for production.

    The pipeline:

        ingest  → structured events
        detect  → findings, and a reduced event set
        extract → indicators
        enrich  → indicators with external verdicts
        recall  → similar past incidents
        reason  → correlation, severity, narrative
        report  → the alert

    The ordering carries the main lesson. Deterministic, cheap, reliable work
    happens first; the expensive non-deterministic step runs last, on a small
    curated slice. Reversing that — handing raw logs straight to a model — is
    the most common way these systems get built badly.
    """

    def __init__(self,
                 config: AgentConfig | None = None,
                 providers: list[SimulatedIntelProvider] | None = None,
                 reasoner: SimulatedReasoner | None = None,
                 memory: stages.IncidentMemory | None = None,
                 tools: list[SOCTool] | None = None):
        self.config = config or AgentConfig()
        self.providers = providers if providers is not None else default_providers()
        self.reasoner = reasoner or SimulatedReasoner(
            seed=self.config.reasoner_seed,
            malformed_rate=self.config.malformed_rate)
        self.memory = memory or stages.IncidentMemory()
        self.tools = tools if tools is not None else [FileLogReaderTool()]
        # Shared across analyses, like a real cache. Watch the hit rate climb
        # when the same attacker appears twice.
        self.intel_cache: dict[str, Intel] = {}

    # ------------------------------------------------------------------

    def analyze(self, log_text: str) -> Result:
        return self.analyze_text(log_text)

    def analyze_text(self, log_text: str) -> Result:
        trace = Trace(enabled=self.config.trace_enabled)
        cfg = self.config
        started = time.perf_counter()

        def timed(stage: Stage, fn):
            t0 = time.perf_counter()
            out = fn()
            trace.stage(stage).elapsed_ms = (time.perf_counter() - t0) * 1000
            return out

        # 1 — raw text becomes structured events
        events = timed(Stage.INGEST, lambda: stages.ingest(log_text, trace))

        # 2 — deterministic detection, then reduce the log to what matters
        findings = timed(Stage.DETECT, lambda: stages.detect(
            events, trace,
            brute_threshold=cfg.brute_threshold,
            window_seconds=cfg.window_seconds,
            beacon_min=cfg.beacon_min_events,
            beacon_jitter=cfg.beacon_jitter))

        selected = stages.select_relevant(
            events, findings, trace,
            context=cfg.context_events, cap=cfg.max_events_to_reasoner)

        # 3 — indicators, from the reduced set only
        #
        # Extracting from `selected` rather than all events is a real tradeoff:
        # it saves enrichment quota but can miss an indicator that appears only
        # in an event no detector flagged. Worth it here because unflagged
        # events rarely contain the decisive indicator — but it is a choice,
        # not an obvious truth.
        indicators = timed(Stage.EXTRACT,
                           lambda: stages.extract(selected, trace))

        # 4 — what the outside world knows
        enriched = timed(Stage.ENRICH, lambda: stages.enrich(
            indicators, self.providers, trace,
            cache=self.intel_cache, seed=cfg.provider_seed))

        # Roles can only be settled once verdicts exist — the extractor cannot
        # tell a routine login from an attacker's in isolation.
        stages.assign_roles(enriched, selected, trace)

        # 5 — what the agent has seen before
        shape = stages.incident_shape(findings)
        memories = timed(Stage.RECALL, lambda: self.memory.recall(
            shape, trace,
            threshold=cfg.recall_threshold, top_k=cfg.recall_top_k))

        # Assemble the prompt. Choosing *what goes in* is the engineering;
        # rendering it to text is formatting.
        _, injections = scan_for_injection(
            "\n".join(e.summarize() for e in selected))

        bundle = PromptBundle(
            events=selected, findings=findings, indicators=enriched,
            memories=memories, injection_attempts=injections,
            truncated_from=len(events) if len(events) > len(selected) else 0)

        # 6 — correlation and judgement
        assessment = timed(Stage.REASON,
                           lambda: stages.reason(bundle, self.reasoner, trace))

        # 7 — the analyst-facing artifact
        alert = timed(Stage.REPORT, lambda: stages.report(
            assessment, findings, enriched, memories, trace,
            reasoned_by=self.reasoner.name))

        return Result(alert=alert, trace=trace, events=events, prompt=bundle,
                      elapsed_ms=(time.perf_counter() - started) * 1000)

    def analyze_file(self, path: str | Path) -> Result:
        """Analyze a real log file with the existing SOC triage pipeline."""
        source = Path(path)
        if not source.exists():
            raise FileNotFoundError(f"log file not found: {source}")
        if not source.is_file():
            raise IsADirectoryError(f"expected a file path, got: {source}")

        for tool in self.tools:
            if getattr(tool, "name", "") == "file-log-reader":
                result = tool.execute(source)
                if not result.ok:
                    raise FileNotFoundError(result.error or str(source))
                return self.analyze_text(result.payload)

        return self.analyze_text(source.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------

    def record_verdict(self, result: Result, verdict: str,
                       note: str = "") -> None:
        """Stage 8 — the analyst rules on the alert.

        This is what separates an agent from a pipeline. The verdict is stored
        against the incident's *shape*, so the next time something structurally
        similar arrives the agent recalls how a human judged it.

        Without this the agent makes the same mistake indefinitely.
        """
        if verdict not in {"true_positive", "false_positive", "benign"}:
            raise ValueError(f"unrecognised verdict: {verdict!r}")

        shape = stages.incident_shape(result.alert.findings)
        self.memory.remember(
            incident_id=result.alert.alert_id,
            title=result.alert.title,
            shape=shape,
            analyst_verdict=verdict,
            note=note)

        result.trace.stage(Stage.FEEDBACK, "Analyst records a verdict.")
        result.trace.decide(
            Stage.FEEDBACK, result.alert.alert_id, verdict,
            note or "analyst judgement recorded against the incident shape, so "
                    "structurally similar activity recalls it in future",
            Confidence.CERTAIN)

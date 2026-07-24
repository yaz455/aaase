"""Domain types.

Deliberately smaller than the production version. Every field here earns its
place by being read somewhere in the agent's reasoning — nothing is included
just because a real SIEM would have it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1,
                 Severity.HIGH: 2, Severity.CRITICAL: 3}


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"      # never treat as clean — see enrich.py


class IoCType(str, Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    PATH = "path"
    USER = "user"
    PROCESS = "process"


@dataclass
class Event:
    """One log line, parsed into fields the agent reasons about."""
    timestamp: datetime
    raw: str
    host: str | None = None
    process: str | None = None
    user: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    action: str | None = None       # login_failed, login_success, sudo_command...
    outcome: str | None = None      # success | failure
    message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return hashlib.sha256(
            f"{self.timestamp.isoformat()}|{self.raw}".encode()).hexdigest()[:12]

    def summarize(self) -> str:
        """Compact form. This is what the model sees — not the raw line.

        Raw log lines are mostly punctuation and repeated hostnames. Sending
        them wastes context the agent needs for correlation.
        """
        bits = [self.timestamp.strftime("%H:%M:%S")]
        for label, value in (("host", self.host), ("user", self.user),
                             ("src", self.source_ip), ("dst", self.dest_ip),
                             ("port", self.dest_port), ("proc", self.process),
                             ("action", self.action)):
            if value not in (None, ""):
                bits.append(f"{label}={value}")
        if self.message:
            bits.append(f'"{self.message[:110]}"')
        return " ".join(bits)


@dataclass
class Finding:
    """A detector firing. Not yet an alert — one signal among several."""
    rule_id: str
    title: str
    severity: Severity
    why: str
    events: list[Event] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    kind: str = "rule"              # rule | pattern


@dataclass
class Indicator:
    """An extracted IoC before enrichment."""
    type: IoCType
    value: str
    count: int = 1
    role: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value}"


@dataclass
class Intel:
    """One provider's opinion about one indicator."""
    provider: str
    verdict: Verdict
    score: float
    detail: str = ""
    cached: bool = False


@dataclass
class EnrichedIndicator:
    """An indicator plus every provider's opinion, merged."""
    indicator: Indicator
    intel: list[Intel] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    score: float = 0.0
    why: str = ""

    def summarize(self) -> str:
        base = (f"{self.indicator.type.value} {self.indicator.value} → "
                f"{self.verdict.value} ({self.score:.2f})")
        if self.indicator.role:
            base += f" [{self.indicator.role}]"
        sources = "; ".join(f"{i.provider}: {i.detail}"
                            for i in self.intel if i.detail)
        return f"{base} | {sources}" if sources else base


@dataclass
class Memory:
    """A past incident the agent recalls."""
    incident_id: str
    title: str
    shape: str                   # the abstract pattern, not the literal values
    analyst_verdict: str         # true_positive | false_positive | benign
    note: str = ""
    similarity: float = 0.0


@dataclass
class Alert:
    """The agent's final output."""
    alert_id: str
    timestamp: datetime
    severity: Severity
    confidence: float
    title: str
    narrative: str
    indicators: list[EnrichedIndicator] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    recalled: list[Memory] = field(default_factory=list)
    would_change_mind: str = ""
    reasoned_by: str = "simulated"

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "title": self.title,
            "narrative": self.narrative,
            "indicators": [
                {"type": e.indicator.type.value, "value": e.indicator.value,
                 "role": e.indicator.role, "verdict": e.verdict.value,
                 "score": round(e.score, 3), "why": e.why}
                for e in self.indicators],
            "findings": [
                {"rule_id": f.rule_id, "title": f.title,
                 "severity": f.severity.value, "why": f.why,
                 "mitre": f.mitre, "kind": f.kind}
                for f in self.findings],
            "mitre": self.mitre,
            "reasoning": self.reasoning,
            "actions": self.actions,
            "recalled": [
                {"incident_id": m.incident_id, "title": m.title,
                 "analyst_verdict": m.analyst_verdict,
                 "similarity": round(m.similarity, 3)}
                for m in self.recalled],
            "would_change_mind": self.would_change_mind,
            "reasoned_by": self.reasoned_by,
        }


def new_alert_id() -> str:
    import uuid
    now = datetime.now(timezone.utc)
    return f"EDU-{now:%Y%m%d}-{uuid.uuid4().hex[:5].upper()}"

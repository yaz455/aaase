"""The agent's stages.

Each function here is one step the agent takes. They share a shape:

    def stage(input, ..., trace) -> output

Taking the trace as a parameter rather than returning it keeps signatures
honest and lets a stage record a decision from inside a helper.

Read them in order — ingest, detect, extract, enrich, recall, reason, report.
That order *is* the architecture, and the ordering itself is the main design
decision: deterministic work happens before the expensive, non-deterministic
reasoning step.
"""

from __future__ import annotations

import ipaddress
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .simulation import (
    KNOWN_BAD, PromptBundle, SimulatedIntelProvider, SimulatedReasoner,
    extract_json, scan_for_injection,
)
from .trace import Confidence, Stage, Trace
from .types import (
    Alert, EnrichedIndicator, Event, Finding, Indicator, Intel, IoCType,
    Memory, Severity, SEVERITY_RANK, Verdict, new_alert_id,
)


# ==========================================================================
# Stage 1 — INGEST
# ==========================================================================

_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Ordered most-specific first; the first match wins.
_SEMANTICS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from "
                r"(?P<ip>\S+) port (?P<port>\d+)", re.I), "login_failed", "failure"),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from "
                r"(?P<ip>\S+) port (?P<port>\d+)", re.I), "login_success", "success"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.I),
     "invalid_user", "failure"),
    (re.compile(r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=\S+\s*;"
                r"\s*COMMAND=(?P<cmd>.+)", re.I), "sudo_command", "success"),
    (re.compile(r"\((?P<user>[^)]+)\)\s+REPLACE", re.I), "cron_modified", "success"),
    (re.compile(r"UFW BLOCK", re.I), "firewall_block", "failure"),
    (re.compile(r"UFW ALLOW", re.I), "connection", "success"),
]

# Actions where a bare IP in the text is a *target*, not the connection source.
_NO_IP_FALLBACK = {"sudo_command", "cron_modified"}


def ingest(log_text: str, trace: Trace, year: int = 2026) -> list[Event]:
    """Parse raw log text into structured events.

    Deliberately regex-based. Parsing is a solved deterministic problem —
    spending model tokens on it costs more and works worse than a regex that
    either matches or does not.
    """
    trace.stage(Stage.INGEST, "Turn raw log lines into structured events.")
    lines = [ln for ln in log_text.splitlines() if ln.strip()]
    events: list[Event] = []
    unparsed = 0

    for line in lines:
        match = _SYSLOG.match(line)
        if not match:
            unparsed += 1
            events.append(Event(
                timestamp=datetime.now(timezone.utc), raw=line, message=line))
            continue

        g = match.groupdict()
        hour, minute, second = (int(p) for p in g["time"].split(":"))
        stamp = datetime(year, _MONTHS[g["mon"]], int(g["day"]),
                         hour, minute, second, tzinfo=timezone.utc)

        event = Event(
            timestamp=stamp, raw=line, host=g["host"],
            process=g["proc"], message=g["msg"].strip())
        _apply_semantics(event)
        events.append(event)

    events.sort(key=lambda e: e.timestamp)

    if unparsed:
        trace.decide(
            Stage.INGEST, f"{unparsed} unparsed line(s)",
            "kept with raw text preserved",
            "a line the parser does not understand may still be the important "
            "one; dropping it silently would hide evidence",
            Confidence.CERTAIN,
            alternatives=["discard unparsed lines — loses evidence",
                          "abort the analysis — one odd line should not stop triage"])

    parsed = len(events) - unparsed
    trace.finish(
        Stage.INGEST,
        f"Parsed {parsed}/{len(lines)} lines into structured events.",
        parsed=parsed, unparsed=unparsed)
    return events


def _apply_semantics(event: Event) -> None:
    """Extract meaning from the message body: who, from where, success or not."""
    for pattern, action, outcome in _SEMANTICS:
        m = pattern.search(event.message)
        if not m:
            continue
        event.action = action
        event.outcome = outcome
        groups = m.groupdict()
        if groups.get("user"):
            event.user = groups["user"]
        if groups.get("ip"):
            event.source_ip = groups["ip"]
        if groups.get("cmd"):
            event.extra["command"] = groups["cmd"].strip()
        break

    for key, attr, cast in (("SRC", "source_ip", str), ("DST", "dest_ip", str),
                            ("DPT", "dest_port", int)):
        m = re.search(rf"\b{key}=(\S+)", event.message)
        if m and getattr(event, attr) is None:
            try:
                setattr(event, attr, cast(m.group(1)))
            except ValueError:
                pass

    # An IP inside a command argument is a download target, not the source of
    # the connection. Attributing it as the source would point the whole
    # investigation at the wrong host.
    if event.source_ip is None and event.action not in _NO_IP_FALLBACK:
        m = _IP.search(event.message)
        if m:
            event.source_ip = m.group(0)


# ==========================================================================
# Stage 2 — DETECT
# ==========================================================================

RULES: list[dict] = [
    {"id": "R-DOWNLOAD", "title": "Download utility fetched a remote file",
     "severity": Severity.HIGH, "mitre": ["T1105"],
     "pattern": re.compile(r"\b(wget|curl|certutil)\b.*https?://", re.I),
     "why": "A file-transfer tool pulling a remote URL is the standard way a "
            "payload reaches a compromised host."},
    {"id": "R-TMPEXEC", "title": "Execution from a world-writable directory",
     "severity": Severity.HIGH, "mitre": ["T1059.004"],
     "pattern": re.compile(r"(/tmp/|/dev/shm/|/var/tmp/|/\.\w+/)[\w.\-]+\.(sh|py|elf|bin)"),
     "why": "Attackers stage payloads where any user can write. Legitimate "
            "software installs to /usr or /opt."},
    {"id": "R-CRON", "title": "Scheduled task created or replaced",
     "severity": Severity.HIGH, "mitre": ["T1053.003"],
     "action": "cron_modified",
     "why": "A cron entry survives reboots. This is how short-lived access "
            "becomes durable access."},
    {"id": "R-AUTHKEYS", "title": "SSH authorized_keys modified",
     "severity": Severity.HIGH, "mitre": ["T1098.004"],
     "pattern": re.compile(r"authorized_keys", re.I),
     "why": "Adding a public key grants permanent entry that survives a "
            "password change."},
    {"id": "R-LOGCLEAR", "title": "History or log clearing",
     "severity": Severity.HIGH, "mitre": ["T1070.003"],
     "pattern": re.compile(r"(history\s+-c|rm\s+.*/var/log|shred\s+.*log)", re.I),
     "why": "Deliberate anti-forensics. Difficult to explain as a mistake."},
    {"id": "R-CREDFILE", "title": "Credential store accessed",
     "severity": Severity.HIGH, "mitre": ["T1003"],
     "pattern": re.compile(r"(/etc/shadow|\.ssh/id_rsa|\.aws/credentials)"),
     "why": "Reading credential files is a precursor to lateral movement."},
    {"id": "R-C2PORT", "title": "Connection to a common C2 port",
     "severity": Severity.MEDIUM, "mitre": ["T1571"],
     "ports": {4444, 1337, 31337, 8888, 9001},
     "why": "These ports are defaults in widely used offensive tooling."},
    {"id": "R-ROOTSSH", "title": "Direct root login over SSH",
     "severity": Severity.MEDIUM, "mitre": ["T1078.003"],
     "action": "login_success", "users": {"root", "admin"},
     "why": "Most hardened estates disable direct root SSH, so a success "
            "warrants review even when legitimate."},
]


def detect(events: list[Event], trace: Trace,
           brute_threshold: int = 4, window_seconds: int = 300,
           beacon_min: int = 5, beacon_jitter: float = 0.15) -> list[Finding]:
    """Run deterministic detectors before the reasoner.

    This ordering is the central design decision of the whole agent. Three
    reasons, in order of importance:

    1. Reliability. "Four failures then a success from one address" is a
       counter, not a judgement. Code answers it identically every time.
    2. Cost. Fifty thousand log lines will not fit in a context window and
       would be expensive if they did. Detectors reduce that to the dozen
       events worth reasoning about.
    3. Explainability. A rule hit names the rule. That is auditable in a way
       model output alone is not.
    """
    trace.stage(Stage.DETECT, "Find suspicious patterns using deterministic logic.")
    findings: list[Finding] = []

    # --- declarative rules -------------------------------------------------
    for rule in RULES:
        matched = [e for e in events if _rule_matches(rule, e)]
        if not matched:
            continue
        findings.append(Finding(
            rule_id=rule["id"], title=rule["title"], severity=rule["severity"],
            why=rule["why"], events=matched, mitre=rule["mitre"], kind="rule"))
        trace.decide(
            Stage.DETECT, rule["id"], f"fired on {len(matched)} event(s)",
            rule["why"], Confidence.CERTAIN,
            evidence=[matched[0].summarize()])

    # --- sequence and frequency patterns ----------------------------------
    findings += _detect_brute_force(events, trace, brute_threshold, window_seconds)
    findings += _detect_breach(events, trace, window_seconds)
    findings += _detect_beaconing(events, trace, beacon_min, beacon_jitter)

    findings.sort(key=lambda f: -SEVERITY_RANK[f.severity])

    if not findings:
        trace.decide(
            Stage.DETECT, "whole log window", "nothing fired",
            "no rule or pattern matched; the agent should say so plainly rather "
            "than manufacture a finding to look useful",
            Confidence.CERTAIN)

    trace.finish(Stage.DETECT,
                 f"{len(findings)} finding(s) from {len(events)} events.",
                 findings=len(findings))
    return findings


def _rule_matches(rule: dict, event: Event) -> bool:
    if "action" in rule and event.action != rule["action"]:
        return False
    if "users" in rule and (event.user or "").lower() not in rule["users"]:
        return False
    if "ports" in rule and event.dest_port not in rule["ports"]:
        return False
    if "pattern" in rule:
        haystack = f"{event.message} {event.extra.get('command', '')}"
        if not rule["pattern"].search(haystack):
            return False
    return "pattern" in rule or "action" in rule or "ports" in rule


def _detect_brute_force(events, trace, threshold, window) -> list[Finding]:
    by_source: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.outcome == "failure" and e.source_ip and e.action in (
                "login_failed", "invalid_user"):
            by_source[e.source_ip].append(e)

    out: list[Finding] = []
    for ip, failures in by_source.items():
        if len(failures) < threshold:
            trace.decide(
                Stage.DETECT, f"failures from {ip}", "below threshold",
                f"{len(failures)} failure(s) is under the threshold of "
                f"{threshold}; internet-facing hosts see constant background "
                f"scanning and alerting on it would bury real findings",
                Confidence.STRONG)
            continue
        span = (failures[-1].timestamp - failures[0].timestamp).total_seconds()
        users = {f.user for f in failures if f.user}
        out.append(Finding(
            rule_id="P-BRUTE",
            title=f"Credential attack from {ip}",
            severity=Severity.HIGH,
            why=(f"{len(failures)} failures in {span:.0f}s against "
                 f"{len(users)} account(s). Threshold is {threshold} "
                 f"in {window}s."),
            events=failures, mitre=["T1110.001"], kind="pattern"))
        trace.decide(
            Stage.DETECT, f"failures from {ip}", "credential attack",
            f"{len(failures)} failures in {span:.0f}s exceeds the threshold",
            Confidence.STRONG,
            evidence=[f"targeted accounts: {', '.join(sorted(users)[:5])}"],
            alternatives=["a user mistyping a password — would not reach "
                          f"{threshold} attempts across multiple accounts"])
    return out


def _detect_breach(events, trace, window) -> list[Finding]:
    """The highest-value pattern in authentication logs.

    Failures alone are noise. A success from a source that just failed
    repeatedly is a probable compromise, and it should dominate the alert.
    """
    by_source: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source_ip and e.action in (
                "login_failed", "login_success", "invalid_user"):
            by_source[e.source_ip].append(e)

    out: list[Finding] = []
    for ip, sequence in by_source.items():
        sequence.sort(key=lambda e: e.timestamp)
        recent: list[Event] = []
        for event in sequence:
            if event.outcome == "failure":
                recent = [f for f in recent
                          if (event.timestamp - f.timestamp).total_seconds() <= window]
                recent.append(event)
            elif event.action == "login_success" and len(recent) >= 3:
                gap = (event.timestamp - recent[-1].timestamp).total_seconds()
                out.append(Finding(
                    rule_id="P-BRUTE-SUCCESS",
                    title=f"Successful login after {len(recent)} failures from {ip}",
                    severity=Severity.CRITICAL,
                    why=(f"{len(recent)} failures then success as "
                         f"'{event.user}' {gap:.0f}s later."),
                    events=recent + [event],
                    mitre=["T1110.001", "T1078"], kind="pattern"))
                trace.decide(
                    Stage.DETECT, f"login sequence from {ip}",
                    "compromise likely",
                    "failures alone are background noise; a success from the "
                    "same source immediately afterwards is the signature of a "
                    "credential attack that worked",
                    Confidence.STRONG,
                    evidence=[f"account '{event.user}' authenticated {gap:.0f}s "
                              f"after the last failure"],
                    alternatives=["a user who eventually remembered their "
                                  "password — possible, but not across "
                                  "multiple different usernames"])
                recent = []
    return out


def _detect_beaconing(events, trace, min_events, max_jitter) -> list[Finding]:
    """Regular-interval outbound connections suggest automated check-in.

    Human and application traffic is bursty. A timer is not.
    """
    by_pair: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.source_ip and e.dest_ip:
            by_pair[(e.source_ip, e.dest_ip)].append(e)

    out: list[Finding] = []
    for (src, dst), group in by_pair.items():
        if len(group) < min_events:
            continue
        group.sort(key=lambda e: e.timestamp)
        gaps = [(group[i + 1].timestamp - group[i].timestamp).total_seconds()
                for i in range(len(group) - 1)]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < 3:
            continue
        mean = sum(gaps) / len(gaps)
        deviation = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5
        jitter = deviation / mean if mean else 1.0
        if jitter > max_jitter:
            trace.decide(
                Stage.DETECT, f"traffic {src} → {dst}", "not beaconing",
                f"interval jitter {jitter:.1%} exceeds the {max_jitter:.0%} "
                f"threshold; irregular timing is what human and application "
                f"traffic looks like",
                Confidence.MODERATE)
            continue
        out.append(Finding(
            rule_id="P-BEACON",
            title=f"Periodic connections {src} → {dst}",
            severity=Severity.HIGH,
            why=(f"{len(group)} connections at a near-constant {mean:.0f}s "
                 f"interval (jitter {jitter:.1%})."),
            events=group, mitre=["T1071"], kind="pattern"))
        trace.decide(
            Stage.DETECT, f"traffic {src} → {dst}", "beaconing",
            f"jitter of {jitter:.1%} is below the {max_jitter:.0%} threshold — "
            f"regular timing indicates a timer, not a person",
            Confidence.STRONG,
            evidence=[f"{len(group)} connections, mean interval {mean:.0f}s"])
    return out


def select_relevant(events: list[Event], findings: list[Finding],
                    trace: Trace, context: int = 2,
                    cap: int = 60) -> list[Event]:
    """Reduce the full log to what the reasoner should actually see.

    This is the cost lever. Everything the agent knows about the incident has
    to fit in one prompt, so choosing *what to include* is a real engineering
    decision, not plumbing.
    """
    if not findings:
        chosen = events[-cap:]
        trace.decide(
            Stage.DETECT, "event selection", f"most recent {len(chosen)}",
            "nothing fired, so there is no anchor to select around; recent "
            "events are the least-bad default",
            Confidence.WEAK)
        return chosen

    index = {e.id: i for i, e in enumerate(events)}
    keep: set[int] = set()
    for finding in findings:
        for event in finding.events:
            i = index.get(event.id)
            if i is None:
                continue
            keep.update(range(max(0, i - context),
                              min(len(events), i + context + 1)))

    chosen = [events[i] for i in sorted(keep)]
    if len(chosen) > cap:
        chosen = chosen[:cap]

    trace.decide(
        Stage.DETECT, "event selection",
        f"{len(chosen)} of {len(events)} events",
        f"every event that triggered a finding, plus {context} either side for "
        f"context — an attack step is often only intelligible next to what "
        f"preceded it",
        Confidence.STRONG,
        alternatives=["send everything — will not fit and costs far more",
                      "send only the triggering events — strips the context "
                      "needed to tell an attack from a maintenance window"])
    return chosen


# ==========================================================================
# Stage 3 — EXTRACT
# ==========================================================================

_URL = re.compile(r"\bhttps?://[^\s\"'<>]+")
_PATH = re.compile(r"(?:^|[\s\"'=])((?:/[\w.\-]+){2,})")
_HASH = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|onion)\b", re.I)

_BENIGN_PREFIXES = ("/usr/bin", "/usr/sbin", "/usr/lib", "/bin/", "/sbin/",
                    "/etc/passwd", "/proc/", "/dev/null")
_INTERESTING_MARKERS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/.", "/root/.ssh")


def extract(events: list[Event], trace: Trace) -> list[Indicator]:
    """Pull indicators out of events.

    Finding indicators is easy. *Not* returning the useless ones is the hard
    part — an extractor that emits every internal IP and every path under
    /usr/bin buries the two indicators that matter.
    """
    trace.stage(Stage.EXTRACT, "Pull indicators out of the selected events.")
    found: dict[str, Indicator] = {}
    filtered = Counter()

    for event in events:
        haystack = f"{event.message} {event.extra.get('command', '')}"

        for match in _URL.finditer(haystack):
            _add(found, IoCType.URL, match.group(0).rstrip(".,;)"), event)
        for match in _HASH.finditer(haystack):
            _add(found, IoCType.HASH, match.group(0), event)
        for match in _DOMAIN.finditer(haystack):
            _add(found, IoCType.DOMAIN, match.group(0), event)

        for match in _PATH.finditer(haystack):
            path = match.group(1)
            if _interesting_path(path):
                _add(found, IoCType.PATH, path, event)
            else:
                filtered["system path"] += 1

        for ip in (event.source_ip, event.dest_ip):
            if not ip:
                continue
            if _is_public(ip):
                _add(found, IoCType.IP, ip, event)
            else:
                filtered["private IP"] += 1

        if event.user and event.user.lower() not in {"-", "unknown"}:
            _add(found, IoCType.USER, event.user, event)
        if event.process and event.process not in {"kernel", "systemd"}:
            _add(found, IoCType.PROCESS, event.process, event)

    for reason, count in filtered.items():
        trace.decide(
            Stage.EXTRACT, f"{count} {reason} candidate(s)", "filtered out",
            "private addresses and system binaries appear in nearly every log "
            "line; keeping them would bury the indicators that matter and leak "
            "internal topology to third-party intel providers"
            if reason == "private IP" else
            "system binaries appear constantly and are almost never the "
            "indicator; keeping them dilutes the list",
            Confidence.STRONG)

    indicators = sorted(found.values(), key=lambda i: (-i.count, i.value))
    trace.finish(Stage.EXTRACT,
                 f"{len(indicators)} indicator(s) kept, "
                 f"{sum(filtered.values())} filtered.",
                 kept=len(indicators), filtered=sum(filtered.values()))
    return indicators


def _add(store: dict, kind: IoCType, value: str, event: Event) -> None:
    key = f"{kind.value}:{value}"
    existing = store.get(key)
    if existing:
        existing.count += 1
        existing.last_seen = max(existing.last_seen or event.timestamp,
                                 event.timestamp)
        if existing.role is None:
            existing.role = _guess_role(kind, value, event)
        return
    store[key] = Indicator(
        type=kind, value=value, count=1,
        role=_guess_role(kind, value, event),
        first_seen=event.timestamp, last_seen=event.timestamp)


def _guess_role(kind: IoCType, value: str, event: Event) -> str | None:
    """A first guess only. Refined after enrichment — see `assign_roles`."""
    if kind is IoCType.IP:
        if event.source_ip == value and event.outcome == "failure":
            return "attacker"
        if event.dest_ip == value and "wget" in event.message:
            return "payload_host"
        return None
    if kind is IoCType.URL:
        return "payload_delivery" if re.search(
            r"wget|curl|certutil", event.message, re.I) else None
    if kind is IoCType.PATH:
        if event.action == "cron_modified":
            return "persistence"
        if any(m in value for m in ("/tmp/", "/dev/shm/")):
            return "staged_payload"
        return None
    if kind is IoCType.USER:
        # Cannot distinguish a routine login from an attacker's here — both
        # look identical in one event. Resolved after enrichment.
        return "targeted_account" if event.outcome == "failure" else None
    return None


# RFC 5737 documentation ranges. Real deployments should filter these as
# non-routable, but every published example and teaching scenario uses them —
# including this package's own. Excluding them would mean the scenarios never
# reach threat intelligence, which is exactly the stage they exist to teach.
_DOC_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def _is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(ip in network for network in _DOC_RANGES):
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved)


def _interesting_path(path: str) -> bool:
    low = path.lower()
    if any(m in low for m in _INTERESTING_MARKERS):
        return True
    return not any(low.startswith(p) for p in _BENIGN_PREFIXES)


# ==========================================================================
# Stage 4 — ENRICH
# ==========================================================================

_NO_REPUTATION = {IoCType.USER, IoCType.PROCESS, IoCType.PATH}


def enrich(indicators: list[Indicator],
           providers: list[SimulatedIntelProvider],
           trace: Trace,
           cache: dict[str, Intel] | None = None,
           seed: int = 11) -> list[EnrichedIndicator]:
    """Ask external sources what they know about each indicator."""
    trace.stage(Stage.ENRICH, "Ask threat intelligence about each indicator.")
    cache = cache if cache is not None else {}
    rng = random.Random(seed)
    enriched: list[EnrichedIndicator] = []
    stats = Counter()

    for indicator in indicators:
        item = EnrichedIndicator(indicator=indicator)
        enriched.append(item)

        if indicator.type in _NO_REPUTATION:
            stats["skipped"] += 1
            item.why = "no external reputation exists for this indicator type"
            continue

        for provider in providers:
            if not provider.supports(indicator):
                continue
            cache_key = f"{provider.name}|{indicator.key}"
            cached = cache.get(cache_key)
            if cached is not None:
                stats["cache_hit"] += 1
                item.intel.append(
                    Intel(cached.provider, cached.verdict, cached.score,
                          cached.detail, cached=True))
                continue
            result = provider.query(indicator, rng)
            cache[cache_key] = result
            stats["queried"] += 1
            item.intel.append(result)

        if item.intel:
            item.verdict, item.score, item.why = merge(item.intel, providers)
            if item.verdict is not Verdict.UNKNOWN:
                trace.decide(
                    Stage.ENRICH, indicator.value, item.verdict.value,
                    item.why,
                    Confidence.STRONG if item.verdict is Verdict.MALICIOUS
                    else Confidence.MODERATE,
                    evidence=[f"{i.provider}: {i.detail}"
                              for i in item.intel if i.detail])

    if stats["skipped"]:
        trace.decide(
            Stage.ENRICH, f"{stats['skipped']} indicator(s)", "not queried",
            "usernames, process names and file paths have no meaningful "
            "external reputation; querying them wastes quota and sends "
            "internal detail to third parties",
            Confidence.CERTAIN)

    unknowns = [e for e in enriched
                if e.verdict is Verdict.UNKNOWN
                and e.indicator.type not in _NO_REPUTATION]
    if unknowns:
        trace.decide(
            Stage.ENRICH, f"{len(unknowns)} indicator(s)", "unknown, not clean",
            "no provider had data. This is the most misread state in threat "
            "intelligence: freshly registered attacker infrastructure is always "
            "unknown, so absence of evidence must not be recorded as evidence "
            "of absence",
            Confidence.CERTAIN,
            alternatives=["treat unknown as clean — the single most common way "
                          "an agent misses a novel attack"])

    order = {Verdict.MALICIOUS: 0, Verdict.SUSPICIOUS: 1,
             Verdict.UNKNOWN: 2, Verdict.CLEAN: 3}
    enriched.sort(key=lambda e: (order[e.verdict], -e.score, -e.indicator.count))

    trace.finish(
        Stage.ENRICH,
        f"{stats['queried']} live queries, {stats['cache_hit']} cache hits, "
        f"{stats['skipped']} skipped.",
        **dict(stats))
    return enriched


def merge(intel: list[Intel],
          providers: list[SimulatedIntelProvider]) -> tuple[Verdict, float, str]:
    """Combine several providers' opinions into one verdict.

    Two rules do most of the work:

    * Providers returning UNKNOWN are excluded from the average. A provider
      with no data should not dilute a provider that has strong data.
    * A single high-confidence malicious call promotes the verdict even if the
      weighted mean sits lower. Missing a real threat costs more than an extra
      investigation.
    """
    weights = {p.name: p.weight for p in providers}
    informed = [i for i in intel if i.verdict is not Verdict.UNKNOWN]
    if not informed:
        names = ", ".join(sorted({i.provider for i in intel}))
        return Verdict.UNKNOWN, 0.0, f"no data from {names}"

    total_weight = sum(weights.get(i.provider, 1.0) for i in informed)
    score = sum(i.score * weights.get(i.provider, 1.0)
                for i in informed) / total_weight

    if score >= 0.7:
        verdict = Verdict.MALICIOUS
    elif score >= 0.3:
        verdict = Verdict.SUSPICIOUS
    elif any(i.verdict is Verdict.CLEAN for i in informed):
        verdict = Verdict.CLEAN
    else:
        verdict = Verdict.UNKNOWN

    strong = [i for i in informed
              if i.verdict is Verdict.MALICIOUS and i.score >= 0.75]
    note = ""
    if strong and verdict is not Verdict.MALICIOUS:
        verdict = Verdict.MALICIOUS
        score = max(score, 0.75)
        note = (f" — promoted by {strong[0].provider}, which has specific "
                f"high-confidence data the others lack")

    detail = "; ".join(f"{i.provider}={i.verdict.value}({i.score:.2f})"
                       for i in informed)
    silent = [i.provider for i in intel if i.verdict is Verdict.UNKNOWN]
    if silent:
        detail += f" (no data: {', '.join(silent)})"
    return verdict, round(score, 3), detail + note


def assign_roles(enriched: list[EnrichedIndicator], events: list[Event],
                 trace: Trace) -> None:
    """Refine roles now that verdicts are known.

    The extractor sees one event at a time and cannot tell a routine deploy
    login from an attacker's successful login — they are identical in
    isolation. Once intelligence has flagged the source address, the account
    that authenticated from it can be promoted.

    This is a general lesson about agent design: some conclusions are only
    available after a later stage returns, so the pipeline needs a place to
    revisit earlier guesses.
    """
    hostile = {e.indicator.value for e in enriched
               if e.indicator.type is IoCType.IP
               and e.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)}
    if not hostile:
        return

    compromised = {
        event.user for event in events
        if event.action == "login_success" and event.user
        and event.source_ip in hostile}

    for item in enriched:
        if item.indicator.type is IoCType.USER:
            if item.indicator.value in compromised:
                item.indicator.role = "compromised_account"
                trace.decide(
                    Stage.ENRICH, f"account '{item.indicator.value}'",
                    "compromised",
                    "this account authenticated successfully from an address "
                    "threat intelligence flagged as hostile",
                    Confidence.STRONG)
            elif item.indicator.role is None:
                item.indicator.role = "authenticated_account"
                trace.decide(
                    Stage.ENRICH, f"account '{item.indicator.value}'",
                    "not compromised",
                    "this account only authenticated from addresses with no "
                    "adverse intelligence; marking every successful login as "
                    "compromised would bury the one that matters",
                    Confidence.MODERATE)


# ==========================================================================
# Stage 5 — RECALL
# ==========================================================================

class IncidentMemory:
    """Past incidents the agent can recall.

    Similarity is computed over the *shape* of an incident — which detectors
    fired, which MITRE techniques — rather than literal values. That way a new
    attack from a different address still matches a past incident with the same
    structure, which is what makes recall useful rather than a lookup table.
    """

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def remember(self, incident_id: str, title: str, shape: set[str],
                 analyst_verdict: str, note: str = "") -> None:
        self.entries.append({
            "incident_id": incident_id, "title": title, "shape": shape,
            "analyst_verdict": analyst_verdict, "note": note})

    def recall(self, shape: set[str], trace: Trace,
               threshold: float = 0.3, top_k: int = 3) -> list[Memory]:
        trace.stage(Stage.RECALL,
                    "Look for past incidents with a similar shape.")
        if not self.entries:
            trace.decide(
                Stage.RECALL, "memory", "empty",
                "a new deployment has no history; the agent must reason from "
                "evidence alone until analysts start recording verdicts",
                Confidence.CERTAIN)
            trace.finish(Stage.RECALL, "No memories available.", recalled=0)
            return []

        scored: list[tuple[float, dict]] = []
        for entry in self.entries:
            overlap = shape & entry["shape"]
            union = shape | entry["shape"]
            similarity = len(overlap) / len(union) if union else 0.0
            if similarity >= threshold:
                scored.append((similarity, entry))

        scored.sort(key=lambda pair: -pair[0])
        results = [
            Memory(incident_id=e["incident_id"], title=e["title"],
                   shape=" ".join(sorted(e["shape"])),
                   analyst_verdict=e["analyst_verdict"],
                   note=e["note"], similarity=round(s, 3))
            for s, e in scored[:top_k]]

        for memory in results:
            trace.decide(
                Stage.RECALL, memory.incident_id,
                f"recalled ({memory.similarity:.0%} similar)",
                f"an analyst previously ruled this {memory.analyst_verdict}. "
                f"A human verdict on near-identical activity is the strongest "
                f"calibration signal available to the agent"
                + (f": {memory.note}" if memory.note else ""),
                Confidence.STRONG)

        if not results:
            trace.decide(
                Stage.RECALL, "memory", "no match",
                f"no stored incident reached {threshold:.0%} similarity; this "
                f"pattern is new to the agent",
                Confidence.MODERATE)

        trace.finish(Stage.RECALL, f"{len(results)} memory(ies) recalled.",
                     recalled=len(results))
        return results


def incident_shape(findings: list[Finding]) -> set[str]:
    """The abstract signature of an incident: rules fired plus techniques."""
    shape = {f.rule_id for f in findings}
    shape |= {t for f in findings for t in f.mitre}
    return shape


# ==========================================================================
# Stage 6 — REASON
# ==========================================================================

def reason(bundle: PromptBundle, reasoner: SimulatedReasoner,
           trace: Trace) -> dict:
    """Hand the assembled context to the reasoner and parse what comes back."""
    trace.stage(Stage.REASON,
                "Correlate findings into one narrative and judge severity.")

    if bundle.injection_attempts:
        trace.decide(
            Stage.REASON, "log content",
            f"{len(bundle.injection_attempts)} injection attempt(s) neutralised",
            "log fields are attacker-controlled — usernames, user-agents and "
            "filenames are all chosen by whoever is attacking. Strings shaped "
            "like instructions were neutralised before reaching the reasoner, "
            "and surfaced as a finding rather than dropped",
            Confidence.CERTAIN,
            evidence=bundle.injection_attempts[:3],
            alternatives=["pass log text through unchanged — lets an attacker "
                          "who knows you run an AI analyst talk to it directly"])

    trace.note(Stage.REASON,
               f"Prompt assembled from {len(bundle.events)} events, "
               f"{len(bundle.findings)} findings, {len(bundle.indicators)} "
               f"indicators, {len(bundle.memories)} memories.")

    raw = reasoner.reason(bundle)
    if "__raw__" in raw:
        trace.decide(
            Stage.REASON, "reasoner output", "malformed, recovered",
            "the model wrapped its JSON in prose despite instructions. Agents "
            "must parse defensively — a strict parser turns a cosmetic problem "
            "into a total failure",
            Confidence.CERTAIN)
        try:
            raw = extract_json(raw["__raw__"])
        except ValueError:
            trace.decide(
                Stage.REASON, "reasoner output", "unrecoverable — using fallback",
                "nothing parseable came back. The agent falls back to a "
                "rule-derived assessment rather than producing nothing: a "
                "degraded alert beats silence during an incident",
                Confidence.CERTAIN)
            raw = _fallback(bundle)

    trace.decide(
        Stage.REASON, "severity",
        f"{raw.get('severity', 'MEDIUM')} at "
        f"{float(raw.get('confidence', 0.5)):.0%} confidence",
        "; ".join(raw.get("reasoning", [])[:2]) or "no reasoning returned",
        Confidence.MODERATE)

    trace.finish(Stage.REASON,
                 f"Assessed as {raw.get('severity')} "
                 f"({float(raw.get('confidence', 0)):.0%} confidence).")
    return raw


def _fallback(bundle: PromptBundle) -> dict:
    """Rule-derived assessment for when the reasoner fails entirely.

    An agent that produces nothing when its model is unavailable is worse than
    one that produces a clearly-labelled degraded answer.
    """
    if not bundle.findings:
        return {"title": "No findings", "severity": "LOW", "confidence": 0.3,
                "narrative": "No detectors fired.", "reasoning": [],
                "mitre": [], "actions": ["No action required."],
                "would_change_mind": ""}
    worst = max(bundle.findings, key=lambda f: SEVERITY_RANK[f.severity])
    return {
        "title": worst.title,
        "severity": worst.severity.value,
        "confidence": 0.5,
        "narrative": (f"{len(bundle.findings)} detector(s) fired. Correlation "
                      f"unavailable — this assessment is rule-derived only."),
        "reasoning": [f.why for f in bundle.findings[:4]],
        "mitre": sorted({t for f in bundle.findings for t in f.mitre}),
        "actions": ["Review the findings manually."],
        "would_change_mind": "",
    }


# ==========================================================================
# Stage 7 — REPORT
# ==========================================================================

def report(assessment: dict, findings: list[Finding],
           indicators: list[EnrichedIndicator], memories: list[Memory],
           trace: Trace, reasoned_by: str = "simulated") -> Alert:
    """Assemble the final alert."""
    trace.stage(Stage.REPORT, "Assemble the analyst-facing alert.")

    try:
        severity = Severity(str(assessment.get("severity", "MEDIUM")).upper())
    except ValueError:
        severity = Severity.MEDIUM

    try:
        confidence = max(0.0, min(1.0, float(assessment.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5

    alert = Alert(
        alert_id=new_alert_id(),
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        confidence=confidence,
        title=str(assessment.get("title", "Unclassified activity"))[:110],
        narrative=str(assessment.get("narrative", "")),
        indicators=indicators,
        findings=findings,
        mitre=list(assessment.get("mitre", [])),
        reasoning=[str(r) for r in assessment.get("reasoning", [])],
        actions=[str(a) for a in assessment.get("actions", [])],
        recalled=memories,
        would_change_mind=str(assessment.get("would_change_mind", "")),
        reasoned_by=reasoned_by,
    )

    trace.decide(
        Stage.REPORT, "alert", f"{severity.value} at {confidence:.0%}",
        "the alert carries its own reasoning and a counterfactual, so an "
        "analyst can check the agent's logic instead of trusting the verdict",
        Confidence.CERTAIN)

    if confidence < 0.5:
        trace.decide(
            Stage.REPORT, "low confidence", "stated plainly in the alert",
            "an agent that hides uncertainty trains analysts to distrust it. "
            "Saying 'I am not sure' is more useful than a confident guess",
            Confidence.CERTAIN)

    trace.finish(Stage.REPORT, f"Alert {alert.alert_id} assembled.")
    return alert

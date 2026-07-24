"""Command line entry point.

    python -m socedu.cli run breach
    python -m socedu.cli run breach --explain
    python -m socedu.cli why breach 185.220.101.34
    python -m socedu.cli prompt breach
    python -m socedu.cli compare
    python -m socedu.cli scenarios
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agent import AgentConfig, SOCAgent
from .groq_reasoner import DEFAULT_MODEL, GroqReasoner
from .scenarios import SCENARIOS
from .types import IoCType, SEVERITY_RANK


def _load_dotenv() -> None:
    """Minimal .env loader — no extra dependency for one file of key=value.

    Only fills in variables not already set in the environment, so a real
    shell export always wins over the file.
    """
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
RED, YELLOW, BLUE, GREEN = "\033[31m", "\033[33m", "\033[34m", "\033[32m"

SEV_COLOR = {"CRITICAL": RED + BOLD, "HIGH": RED,
             "MEDIUM": YELLOW, "LOW": GREEN}


def _wrap(text: str, width: int = 72) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur); cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur: lines.append(cur)
    return lines or [""]


def render(result) -> str:
    a = result.alert
    out = ["", "═" * 74]
    colour = SEV_COLOR.get(a.severity.value, "")
    out.append(f"{colour}{a.severity.value}{RESET}  {BOLD}{a.title}{RESET}")
    out.append(f"{DIM}{a.alert_id}   confidence {a.confidence:.0%}   "
               f"reasoned by {a.reasoned_by}{RESET}")
    out.append("═" * 74)

    if a.narrative:
        out.append("")
        out += _wrap(a.narrative)

    if a.findings:
        out += ["", f"{BLUE}FINDINGS{RESET}"]
        for f in a.findings[:8]:
            out.append(f"  [{f.severity.value:8}] {f.rule_id:16} {f.title}")

    notable = [i for i in a.indicators
               if i.verdict.value != "unknown" or i.indicator.role]
    if notable:
        out += ["", f"{BLUE}INDICATORS{RESET}"]
        for i in notable[:12]:
            role = f" [{i.indicator.role}]" if i.indicator.role else ""
            out.append(f"  {i.verdict.value:11} {i.indicator.type.value:8} "
                       f"{i.indicator.value}{role}")

    if a.mitre:
        out += ["", f"{BLUE}MITRE{RESET}", "  " + ", ".join(a.mitre)]

    if a.recalled:
        out += ["", f"{BLUE}RECALLED{RESET}"]
        for m in a.recalled:
            out.append(f"  [{m.incident_id}] {m.analyst_verdict} "
                       f"({m.similarity:.0%} similar)")

    if a.reasoning:
        out += ["", f"{BLUE}REASONING{RESET}"]
        for n, step in enumerate(a.reasoning, 1):
            lines = _wrap(step, 68)
            out.append(f"  {n}. {lines[0]}")
            out += [f"     {l}" for l in lines[1:]]

    if a.actions:
        out += ["", f"{BLUE}ACTIONS{RESET}"]
        for n, act in enumerate(a.actions, 1):
            out.append(f"  {n}. {act}")

    if a.would_change_mind:
        out += ["", f"{BLUE}WHAT WOULD CHANGE THIS{RESET}"]
        out += [f"  {l}" for l in _wrap(a.would_change_mind, 70)]

    out += ["", "─" * 74,
            f"{DIM}{len(result.events)} events · "
            f"{len(result.prompt.events)} sent to reasoner · "
            f"{len(a.findings)} findings · {result.elapsed_ms:.1f}ms{RESET}"]
    return "\n".join(out)


def _agent(args) -> SOCAgent:
    config = AgentConfig(
        brute_threshold=getattr(args, "brute_threshold", 4),
        max_events_to_reasoner=getattr(args, "max_events", 60),
        malformed_rate=getattr(args, "malformed", 0.0))

    reasoner = None
    if getattr(args, "reasoner", "simulated") == "groq":
        reasoner = GroqReasoner(model=args.model)
        if not reasoner.api_key:
            print(f"{YELLOW}warning: GROQ_API_KEY not set — the reasoner "
                  f"will fall back to a rule-derived assessment{RESET}",
                  file=sys.stderr)

    return SOCAgent(config, reasoner=reasoner)


def cmd_run(args) -> int:
    if args.scenario not in SCENARIOS:
        print(f"unknown scenario: {args.scenario}", file=sys.stderr)
        print(f"available: {', '.join(SCENARIOS)}", file=sys.stderr)
        return 2
    scenario = SCENARIOS[args.scenario]
    agent = _agent(args)
    result = agent.analyze(scenario.log)

    if args.json:
        print(json.dumps(result.alert.to_dict(), indent=2))
        return 0

    print(f"\n{BOLD}{scenario.name}{RESET}")
    print(f"{DIM}Teaches: {scenario.teaches}{RESET}")
    print(f"{DIM}Expected: {scenario.expect}{RESET}")
    if scenario.trap:
        print(f"{YELLOW}Trap: {scenario.trap}{RESET}")
    print(render(result))
    if args.explain:
        print()
        print(result.explain())
    return 0


def cmd_run_file(args) -> int:
    path = Path(args.path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        print(f"log file not found: {path}", file=sys.stderr)
        return 2

    agent = _agent(args)
    result = agent.analyze_file(path)

    if args.json:
        print(json.dumps(result.alert.to_dict(), indent=2))
        return 0

    print(f"\n{BOLD}{path.name}{RESET}")
    print(render(result))
    if args.explain:
        print()
        print(result.explain())
    return 0


def cmd_why(args) -> int:
    result = _agent(args).analyze(SCENARIOS[args.scenario].log)
    print(result.why(args.value))
    return 0


def cmd_prompt(args) -> int:
    result = _agent(args).analyze(SCENARIOS[args.scenario].log)
    print(result.prompt.render())
    return 0


def cmd_compare(args) -> int:
    agent = SOCAgent()
    print(f"\n{BOLD}{'scenario':16} {'severity':10} {'conf':>5}  "
          f"{'findings':>8}  title{RESET}")
    print("─" * 74)
    for key, scenario in SCENARIOS.items():
        r = agent.analyze(scenario.log)
        colour = SEV_COLOR.get(r.alert.severity.value, "")
        print(f"{key:16} {colour}{r.alert.severity.value:10}{RESET} "
              f"{r.alert.confidence:5.0%}  {len(r.alert.findings):>8}  "
              f"{r.alert.title[:30]}")
    print()
    return 0


def cmd_scenarios(args) -> int:
    print()
    for key, s in SCENARIOS.items():
        print(f"{BOLD}{key}{RESET} — {s.name}")
        for line in _wrap(s.teaches, 70):
            print(f"    {line}")
        if s.trap:
            for line in _wrap(f"Trap: {s.trap}", 70):
                print(f"    {DIM}{line}{RESET}")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252, which can't encode the arrows and
    # box-drawing characters used below.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    _load_dotenv()
    p = argparse.ArgumentParser(prog="socedu",
                                description="Educational SOC agent.")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--brute-threshold", type=int, default=4)
    common.add_argument("--max-events", type=int, default=60)
    common.add_argument("--malformed", type=float, default=0.0)
    common.add_argument("--reasoner", choices=["simulated", "groq"],
                        default="simulated",
                        help="'groq' calls the real Groq API (needs "
                             "GROQ_API_KEY); default is the deterministic "
                             "simulation")
    common.add_argument("--model", default=DEFAULT_MODEL,
                        help="Groq model id, only used with --reasoner groq")

    r = sub.add_parser("run", parents=[common], help="Analyze a scenario")
    r.add_argument("scenario")
    r.add_argument("--explain", action="store_true", help="Show the full trace")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_run)

    rf = sub.add_parser("run-file", parents=[common],
                        help="Analyze a real log file with the SOC triage pipeline")
    rf.add_argument("path")
    rf.add_argument("--explain", action="store_true", help="Show the full trace")
    rf.add_argument("--json", action="store_true")
    rf.set_defaults(func=cmd_run_file)

    w = sub.add_parser("why", parents=[common],
                       help="Every decision touching a value")
    w.add_argument("scenario")
    w.add_argument("value")
    w.set_defaults(func=cmd_why)

    pr = sub.add_parser("prompt", parents=[common],
                        help="Show the assembled prompt")
    pr.add_argument("scenario")
    pr.set_defaults(func=cmd_prompt)

    c = sub.add_parser("compare", help="All scenarios side by side")
    c.set_defaults(func=cmd_compare)

    s = sub.add_parser("scenarios", help="List scenarios")
    s.set_defaults(func=cmd_scenarios)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

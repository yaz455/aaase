"""Real SOC-style tool adapters used by the agent.

This module is intentionally lightweight: it exposes a small, explicit tool
interface and a couple of concrete adapters that can be swapped into a real
SOC environment. The goal is to keep the project usable without pulling in a
large SDK stack.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib import error, parse, request


@dataclass
class SOCToolResult:
    """Normalised response returned by a tool execution."""

    name: str
    ok: bool
    summary: str
    payload: Any | None = None
    error: str | None = None


class SOCTool(Protocol):
    name: str
    description: str

    def execute(self, **kwargs: Any) -> SOCToolResult:
        ...


@dataclass
class FileLogReaderTool:
    """Read a log file from disk and return the exact text to the agent."""

    name: str = "file-log-reader"
    description: str = "Reads a plain-text SOC log file from disk."

    def execute(self, path: str | Path, **_: Any) -> SOCToolResult:
        source = Path(path)
        if not source.exists():
            return SOCToolResult(
                name=self.name,
                ok=False,
                summary="File not found",
                error=f"log file not found: {source}",
            )
        if not source.is_file():
            return SOCToolResult(
                name=self.name,
                ok=False,
                summary="Path is not a file",
                error=f"expected a file path, got: {source}",
            )
        text = source.read_text(encoding="utf-8")
        return SOCToolResult(
            name=self.name,
            ok=True,
            summary=f"Read {source.name} ({len(text.splitlines())} lines)",
            payload=text,
        )


@dataclass
class SIEMQueryTool:
    """HTTP-backed SIEM query adapter.

    The endpoint and token are read from environment variables, so the same
    agent code can be wired to an internal SIEM without changing the pipeline.
    """

    name: str = "siem-query"
    description: str = "Queries a SIEM endpoint over HTTP."
    base_url: str | None = None
    token: str | None = None
    timeout: float = 10.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url or os.environ.get("SOC_SIEM_URL")
        self.token = self.token or os.environ.get("SOC_SIEM_TOKEN")

    def execute(self, query: str, **_: Any) -> SOCToolResult:
        if not self.base_url:
            return SOCToolResult(
                name=self.name,
                ok=False,
                summary="SIEM endpoint is not configured",
                error="Set SOC_SIEM_URL to enable the SIEM tool.",
            )

        params = parse.urlencode({"query": query})
        url = f"{self.base_url}?{params}"
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = request.Request(url, headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
            payload = json.loads(body)
        except (error.HTTPError, error.URLError, TimeoutError, OSError,
                json.JSONDecodeError) as exc:
            return SOCToolResult(
                name=self.name,
                ok=False,
                summary="SIEM query failed",
                error=str(exc),
            )

        return SOCToolResult(
            name=self.name,
            ok=True,
            summary="SIEM query completed",
            payload=payload,
        )


@dataclass
class EDRActionTool:
    """EDR containment adapter.

    This is a thin wrapper around a real EDR API endpoint. It keeps the
    orchestration consistent with the rest of the agent, while the actual
    endpoint stays external to the project.
    """

    name: str = "edr-action"
    description: str = "Issues a containment or isolation action via an EDR API."
    base_url: str | None = None
    token: str | None = None
    timeout: float = 10.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url or os.environ.get("SOC_EDR_URL")
        self.token = self.token or os.environ.get("SOC_EDR_TOKEN")

    def execute(self, action: str, target: str, **_: Any) -> SOCToolResult:
        if not self.base_url:
            return SOCToolResult(
                name=self.name,
                ok=False,
                summary="EDR endpoint is not configured",
                error="Set SOC_EDR_URL to enable the EDR tool.",
            )

        payload = json.dumps({"action": action, "target": target}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = request.Request(
            f"{self.base_url}/containment",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
            parsed = json.loads(body)
        except (error.HTTPError, error.URLError, TimeoutError, OSError,
                json.JSONDecodeError) as exc:
            return SOCToolResult(
                name=self.name,
                ok=False,
                summary="EDR action failed",
                error=str(exc),
            )

        return SOCToolResult(
            name=self.name,
            ok=True,
            summary=f"EDR action '{action}' completed",
            payload=parsed,
        )


@dataclass
class ToolGuard:
    """Simple approval policy for SOC tools.

    When approval is required, a tool call is blocked until the caller passes
    an explicit approval signal. This keeps the agent from taking destructive
    actions like isolating a host or rotating credentials by accident.
    """

    approval_required: bool = True
    risky_actions: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.risky_actions is None:
            self.risky_actions = {
                "isolate", "block", "quarantine", "contain",
                "delete", "wipe", "credential-rotation", "rotate",
            }

    def can_execute(self, tool_name: str, action: str | None = None,
                    approved: bool = False) -> tuple[bool, str | None]:
        if not self.approval_required:
            return True, None

        if approved:
            return True, None

        action_key = (action or "").lower()
        if action_key in self.risky_actions or tool_name.endswith("-action"):
            return False, "approval required before executing risky SOC actions"

        return True, None


@dataclass
class GuardedTool:
    """A policy wrapper around an arbitrary SOC tool."""

    inner: SOCTool
    guard: ToolGuard

    def execute(self, **kwargs: Any) -> SOCToolResult:
        tool_name = getattr(self.inner, "name", type(self.inner).__name__)
        action = str(kwargs.get("action", "")).lower()
        approved = bool(kwargs.get("approved", False))

        ok, error = self.guard.can_execute(tool_name, action=action,
                                            approved=approved)
        if not ok:
            return SOCToolResult(
                name=tool_name,
                ok=False,
                summary="Tool execution blocked by guard",
                error=error,
            )

        return self.inner.execute(**kwargs)

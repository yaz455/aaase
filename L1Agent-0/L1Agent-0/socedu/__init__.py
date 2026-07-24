"""Educational SOC agent — see README.md for the architecture."""

from .agent import AgentConfig, SOCAgent
from .scenarios import SCENARIOS
from .simulation import (
    PromptBundle, SimulatedIntelProvider, SimulatedReasoner,
    default_providers, extract_json, scan_for_injection,
)
from .stages import IncidentMemory, incident_shape
from .tools import (
    EDRActionTool, FileLogReaderTool, GuardedTool, SIEMQueryTool,
    SOCToolResult, ToolGuard,
)
from .types import (
    Alert, EnrichedIndicator, Event, Finding, IoCType, Indicator, Intel,
    Memory, Severity, Verdict,
)

__all__ = [
    "AgentConfig", "SOCAgent", "SCENARIOS",
    "PromptBundle", "SimulatedIntelProvider", "SimulatedReasoner",
    "default_providers", "extract_json", "scan_for_injection",
    "IncidentMemory", "incident_shape",
    "FileLogReaderTool", "SIEMQueryTool", "EDRActionTool",
    "GuardedTool", "ToolGuard", "SOCToolResult",
    "Alert", "EnrichedIndicator", "Event", "Finding", "IoCType", "Indicator",
    "Intel", "Memory", "Severity", "Verdict",
]

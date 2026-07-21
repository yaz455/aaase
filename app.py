import operator
import os
import re
import uuid

from typing import Annotated, List
from typing_extensions import TypedDict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

if not OPENROUTER_API_KEY:
    raise ValueError("OPENROUTER_API_KEY is missing")


# ============================================================
# MODEL
# ============================================================

model = ChatOpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
    temperature=0,
    timeout=60,
    max_retries=0
)


# ============================================================
# STATE
# ============================================================

class ReportState(TypedDict, total=False):
    run_id: str
    topic: str
    research_notes: str
    summary: str
    draft: str
    review_feedback: str
    score: int
    revision_count: int
    execution_logs: Annotated[List[str], operator.add]


# ============================================================
# RESEARCH AGENT
# ============================================================

def research_node(state: ReportState):

    prompt = f"""
You are a professional Research Agent.

Research the following topic:

{state["topic"]}

Provide:
- Key concepts
- Important facts
- Business relevance
- Risks
- Opportunities
"""

    response = model.invoke(prompt)

    return {
        "research_notes": response.content,
        "execution_logs": [
            "Research Agent completed"
        ]
    }


# ============================================================
# SUMMARIZATION AGENT
# ============================================================

def summarize_node(state: ReportState):

    prompt = f"""
You are a Summarization Agent.

Summarize these research notes:

{state["research_notes"]}

Create a concise professional summary.
"""

    response = model.invoke(prompt)

    return {
        "summary": response.content,
        "execution_logs": [
            "Summarization Agent completed"
        ]
    }


# ============================================================
# WRITING AGENT
# ============================================================

def write_node(state: ReportState):

    feedback = state.get("review_feedback", "")

    prompt = f"""
You are a professional Writing Agent.

Topic:
{state["topic"]}

Research Summary:
{state["summary"]}

Write a professional enterprise report containing:

1. Executive Summary
2. Key Findings
3. Business Impact
4. Risks
5. Opportunities
6. Recommendations
7. Conclusion
"""

    if feedback:

        prompt += f"""

The Reviewer Agent provided this feedback:

{feedback}

Improve the report based on this feedback.
"""

    response = model.invoke(prompt)

    return {
        "draft": response.content,
        "execution_logs": [
            "Writing Agent completed"
        ]
    }


# ============================================================
# REVIEW AGENT
# ============================================================

def review_node(state: ReportState):

    prompt = f"""
You are a professional Reviewer Agent.

Review this report:

{state["draft"]}

Evaluate:
- Accuracy
- Structure
- Clarity
- Professional quality
- Completeness

Return exactly:

SCORE: <1-10>
FEEDBACK: <one sentence>
"""

    response = model.invoke(prompt)

    text = response.content

    score_match = re.search(
        r"SCORE:\s*(10|[1-9])",
        text,
        re.IGNORECASE
    )

    feedback_match = re.search(
        r"FEEDBACK:\s*(.*)",
        text,
        re.IGNORECASE
    )

    score = (
        int(score_match.group(1))
        if score_match
        else 5
    )

    feedback = (
        feedback_match.group(1).strip()
        if feedback_match
        else "Improve overall report quality."
    )

    revision_count = (
        state.get("revision_count", 0) + 1
    )

    return {
        "score": score,
        "review_feedback": feedback,
        "revision_count": revision_count,
        "execution_logs": [
            f"Reviewer completed with score {score}"
        ]
    }


# ============================================================
# SUPERVISOR
# ============================================================

QUALITY_THRESHOLD = 8
MAX_REVISIONS = 2


def review_gate(state: ReportState) -> str:

    if state["score"] >= QUALITY_THRESHOLD:
        return "approve"

    if state["revision_count"] > MAX_REVISIONS:
        return "give_up"

    return "revise"


# ============================================================
# LANGGRAPH
# ============================================================

workflow = StateGraph(ReportState)

workflow.add_node(
    "research",
    research_node
)

workflow.add_node(
    "summarize",
    summarize_node
)

workflow.add_node(
    "write",
    write_node
)

workflow.add_node(
    "review",
    review_node
)

workflow.add_edge(
    START,
    "research"
)

workflow.add_edge(
    "research",
    "summarize"
)

workflow.add_edge(
    "summarize",
    "write"
)

workflow.add_edge(
    "write",
    "review"
)

workflow.add_conditional_edges(
    "review",
    review_gate,
    {
        "approve": END,
        "give_up": END,
        "revise": "write"
    }
)

graph = workflow.compile()


# ============================================================
# REPORT FUNCTION
# ============================================================

def generate_report(topic: str):

    initial_state = {
        "run_id": str(uuid.uuid4()),
        "topic": topic,
        "research_notes": "",
        "summary": "",
        "draft": "",
        "review_feedback": "",
        "score": 0,
        "revision_count": 0,
        "execution_logs": []
    }

    return graph.invoke(initial_state)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Enterprise Multi-Agent AI",
    version="1.0"
)


class ReportRequest(BaseModel):
    topic: str


@app.get("/health")
def health():

    return {
        "status": "ok"
    }


@app.post("/report")
def create_report(request: ReportRequest):

    try:

        result = generate_report(
            request.topic
        )

        return {
            "run_id": result["run_id"],
            "topic": result["topic"],
            "report": result["draft"],
            "score": result["score"],
            "revisions": result["revision_count"],
            "logs": result["execution_logs"]
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
"""Streamlit frontend for the AI Red Teaming platform."""

from __future__ import annotations

import asyncio
import html
import json
import queue
import sys
import threading
from datetime import datetime
from functools import lru_cache
from pathlib import Path
import re
from textwrap import wrap
from typing import Any
from uuid import uuid4

import streamlit as st
from pydantic import ValidationError

# On Windows, ProactorEventLoop can emit noisy connection_lost errors
# (WinError 10054) during socket teardown in some async client flows.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import ROOT_DIR, get_settings
from core.llm_client import AzureOpenAIClient
from core.schemas import AttackPrompt, ScanRequest, ScanResult, ScanSettings, TargetConfig
from database.repository import Repository
from database.session import AsyncSessionLocal, init_db
from engine.report_generator import generate_enterprise_report
from engine.scan_orchestrator import ScanOrchestrator
from engine.scenario_loader import PluginLoader
from engine.target_executor import TargetExecutor


CRESCENDO_PROFILE_OPTIONS = {
    "authority_escalation_system_prompt": "Authority Escalation: System Prompt Extraction",
    "hypothetical_phishing_campaign": "Hypothetical Framing: Phishing Campaign",
    "roleplay_physical_security_bypass": "Role-Playing: Physical Security Bypass",
    "incremental_policy_disable": "Incremental Normalization: Disable Policy",
    "educational_malware_code": "Educational Framing: Malware Code",
}

OWASP_CATEGORY_OPTIONS = [
    "LLM01-Prompt Injection",
    "LLM02-Sensitive Information Disclosure",
    "LLM03-Supply Chain",
    "LLM04-Data_model_poisoning",
    "LLM05-Improper_output_handling",
    "LLM06-Excessive_agency",
    "LLM07-Insecure Plugin Design",
    "LLM08-Vector_Embedding_Weaknesses",
    "LLM09-Misinformation",
    "LLM10-Unbounded_Consumption",
]

WORKFLOW_PRESETS: dict[str, dict[str, Any]] = {
    "OpenAI SSE ([DONE])": {
        "next_turn": {
            "enabled": True,
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            "body": {
                "messages": [{"role": "user", "content": "{{prompt}}"}],
                "stream": True,
            },
            "streaming": {
                "enabled": True,
                "response_message_path": "choices[0].delta.content",
                "stop_conditions": [{"value": "[DONE]"}],
            },
        }
    },
    "Cohere SSE (is_finished)": {
        "next_turn": {
            "enabled": True,
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            "body": {
                "message": "{{prompt}}",
                "stream": True,
            },
            "streaming": {
                "enabled": True,
                "response_message_path": "text",
                "stop_conditions": [{"path": "is_finished", "value": "*"}],
            },
        }
    },
    "A2A Agent-only + final stop": {
        "start_session": {
            "enabled": True,
            "method": "POST",
            "body": {},
            "response_session_id_path": "meta.task_id",
        },
        "next_turn": {
            "enabled": True,
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            "body": {
                "session_id": "{{session_id}}",
                "message": "{{prompt}}",
                "stream": True,
            },
            "streaming": {
                "enabled": True,
                "response_message_path": "result.status.message.content",
                "response_session_id_path": "meta.task_id",
                "stop_conditions": [{"path": "result.final", "value": "true"}],
                "select_conditions": [{"path": "result.status.message.role", "value": "agent"}],
            },
        },
    },
}


TARGET_DIR = ROOT_DIR / "targets"
REPORT_DIR = ROOT_DIR / "reports"
AUTH_TEMPLATE_FILE = TARGET_DIR / "AUTH_TEMPLATES.json"
REFERENCE_TARGET_PREFIX = "[REFERENCE]"
CREATE_TARGET_PREFILL_KEY = "create_target_prefill"
CREATE_TARGET_ASSISTANT_KEY = "create_target_assistant_generated"

SUPPORTED_AUTH_TEMPLATE_KEYS = [
    "none",
    "bearer_token_from_env",
    "bearer_token_in_header",
    "api_key_header",
    "basic_auth",
    "oauth2_client_credentials",
    "jwt_token_auth",
]

STREAMING_SUBTYPE_OPTIONS = ["token", "chunk", "event", "sse", "websocket"]
NON_STREAMING_SUBTYPE_OPTIONS = ["synchronous", "retrieval", "generative", "batch", "workflow"]

STREAMING_TIMEOUT_SECONDS = 0
NON_STREAMING_TIMEOUT_BY_TYPE = {
    "synchronous": 120,
    "retrieval": 30,
    "generative": 120,
    "batch": 300,
    "workflow": 180,
}

TARGET_TEMPLATE_MD_CANDIDATES = [
    PROJECT_ROOT / "targets" / "70_Target_Configuration_Templates.md",
    Path.home() / "Downloads" / "70_Target_Configuration_Templates.md",
]

APP_STYLES = """
<style>
:root {
    --bg:           #0D1218;
    --bg-2:         #111820;
    --bg-3:         #1A2232;
    --surface:      #16202B;
    --surface-2:    #1E2A38;
    --line:         #243044;
    --line-bright:  #2E3F58;
    --text:         #E8EDF5;
    --text-muted:   #7A8FA8;
    --text-dim:     #4A5F7A;

    --red:    #FF4D4F;
    --green:  #00C853;
    --yellow: #FFD600;
    --blue:   #2979FF;

    --red-glow:    0 0 16px rgba(255,77,79,0.35);
    --green-glow:  0 0 16px rgba(0,200,83,0.35);
    --blue-glow:   0 0 16px rgba(41,121,255,0.35);
    --yellow-glow: 0 0 16px rgba(255,214,0,0.30);

    --radius-sm:  8px;
    --radius-md:  12px;
    --radius-lg:  16px;
    --shadow:     0 4px 24px rgba(0,0,0,0.45);
    --shadow-soft: 0 2px 12px rgba(0,0,0,0.24);
}

/* ── BASE ────────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: "Manrope", "Segoe UI", sans-serif;
    background: var(--bg) !important;
    color: var(--text) !important;
}

[data-testid="stAppViewContainer"] {
    background: var(--bg) !important;
}

[data-testid="stAppViewContainer"] * {
    color: var(--text) !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
    border: none !important;
    height: 0 !important;
}

[data-testid="stToolbar"] {
    visibility: visible;
    height: auto;
    position: fixed;
    top: 0.25rem;
    right: 0.5rem;
    background: transparent;
    z-index: 1000;
}

[data-testid="stDecoration"] { display: none; }

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1200px;
}

/* ── TYPOGRAPHY ──────────────────────────────────────────── */
h1 {
    font-family: "DM Serif Display", Georgia, serif !important;
    font-weight: 400 !important;
    font-size: clamp(1.8rem, 1.4rem + 1.4vw, 2.6rem) !important;
    color: var(--text) !important;
    letter-spacing: -0.01em;
    margin-bottom: 0.4rem;
}

h2 {
    font-family: "Space Grotesk", sans-serif !important;
    font-weight: 700 !important;
    font-size: clamp(1.2rem, 1rem + 0.7vw, 1.6rem) !important;
    color: var(--text) !important;
}

h3 {
    font-family: "Space Grotesk", sans-serif !important;
    font-weight: 600 !important;
    color: var(--text) !important;
}

p, span, label, li, div {
    color: var(--text) !important;
}

/* ── SIDEBAR ─────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: var(--bg-2) !important;
    border-right: 1px solid var(--line) !important;
}

[data-testid="stSidebar"] * {
    color: var(--text) !important;
}

.sidebar-brand {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-family: "Space Grotesk", sans-serif;
    font-weight: 700;
    font-size: 1.4rem;
    padding: 0.9rem 1rem;
    background: var(--bg-3);
    border: 1px solid var(--line-bright);
    border-radius: var(--radius-md);
    margin: 0.8rem 0.5rem;
    width: 100%;
    box-sizing: border-box;
    justify-content: center;
    color: var(--text) !important;
    letter-spacing: 0.04em;
}

.sidebar-brand-badge {
    width: 1.4rem;
    height: 1.4rem;
    border-radius: 6px;
    background: var(--blue);
    box-shadow: var(--blue-glow);
}

[data-testid="stSidebar"] [role="radiogroup"] > label {
    border-radius: var(--radius-sm);
    padding: 0.5rem 0.6rem;
    border: 1px solid transparent;
    transition: all 0.15s ease;
    color: var(--text-muted) !important;
}

[data-testid="stSidebar"] [role="radiogroup"] > label:hover {
    background: var(--surface);
    border-color: var(--line-bright);
    color: var(--text) !important;
}

[data-testid="stSidebar"] [role="radiogroup"] > label:has(input:checked) {
    background: var(--surface-2);
    border-color: var(--blue);
    color: var(--blue) !important;
}

[data-testid="stSidebar"] [role="radiogroup"] > label > div:first-child {
    display: none;
}

[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"] {
    background: var(--surface) !important;
    border: 1px solid var(--line-bright) !important;
    border-radius: var(--radius-sm);
}

/* ── BUTTONS ─────────────────────────────────────────────── */
.stButton > button,
.stDownloadButton > button,
[data-testid="baseButton-secondary"],
[data-testid="baseButton-primary"] {
    border-radius: 999px;
    border: 1px solid var(--line-bright);
    min-height: 2.5rem;
    font-weight: 600;
    font-size: 0.95rem;
    transition: all 0.2s ease;
    font-family: "Space Grotesk", sans-serif;
}

[data-testid="baseButton-primary"] {
    background: var(--blue) !important;
    color: #ffffff !important;
    border-color: var(--blue) !important;
    box-shadow: var(--blue-glow);
}

[data-testid="baseButton-primary"]:hover {
    background: #1565C0 !important;
    transform: translateY(-1px);
    box-shadow: 0 0 24px rgba(41,121,255,0.5);
}

.stButton > button:not([data-testid="baseButton-primary"]),
.stDownloadButton > button,
[data-testid="baseButton-secondary"] {
    background: var(--surface) !important;
    border-color: var(--line-bright) !important;
    color: var(--text) !important;
}

.stButton > button:not([data-testid="baseButton-primary"]):hover,
[data-testid="baseButton-secondary"]:hover {
    background: var(--surface-2) !important;
    border-color: var(--blue) !important;
    color: var(--blue) !important;
}

/* ── INPUTS ──────────────────────────────────────────────── */
.stTextInput input,
.stTextArea textarea,
.stSelectbox [data-baseweb="select"] > div,
.stNumberInput [data-baseweb="base-input"],
.stNumberInput input {
    background: var(--surface) !important;
    border: 1px solid var(--line-bright) !important;
    color: var(--text) !important;
    border-radius: var(--radius-md) !important;
}

.stTextInput input:focus,
.stTextArea textarea:focus {
    border-color: var(--blue) !important;
    box-shadow: 0 0 0 2px rgba(41,121,255,0.2) !important;
}

[data-baseweb="popover"],
[data-baseweb="popover"] [role="listbox"],
[data-baseweb="popover"] [role="option"] {
    background: var(--surface-2) !important;
    color: var(--text) !important;
    border-color: var(--line-bright) !important;
}

.stMultiSelect [data-baseweb="tag"] {
    background: rgba(41,121,255,0.2) !important;
    border: 1px solid var(--blue) !important;
    color: var(--text) !important;
}

/* ── METRICS ─────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: var(--surface);
    border: 1px solid var(--line-bright);
    border-radius: var(--radius-lg);
    padding: 1rem 1.1rem;
    box-shadow: var(--shadow);
}

[data-testid="stMetricLabel"] {
    color: var(--text-muted) !important;
    font-size: 0.82rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-family: "Space Grotesk", sans-serif;
}

[data-testid="stMetricValue"] {
    font-family: "Space Mono", monospace !important;
    font-weight: 700 !important;
    font-size: 1.9rem !important;
    color: var(--text) !important;
}

[data-testid="stExpander"] {
    border: 1px solid var(--line);
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-soft);
    margin-bottom: 0.62rem;
}

[data-testid="stExpander"] summary {
    font-weight: 600;
    min-height: 0 !important;
    padding-top: 0.45rem !important;
    padding-bottom: 0.45rem !important;
}

[data-testid="stExpander"] summary,
[data-testid="stExpander"] summary * {
    color: var(--text) !important;
}

[data-testid="stExpander"] details {
    background: var(--surface) !important;
    border-radius: var(--radius-lg);
}

[data-testid="stExpander"] details[open] {
    background: var(--surface) !important;
}

[data-testid="stExpander"] details[open] summary,
[data-testid="stExpander"] details[open] summary * {
    color: var(--text) !important;
}

.stButton > button,
.stDownloadButton > button,
[data-testid="baseButton-secondary"],
[data-testid="baseButton-primary"] {
    border-radius: 999px;
    border: 1px solid transparent;
    min-height: 2.5rem;
    font-weight: 600;
    font-size: 0.96rem;
    white-space: nowrap;
    transition: all 0.2s ease;
}

[data-testid="baseButton-primary"] {
    background: var(--blue) !important;
    color: #ffffff !important;
    border-color: var(--blue) !important;
    box-shadow: var(--blue-glow);
}

[data-testid="baseButton-primary"]:hover {
    background: #1565C0 !important;
    transform: translateY(-1px);
    box-shadow: 0 0 24px rgba(41,121,255,0.5);
}

.stButton > button:not([data-testid="baseButton-primary"]),
.stDownloadButton > button,
[data-testid="baseButton-secondary"] {
    background: var(--surface) !important;
    color: var(--text) !important;
    border-color: var(--line-bright) !important;
}

.stButton > button:not([data-testid="baseButton-primary"]):hover,
.stDownloadButton > button:hover,
[data-testid="baseButton-secondary"]:hover {
    background: var(--surface-2) !important;
    border-color: var(--blue) !important;
    color: var(--blue) !important;
}

/* Icon-only back buttons: outlined look with static white icon text. */
.stButton > button:has(p:only-child) {
    background: transparent !important;
    color: var(--text) !important;
    border: none !important;
    box-shadow: none !important;
}

.stButton > button:has(p:only-child):hover {
    background: transparent !important;
    color: var(--text) !important;
    border: none !important;
    box-shadow: none !important;
    transform: none !important;
}

.stTextInput input,
.stTextArea textarea,
.stSelectbox [data-baseweb="select"] > div,
.stMultiSelect [data-baseweb="tag"] {
    border-radius: var(--radius-md) !important;
}

.stTextInput input,
.stTextArea textarea,
.stSelectbox [data-baseweb="select"] > div {
    background: var(--surface) !important;
    border: 1px solid var(--line-bright) !important;
    color: var(--text) !important;
}

.stNumberInput [data-baseweb="input"] > div,
.stNumberInput [data-baseweb="base-input"],
.stNumberInput input,
.stSelectbox [data-baseweb="select"] > div,
.stMultiSelect [data-baseweb="select"] > div,
.stMultiSelect [data-baseweb="tag"],
.stMultiSelect [role="listbox"],
[data-baseweb="popover"],
[data-baseweb="popover"] [role="listbox"],
[data-baseweb="popover"] [role="option"] {
    background: var(--surface) !important;
    color: var(--text) !important;
    border-color: var(--line-bright) !important;
}

.stNumberInput button,
.stSelectbox button,
.stMultiSelect button {
    background: var(--surface-2) !important;
    color: var(--text) !important;
    border-color: var(--line-bright) !important;
}

.stSlider [data-baseweb="slider"] * {
    color: var(--text) !important;
}

.stTextInput input,
.stTextArea textarea {
    font-size: 0.95rem;
    line-height: 1.45;
    color: var(--text) !important;
}

[data-testid="stForm"] {
    background: var(--surface);
    border: 1px solid var(--line-bright);
    border-radius: var(--radius-lg);
    padding: 1rem 1.1rem;
}

[data-testid="stAlert"] {
    border-radius: var(--radius-md);
    border: 1px solid var(--line-bright);
    background: var(--surface-2) !important;
    color: var(--text) !important;
}

[data-testid="stJson"] {
    background: var(--bg-3) !important;
    border: 1px solid var(--line-bright) !important;
    border-radius: var(--radius-md);
    padding: 0.5rem;
}

[data-testid="stJson"] * {
    font-family: "Space Mono", monospace !important;
    font-size: 0.82rem !important;
    color: var(--text) !important;
}

[data-testid="stMarkdownContainer"] code {
    background: rgba(0,200,83,0.12) !important;
    color: #00C853 !important;
    border: 1px solid rgba(0,200,83,0.3);
    border-radius: 6px;
    padding: 0.12rem 0.35rem;
}

pre, code {
    font-family: "Space Mono", monospace !important;
    background: var(--bg-3) !important;
    color: var(--green) !important;
}

[data-testid="stProgressBar"] > div > div {
    background: #333333;
}

.page-hero {
    border: 1px solid var(--line);
    border-radius: var(--radius-lg);
    padding: 1rem 1.15rem;
    margin-bottom: 1rem;
    box-shadow: var(--shadow-soft);
    background: var(--surface);
}

.page-hero h3 {
    margin: 0;
    font-size: 1.05rem;
}

.page-hero p {
    margin: 0.25rem 0 0 0;
    color: var(--text-muted);
    font-size: 0.92rem;
}

.page-hero.dashboard {
    background: var(--surface) !important;
}

.page-hero.targets {
    background: var(--surface) !important;
}

.page-hero.simulations {
    background: var(--surface) !important;
}

.page-hero.results {
    background: var(--surface) !important;
}

.page-hero.settings {
    background: var(--surface) !important;
}

.accent-strip {
    display: flex;
    gap: 0.6rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
}

.accent-pill {
    padding: 0.3rem 0.7rem;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
    border: 1px solid var(--line-bright);
    background: var(--surface);
    color: var(--text-muted) !important;
    font-family: "Space Grotesk", sans-serif;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

.accent-pill.dashboard {
    background: var(--surface) !important;
    border-color: var(--line-bright) !important;
}

.accent-pill.targets {
    background: var(--surface) !important;
    border-color: var(--line-bright) !important;
}

.accent-pill.simulations {
    background: var(--surface) !important;
    border-color: var(--line-bright) !important;
}

.accent-pill.results {
    background: var(--surface) !important;
    border-color: var(--line-bright) !important;
}

.accent-pill.settings {
    background: var(--surface) !important;
    border-color: var(--line-bright) !important;
}

/* ── SIMULATION CARDS ────────────────────────────────────── */
[data-testid="stVerticalBlockBorderWrapper"] {
    border: 1.5px solid var(--line-bright) !important;
    border-left: 4px solid var(--blue) !important;
    border-radius: var(--radius-lg) !important;
    background: var(--surface) !important;
    box-shadow: var(--shadow) !important;
    transition: box-shadow 0.18s ease, border-color 0.18s ease;
}

[data-testid="stVerticalBlockBorderWrapper"]:hover {
    border-color: var(--blue) !important;
    box-shadow: 0 0 24px rgba(41,121,255,0.18) !important;
}

/* Clickable card link */
.sim-card-clickable {
    border: 1.5px solid var(--line-bright);
    border-left: 4px solid var(--blue);
    border-radius: var(--radius-lg);
    padding: 0.95rem 1rem;
    background: var(--surface);
    cursor: pointer;
    transition: box-shadow 0.18s ease, border-color 0.18s ease, background 0.18s ease;
    box-shadow: var(--shadow);
    margin-bottom: 0.72rem;
    display: block;
}

.sim-card-clickable:hover {
    box-shadow: 0 0 28px rgba(41,121,255,0.22);
    border-color: var(--blue);
    background: var(--surface-2);
}

/* Clickable target card link */
.target-card-clickable {
    border: 1.5px solid var(--line-bright);
    border-left: 4px solid var(--green);
    border-radius: var(--radius-lg);
    padding: 0.95rem 1rem;
    background: var(--surface);
    cursor: pointer;
    transition: box-shadow 0.18s ease, border-color 0.18s ease, background 0.18s ease;
    box-shadow: var(--shadow);
    margin-bottom: 0.72rem;
    display: block;
}

.target-card-clickable:hover {
    box-shadow: 0 0 28px rgba(0,200,83,0.22);
    border-color: var(--green);
    background: var(--surface-2);
}

a:has(.target-card-clickable),
a:has(.target-card-clickable):visited {
    text-decoration: none !important;
    display: block;
}

a:has(.target-card-clickable) * {
    color: var(--text) !important;
    text-decoration: none !important;
}

a:has(.sim-card-clickable),
a:has(.sim-card-clickable):visited {
    text-decoration: none !important;
    display: block;
}

a:has(.sim-card-clickable) * {
    color: var(--text) !important;
    text-decoration: none !important;
}

.simulation-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.65rem;
}

.simulation-card-title {
    font-family: "Space Grotesk", sans-serif;
    font-weight: 700;
    font-size: 0.98rem;
    color: var(--text) !important;
    max-width: 68%;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.simulation-status {
    border-radius: 999px;
    padding: 0.18rem 0.65rem;
    font-size: 0.7rem;
    font-weight: 700;
    font-family: "Space Grotesk", sans-serif;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border: 1px solid transparent;
}

.simulation-status.complete {
    background: rgba(0,200,83,0.12);
    color: #00C853 !important;
    border-color: rgba(0,200,83,0.35);
}

.simulation-status.failed {
    background: rgba(255,77,79,0.12);
    color: #FF4D4F !important;
    border-color: rgba(255,77,79,0.35);
}

.simulation-status.running {
    background: rgba(255,214,0,0.1);
    color: #FFD600 !important;
    border-color: rgba(255,214,0,0.3);
}

.simulation-card-meta {
    color: var(--text-muted) !important;
    font-size: 0.87rem;
    line-height: 1.4;
    margin-top: 0.22rem;
}

.simulation-card-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.4rem;
    color: var(--text-muted) !important;
    font-size: 0.87rem;
    margin-top: 0.38rem;
    border-top: 1px solid var(--line);
    padding-top: 0.3rem;
}

.simulation-card-row:first-of-type {
    border-top: none;
    padding-top: 0;
    margin-top: 0.5rem;
}

.simulation-percent {
    font-weight: 700;
    font-family: "Space Mono", monospace;
    color: var(--yellow) !important;
}

/* Target detail metric cards with compact text for long values (for example URLs). */
.target-detail-metric {
    background: var(--surface);
    border: 1px solid var(--line-bright);
    border-radius: var(--radius-lg);
    padding: 0.8rem 0.95rem;
    box-shadow: var(--shadow);
    min-height: 92px;
}

.target-detail-metric-label {
    color: var(--text-muted) !important;
    font-size: 0.76rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-family: "Space Grotesk", sans-serif;
    font-weight: 700;
    margin-bottom: 0.36rem;
}

.target-detail-metric-value {
    color: var(--text) !important;
    font-size: clamp(0.9rem, 0.84rem + 0.3vw, 1.05rem);
    font-family: "Space Mono", monospace;
    font-weight: 600;
    line-height: 1.2;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.target-detail-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    border: 1px solid var(--line-bright);
    border-radius: var(--radius-lg);
    overflow: hidden;
    box-shadow: var(--shadow);
    background: var(--surface);
    margin-bottom: 0.8rem;
}

.target-detail-table th,
.target-detail-table td {
    padding: 0.75rem 0.9rem;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
}

.target-detail-table tr:last-child th,
.target-detail-table tr:last-child td {
    border-bottom: none;
}

.target-detail-table th {
    width: 180px;
    color: var(--text-muted) !important;
    font-size: 0.76rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-family: "Space Grotesk", sans-serif;
    font-weight: 700;
    background: var(--surface-2);
}

.target-detail-table td {
    color: var(--text) !important;
    font-size: 0.94rem;
    line-height: 1.35;
    word-break: break-word;
    overflow-wrap: anywhere;
    font-family: "Space Mono", monospace;
}

.plain-back-link,
.plain-back-link:visited,
.plain-back-link:hover,
.plain-back-link:active {
    display: inline-block;
    color: var(--text) !important;
    text-decoration: none !important;
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
    font-family: "Space Grotesk", sans-serif;
    font-weight: 700;
    font-size: 1.1rem;
    line-height: 1;
    padding: 0.12rem 0.25rem;
}

/* ── TARGETS PAGE ────────────────────────────────────────── */
.target-summary {
    background: var(--surface);
    border: 1px solid var(--line-bright);
    border-left: 4px solid var(--blue);
    border-radius: var(--radius-lg);
    padding: 1rem;
    margin-bottom: 0.75rem;
    box-shadow: var(--shadow);
}

.target-name {
    font-weight: 700;
    font-family: "Space Grotesk", sans-serif;
    color: var(--text) !important;
    margin-bottom: 0.2rem;
}

.target-meta {
    color: var(--text-muted) !important;
    font-size: 0.88rem;
    font-family: "Space Mono", monospace;
}
/* ── CHAT TRANSCRIPT ─────────────────────────────────────── */
.chat-transcript {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    max-width: 980px;
}

.chat-row { display: flex; width: 100%; }
.chat-row.user { justify-content: flex-end; }
.chat-row.assistant { justify-content: flex-start; }

.chat-bubble {
    border-radius: var(--radius-md);
    line-height: 1.5;
    max-width: min(76%, 720px);
    padding: 0.85rem 1rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    border: 1px solid transparent;
    box-shadow: var(--shadow);
    color: var(--text) !important;
}

.chat-row.user .chat-bubble {
    background: rgba(255,77,79,0.08);
    border-color: rgba(255,77,79,0.25);
    color: var(--text) !important;
}

.chat-row.assistant .chat-bubble {
    background: rgba(41,121,255,0.08);
    border-color: rgba(41,121,255,0.25);
    color: var(--text) !important;
}

.chat-label {
    display: block;
    font-size: 0.73rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
    opacity: 0.8;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-family: "Space Grotesk", sans-serif;
    color: var(--text-muted) !important;
}

/* ── SLIDER ──────────────────────────────────────────────── */
.stSlider [data-baseweb="slider"] * {
    color: var(--text) !important;
}

/* ── SCROLLBAR ───────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-2); }
::-webkit-scrollbar-thumb { background: var(--line-bright); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--blue); }

</style>
"""


def _is_ignorable_windows_socket_teardown(context: dict[str, Any]) -> bool:
    """Return True for known harmless WinError 10054 teardown callbacks."""

    message = str(context.get("message") or "")
    exc = context.get("exception")
    if not isinstance(exc, ConnectionResetError):
        return False
    if getattr(exc, "winerror", None) != 10054:
        return False
    return "_call_connection_lost" in message or "_ProactorBasePipeTransport" in message


def _windows_asyncio_exception_handler(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    """Ignore noisy Windows socket teardown callbacks, forward everything else."""

    if _is_ignorable_windows_socket_teardown(context):
        return
    loop.default_exception_handler(context)


def run_async(coro):
    """Run async code from Streamlit's synchronous execution model."""
    if sys.platform == "win32":
        with asyncio.Runner() as runner:
            runner.get_loop().set_exception_handler(_windows_asyncio_exception_handler)
            return runner.run(coro)
    return asyncio.run(coro)


def _workflow_editor_default(scope_key: str, current_workflow: dict[str, Any]) -> str:
    pending_key = f"{scope_key}-workflow-preset"
    if pending_key in st.session_state:
        return str(st.session_state[pending_key])
    return json.dumps(current_workflow, indent=2)


def _render_workflow_preset_controls(scope_key: str, current_workflow: dict[str, Any]) -> None:
    st.markdown("**Workflow presets**")
    preset_names = ["Custom (keep current)"] + list(WORKFLOW_PRESETS.keys())
    selected_preset = st.selectbox(
        "Preset",
        preset_names,
        index=0,
        key=f"{scope_key}-preset-select",
        help="Apply a starter template for common streaming protocols.",
    )

    apply_col, reset_col = st.columns([1.3, 1.2])
    if apply_col.button("Apply preset", key=f"{scope_key}-preset-apply", use_container_width=True):
        if selected_preset == "Custom (keep current)":
            st.session_state[f"{scope_key}-workflow-preset"] = json.dumps(current_workflow, indent=2)
        else:
            st.session_state[f"{scope_key}-workflow-preset"] = json.dumps(WORKFLOW_PRESETS[selected_preset], indent=2)
        st.rerun()
    if reset_col.button("Reset", key=f"{scope_key}-preset-reset", use_container_width=True):
        st.session_state[f"{scope_key}-workflow-preset"] = json.dumps(current_workflow, indent=2)
        st.rerun()


def _validate_workflow_config(workflow: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(workflow, dict):
        return ["Workflow must be a JSON object."], []

    if not workflow:
        warnings.append("Workflow is empty. Target execution will use base request settings.")
        return errors, warnings

    known_steps = ["credential_authentication", "start_session", "next_turn"]
    enabled_steps = 0

    for step_name in known_steps:
        step = workflow.get(step_name)
        if step is None:
            continue
        if not isinstance(step, dict):
            errors.append(f"{step_name}: must be an object.")
            continue
        if not bool(step.get("enabled", True)):
            continue

        enabled_steps += 1
        method = str(step.get("method", "")).strip().upper()
        if method and method not in {"GET", "POST", "PUT", "PATCH"}:
            errors.append(f"{step_name}.method: unsupported method '{method}'.")

        streaming = step.get("streaming")
        if streaming is None:
            continue
        if not isinstance(streaming, dict):
            errors.append(f"{step_name}.streaming: must be an object when provided.")
            continue
        if not bool(streaming.get("enabled", True)):
            continue

        response_message_path = str(streaming.get("response_message_path") or "").strip()
        if not response_message_path:
            warnings.append(f"{step_name}.streaming: response_message_path is empty, raw SSE data lines will be appended.")

        stop_conditions = streaming.get("stop_conditions", [])
        if not isinstance(stop_conditions, list):
            errors.append(f"{step_name}.streaming.stop_conditions: must be an array.")
        else:
            if not stop_conditions:
                warnings.append(f"{step_name}.streaming: no stop_conditions configured; stream ends only when connection closes.")
            for idx, condition in enumerate(stop_conditions):
                if not isinstance(condition, dict):
                    errors.append(f"{step_name}.streaming.stop_conditions[{idx}]: must be an object.")
                    continue
                signal = str(condition.get("value") or "").strip()
                if not signal:
                    errors.append(f"{step_name}.streaming.stop_conditions[{idx}].value: required.")

        select_conditions = streaming.get("select_conditions", [])
        if not isinstance(select_conditions, list):
            errors.append(f"{step_name}.streaming.select_conditions: must be an array.")
        else:
            for idx, condition in enumerate(select_conditions):
                if not isinstance(condition, dict):
                    errors.append(f"{step_name}.streaming.select_conditions[{idx}]: must be an object.")
                    continue
                path = str(condition.get("path") or "").strip()
                signal = str(condition.get("value") or "").strip()
                if not path:
                    errors.append(f"{step_name}.streaming.select_conditions[{idx}].path: required.")
                if not signal:
                    errors.append(f"{step_name}.streaming.select_conditions[{idx}].value: required.")

    if enabled_steps == 0:
        warnings.append("All workflow steps are disabled. Target execution will use base request settings.")

    allowed_placeholders = {"prompt", "latest_message", "conversation_id", "session_id", "access_token"}
    unknown_placeholders = sorted(
        {
            name
            for name in re.findall(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", json.dumps(workflow))
            if name not in allowed_placeholders
        }
    )
    if unknown_placeholders:
        warnings.append(
            "Unknown placeholders detected: " + ", ".join(unknown_placeholders) + "."
        )

    return errors, warnings


async def run_target_test_call(target_payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a single connectivity probe for the selected target configuration."""

    target = TargetConfig.model_validate(target_payload)
    executor = TargetExecutor(settings=ScanSettings(max_turns=1, retry_count=0, timeout_seconds=30))
    test_method = getattr(executor, "test_connection", None)
    if callable(test_method):
        return await test_method(target, sample_message="hi")

    # Backward-compatibility fallback for stale runtimes that loaded an older TargetExecutor.
    probe = AttackPrompt(prompt="hi", category="connectivity", stage="test_call")
    response = await executor.execute(target=target, attack_prompt=probe, conversation_id=f"test-{int(datetime.now().timestamp())}")
    return {
        "ok": response.error is None and 200 <= response.status_code < 500,
        "status_code": response.status_code,
        "elapsed_ms": round(response.elapsed_ms, 2),
        "preview": response.body[:600],
        "error": response.error,
    }


def _run_target_test_and_store(path_name: str, target_payload: dict[str, Any]) -> None:
    try:
        result = run_async(run_target_test_call(target_payload))
        st.session_state[f"target_test_result_{path_name}"] = result
    except Exception as exc:
        st.session_state[f"target_test_result_{path_name}"] = {
            "ok": False,
            "status_code": 0,
            "elapsed_ms": 0,
            "preview": "",
            "error": str(exc),
        }


async def with_repository(fn):
    await init_db()
    async with AsyncSessionLocal() as session:
        return await fn(Repository(session))


def _target_executor_call(method_name: str, scan_id: str) -> None:
    """Call optional TargetExecutor cancellation hooks without breaking UI on stale reloads."""

    method = getattr(TargetExecutor, method_name, None)
    if callable(method):
        method(scan_id)


def _drain_simulation_scan_updates() -> dict[str, Any] | None:
    """Consume background scan queue events into session state."""

    scan_state = st.session_state.get("simulation_scan")
    if not scan_state:
        return None

    events_queue = scan_state.get("events_queue")
    if not events_queue:
        return scan_state

    while True:
        try:
            item = events_queue.get_nowait()
        except queue.Empty:
            break

        kind = item.get("kind")
        if kind == "progress":
            event = item.get("event", {})
            scan_state["events"].append(event)
            scan_state["stage"] = event.get("event", "running")
            completed = len(
                [entry for entry in scan_state["events"] if entry.get("event") in {"scenario_completed", "detectors_completed"}]
            )
            total_steps = max(1, int(scan_state.get("scenario_count", 1)) * 2)
            scan_state["progress"] = min(100, int((completed / total_steps) * 100))
        elif kind == "result":
            scan_state["result"] = item.get("result")
        elif kind == "error":
            scan_state["error"] = str(item.get("error", "Unknown scan execution error"))
        elif kind == "done":
            scan_state["running"] = False
            scan_state["progress"] = scan_state.get("progress", 0) or 0

    st.session_state.simulation_scan = scan_state
    return scan_state


def _start_background_scan(scan_payload: dict[str, Any], scan_state: dict[str, Any]) -> None:
    """Run a scan on a worker thread so the UI remains interactive."""

    _target_executor_call("register_scan", scan_payload["scan_id"])

    def worker() -> None:
        try:
            async def run() -> Any:
                await init_db()
                async with AsyncSessionLocal() as session:
                    request = ScanRequest(**scan_payload)
                    orchestrator = ScanOrchestrator(repository=Repository(session))

                    def progress(event: dict[str, Any]) -> None:
                        scan_state["events_queue"].put({"kind": "progress", "event": event})

                    return await orchestrator.run_scan(request, progress=progress)

            result = run_async(run())
            scan_state["events_queue"].put({"kind": "result", "result": result_to_report(result)})
        except Exception as exc:
            scan_state["events_queue"].put({"kind": "error", "error": str(exc)})
        finally:
            _target_executor_call("clear_cancel", scan_payload["scan_id"])
            scan_state["events_queue"].put({"kind": "done"})

    worker_thread = threading.Thread(target=worker, daemon=True, name=f"scan-worker-{scan_payload['scan_id'][:8]}")
    worker_thread.start()
    scan_state["worker"] = worker_thread


def load_target_files() -> list[tuple[Path, dict[str, Any]]]:
    targets: list[tuple[Path, dict[str, Any]]] = []
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    for path in sorted(TARGET_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                st.warning(f"Invalid target skipped: {path.name} is not a JSON object.")
                continue
            if str(payload.get("name") or "").startswith(REFERENCE_TARGET_PREFIX):
                continue
            targets.append((path, payload))
        except json.JSONDecodeError:
            st.warning(f"Invalid JSON target skipped: {path.name}")
    return targets


def load_reports() -> list[tuple[Path, dict[str, Any]]]:
    reports: list[tuple[Path, dict[str, Any]]] = []
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for path in sorted(REPORT_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            reports.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except json.JSONDecodeError:
            continue
    return reports


def _delete_report_files(paths: list[Path]) -> int:
    deleted = 0
    report_root = REPORT_DIR.resolve()
    for path in {item for item in paths if isinstance(item, Path)}:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.parent != report_root:
            continue
        if resolved.exists() and resolved.is_file():
            resolved.unlink()
            deleted += 1
    return deleted


def _delete_target_files(paths: list[Path]) -> int:
    deleted = 0
    target_root = TARGET_DIR.resolve()
    for path in {item for item in paths if isinstance(item, Path)}:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.parent != target_root:
            continue
        if resolved.exists() and resolved.is_file():
            resolved.unlink()
            deleted += 1
    return deleted


def save_target_file(target: TargetConfig, filename: str | None = None) -> Path:
    safe_name = filename or "".join(char.lower() if char.isalnum() else "-" for char in target.name).strip("-")
    path = TARGET_DIR / f"{safe_name}.json"
    path.write_text(json.dumps(target.model_dump(mode="json"), indent=2), encoding="utf-8")
    return path


def load_auth_template_catalog() -> dict[str, Any]:
    if not AUTH_TEMPLATE_FILE.exists():
        return {}
    try:
        payload = json.loads(AUTH_TEMPLATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _auth_template_entries() -> dict[str, dict[str, Any]]:
    catalog = load_auth_template_catalog()
    entries = catalog.get("auth_types") or {}
    return entries if isinstance(entries, dict) else {}


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _current_target_delivery_selection() -> tuple[str, str] | None:
    mode = str(st.session_state.get("target_streaming_type") or "").strip().lower()
    subtype = str(st.session_state.get("target_delivery_subtype") or "").strip()
    if mode not in {"streaming", "non-streaming"} or not subtype:
        return None
    return mode, subtype


def _apply_target_delivery(payload: dict[str, Any], mode: str | None = None, subtype: str | None = None) -> dict[str, Any]:
    enriched = _json_clone(payload)
    auth = enriched.get("auth")
    if not isinstance(auth, dict):
        auth = {"type": "none"}
    if mode and subtype:
        auth["target_delivery"] = {
            "mode": _normalize_delivery_mode(mode),
            "type": str(subtype).strip().lower(),
        }
    enriched["auth"] = auth
    return enriched


def _template_select_options() -> list[str]:
    entries = _auth_template_entries()
    available = [key for key in SUPPORTED_AUTH_TEMPLATE_KEYS if key in entries]
    return available or SUPPORTED_AUTH_TEMPLATE_KEYS.copy()


def _template_label(template_key: str) -> str:
    entry = _auth_template_entries().get(template_key) or {}
    fallback = template_key.replace("_", " ")
    description = str(entry.get("description") or fallback).strip()
    return f"{template_key} - {description}"


def _normalize_delivery_mode(value: str) -> str:
    raw = str(value or "").strip().lower()
    return "non-streaming" if raw in {"non-streaming", "non_streaming"} else raw


@lru_cache(maxsize=1)
def _load_combination_template_index() -> dict[tuple[str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    markdown_path = next((path for path in TARGET_TEMPLATE_MD_CANDIDATES if path.exists()), None)
    if not markdown_path:
        return index

    try:
        markdown_text = markdown_path.read_text(encoding="utf-8")
    except OSError:
        return index

    pattern = re.compile(r"##\s*Template\s+\d+:.*?\n```json\n(.*?)\n```", re.DOTALL)
    for match in pattern.finditer(markdown_text):
        block = match.group(1)
        try:
            payload = json.loads(block)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue

        auth_payload = payload.get("auth") or {}
        delivery = payload.get("target_delivery") or {}
        auth_type = str((auth_payload if isinstance(auth_payload, dict) else {}).get("type") or "").strip()
        mode = _normalize_delivery_mode(str((delivery if isinstance(delivery, dict) else {}).get("mode") or ""))
        delivery_type = str((delivery if isinstance(delivery, dict) else {}).get("type") or "").strip().lower()
        if auth_type and mode and delivery_type:
            index[(auth_type, mode, delivery_type)] = payload

    return index


def _fallback_combination_template(auth_type: str, mode: str, delivery_type: str) -> dict[str, Any]:
    headers = {"Accept": "text/event-stream"} if mode == "streaming" and delivery_type != "websocket" else {"Content-Type": "application/json"}
    template: dict[str, Any] = {
        "name": "Generated Template",
        "url": "https://example.com/chat",
        "method": "POST",
        "headers": headers,
        "request_template": {"message": "{{prompt}}"},
        "auth": {"type": auth_type},
        "target_delivery": {"mode": mode, "type": delivery_type},
        "timeout_seconds": STREAMING_TIMEOUT_SECONDS if mode == "streaming" else NON_STREAMING_TIMEOUT_BY_TYPE.get(delivery_type, 120),
    }

    if auth_type == "bearer_token_from_env":
        template["auth"]["env_variable"] = "API_TOKEN"
    elif auth_type == "bearer_token_in_header":
        template["auth"]["header_name"] = "Authorization"
        template["auth"]["format"] = "Bearer {{token}}"
    elif auth_type == "api_key_header":
        template["auth"]["header_name"] = "X-API-Key"
        template["auth"]["env_variable"] = "API_KEY"
    elif auth_type == "basic_auth":
        template["auth"]["username_env"] = "BASIC_USER"
        template["auth"]["password_env"] = "BASIC_PASS"
    elif auth_type == "oauth2_client_credentials":
        template["auth"].update(
            {
                "token_url": "https://example.com/oauth/token",
                "client_id_env": "CLIENT_ID",
                "client_secret_env": "CLIENT_SECRET",
                "scope": "default",
            }
        )
    elif auth_type == "jwt_token_auth":
        template["auth"]["jwt_env"] = "JWT_TOKEN"

    if mode == "streaming":
        template["request_overrides"] = {"stream": True}
        if delivery_type == "chunk":
            template["request_overrides"]["chunk_type"] = "paragraph"
        if delivery_type == "event":
            template["request_overrides"]["emit_events"] = True
        if delivery_type == "websocket":
            template["transport"] = {"protocol": "ws"}

    return template


def _preview_template_for_selection(auth_type: str, mode: str, delivery_type: str) -> dict[str, Any]:
    template_index = _load_combination_template_index()
    normalized_mode = _normalize_delivery_mode(mode)
    matched = template_index.get((auth_type, normalized_mode, delivery_type))
    if isinstance(matched, dict):
        return _json_clone(matched)
    return _fallback_combination_template(auth_type, normalized_mode, delivery_type)


def _build_target_from_auth_template(template_key: str, responses: dict[str, Any] | None = None) -> dict[str, Any]:
    responses = responses or {}
    selected_delivery = _current_target_delivery_selection()
    selected_mode = str(responses.get("target_mode") or "").strip().lower() if isinstance(responses, dict) else ""
    selected_subtype = str(responses.get("target_delivery_subtype") or "").strip().lower() if isinstance(responses, dict) else ""
    if not (selected_mode and selected_subtype) and selected_delivery:
        selected_mode, selected_subtype = selected_delivery

    mode_for_template = selected_mode or "streaming"
    subtype_for_template = selected_subtype or "token"
    base_payload = _preview_template_for_selection(template_key, mode_for_template, subtype_for_template)

    base_headers = base_payload.get("headers") if isinstance(base_payload.get("headers"), dict) else {"Content-Type": "application/json"}
    auth_payload = base_payload.get("auth") if isinstance(base_payload.get("auth"), dict) else {"type": template_key}

    target_payload: dict[str, Any] = {
        "name": str(responses.get("name") or base_payload.get("name") or "New Target"),
        "url": str(responses.get("chat_url") or responses.get("url") or base_payload.get("url") or "https://example.com/chat"),
        "method": str(responses.get("method") or base_payload.get("method") or "POST"),
        "headers": _json_clone(base_headers),
        "request_template": responses.get("request_template") or base_payload.get("request_template") or {"message": "{{prompt}}"},
        "auth": _json_clone(auth_payload),
        "timeout_seconds": int(responses.get("timeout_seconds") or base_payload.get("timeout_seconds") or 120),
    }

    if isinstance(base_payload.get("request_overrides"), dict):
        target_payload["request_overrides"] = _json_clone(base_payload["request_overrides"])
    if isinstance(base_payload.get("transport"), dict):
        target_payload["transport"] = _json_clone(base_payload["transport"])

    if template_key == "bearer_token_from_env":
        target_payload["auth"]["token_env"] = str(responses.get("token_env") or "API_TOKEN")

    existing_headers = target_payload.get("headers") if isinstance(target_payload.get("headers"), dict) else {}
    header_replacements = {
        "Authorization": str(responses.get("authorization_header") or responses.get("static_token") or existing_headers.get("Authorization", "")),
        "X-API-Key": str(responses.get("api_key") or existing_headers.get("X-API-Key", "")),
        "X-Auth-Token": str(responses.get("custom_token") or existing_headers.get("X-Auth-Token", "")),
        "X-Client-ID": str(responses.get("client_id") or existing_headers.get("X-Client-ID", "")),
    }
    for header_name, header_value in header_replacements.items():
        if header_name in target_payload["headers"] and header_value:
            target_payload["headers"][header_name] = header_value

    workflow = (target_payload.get("auth") or {}).get("workflow")
    if isinstance(workflow, dict):
        credential_step = workflow.get("credential_authentication")
        if isinstance(credential_step, dict):
            if responses.get("login_url"):
                credential_step["url"] = str(responses["login_url"])
            content_type = str((credential_step.get("headers") or {}).get("Content-Type") or "").lower()
            if "application/x-www-form-urlencoded" in content_type and not credential_step.get("body_encoding"):
                credential_step["body_encoding"] = "form"
            body = credential_step.get("body")
            if isinstance(body, dict):
                replacements = {
                    "username": responses.get("username"),
                    "password": responses.get("password"),
                    "email": responses.get("username"),
                    "client_id": responses.get("client_id"),
                    "client_secret": responses.get("client_secret") or responses.get("password"),
                    "grant_type": responses.get("grant_type"),
                }
                for key, replacement in replacements.items():
                    if key in body and replacement:
                        body[key] = replacement

        next_turn_step = workflow.get("next_turn")
        if isinstance(next_turn_step, dict):
            next_turn_step["url"] = str(responses.get("chat_url") or responses.get("url") or target_payload["url"])
            if responses.get("response_message_path"):
                next_turn_step["response_message_path"] = str(responses["response_message_path"])

    return _apply_target_delivery(
        target_payload,
        mode=selected_mode or None,
        subtype=selected_subtype or None,
    )


def _format_validation_error(exc: ValidationError) -> list[str]:
    messages: list[str] = []
    for item in exc.errors():
        path = ".".join(str(part) for part in item.get("loc", []))
        messages.append(f"{path}: {item.get('msg', 'Invalid value')}")
    return messages


def _validate_target_payload(payload: dict[str, Any], template_key: str | None = None) -> tuple[list[str], list[str], dict[str, Any] | None]:
    errors: list[str] = []
    warnings: list[str] = []
    normalized: dict[str, Any] | None = None

    try:
        target = TargetConfig.model_validate(payload)
        normalized = target.model_dump(mode="json")
    except ValidationError as exc:
        errors.extend(_format_validation_error(exc))

    auth = payload.get("auth") or {}
    if not isinstance(auth, dict):
        errors.append("auth: must be a JSON object.")
        return errors, warnings, normalized

    auth_type = str(auth.get("type") or "none").strip().lower()
    workflow = auth.get("workflow")
    if workflow is not None:
        if not isinstance(workflow, dict):
            errors.append("auth.workflow: must be a JSON object.")
        else:
            workflow_errors, workflow_warnings = _validate_workflow_config(workflow)
            errors.extend(workflow_errors)
            warnings.extend(workflow_warnings)

            credential_step = workflow.get("credential_authentication")
            if isinstance(credential_step, dict):
                cred_headers = credential_step.get("headers") or {}
                content_type = str((cred_headers if isinstance(cred_headers, dict) else {}).get("Content-Type") or "").lower()
                body_encoding = str(credential_step.get("body_encoding") or "").lower().strip()
                if body_encoding == "form" or "application/x-www-form-urlencoded" in content_type:
                    if not isinstance(credential_step.get("body"), dict):
                        errors.append("auth.workflow.credential_authentication.body: must be an object for form-encoded login.")

    if auth_type == "bearer" and not str(auth.get("token_env") or "").strip():
        errors.append("auth.token_env: required for bearer authentication.")
    if auth_type == "session" and not isinstance(workflow, dict):
        errors.append("auth.workflow: required for session authentication.")

    if template_key == "session_cookie_auth" and isinstance(workflow, dict):
        if not isinstance(workflow.get("credential_authentication"), dict):
            errors.append("auth.workflow.credential_authentication: required for session cookie auth.")
        if not isinstance(workflow.get("next_turn"), dict):
            errors.append("auth.workflow.next_turn: required for session cookie auth.")
    if template_key == "bearer_token_from_env" and auth_type != "bearer":
        errors.append("auth.type: must be 'bearer' for the bearer token env template.")

    return errors, warnings, normalized


def _target_structure_summary(payload: dict[str, Any]) -> dict[str, Any]:
    auth = payload.get("auth") or {}
    workflow = auth.get("workflow") or {}
    return {
        "top_level_keys": sorted(payload.keys()),
        "auth_type": auth.get("type", "none"),
        "workflow_steps": [name for name in ["credential_authentication", "start_session", "next_turn"] if name in workflow],
        "has_timeout": "timeout_seconds" in payload,
    }


def _save_created_target_from_payload(payload: dict[str, Any], success_message: str) -> None:
    selected_delivery = _current_target_delivery_selection()
    enriched_payload = payload
    if selected_delivery:
        enriched_payload = _apply_target_delivery(payload, mode=selected_delivery[0], subtype=selected_delivery[1])

    target = TargetConfig.model_validate(enriched_payload)
    save_target_file(target)
    run_async(with_repository(lambda repo: repo.upsert_target(target)))
    st.session_state.target_editor = None
    st.session_state.targets_view = "list"
    st.session_state.pop(CREATE_TARGET_PREFILL_KEY, None)
    st.session_state.pop(CREATE_TARGET_ASSISTANT_KEY, None)
    st.session_state.target_saved_message = success_message
    st.rerun()


def _render_create_target_upload_tools(selected_template: str) -> None:
    st.markdown("**JSON File Upload & Auto Processing**")
    uploaded_file = st.file_uploader(
        "Upload target JSON",
        type=["json"],
        key="create-target-upload-json",
        help="Upload a target configuration file to analyze, validate, and normalize.",
    )
    if not uploaded_file:
        return

    try:
        payload = json.loads(uploaded_file.getvalue().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        st.error(f"Invalid JSON file: {exc}")
        return

    if not isinstance(payload, dict):
        st.error("Uploaded JSON must be an object.")
        return

    st.caption("Detected structure")
    st.json(_target_structure_summary(payload))

    errors, warnings, normalized = _validate_target_payload(payload, selected_template)
    if errors:
        st.error("Validation failed:\n- " + "\n- ".join(errors))
        return

    if warnings:
        st.warning("Validation passed with warnings:\n- " + "\n- ".join(warnings))
    else:
        st.success("Uploaded JSON is valid.")

    normalized_payload = normalized or payload
    normalized_json = json.dumps(normalized_payload, indent=2)
    download_col, apply_col = st.columns([1.5, 1.2])
    download_col.download_button(
        "Download validated JSON",
        normalized_json,
        file_name=uploaded_file.name,
        mime="application/json",
        use_container_width=True,
    )
    if apply_col.button("Use uploaded JSON", key="create-target-apply-upload", use_container_width=True):
        st.session_state[CREATE_TARGET_PREFILL_KEY] = normalized_payload
        st.rerun()


def _extract_json_object(text: str) -> dict[str, Any] | None:
    candidate = str(text or "").strip()
    if not candidate:
        return None

    fence_match = re.search(r"```json\s*(.*?)\s*```", candidate, re.DOTALL | re.IGNORECASE)
    if fence_match:
        candidate = fence_match.group(1).strip()

    decoder = json.JSONDecoder()
    for index, char in enumerate(candidate):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(candidate[index:])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def _assistant_system_prompt(selected_template: str, mode: str, delivery_type: str, template_payload: dict[str, Any]) -> str:
    return (
        "You are an expert target-configuration assistant for an LLM security platform. "
        "Your job is conversational intake first, JSON generation second. "
        "Ask targeted follow-up questions when information is missing. "
        "Do not output JSON for greetings or casual messages. "
        "Only output a final JSON object when the user explicitly asks to generate/finalize JSON. "
        "Before final JSON, ask for missing essentials: application name, endpoint URL, method, "
        "authentication details, and any required headers/body fields. "
        "Keep questions short and practical, 1-3 questions at a time. "
        f"Selected auth type: {selected_template}. "
        f"Selected delivery mode/type: {mode}/{delivery_type}. "
        "Always keep auth.type aligned to the selected auth type. "
        "Always include target_delivery with keys mode and type. "
        "Use placeholders (example.com URLs and env names) when user details are missing. "
        "If the user asks to generate JSON but details are still missing, ask follow-up questions instead of returning JSON. "
        f"Reference template:\n{json.dumps(template_payload, indent=2)}"
    )


def _assistant_user_prompt(messages: list[dict[str, str]], latest_user_message: str) -> str:
    recent = messages[-8:]
    transcript = "\n".join(
        f"{item.get('role', 'user').upper()}: {str(item.get('content') or '').strip()}" for item in recent
    )
    return f"Conversation so far:\n{transcript}\n\nLatest user message:\n{latest_user_message}"


def _wants_json_generation(user_message: str) -> bool:
    text = str(user_message or "").strip().lower()
    if not text:
        return False
    keywords = [
        "generate json",
        "final json",
        "create json",
        "build json",
        "give me json",
        "output json",
        "generate target",
        "finalize",
    ]
    return any(keyword in text for keyword in keywords)


def _render_chatbot_modal(selected_template: str) -> None:
    mode = str(st.session_state.get("target_streaming_type") or "streaming")
    delivery_type = str(st.session_state.get("target_delivery_subtype") or "token")
    template_payload = _preview_template_for_selection(selected_template, mode, delivery_type)

    st.markdown("### AI Assistance Chatbot")
    st.caption("Ask for modifications or say: generate final JSON for my selected configuration.")

    scope_key = f"assistant-chat-{selected_template}-{mode}-{delivery_type}"
    messages = st.session_state.get(scope_key)
    if not isinstance(messages, list):
        messages = [
            {
                "role": "assistant",
                "content": (
                    "Let us create your target JSON step by step. "
                    "What is your application name and chatbot endpoint URL?"
                ),
            }
        ]
        st.session_state[scope_key] = messages

    controls_col1, controls_col2 = st.columns([1.3, 1.6])
    if controls_col1.button("Clear chat", key=f"assistant-clear-{scope_key}", use_container_width=True):
        st.session_state.pop(scope_key, None)
        st.session_state.pop(CREATE_TARGET_ASSISTANT_KEY, None)
        st.rerun()
    controls_col2.caption("Azure OpenAI is used when configured; otherwise fallback mode is used.")

    for message in messages:
        role = str(message.get("role") or "assistant")
        st.chat_message("assistant" if role != "user" else "user").write(str(message.get("content") or ""))

    user_message = st.chat_input("Describe what you want in the target JSON", key=f"assistant-chat-input-{scope_key}")
    if user_message:
        messages.append({"role": "user", "content": user_message})
        with st.spinner("Generating response..."):
            try:
                client = AzureOpenAIClient(get_settings(), temperature=0.2)
                system_prompt = _assistant_system_prompt(selected_template, mode, delivery_type, template_payload)
                prompt = _assistant_user_prompt(messages, user_message)
                reply = run_async(client.complete(system_prompt, prompt)).content
            except Exception as exc:
                reply = f"Unable to reach Azure OpenAI right now: {exc}"

        messages.append({"role": "assistant", "content": reply})
        st.session_state[scope_key] = messages

        wants_generation = _wants_json_generation(user_message)
        parsed = _extract_json_object(reply)
        if isinstance(parsed, dict):
            st.session_state[CREATE_TARGET_ASSISTANT_KEY] = parsed
        elif not wants_generation:
            st.session_state.pop(CREATE_TARGET_ASSISTANT_KEY, None)
        st.rerun()

    st.markdown("---")
    generated_payload = st.session_state.get(CREATE_TARGET_ASSISTANT_KEY)
    if not isinstance(generated_payload, dict):
        return

    st.markdown("### Generated Target Configuration")
    errors, warnings, normalized = _validate_target_payload(generated_payload, selected_template)
    if errors:
        st.error("⚠️ Validation failed:\n- " + "\n- ".join(errors))
        return
    if warnings:
        st.warning("⚠️ Warnings:\n- " + "\n- ".join(warnings))
    else:
        st.success("✅ Configuration is valid!")

    final_payload = normalized or generated_payload
    st.json(final_payload)

    st.markdown("### What do you want to do next?")
    next_action = st.radio(
        "Select one option",
        options=["Download JSON", "Create target with generated JSON"],
        key="assistant-generated-next-action",
        horizontal=True,
        label_visibility="collapsed",
    )
    if next_action == "Download JSON":
        st.download_button(
            "📥 Download JSON",
            json.dumps(final_payload, indent=2),
            file_name=f"{str(final_payload.get('name') or 'target').lower().replace(' ', '-')}.json",
            mime="application/json",
            use_container_width=True,
            key="assistant-download-generated-json",
        )
    else:
        if st.button(
            "✅ Create target with generated JSON",
            key="assistant-create-target",
            type="primary",
            use_container_width=True,
        ):
            _save_created_target_from_payload(final_payload, "Target created from AI assistant.")


def _render_create_target_tools() -> None:
    st.subheader("Configure Your Target")

    st.markdown("### Step 1: Target Type")
    target_mode = st.radio(
        "Is your target streaming or non-streaming?",
        options=["streaming", "non-streaming"],
        horizontal=True,
        key="create-target-streaming-type",
        help="Streaming targets return responses in incremental chunks. Non-streaming targets return the full response at once.",
    )
    st.session_state["target_streaming_type"] = target_mode

    if target_mode == "streaming":
        selected_target_subtype = st.selectbox(
            "Select streaming type",
            STREAMING_SUBTYPE_OPTIONS,
            key="create-target-streaming-subtype",
        )
        st.caption("Choose one: token, chunk, event, sse, websocket.")
    else:
        selected_target_subtype = st.selectbox(
            "Select non-streaming type",
            NON_STREAMING_SUBTYPE_OPTIONS,
            key="create-target-non-streaming-subtype",
        )
        st.caption("Choose one: synchronous, retrieval, generative, batch, workflow.")

    st.session_state["target_delivery_subtype"] = selected_target_subtype

    st.divider()

    st.markdown("### Step 2: Authentication Type")
    template_options = _template_select_options()
    selected_template = st.selectbox(
        "Select authentication type",
        template_options,
        format_func=_template_label,
        key="create-target-template-select",
        help="Choose the authentication pattern that matches the target you want to test.",
    )
    st.session_state["target_auth_template"] = selected_template

    st.divider()

    st.markdown("### Step 3: Preview and Download JSON")
    template_payload = _preview_template_for_selection(selected_template, target_mode, selected_target_subtype)
    st.caption(
        f"Target mode: {target_mode.title()} | Type: {selected_target_subtype}"
    )
    preview_col, download_col = st.columns([4, 1.6])
    with preview_col.expander("Template preview", expanded=False):
        st.json(template_payload)
    download_col.download_button(
        "Download template",
        json.dumps(template_payload, indent=2),
        file_name=f"{_normalize_delivery_mode(target_mode).replace('-', '_')}-{selected_target_subtype}-{selected_template}-template.json",
        mime="application/json",
        use_container_width=True,
    )

    st.divider()

    st.markdown("### Step 4: Create Target Options")
    selected_create_option = st.radio(
        "Choose an option",
        options=["Upload JSON", "AI Assistance Chatbot", "Manual Form"],
        horizontal=True,
        key="create-target-step4-option",
        label_visibility="collapsed",
    )
    st.session_state["create_target_option"] = selected_create_option

    if selected_create_option == "Upload JSON":
        st.caption("Upload an existing target JSON, validate it, and optionally load it into the form below.")
        _render_create_target_upload_tools(selected_template)

    elif selected_create_option == "AI Assistance Chatbot":
        st.caption("Use real-time AI chat to generate/refine target JSON aligned to your selected auth and delivery type.")
        _render_chatbot_modal(selected_template)

    else:
        st.caption("Use the manual form below to enter or refine the target configuration directly.")
        st.info("After choosing the target type and authentication template above, complete the Create target form below.")


def export_pdf(report: dict[str, Any]) -> bytes:
    """Create a colorful, chart-rich PDF report for business and technical stakeholders."""

    try:
        from io import BytesIO

        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.shapes import Drawing, Line, String
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        lines = [
            "LLM Security Assessment Report",
            f"Scan name: {report.get('scan_name')}",
            f"Target: {report.get('target_name')}",
            f"Status: {report.get('status')}",
        ]
        for scenario in report.get("scenario_results", []):
            lines.extend(
                [
                    "",
                    f"Scenario: {scenario.get('scenario_name')}",
                    f"Vulnerability: {scenario_vulnerability_percent(scenario)}%",
                    f"Reason: {vulnerability_reason(scenario)}",
                    f"Remediation: {remediation_text(scenario)}",
                ]
            )
        markdown_fallback = enterprise_markdown_text(report)
        if markdown_fallback:
            lines.extend(["", "Enterprise Markdown Report", "---------------------------", markdown_fallback])
        return "\n".join(lines).encode("utf-8")

    scenario_results = report.get("scenario_results", [])
    scenario_names = [str(item.get("scenario_name", "Scenario")) for item in scenario_results]
    scenario_percents = [scenario_vulnerability_percent(item) for item in scenario_results]
    avg_vulnerability = int(round(sum(scenario_percents) / len(scenario_percents))) if scenario_percents else 0
    vulnerable_scenarios = sum(1 for value in scenario_percents if value > 0)
    total_scenarios = len(scenario_results)
    safe_scenarios = max(0, total_scenarios - vulnerable_scenarios)
    attack_success_rate = round((vulnerable_scenarios / total_scenarios) * 100, 2) if total_scenarios else 0.0
    safe_response_rate = round((safe_scenarios / total_scenarios) * 100, 2) if total_scenarios else 0.0

    if avg_vulnerability >= 75:
        risk_level = "CRITICAL"
        risk_color = colors.HexColor("#D32F2F")
    elif avg_vulnerability >= 50:
        risk_level = "HIGH"
        risk_color = colors.HexColor("#F57C00")
    elif avg_vulnerability >= 25:
        risk_level = "MEDIUM"
        risk_color = colors.HexColor("#FBC02D")
    else:
        risk_level = "LOW"
        risk_color = colors.HexColor("#2E7D32")

    severity_counter = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for scenario in scenario_results:
        for detector in scenario.get("detector_results", []):
            if detector.get("vulnerable"):
                severity = str(detector.get("severity", "LOW")).upper()
                if severity not in severity_counter:
                    severity = "LOW"
                severity_counter[severity] += 1

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
    )

    brand_navy = colors.HexColor("#0B2545")
    brand_blue = colors.HexColor("#1D4ED8")
    brand_cyan = colors.HexColor("#0EA5E9")
    brand_slate = colors.HexColor("#334155")
    brand_panel = colors.HexColor("#F8FAFC")
    brand_border = colors.HexColor("#CBD5E1")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.white,
        alignment=1,
        spaceAfter=8,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#E5EAF5"),
        alignment=1,
        spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=brand_blue,
        spaceAfter=8,
        spaceBefore=8,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=brand_slate,
    )
    small_muted_style = ParagraphStyle(
        "SmallMuted",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
    )
    markdown_h1_style = ParagraphStyle(
        "MarkdownH1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=brand_navy,
        spaceBefore=4,
        spaceAfter=2,
    )
    markdown_h2_style = ParagraphStyle(
        "MarkdownH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=brand_blue,
        spaceBefore=3,
        spaceAfter=2,
    )
    markdown_h3_style = ParagraphStyle(
        "MarkdownH3",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=brand_cyan,
        spaceBefore=2,
        spaceAfter=1,
    )
    markdown_body_style = ParagraphStyle(
        "MarkdownBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=11,
        textColor=brand_slate,
        spaceAfter=0,
    )
    markdown_metric_style = ParagraphStyle(
        "MarkdownMetric",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=13,
        textColor=brand_navy,
        alignment=1,
    )
    markdown_label_style = ParagraphStyle(
        "MarkdownLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
        alignment=1,
    )

    def _append_section_divider() -> None:
        divider = Drawing(500, 10)
        divider.add(Line(0, 5, 500, 5, strokeColor=colors.HexColor("#93C5FD"), strokeWidth=1))
        story.append(Spacer(1, 0.04 * inch))
        story.append(divider)
        story.append(Spacer(1, 0.04 * inch))

    def _escape_md_text(text: str) -> str:
        escaped = html.escape(text)
        escaped = escaped.replace("**", "")
        escaped = escaped.replace("__", "")
        escaped = escaped.replace("`", "")
        return escaped

    def _append_markdown_report(markdown_text: str) -> None:
        if not markdown_text.strip():
            return

        story.append(Spacer(1, 0.04 * inch))
        story.append(Paragraph("Full Enterprise Narrative", heading_style))
        md_lines = markdown_text.splitlines()
        for raw_line in md_lines:
            line = raw_line.rstrip()
            stripped = line.strip()

            if not stripped:
                story.append(Spacer(1, 0.02 * inch))
                continue

            if stripped.startswith("### "):
                story.append(Paragraph(_escape_md_text(stripped[4:]), markdown_h3_style))
                continue

            if stripped.startswith("## "):
                story.append(Paragraph(_escape_md_text(stripped[3:]), markdown_h2_style))
                continue

            if stripped.startswith("# "):
                story.append(Paragraph(_escape_md_text(stripped[2:]), markdown_h1_style))
                continue

            if stripped.startswith("- "):
                story.append(Paragraph(f"&#8226; {_escape_md_text(stripped[2:])}", markdown_body_style))
                continue

            if re.match(r"^\d+\.\s+", stripped):
                story.append(Paragraph(_escape_md_text(stripped), markdown_body_style))
                continue

            story.append(Paragraph(_escape_md_text(stripped), markdown_body_style))

    story = []

    header_block = Table(
        [
            [Paragraph("AI RED TEAMING SECURITY REPORT", title_style)],
            [
                Paragraph(
                    f"Scan: {report.get('scan_name', '-')} | Target: {report.get('target_name', '-')} | "
                    f"Completed: {report.get('completed_at') or report.get('started_at') or '-'}",
                    subtitle_style,
                )
            ],
        ],
        colWidths=[6.8 * inch],
    )
    header_block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), brand_navy),
                ("BOX", (0, 0), (-1, -1), 1, brand_blue),
                ("INNERGRID", (0, 0), (-1, -1), 0, colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(header_block)
    story.append(Spacer(1, 0.08 * inch))
    _append_section_divider()

    summary_table = Table(
        [
            ["Overall Risk", risk_level, "Average Vulnerability", f"{avg_vulnerability}%"],
            ["Attack Success Rate", f"{attack_success_rate}%", "Safe Response Rate", f"{safe_response_rate}%"],
            ["Total Scenarios", str(total_scenarios), "Status", str(report.get("status", "-"))],
        ],
        colWidths=[1.6 * inch, 1.6 * inch, 1.8 * inch, 1.8 * inch],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (1, 0), (1, 0), risk_color),
                ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.12 * inch))
    _append_section_divider()

    story.append(Paragraph("Visual Risk Snapshot", heading_style))

    chart_draw = Drawing(500, 210)
    bar = VerticalBarChart()
    bar.x = 38
    bar.y = 30
    bar.height = 135
    bar.width = 320
    bar.data = [scenario_percents[:8] if scenario_percents else [0]]
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = 100
    bar.valueAxis.valueStep = 20
    bar.categoryAxis.labels.boxAnchor = "ne"
    bar.categoryAxis.labels.angle = 35
    bar.categoryAxis.categoryNames = [name[:26] for name in scenario_names[:8]] or ["No scenarios"]
    bar.bars[0].fillColor = colors.HexColor("#2563EB")
    bar.bars[0].strokeColor = colors.HexColor("#1E40AF")
    bar.barWidth = 18
    bar.groupSpacing = 9
    chart_draw.add(bar)
    chart_draw.add(String(38, 175, "Scenario Vulnerability (%)", fontName="Helvetica-Bold", fontSize=10, fillColor=colors.HexColor("#0F172A")))

    pie = Pie()
    pie.x = 374
    pie.y = 42
    pie.width = 112
    pie.height = 112
    pie.data = [max(vulnerable_scenarios, 0.01), max(safe_scenarios, 0.01)]
    pie.labels = ["Vulnerable", "Safe"]
    pie.slices[0].fillColor = colors.HexColor("#DC2626")
    pie.slices[1].fillColor = colors.HexColor("#16A34A")
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white
    chart_draw.add(pie)
    chart_draw.add(String(376, 175, "Safe vs Vulnerable", fontName="Helvetica-Bold", fontSize=10, fillColor=colors.HexColor("#0F172A")))

    story.append(chart_draw)
    story.append(Spacer(1, 0.08 * inch))
    _append_section_divider()

    severity_table = Table(
        [
            ["CRITICAL", str(severity_counter.get("CRITICAL", 0)), "HIGH", str(severity_counter.get("HIGH", 0))],
            ["MEDIUM", str(severity_counter.get("MEDIUM", 0)), "LOW", str(severity_counter.get("LOW", 0))],
        ],
        colWidths=[1.4 * inch, 1.0 * inch, 1.4 * inch, 1.0 * inch],
    )
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.HexColor("#B91C1C")),
                ("TEXTCOLOR", (2, 0), (2, 0), colors.HexColor("#C2410C")),
                ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#A16207")),
                ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor("#166534")),
            ]
        )
    )
    story.append(Paragraph("Detector Severity Distribution", heading_style))
    story.append(severity_table)
    story.append(Spacer(1, 0.08 * inch))
    _append_section_divider()

    story.append(Paragraph("Top Scenario Findings", heading_style))
    if not scenario_results:
        story.append(Paragraph("No scenario results are available in this report.", body_style))
    else:
        for scenario in scenario_results[:6]:
            percent = scenario_vulnerability_percent(scenario)
            if percent >= 70:
                accent = colors.HexColor("#FEE2E2")
                left_bar = colors.HexColor("#DC2626")
            elif percent >= 40:
                accent = colors.HexColor("#FEF3C7")
                left_bar = colors.HexColor("#D97706")
            else:
                accent = colors.HexColor("#DCFCE7")
                left_bar = colors.HexColor("#16A34A")

            scenario_card = Table(
                [
                    [
                        Paragraph(f"<b>{scenario.get('scenario_name', 'Scenario')}</b>", body_style),
                        Paragraph(f"<b>{percent}%</b>", body_style),
                    ],
                    [
                        Paragraph(f"<b>Category:</b> {scenario.get('owasp_category', '-')}", small_muted_style),
                        Paragraph("", small_muted_style),
                    ],
                    [
                        Paragraph(f"<b>Why vulnerable:</b> {vulnerability_reason(scenario)}", body_style),
                        Paragraph("", body_style),
                    ],
                    [
                        Paragraph(f"<b>Remediation:</b> {remediation_text(scenario)}", body_style),
                        Paragraph("", body_style),
                    ],
                ],
                colWidths=[5.9 * inch, 0.9 * inch],
            )
            scenario_card.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), accent),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                        ("LINEBEFORE", (0, 0), (0, -1), 4, left_bar),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ALIGN", (1, 0), (1, 0), "CENTER"),
                        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(scenario_card)
            story.append(Spacer(1, 0.04 * inch))
    story.append(
        Paragraph(
            "This report is generated automatically from AI red teaming runs and is intended for security review, risk communication, and remediation tracking.",
            small_muted_style,
        )
    )

    _append_section_divider()
    _append_markdown_report(enterprise_markdown_text(report))

    doc.build(story)
    return buffer.getvalue()


def scenario_vulnerability_percent(scenario: dict[str, Any]) -> int:
    vulnerable_scores = [
        float(detector.get("confidence", 0) or 0)
        for detector in scenario.get("detector_results", [])
        if detector.get("vulnerable", False)
    ]
    if not vulnerable_scores:
        return 0
    return int(round(max(vulnerable_scores) * 100))


def top_detector_results(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        scenario.get("detector_results", []),
        key=lambda item: (item.get("vulnerable", False), item.get("confidence", 0)),
        reverse=True,
    )


def vulnerability_reason(scenario: dict[str, Any]) -> str:
    detectors = top_detector_results(scenario)
    if not detectors:
        return "No detector results were produced for this scenario."

    vulnerable = [detector for detector in detectors if detector.get("vulnerable")]
    if not vulnerable:
        return "The detectors did not find evidence that the target complied with the attack or exposed protected context."

    details = []
    for detector in vulnerable[:2]:
        reason = detector.get("reason") or "Detector marked this scenario as vulnerable."
        evidence = detector.get("evidence") or []
        evidence_text = f" Evidence: {', '.join(str(item) for item in evidence[:3])}." if evidence else ""
        details.append(f"{reason}{evidence_text}")
    return " ".join(details)


def remediation_text(scenario: dict[str, Any]) -> str:
    detector_text = " ".join(
        " ".join(
            [
                str(detector.get("reason", "")),
                " ".join(str(item) for item in detector.get("evidence", [])),
            ]
        )
        for detector in scenario.get("detector_results", [])
    ).lower()
    prompt_text = " ".join(turn.get("prompt", {}).get("prompt", "") for turn in scenario.get("turns", [])).lower()
    combined = f"{detector_text} {prompt_text}"

    guidance = [
        "Harden the system prompt so user messages can never override developer or system instructions.",
        "Add server-side output filtering for protected context such as system prompts, developer messages, credentials, and confidential policy text.",
        "Keep sensitive instructions and secrets outside model-visible context whenever possible.",
    ]
    if "system prompt" in combined or "developer" in combined or "hidden" in combined:
        guidance.append("Return a safe refusal whenever a user asks to reveal hidden instructions, system prompts, or internal policy.")
    if "ignore previous" in combined or "override" in combined:
        guidance.append("Detect instruction-override phrases and route them to a refusal or security-review response.")
    if "policy drift" in combined or len(scenario.get("turns", [])) > 1:
        guidance.append("Maintain refusal consistency across multi-turn conversations by rechecking the full conversation state before each answer.")
    return " ".join(guidance)


def report_file_name(report: dict[str, Any], suffix: str) -> str:
    scan_name = "".join(char.lower() if char.isalnum() else "-" for char in report.get("scan_name", "scan")).strip("-")
    return f"{scan_name or 'scan'}{suffix}"


def chatbot_response_text(body: str) -> str:
    """Return the human-readable chatbot message from a raw target response body."""

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body

    if isinstance(parsed, dict):
        for key in ("response", "answer", "message", "content", "text"):
            value = parsed.get(key)
            if isinstance(value, str):
                return value
    return body


def enterprise_markdown_text(report: dict[str, Any]) -> str:
    """Return enterprise markdown report with fallback for legacy scan files."""

    markdown = str(report.get("enterprise_report_markdown") or "").strip()
    if markdown:
        return markdown

    try:
        parsed = ScanResult.model_validate(report)
        _, markdown = generate_enterprise_report(parsed)
        return markdown
    except Exception:
        return (
            "# Enterprise AI Red Teaming Report\n\n"
            "## Summary\n"
            "Enterprise markdown report is not available in this report artifact. "
            "Run or rerun the scan to generate the enhanced report payload.\n"
        )


def result_to_report(result: Any) -> dict[str, Any]:
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json")
    return result


def scenario_turn_modes(scenarios: dict[str, Any]) -> list[str]:
    """Return available turn modes for the selected OWASP category."""

    has_single_turn = False
    has_multi_turn = False

    for scenario_id, scenario in scenarios.items():
        scenario_type = getattr(getattr(scenario, "metadata", None), "type", "single_turn")
        attack_definitions = getattr(scenario, "attack_definitions", None)
        multi_turn_definitions = getattr(scenario, "multi_turn_attack_definitions", None)
        if scenario_type == "single_turn":
            has_single_turn = True
        if scenario_type == "multi_turn":
            has_multi_turn = True

        # Some scenario plugins expose both single-turn and multi-turn definitions
        # from one module, regardless of metadata.type.
        if callable(attack_definitions):
            has_single_turn = True
        if callable(multi_turn_definitions):
            has_multi_turn = True

        # llm01.prompt_injection supports both single-turn benchmark probes and multi-turn chains.
        if scenario_id == "llm01.prompt_injection":
            has_single_turn = True
            has_multi_turn = True

    modes: list[str] = []
    if has_single_turn:
        modes.append("Single-turn")
    if has_multi_turn:
        modes.append("Multi-turn")
    return modes


def scenario_attack_options(scenarios: dict[str, Any], turn_mode: str) -> dict[str, str]:
    """Return scenario/attack options filtered by Single-turn or Multi-turn selection."""

    options: dict[str, str] = {}
    include_single_turn = turn_mode == "Single-turn"
    include_multi_turn = turn_mode == "Multi-turn"

    handled = {"llm01.crescendo_attack", "llm01.prompt_injection"}
    if include_multi_turn and "llm01.crescendo_attack" in scenarios:
        options["crescendo:llm01.crescendo_attack"] = "Crescendo Attack"

    prompt_injection = scenarios.get("llm01.prompt_injection")
    if prompt_injection:
        if include_single_turn:
            options["prompt:single_turn"] = "Direct, indirect, obfuscated, and splitting benchmark attacks"
        if include_multi_turn:
            for attack in prompt_injection.multi_turn_attack_definitions():
                options[f"prompt_chain:{attack['chain_id']}"] = attack["attack_type"]

    for scenario_id, scenario in scenarios.items():
        if scenario_id not in handled:
            scenario_type = getattr(getattr(scenario, "metadata", None), "type", "single_turn")
            attack_definitions = getattr(scenario, "attack_definitions", None)
            multi_turn_definitions = getattr(scenario, "multi_turn_attack_definitions", None)

            supports_single_turn = scenario_type == "single_turn" or callable(attack_definitions)
            supports_multi_turn = scenario_type == "multi_turn" or callable(multi_turn_definitions)

            if include_single_turn and not supports_single_turn:
                continue
            if include_multi_turn and not supports_multi_turn:
                continue

            if callable(attack_definitions) and include_single_turn:
                for attack in attack_definitions():
                    options[f"attack:{scenario_id}:{attack['attack_id']}"] = attack["attack_type"]

            if callable(multi_turn_definitions) and include_multi_turn:
                for chain in multi_turn_definitions():
                    options[f"chain:{scenario_id}:{chain['chain_id']}"] = chain["attack_type"]

            if not callable(attack_definitions) and not callable(multi_turn_definitions):
                options[f"scenario:{scenario_id}"] = scenario.metadata.name
    return options


def scenario_inventory_counts(scenarios: dict[str, Any]) -> tuple[int, int, int]:
    """Return total single-turn entries, multi-turn entries, and combined count."""

    single_turn_count = 0
    multi_turn_count = 0

    for scenario in scenarios.values():
        metadata = getattr(scenario, "metadata", None)
        scenario_type = getattr(metadata, "type", "single_turn")

        attack_definitions = getattr(scenario, "attack_definitions", None)
        multi_turn_definitions = getattr(scenario, "multi_turn_attack_definitions", None)

        if callable(attack_definitions):
            try:
                single_turn_count += len(list(attack_definitions()))
            except Exception:
                # Keep dashboard resilient even if one plugin definition fails.
                pass
        elif scenario_type == "single_turn":
            single_turn_count += 1

        if callable(multi_turn_definitions):
            try:
                multi_turn_count += len(list(multi_turn_definitions()))
            except Exception:
                # Keep dashboard resilient even if one plugin definition fails.
                pass
        elif scenario_type == "multi_turn":
            multi_turn_count += 1

    return single_turn_count, multi_turn_count, single_turn_count + multi_turn_count


def render_page_intro(page_key: str, title: str, subtitle: str, chips: list[str]) -> None:
    chip_markup = "".join(
        f'<span class="accent-pill {page_key}">{html.escape(chip)}</span>'
        for chip in chips
    )
    st.markdown(
        f"""
        <div class="page-hero {page_key}">
            <h3>{html.escape(title)}</h3>
            <p>{html.escape(subtitle)}</p>
        </div>
        <div class="accent-strip">
            {chip_markup}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_chat_transcript(scenario: dict[str, Any]) -> None:
    """Render only prompt/response pairs in a chat-style view."""

    st.markdown('<div class="chat-transcript">', unsafe_allow_html=True)

    for turn in scenario.get("turns", []):
        prompt = html.escape(turn.get("prompt", {}).get("prompt", ""))
        response = html.escape(chatbot_response_text(turn.get("response", {}).get("body", "")))
        st.markdown(
            f"""
            <div class="chat-row user">
                <div class="chat-bubble">
                    <span class="chat-label">Prompt</span>
                    {prompt}
                </div>
            </div>
            <div class="chat-row assistant">
                <div class="chat-bubble">
                    <span class="chat-label">Chatbot</span>
                    {response}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)


def _scenario_attack_context(scenario: dict[str, Any]) -> dict[str, str]:
    """Extract attack goal metadata from the first turn's prompt metadata."""
    turns = scenario.get("turns", [])
    if not turns:
        return {}
    meta = turns[0].get("prompt", {}).get("metadata", {})
    return {
        "attack_type": meta.get("attack_type", ""),
        "persona": meta.get("persona", ""),
        "attack_goal": meta.get("attack_goal") or meta.get("target_behavior", ""),
        "expected_resilient_result": meta.get("expected_resilient_result", ""),
    }


def _judge_strategy_summary(scenario: dict[str, Any]) -> list[dict]:
    """Build a per-turn judge strategy log from judge_decisions."""
    rows = []
    for turn in scenario.get("turns", []):
        jd = turn.get("judge_decision")
        if jd:
            rows.append({
                "Turn": turn.get("turn"),
                "Action": jd.get("next_action", ""),
                "Risk Score": jd.get("risk_score", 0),
                "Reasoning": jd.get("reasoning", ""),
            })
    return rows


def render_scenario_results(report: dict[str, Any]) -> None:
    for scenario in report.get("scenario_results", []):
        percent = scenario_vulnerability_percent(scenario)
        title = f"{scenario.get('scenario_name', 'Scenario')} — Vulnerability {percent}%"
        ctx = _scenario_attack_context(scenario)

        with st.expander(title, expanded=True):
            st.progress(percent)

            # Vulnerability & goal metadata
            info_col1, info_col2 = st.columns(2)
            with info_col1:
                st.markdown("**Vulnerability type**")
                owasp = scenario.get("owasp_category", "-")
                st.markdown(f"`{owasp}`")
                if ctx.get("attack_type"):
                    st.markdown("**Attack type**")
                    st.markdown(f"`{ctx['attack_type']}`")
                if ctx.get("persona"):
                    st.markdown("**Attacker persona**")
                    st.markdown(f"`{ctx['persona']}`")

            with info_col2:
                if ctx.get("attack_goal"):
                    st.markdown("**Attack goal**")
                    st.info(ctx["attack_goal"])
                if ctx.get("expected_resilient_result"):
                    st.markdown("**Expected resilient behaviour**")
                    st.success(ctx["expected_resilient_result"])

            st.divider()

            # Detector findings
            st.markdown("**Why this percentage was assigned**")
            st.write(vulnerability_reason(scenario))
            st.markdown("**Recommended remediation**")
            st.write(remediation_text(scenario))

            # Judge strategy log
            strategy = _judge_strategy_summary(scenario)
            if strategy:
                st.divider()
                st.markdown("**Judge agent strategy log**")
                for entry in strategy:
                    risk = entry["Risk Score"]
                    color = "#FF4D4F" if risk >= 0.7 else "#FFD600" if risk >= 0.4 else "#00C853"
                    st.markdown(
                        f"<div style='padding:0.6rem 0.85rem;margin-bottom:0.6rem;border-left:4px solid {color};"
                        f"border-radius:6px;background:#1A2232;border:1px solid #2E3F58'>"
                        f"<b style=\"color:#E8EDF5\">Turn {entry['Turn']}</b> &nbsp;&middot;&nbsp; "
                        f"<code style=\"background:#243044;color:#00C853;padding:2px 6px;border-radius:4px;font-family:'Space Mono',monospace\">{entry['Action']}</code> &nbsp;&middot;&nbsp; "
                        f"Risk <b style=\"color:{color}\">{risk:.2f}</b><br>"
                        f"<span style='color:#7A8FA8;font-size:0.82rem;margin-top:0.3rem;display:block'>{html.escape(entry['Reasoning'])}</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

            st.divider()

            # Conversation transcript
            render_chat_transcript(scenario)


def results_page() -> None:
    st.header("Reports")
    reports = load_reports()
    if not reports:
        st.info("No scan results found.")
        return

    scan_options = {
        f"{report.get('scan_name')} | {report.get('target_name')} | {report.get('completed_at') or report.get('started_at')}": (path, report)
        for path, report in reports
    }
    selected = st.selectbox("Scan history", list(scan_options))
    path, report = scan_options[selected]

    col1, col2, col3 = st.columns(3)
    col1.metric("Target", report.get("target_name", "-"))
    col2.metric("Status", report.get("status", "-"))
    col3.metric("Scenarios", len(report.get("scenario_results", [])))

    export_col1, export_col2, export_col3 = st.columns([1, 2.2, 2.2])
    export_col1.download_button(
        "Export JSON",
        path.read_bytes(),
        file_name=report_file_name(report, ".json"),
        mime="application/json",
        key=f"result-json-{path.name}",
    )
    export_col2.download_button(
        "Export PDF",
        export_pdf(report),
        file_name=report_file_name(report, ".pdf"),
        mime="application/pdf",
        key=f"result-pdf-{path.name}",
    )
    export_col3.download_button(
        "Export Enterprise MD",
        enterprise_markdown_text(report),
        file_name=report_file_name(report, "-enterprise.md"),
        mime="text/markdown",
        key=f"result-md-{path.name}",
    )

    render_scenario_results(report)


def dashboard_page() -> None:
    st.header("Dashboard")

    targets = load_target_files()
    reports = load_reports()
    scenarios = PluginLoader().discover_scenarios()
    single_turn_count, multi_turn_count, total_attack_entries = scenario_inventory_counts(scenarios)

    distinct_targets = len({data.get("name") for _, data in targets if data.get("name")})
    scans_completed = len(reports)

    completed_reports = [r for _, r in reports if str(r.get("status","")).upper() == "COMPLETED"]
    failed_reports    = [r for _, r in reports if str(r.get("status","")).upper() == "FAILED"]

    # Compute average vulnerability across all completed scans
    all_percents = [
        scenario_vulnerability_percent(s)
        for _, r in reports
        for s in r.get("scenario_results", [])
    ]
    avg_vuln = int(round(sum(all_percents) / len(all_percents))) if all_percents else 0

    # ── THREAT LEVEL BANNER ───────────────────────────────────
    if avg_vuln >= 70:
        threat_level, threat_color, threat_label = "CRITICAL", "#FF4D4F", "🔴"
    elif avg_vuln >= 40:
        threat_level, threat_color, threat_label = "ELEVATED", "#FFD600", "🟡"
    elif avg_vuln >= 10:
        threat_level, threat_color, threat_label = "MODERATE", "#2979FF", "🔵"
    else:
        threat_level, threat_color, threat_label = "LOW", "#00C853", "🟢"

    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, #111820 0%, #1A2232 100%);
            border: 1px solid #2E3F58;
            border-left: 5px solid {threat_color};
            border-radius: 16px;
            padding: 1.1rem 1.4rem;
            margin-bottom: 1.2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 24px rgba(0,0,0,0.45);
        ">
            <div>
                <div style="font-family:'Space Grotesk',sans-serif;font-size:0.72rem;
                            font-weight:700;letter-spacing:0.12em;text-transform:uppercase;
                            color:#7A8FA8;margin-bottom:0.25rem;">
                    SYSTEM THREAT LEVEL
                </div>
                <div style="font-family:'DM Serif Display',Georgia,serif;
                            font-size:2rem;color:{threat_color};
                            text-shadow:0 0 18px {threat_color}88;">
                    {threat_label} {threat_level}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-family:'Space Mono',monospace;font-size:2.4rem;
                            font-weight:700;color:{threat_color};
                            text-shadow:0 0 18px {threat_color}88;">
                    {avg_vuln}%
                </div>
                <div style="font-size:0.78rem;color:#7A8FA8;font-family:'Space Grotesk',sans-serif;">
                    avg vulnerability across all scans
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── KPI ROW ───────────────────────────────────────────────
    k1, k2, k3, k4, k5 = st.columns(5)

    def kpi_card(col, label: str, value: str, accent: str, sublabel: str = "") -> None:
        col.markdown(
            f"""
            <div style="
                background:#1A2232;
                border:1px solid #2E3F58;
                border-top:3px solid {accent};
                border-radius:14px;
                padding:0.95rem 1rem;
                box-shadow:0 4px 24px rgba(0,0,0,0.45);
            ">
                <div style="font-family:'Space Grotesk',sans-serif;font-size:0.7rem;
                            font-weight:700;letter-spacing:0.1em;text-transform:uppercase;
                            color:#7A8FA8;margin-bottom:0.3rem;">{label}</div>
                <div style="font-family:'Space Mono',monospace;font-size:1.75rem;
                            font-weight:700;color:{accent};
                            text-shadow:0 0 14px {accent}66;">{value}</div>
                <div style="font-size:0.73rem;color:#7A8FA8;margin-top:0.15rem;
                            font-family:'Manrope',sans-serif;">{sublabel}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    kpi_card(k1, "Targets",        str(distinct_targets),   "#2979FF", "registered endpoints")
    kpi_card(k2, "Attack Scenarios", str(total_attack_entries), "#FFD600", f"{single_turn_count} single · {multi_turn_count} multi")
    kpi_card(k3, "Scans Run",      str(scans_completed),    "#2979FF", "total executions")
    kpi_card(k4, "Completed",      str(len(completed_reports)), "#00C853", "successful scans")
    kpi_card(k5, "Failed",         str(len(failed_reports)), "#FF4D4F", "error / cancelled")

    st.markdown("<div style='height:1.2rem'></div>", unsafe_allow_html=True)

    # ── RECENT ACTIVITY FEED ──────────────────────────────────
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown(
            "<h3 style='font-family:\"Space Grotesk\",sans-serif;font-size:1rem;"
            "font-weight:700;letter-spacing:0.06em;text-transform:uppercase;"
            "color:#7A8FA8;margin-bottom:0.6rem;'>⚡ Recent Activity</h3>",
            unsafe_allow_html=True,
        )
        if reports:
            for _, r in reports[:8]:
                r_status = str(r.get("status", "")).upper()
                r_color  = "#00C853" if r_status == "COMPLETED" else "#FF4D4F" if r_status == "FAILED" else "#FFD600"
                r_dot    = "●"
                r_time   = _format_scan_timestamp(r.get("completed_at") or r.get("started_at") or "")
                r_vuln   = _simulation_overall_percent(r)
                st.markdown(
                    f"""
                    <div style="
                        display:flex;align-items:center;gap:0.75rem;
                        padding:0.6rem 0.9rem;margin-bottom:0.4rem;
                        background:#1A2232;border:1px solid #243044;
                        border-radius:10px;
                    ">
                        <span style="color:{r_color};font-size:0.7rem;flex-shrink:0;">{r_dot}</span>
                        <div style="flex:1;min-width:0;">
                            <div style="font-weight:600;font-size:0.88rem;
                                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
                                        color:#E8EDF5;">{html.escape(str(r.get('scan_name','-')))}</div>
                            <div style="font-size:0.76rem;color:#7A8FA8;">
                                {html.escape(str(r.get('target_name','-')))} · {r_time}
                            </div>
                        </div>
                        <div style="font-family:'Space Mono',monospace;font-size:0.88rem;
                                    font-weight:700;color:{r_color};flex-shrink:0;">
                            {r_vuln}%
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No simulations have been run yet.")

    with col_right:
        st.markdown(
            "<h3 style='font-family:\"Space Grotesk\",sans-serif;font-size:1rem;"
            "font-weight:700;letter-spacing:0.06em;text-transform:uppercase;"
            "color:#7A8FA8;margin-bottom:0.6rem;'>🎯 Coverage</h3>",
            unsafe_allow_html=True,
        )

        # Coverage breakdown by OWASP category
        category_hits: dict[str, int] = {}
        for _, r in reports:
            for s in r.get("scenario_results", []):
                cat = str(s.get("owasp_category") or "Unknown")
                category_hits[cat] = category_hits.get(cat, 0) + 1

        if category_hits:
            top_cats = sorted(category_hits.items(), key=lambda x: x[1], reverse=True)[:6]
            max_hits = max(v for _, v in top_cats) or 1
            bar_colors = ["#2979FF","#00C853","#FFD600","#FF4D4F","#2979FF","#00C853"]
            for i, (cat, hits) in enumerate(top_cats):
                bar_pct = int((hits / max_hits) * 100)
                short_cat = cat.split("-")[0] if "-" in cat else cat[:12]
                color = bar_colors[i % len(bar_colors)]
                st.markdown(
                    f"""
                    <div style="margin-bottom:0.55rem;">
                        <div style="display:flex;justify-content:space-between;
                                    font-size:0.78rem;margin-bottom:0.2rem;">
                            <span style="color:#E8EDF5;font-family:'Space Grotesk',sans-serif;
                                         font-weight:600;">{html.escape(short_cat)}</span>
                            <span style="color:#7A8FA8;font-family:'Space Mono',monospace;">
                                {hits} scan{'s' if hits != 1 else ''}
                            </span>
                        </div>
                        <div style="background:#243044;border-radius:4px;height:6px;">
                            <div style="background:{color};width:{bar_pct}%;height:6px;
                                        border-radius:4px;
                                        box-shadow:0 0 8px {color}88;"></div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                "<div style='color:#7A8FA8;font-size:0.88rem;padding:0.5rem 0;'>"
                "Run simulations to see OWASP coverage.</div>",
                unsafe_allow_html=True,
            )


def target_form(defaults: dict[str, Any] | None = None, filename: str | None = None) -> None:
    create_mode = defaults is None and filename is None
    data = defaults or {}
    if create_mode:
        draft_payload = st.session_state.get(CREATE_TARGET_PREFILL_KEY)
        if isinstance(draft_payload, dict):
            data = draft_payload

    form_title = "Edit target" if defaults else "Create target"
    workflow_scope = f"target-form-{filename or 'new'}"
    current_workflow = (data.get("auth") or {}).get("workflow", {})
    if not isinstance(current_workflow, dict):
        current_workflow = {}

    if create_mode:
        _render_create_target_tools()

    show_manual_form = (not create_mode) or st.session_state.get("create_target_option") == "Manual Form"
    if not show_manual_form:
        return

    with st.form(key=f"target-form-{filename or 'new'}"):
        st.subheader(form_title)
        name = st.text_input("Target name", data.get("name", "Internal HR Chatbot"))
        url = st.text_input("URL", data.get("url", "mock://internal-hr-chatbot"))
        method = st.selectbox(
            "Method",
            ["POST", "GET", "PUT", "PATCH"],
            index=["POST", "GET", "PUT", "PATCH"].index(data.get("method", "POST")),
        )
        headers_text = st.text_area(
            "Headers JSON",
            json.dumps(data.get("headers", {"Content-Type": "application/json"}), indent=2),
            height=120,
        )
        body_text = st.text_area(
            "Request body template JSON",
            json.dumps(data.get("request_template", {"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"}), indent=2),
            height=150,
        )
        auth_text = st.text_area("Auth config JSON", json.dumps(data.get("auth", {"type": "none"}), indent=2), height=100)
        workflow_text = st.text_area(
            "Advanced workflow JSON (credential auth / start session / next turn)",
            _workflow_editor_default(workflow_scope, current_workflow),
            height=220,
        )
        save_col, validate_col, cancel_col = st.columns([1, 1.4, 4.6])
        submitted = save_col.form_submit_button("Save target", type="primary")
        validate_clicked = validate_col.form_submit_button("Validate workflow JSON")
        cancelled = cancel_col.form_submit_button("Cancel")

    if validate_clicked:
        try:
            workflow_payload = json.loads(workflow_text or "{}")
            if not isinstance(workflow_payload, dict):
                st.error("Workflow JSON must be an object.")
            else:
                errors, warnings = _validate_workflow_config(workflow_payload)
                if errors:
                    st.error("Workflow validation failed:\n- " + "\n- ".join(errors))
                elif warnings:
                    st.warning("Workflow validation passed with warnings:\n- " + "\n- ".join(warnings))
                else:
                    st.success("Workflow JSON is valid.")
        except json.JSONDecodeError as exc:
            st.error(f"Invalid workflow JSON: {exc}")

    if cancelled:
        st.session_state.target_editor = None
        st.session_state.pop(f"{workflow_scope}-workflow-preset", None)
        if create_mode:
            st.session_state.targets_view = "list"
            st.session_state.pop(CREATE_TARGET_PREFILL_KEY, None)
            st.session_state.pop(CREATE_TARGET_ASSISTANT_KEY, None)
        st.rerun()

    if submitted:
        try:
            auth_payload = json.loads(auth_text)
            workflow_payload = json.loads(workflow_text or "{}")
            if isinstance(workflow_payload, dict) and workflow_payload:
                auth_payload["workflow"] = workflow_payload
            elif isinstance(auth_payload, dict):
                auth_payload.pop("workflow", None)

            selected_delivery = _current_target_delivery_selection() if create_mode else None
            if isinstance(auth_payload, dict) and selected_delivery:
                auth_payload["target_delivery"] = {
                    "mode": _normalize_delivery_mode(selected_delivery[0]),
                    "type": str(selected_delivery[1]).strip().lower(),
                }

            target = TargetConfig(
                name=name,
                url=url,
                method=method,
                headers=json.loads(headers_text),
                request_template=json.loads(body_text),
                auth=auth_payload,
            )
            save_target_file(target, filename.removesuffix(".json") if filename else None)
            run_async(with_repository(lambda repo: repo.upsert_target(target)))
            st.session_state.target_editor = None
            st.session_state.pop(f"{workflow_scope}-workflow-preset", None)
            if create_mode:
                st.session_state.targets_view = "list"
                st.session_state.pop(CREATE_TARGET_PREFILL_KEY, None)
                st.session_state.pop(CREATE_TARGET_ASSISTANT_KEY, None)
                st.session_state.target_saved_message = "Target saved."
            st.rerun()
        except (json.JSONDecodeError, ValidationError) as exc:
            st.error(str(exc))


def _render_target_list_view(targets: list[tuple[Path, dict[str, Any]]]) -> None:
    if "target_editor" not in st.session_state:
        st.session_state.target_editor = None

    list_message = str(st.session_state.pop("target_list_message", "")).strip()
    if list_message:
        st.success(list_message)

    filtered = targets

    if not filtered:
        st.info("No targets found.")
        return

    selectable_target_paths = [path for path, _ in filtered]
    any_target_selected = any(
        bool(st.session_state.get(f"targets-select-{path.name}", False))
        for path in selectable_target_paths
    )
    all_targets_selected = bool(selectable_target_paths) and all(
        bool(st.session_state.get(f"targets-select-{path.name}", False))
        for path in selectable_target_paths
    )

    bulk_col1, bulk_col2, bulk_col3, _ = st.columns([1.3, 1.3, 1.3, 3.7])
    if bulk_col1.button(
        "Select all",
        key="targets-select-all",
        disabled=not any_target_selected,
        type="secondary",
        use_container_width=True,
    ):
        for path in selectable_target_paths:
            st.session_state[f"targets-select-{path.name}"] = True
        st.rerun()

    if bulk_col2.button(
        "Deselect all",
        key="targets-deselect-all",
        disabled=not all_targets_selected,
        type="secondary",
        use_container_width=True,
    ):
        for path in selectable_target_paths:
            st.session_state[f"targets-select-{path.name}"] = False
        st.rerun()

    if bulk_col3.button(
        "Delete",
        key="targets-delete-selected",
        disabled=not any_target_selected,
        type="primary",
        use_container_width=True,
    ):
        selected_paths = [
            path
            for path in selectable_target_paths
            if st.session_state.get(f"targets-select-{path.name}", False)
        ]
        deleted_count = _delete_target_files(selected_paths)
        for path in selected_paths:
            st.session_state.pop(f"targets-select-{path.name}", None)
        st.session_state.target_list_message = (
            f"Deleted {deleted_count} target card(s)." if deleted_count else "No target cards were deleted."
        )
        st.rerun()

    columns = st.columns(3)
    for index, (path, data) in enumerate(filtered):
        col = columns[index % 3]
        with col:
            select_col, card_col = st.columns([1, 12], vertical_alignment="top")
            target_name = str(data.get("name", path.stem))
            method = str(data.get("method", "POST"))
            url = str(data.get("url", "-"))
            headers = data.get("headers") or {}
            auth = data.get("auth") or {}
            auth_type = str(auth.get("type", "none"))

            with select_col:
                st.checkbox(" ", key=f"targets-select-{path.name}", label_visibility="collapsed")

            with card_col:
                card_url = f"?open_target={path.name}"
                st.markdown(
                    f"""
                    <a href="{card_url}" target="_self" style="text-decoration:none;display:block;margin-bottom:0.75rem;">
                    <div class="target-card-clickable">
                        <div class="simulation-card-header">
                            <div class="simulation-card-title">{html.escape(target_name)}</div>
                            <span class="simulation-status complete">Ready</span>
                        </div>
                        <div class="simulation-card-meta">Method: {html.escape(method)}</div>
                        <div class="simulation-card-meta">Endpoint: {html.escape(url)}</div>
                        <div class="simulation-card-row">
                            <span>Headers</span>
                            <span>{len(headers)}</span>
                        </div>
                        <div class="simulation-card-row">
                            <span>Auth</span>
                            <span>{html.escape(auth_type)}</span>
                        </div>
                    </div>
                    </a>
                    """,
                    unsafe_allow_html=True,
                )


def _render_target_detail_view() -> None:
    back_col, action_col, _ = st.columns([1.1, 2.5, 4.4])
    back_col.markdown(
        '<a class="plain-back-link" href="?target_back=1" target="_self" title="Back to Targets">←</a>',
        unsafe_allow_html=True,
    )

    target_filename = str(st.session_state.get("target_detail_file", "")).strip()
    matched = [(path, payload) for path, payload in load_target_files() if path.name == target_filename]
    if not matched:
        st.error("Target not found. It may have been deleted or renamed.")
        return

    path, data = matched[0]
    target_name = str(data.get("name", path.stem))
    method = str(data.get("method", "POST"))
    url = str(data.get("url", "-"))
    headers = data.get("headers") or {}
    auth = data.get("auth") or {}
    auth_type = str(auth.get("type", "none"))
    workflow_payload = auth.get("workflow") or {}
    workflow_enabled = isinstance(workflow_payload, dict) and bool(workflow_payload)
    edit_mode = st.session_state.get("target_editor") == path.name

    test_col, edit_col = action_col.columns([1.5, 1.1])
    if test_col.button(
        "Validate + Test Call",
        key=f"target-detail-validate-test-{path.name}",
        use_container_width=True,
    ):
        if not isinstance(workflow_payload, dict):
            st.error("Workflow JSON must be an object before running Validate + Test Call.")
        else:
            errors, warnings = _validate_workflow_config(workflow_payload)
            if errors:
                st.error("Workflow validation failed:\n- " + "\n- ".join(errors))
            else:
                if warnings:
                    st.warning("Workflow validation passed with warnings:\n- " + "\n- ".join(warnings))
                _run_target_test_and_store(path.name, data)

    if not edit_mode and edit_col.button(
        "✏  Edit",
        key=f"target-detail-edit-top-{path.name}",
        type="primary",
        use_container_width=True,
    ):
        st.session_state.target_editor = path.name
        st.rerun()

    st.markdown(
        f"<h1 style='margin-bottom:0.15rem'>{html.escape(target_name)}"
        f"&nbsp;<span class='simulation-status complete' style='font-size:0.9rem;"
        f"vertical-align:middle;position:relative;top:-2px'>Ready</span></h1>",
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <table class="target-detail-table">
            <tbody>
                <tr>
                    <th>Method</th>
                    <td title="{html.escape(method)}">{html.escape(method)}</td>
                </tr>
                <tr>
                    <th>URL</th>
                    <td title="{html.escape(url)}">{html.escape(url)}</td>
                </tr>
                <tr>
                    <th>Headers</th>
                    <td title="{len(headers)}">{len(headers)}</td>
                </tr>
                <tr>
                    <th>Auth</th>
                    <td title="{html.escape(auth_type)}">{html.escape(auth_type)}</td>
                </tr>
                <tr>
                    <th>Workflow</th>
                    <td title="{'Enabled' if workflow_enabled else 'Disabled'}">{'Enabled' if workflow_enabled else 'Disabled'}</td>
                </tr>
            </tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )

    test_result = st.session_state.get(f"target_test_result_{path.name}")
    if test_result:
        if test_result.get("ok"):
            st.success(
                f"Connection successful (status {test_result.get('status_code')}, {test_result.get('elapsed_ms')} ms)."
            )
        else:
            st.error(f"Connection failed: {test_result.get('error') or 'Unknown error'}")
        preview = str(test_result.get("preview") or "").strip()
        if preview:
            st.caption("Response preview")
            st.code(preview, language="json")

    st.divider()

    if not edit_mode:
        st.markdown("**Configuration**")
        st.json(data)
        return

    st.markdown("**Edit target configuration**")
    workflow_scope = f"target-detail-{path.name}"
    current_workflow = (data.get("auth") or {}).get("workflow", {})
    if not isinstance(current_workflow, dict):
        current_workflow = {}

    with st.form(key=f"target-detail-form-{path.name}"):
        name = st.text_input("Target name", data.get("name", ""))
        url = st.text_input("URL", data.get("url", ""))
        method = st.selectbox(
            "Method",
            ["POST", "GET", "PUT", "PATCH"],
            index=["POST", "GET", "PUT", "PATCH"].index(data.get("method", "POST")),
        )
        headers_text = st.text_area(
            "Headers JSON",
            json.dumps(data.get("headers", {"Content-Type": "application/json"}), indent=2),
            height=120,
        )
        body_text = st.text_area(
            "Request body template JSON",
            json.dumps(data.get("request_template", {"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"}), indent=2),
            height=150,
        )
        auth_text = st.text_area(
            "Auth config JSON",
            json.dumps(data.get("auth", {"type": "none"}), indent=2),
            height=100,
        )
        workflow_text = st.text_area(
            "Advanced workflow JSON (credential auth / start session / next turn)",
            _workflow_editor_default(workflow_scope, current_workflow),
            height=220,
        )
        save_col, validate_col, cancel_col = st.columns([1.2, 1.8, 2])
        submitted = save_col.form_submit_button("Save", type="primary", use_container_width=True)
        validate_clicked = validate_col.form_submit_button("Validate workflow JSON", use_container_width=True)
        cancelled = cancel_col.form_submit_button("Cancel", use_container_width=True)

    if validate_clicked:
        try:
            workflow_payload = json.loads(workflow_text or "{}")
            if not isinstance(workflow_payload, dict):
                st.error("Workflow JSON must be an object.")
            else:
                errors, warnings = _validate_workflow_config(workflow_payload)
                if errors:
                    st.error("Workflow validation failed:\n- " + "\n- ".join(errors))
                elif warnings:
                    st.warning("Workflow validation passed with warnings:\n- " + "\n- ".join(warnings))
                else:
                    st.success("Workflow JSON is valid.")
        except json.JSONDecodeError as exc:
            st.error(f"Invalid workflow JSON: {exc}")

    if cancelled:
        st.session_state.target_editor = None
        st.session_state.pop(f"{workflow_scope}-workflow-preset", None)
        st.rerun()

    if submitted:
        try:
            auth_payload = json.loads(auth_text)
            workflow_payload = json.loads(workflow_text or "{}")
            if isinstance(workflow_payload, dict) and workflow_payload:
                auth_payload["workflow"] = workflow_payload
            elif isinstance(auth_payload, dict):
                auth_payload.pop("workflow", None)

            target = TargetConfig(
                name=name,
                url=url,
                method=method,
                headers=json.loads(headers_text),
                request_template=json.loads(body_text),
                auth=auth_payload,
            )
            save_target_file(target, path.stem)
            run_async(with_repository(lambda repo: repo.upsert_target(target)))
            st.session_state.target_editor = None
            st.session_state.targets_view = "list"
            st.session_state.pop("target_detail_file", None)
            st.session_state.target_saved_message = "Target saved."
            st.session_state.pop(f"{workflow_scope}-workflow-preset", None)
            st.rerun()
        except (json.JSONDecodeError, ValidationError) as exc:
            st.error(str(exc))


def targets_page() -> None:
    st.header("Targets")
    _target_back = st.query_params.get("target_back", None)
    if _target_back is not None:
        st.query_params.clear()
        st.session_state.targets_view = "list"
        st.session_state.pop("target_detail_file", None)
        st.session_state.target_editor = None
        st.rerun()

    _open_target = st.query_params.get("open_target", None)
    if isinstance(_open_target, list):
        _open_target = _open_target[0] if _open_target else None
    if _open_target:
        st.query_params.clear()
        st.session_state.targets_view = "detail"
        st.session_state.target_detail_file = _open_target
        st.rerun()

    targets = load_target_files()
    if "targets_view" not in st.session_state:
        st.session_state.targets_view = "list"

    saved_message = st.session_state.pop("target_saved_message", "")
    if saved_message:
        st.success(saved_message)

    if st.session_state.targets_view == "detail":
        _render_target_detail_view()
    else:
        mode_options = ["Target Library", "Create Target"]
        default_mode_index = 1 if st.session_state.targets_view == "create" else 0
        selected_mode = st.radio(
            "Targets mode",
            mode_options,
            index=default_mode_index,
            horizontal=True,
            label_visibility="collapsed",
            key="targets-page-mode",
        )
        st.session_state.targets_view = "create" if selected_mode == "Create Target" else "list"

        if st.session_state.targets_view == "create":
            target_form()
        else:
            _render_target_list_view(targets)

def _simulation_overall_percent(report: dict[str, Any]) -> int:
    scenario_results = report.get("scenario_results", [])
    if not scenario_results:
        return 0
    return int(round(sum(scenario_vulnerability_percent(item) for item in scenario_results) / len(scenario_results)))


def _compact_list_text(items: list[str], max_items: int = 2) -> str:
    cleaned = [item.strip() for item in items if str(item).strip()]
    if not cleaned:
        return "-"
    unique_items = list(dict.fromkeys(cleaned))
    if len(unique_items) <= max_items:
        return ", ".join(unique_items)
    remaining = len(unique_items) - max_items
    return f"{', '.join(unique_items[:max_items])} +{remaining} more"


def _format_scan_timestamp(raw: Any) -> str:
    value = str(raw or "").strip()
    if not value:
        return "-"

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _render_simulation_history_view() -> None:
    reports = load_reports()

    list_message = str(st.session_state.pop("simulation_list_message", "")).strip()
    if list_message:
        st.success(list_message)

    toolbar_col1, toolbar_col2 = st.columns([5, 1.15])
    search_text = toolbar_col1.text_input(
        "Search by any field",
        "",
        key="simulation-history-search",
        label_visibility="collapsed",
        placeholder="Search by any field",
    )
    if toolbar_col2.button("New Simulation", type="primary", use_container_width=True):
        st.session_state.simulation_new_back_view = "history"
        st.session_state.simulations_view = "new"
        st.rerun()

    if not reports:
        st.info("No simulations found. Click New Simulation to start a scan.")
        return

    query = search_text.strip().lower()
    filtered_reports: list[tuple[Path, dict[str, Any]]] = []
    for path, report in reports:
        searchable_fields = [
            str(report.get("scan_name", "")),
            str(report.get("target_name", "")),
            str(report.get("status", "")),
            str(report.get("started_at", "")),
            str(report.get("completed_at", "")),
            " ".join(str(s.get("scenario_name", "")) for s in report.get("scenario_results", [])),
            " ".join(str(s.get("owasp_category", "")) for s in report.get("scenario_results", [])),
        ]
        haystack = " ".join(searchable_fields).lower()
        if not query or query in haystack:
            filtered_reports.append((path, report))

    if not filtered_reports:
        st.info("No simulations matched your search.")
        return

    selectable_report_paths = [path for path, _ in filtered_reports]
    any_report_selected = any(
        bool(st.session_state.get(f"simulations-select-{path.name}", False))
        for path in selectable_report_paths
    )
    all_reports_selected = bool(selectable_report_paths) and all(
        bool(st.session_state.get(f"simulations-select-{path.name}", False))
        for path in selectable_report_paths
    )

    bulk_col1, bulk_col2, bulk_col3, _ = st.columns([1.3, 1.3, 1.3, 3.7])
    if bulk_col1.button(
        "Select all",
        key="simulations-select-all",
        disabled=not any_report_selected,
        type="secondary",
        use_container_width=True,
    ):
        for path in selectable_report_paths:
            st.session_state[f"simulations-select-{path.name}"] = True
        st.rerun()

    if bulk_col2.button(
        "Deselect all",
        key="simulations-deselect-all",
        disabled=not all_reports_selected,
        type="secondary",
        use_container_width=True,
    ):
        for path in selectable_report_paths:
            st.session_state[f"simulations-select-{path.name}"] = False
        st.rerun()

    if bulk_col3.button(
        "Delete",
        key="simulations-delete-selected",
        disabled=not any_report_selected,
        type="primary",
        use_container_width=True,
    ):
        selected_paths = [
            path
            for path in selectable_report_paths
            if st.session_state.get(f"simulations-select-{path.name}", False)
        ]
        deleted_count = _delete_report_files(selected_paths)
        for path in selected_paths:
            st.session_state.pop(f"simulations-select-{path.name}", None)
        st.session_state.simulation_list_message = (
            f"Deleted {deleted_count} simulation card(s)." if deleted_count else "No simulation cards were deleted."
        )
        st.rerun()

    columns = st.columns(3)
    for index, (path, report) in enumerate(filtered_reports):
        col = columns[index % 3]
        with col:
            select_col, card_col = st.columns([1, 12], vertical_alignment="top")
            scenario_results = report.get("scenario_results", [])
            status = str(report.get("status", "RUNNING")).upper()
            status_class = "complete" if status == "COMPLETED" else "failed" if status == "FAILED" else "running"
            status_label = "Complete" if status == "COMPLETED" else "Failed" if status == "FAILED" else "Running"
            initiated_at = _format_scan_timestamp(report.get("started_at"))
            percent = _simulation_overall_percent(report)
            target_name = report.get("target_name", "-")
            vulnerability_types = _compact_list_text(
                [str(item.get("owasp_category") or "") for item in scenario_results],
                max_items=2,
            )

            with select_col:
                st.checkbox(" ", key=f"simulations-select-{path.name}", label_visibility="collapsed")

            with card_col:
                card_url = f"?open_sim={path.name}"
                st.markdown(
                    f"""
                    <a href="{card_url}" target="_self" style="text-decoration:none;display:block;margin-bottom:0.75rem;">
                    <div class="sim-card-clickable">
                        <div class="simulation-card-header">
                            <div class="simulation-card-title">{html.escape(str(report.get('scan_name', 'Simulation')))}</div>
                            <span class="simulation-status {status_class}">{status_label}</span>
                        </div>
                        <div class="simulation-card-meta">Target: {html.escape(str(target_name))}</div>
                        <div class="simulation-card-meta">Vulnerability type: {html.escape(vulnerability_types)}</div>
                        <div class="simulation-card-row">
                            <span>Vulnerability Found</span>
                            <span class="simulation-percent">{percent}%</span>
                        </div>
                        <div class="simulation-card-row">
                            <span>Status</span>
                            <span>{html.escape(status_label)}</span>
                        </div>
                        <div class="simulation-card-row">
                            <span>Scan initiated</span>
                            <span>{html.escape(str(initiated_at))}</span>
                        </div>
                    </div>
                    </a>
                    """,
                    unsafe_allow_html=True,
                )


def _render_simulation_detail_view() -> None:
    back_col, _ = st.columns([1.2, 6])
    back_col.markdown(
        '<a class="plain-back-link" href="?sim_back=history" target="_self" title="Back to Simulations">←</a>',
        unsafe_allow_html=True,
    )

    report_filename = st.session_state.get("simulation_detail_report_path", "")
    all_reports = load_reports()
    matched = [(p, r) for p, r in all_reports if p.name == report_filename]
    if not matched:
        st.error("Report not found. It may have been deleted.")
        return
    _, report = matched[0]

    status = str(report.get("status", "RUNNING")).upper()
    status_class = "complete" if status == "COMPLETED" else "failed" if status == "FAILED" else "running"
    status_label = "Complete" if status == "COMPLETED" else "Failed" if status == "FAILED" else "Running"

    st.markdown(
        f"<h1 style='margin-bottom:0.15rem'>{html.escape(str(report.get('scan_name', 'Simulation')))}"
        f"&nbsp;<span class='simulation-status {status_class}' style='font-size:0.9rem;"
        f"vertical-align:middle;position:relative;top:-2px'>{status_label}</span></h1>",
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <table class="target-detail-table">
            <tbody>
                <tr>
                    <th>Target</th>
                    <td title="{html.escape(str(report.get('target_name', '-')))}">{html.escape(str(report.get('target_name', '-')))}</td>
                </tr>
                <tr>
                    <th>Status</th>
                    <td title="{html.escape(status_label)}">{html.escape(status_label)}</td>
                </tr>
                <tr>
                    <th>Scenarios run</th>
                    <td title="{len(report.get('scenario_results', []))}">{len(report.get('scenario_results', []))}</td>
                </tr>
                <tr>
                    <th>Avg vulnerability</th>
                    <td title="{_simulation_overall_percent(report)}%">{_simulation_overall_percent(report)}%</td>
                </tr>
            </tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    scenario_results = report.get("scenario_results", [])
    target_name = str(report.get("target_name", ""))
    base_scan_name = str(report.get("scan_name", "Simulation")).strip() or "Simulation"
    first_category = next(
        (
            str(s.get("owasp_category", ""))
            for s in scenario_results
            if str(s.get("owasp_category", "")) in OWASP_CATEGORY_OPTIONS
        ),
        "",
    )

    action_col1, action_col2, _ = st.columns([1.3, 1.6, 5])

    if action_col1.button("▶  Rerun", key="detail-rerun", type="primary", use_container_width=True):
        st.session_state.simulation_new_back_view = "detail"
        st.session_state.simulations_view = "new"
        st.session_state.simulation_scan_name_prefill = f"{base_scan_name} Rerun"
        st.session_state.simulation_prefill_target = target_name
        st.session_state.simulation_prefill_category = first_category
        st.session_state.simulation_launch_mode = "rerun"
        st.rerun()

    if action_col2.button("✏  Edit & Scan", key="detail-edit-scan", type="primary", use_container_width=True):
        st.session_state.simulation_new_back_view = "detail"
        st.session_state.simulations_view = "new"
        st.session_state.simulation_scan_name_prefill = f"{base_scan_name} Modified"
        st.session_state.simulation_prefill_target = target_name
        st.session_state.simulation_prefill_category = first_category
        st.session_state.simulation_launch_mode = "modify"
        st.rerun()

    st.divider()

    render_scenario_results(report)


def _render_new_simulation_view() -> None:
    back_col, _ = st.columns([1.2, 6])
    back_view = st.session_state.get("simulation_new_back_view", "history")
    back_col.markdown(
        f'<a class="plain-back-link" href="?sim_back={html.escape(str(back_view))}" target="_self" title="Back">←</a>',
        unsafe_allow_html=True,
    )

    targets = load_target_files()
    if not targets:
        st.info("Create a target before starting a scan.")
        return

    target_names = [str(data.get("name") or path.stem) for path, data in targets]
    default_scan_name = st.session_state.pop(
        "simulation_scan_name_prefill",
        f"LLM01 Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    prefill_target = st.session_state.pop("simulation_prefill_target", "")
    prefill_category = st.session_state.pop("simulation_prefill_category", "")
    launch_mode = st.session_state.pop("simulation_launch_mode", "")

    if launch_mode == "rerun":
        st.info("Rerun mode loaded. Review details and click Start scan to execute again.")
    elif launch_mode == "modify":
        st.info("Modify mode loaded. Update configuration, then click Start scan.")

    scan_name = st.text_input("Scan name", default_scan_name)
    target_index = target_names.index(prefill_target) if prefill_target in target_names else 0
    selected_target_name = st.selectbox("Target", target_names, index=target_index)
    selected_target_data = next(data for _, data in targets if data["name"] == selected_target_name)
    category_index = OWASP_CATEGORY_OPTIONS.index(prefill_category) if prefill_category in OWASP_CATEGORY_OPTIONS else 0
    category = st.selectbox("OWASP LLM vulnerability category", OWASP_CATEGORY_OPTIONS, index=category_index)

    loader = PluginLoader()
    scenarios = loader.discover_scenarios(category)
    if not scenarios:
        st.warning("No scenarios are available for the selected OWASP category.")
        return

    available_turn_modes = scenario_turn_modes(scenarios)
    if not available_turn_modes:
        st.warning("No attack turn modes are available for the selected OWASP category.")
        return

    selected_turn_mode = st.radio(
        "Attack turn type",
        available_turn_modes,
        horizontal=True,
        help="Select whether to run single-turn or multi-turn attack scenarios.",
    )

    attack_options = scenario_attack_options(scenarios, selected_turn_mode)
    option_ids = list(attack_options)
    selected_attack_options = st.multiselect(
        "Scenario / attack selection",
        option_ids,
        default=[],
        format_func=lambda option_id: attack_options[option_id],
        help="Only scenarios matching the selected turn type are shown.",
    )

    selected_scenarios = []
    if any(option_id.startswith("crescendo:") for option_id in selected_attack_options):
        selected_scenarios.append("llm01.crescendo_attack")
    selected_scenarios.extend(
        option_id.removeprefix("scenario:")
        for option_id in selected_attack_options
        if option_id.startswith("scenario:")
    )
    selected_scenarios.extend(
        option_id.split(":", 2)[1]
        for option_id in selected_attack_options
        if option_id.startswith("attack:")
    )
    selected_scenarios.extend(
        option_id.split(":", 2)[1]
        for option_id in selected_attack_options
        if option_id.startswith("chain:")
    )
    selected_scenarios = list(dict.fromkeys(selected_scenarios))

    selected_prompt_injection_attack_types = [
        option_id.removeprefix("prompt_chain:")
        for option_id in selected_attack_options
        if option_id.startswith("prompt_chain:")
    ]
    selected_sensitive_information_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm02.sensitive_information_disclosure:")
    ]
    selected_supply_chain_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm03.supply_chain:")
    ]
    selected_data_model_poisoning_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm04.data_model_poisoning:")
    ]
    selected_improper_output_handling_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm05.improper_output_handling:")
    ]
    selected_excessive_agency_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm06.excessive_agency:")
    ]
    selected_excessive_agency_multi_turn_chains = [
        option_id.removeprefix("chain:llm06.excessive_agency:")
        for option_id in selected_attack_options
        if option_id.startswith("chain:llm06.excessive_agency:")
    ]
    selected_system_prompt_leakage_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm07.system_prompt_leakage:")
    ]
    selected_system_prompt_leakage_multi_turn_chains = [
        option_id.removeprefix("chain:llm07.system_prompt_leakage:")
        for option_id in selected_attack_options
        if option_id.startswith("chain:llm07.system_prompt_leakage:")
    ]
    selected_vector_embedding_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm08.vector_embedding_weaknesses:")
    ]
    selected_vector_embedding_multi_turn_chains = [
        option_id.removeprefix("chain:llm08.vector_embedding_weaknesses:")
        for option_id in selected_attack_options
        if option_id.startswith("chain:llm08.vector_embedding_weaknesses:")
    ]
    selected_misinformation_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm09.misinformation:")
    ]
    selected_misinformation_multi_turn_chains = [
        option_id.removeprefix("chain:llm09.misinformation:")
        for option_id in selected_attack_options
        if option_id.startswith("chain:llm09.misinformation:")
    ]
    selected_unbounded_consumption_attack_types = [
        option_id.split(":", 2)[2]
        for option_id in selected_attack_options
        if option_id.startswith("attack:llm10.unbounded_consumption:")
    ]
    selected_unbounded_consumption_multi_turn_chains = [
        option_id.removeprefix("chain:llm10.unbounded_consumption:")
        for option_id in selected_attack_options
        if option_id.startswith("chain:llm10.unbounded_consumption:")
    ]
    include_prompt_injection_single_turn = "prompt:single_turn" in selected_attack_options
    if include_prompt_injection_single_turn or selected_prompt_injection_attack_types:
        selected_scenarios.append("llm01.prompt_injection")

    selected_profile = "authority_escalation_system_prompt"
    if "llm01.crescendo_attack" in selected_scenarios:
        selected_profile_label = st.selectbox(
            "Crescendo attack profile",
            list(CRESCENDO_PROFILE_OPTIONS.values()),
            help="Used by the selected Crescendo multi-turn scenario.",
        )
        selected_profile = next(
            profile_id for profile_id, label in CRESCENDO_PROFILE_OPTIONS.items() if label == selected_profile_label
        )

    col1, col2, col3 = st.columns(3)
    with col1:
        max_turns = 10
        if selected_turn_mode == "Multi-turn":
            max_turns = st.number_input("Max turns", min_value=1, max_value=25, value=10)
        timeout = st.number_input("Timeout", min_value=1, max_value=300, value=30)
    with col2:
        concurrency = st.number_input("Concurrency", min_value=1, max_value=20, value=2)
        retry_count = st.number_input("Retry count", min_value=0, max_value=5, value=2)
    with col3:
        temperature = st.slider("Temperature", min_value=0.0, max_value=2.0, value=0.2, step=0.05)

    if "simulation_scan" not in st.session_state:
        st.session_state.simulation_scan = None

    scan_state = _drain_simulation_scan_updates()
    scan_running = bool(scan_state and scan_state.get("running"))

    progress_value = int(scan_state.get("progress", 0)) if scan_state else 0
    progress_bar = st.progress(progress_value)
    progress_text = st.empty()
    progress_text.markdown(f"**Progress: {progress_value}%**")
    stage_box = st.empty()
    if scan_state and scan_state.get("stage"):
        stage_box.info(f"Current stage: {scan_state['stage']}")

    can_start_scan = bool(scan_name.strip() and selected_target_data and category and selected_scenarios and not scan_running)

    if not scan_running and not can_start_scan:
        if not scan_name.strip():
            st.caption("Enter a scan name to enable Start scan.")
        elif not selected_attack_options:
            st.caption("Select at least one scenario/attack option to enable Start scan.")

    if scan_running:
        stop_col, refresh_col = st.columns([1, 5])
        if stop_col.button("Stop scan", type="secondary", key=f"stop-scan-{scan_state['scan_id']}"):
            _target_executor_call("request_cancel", scan_state["scan_id"])
            scan_state["stop_requested"] = True
            st.session_state.simulation_scan = scan_state
            st.rerun()
        refresh_col.button(
            "Refresh status",
            key=f"refresh-scan-{scan_state['scan_id']}",
            help="Refresh background scan progress.",
        )
        if scan_state.get("stop_requested"):
            st.warning("Stop requested. The active request will terminate, and the scan will stop.")
        else:
            st.info("Scan is running. You can stop it anytime.")

    if st.button("Start scan", type="primary", disabled=not can_start_scan):
        scan_id = str(uuid4())
        scan_payload = {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "target": TargetConfig.model_validate(selected_target_data).model_dump(mode="json"),
            "owasp_category": category,
            "scenario_ids": selected_scenarios,
            "settings": ScanSettings(
                max_turns=int(max_turns) if selected_turn_mode == "Multi-turn" else 1,
                timeout_seconds=float(timeout),
                concurrency=int(concurrency),
                temperature=float(temperature),
                retry_count=int(retry_count),
                crescendo_profile=selected_profile,
                prompt_injection_attack_types=selected_prompt_injection_attack_types,
                prompt_injection_include_single_turn=include_prompt_injection_single_turn,
                sensitive_information_attack_types=selected_sensitive_information_attack_types,
                supply_chain_attack_types=selected_supply_chain_attack_types,
                data_model_poisoning_attack_types=selected_data_model_poisoning_attack_types,
                improper_output_handling_attack_types=selected_improper_output_handling_attack_types,
                excessive_agency_attack_types=selected_excessive_agency_attack_types,
                excessive_agency_multi_turn_chains=selected_excessive_agency_multi_turn_chains,
                system_prompt_leakage_attack_types=selected_system_prompt_leakage_attack_types,
                system_prompt_leakage_multi_turn_chains=selected_system_prompt_leakage_multi_turn_chains,
                vector_embedding_attack_types=selected_vector_embedding_attack_types,
                vector_embedding_multi_turn_chains=selected_vector_embedding_multi_turn_chains,
                misinformation_attack_types=selected_misinformation_attack_types,
                misinformation_multi_turn_chains=selected_misinformation_multi_turn_chains,
                unbounded_consumption_attack_types=selected_unbounded_consumption_attack_types,
                unbounded_consumption_multi_turn_chains=selected_unbounded_consumption_multi_turn_chains,
            ).model_dump(mode="json"),
        }
        scan_state = {
            "scan_id": scan_id,
            "running": True,
            "stop_requested": False,
            "events": [],
            "events_queue": queue.Queue(),
            "progress": 0,
            "stage": "scan_started",
            "scenario_count": len(selected_scenarios),
            "result": None,
            "error": None,
        }
        st.session_state.simulation_scan = scan_state
        _start_background_scan(scan_payload, scan_state)
        st.rerun()

    if scan_state and not scan_state.get("running"):
        report = scan_state.get("result")
        error_text = scan_state.get("error")

        if report:
            status = str(report.get("status", "")).upper()
            if status == "COMPLETED":
                progress_bar.progress(100)
                progress_text.markdown("**Progress: 100%**")
                st.success("Scan finished with status COMPLETED")
                st.info("Open the Results page to review scan history, vulnerability percentages, reasons, chat transcripts, and exports.")
            elif status == "FAILED":
                failure_text = str(report.get("error") or "Unknown error")
                if "cancelled by user request" in failure_text.lower():
                    st.warning("Scan stopped by user request.")
                else:
                    st.error(f"Scan failed: {failure_text}")
            else:
                st.info(f"Scan finished with status {status or '-'}")
        elif error_text:
            st.error(f"Scan failed: {error_text}")

        if st.button("Clear scan state", key=f"clear-scan-{scan_state['scan_id']}"):
            st.session_state.simulation_scan = None
            st.rerun()


def simulations_page() -> None:
    st.header("Simulations")

    _sim_back = st.query_params.get("sim_back", None)
    if isinstance(_sim_back, list):
        _sim_back = _sim_back[0] if _sim_back else None
    if _sim_back:
        st.query_params.clear()
        back_view = str(_sim_back)
        st.session_state.simulations_view = back_view if back_view in {"history", "new", "detail"} else "history"
        if st.session_state.simulations_view == "history":
            st.session_state.pop("simulation_detail_report_path", None)
        st.rerun()

    # Handle card click via query param routing
    _open_sim = st.query_params.get("open_sim", None)
    if isinstance(_open_sim, list):
        _open_sim = _open_sim[0] if _open_sim else None
    if _open_sim:
        st.query_params.clear()
        st.session_state.simulations_view = "detail"
        st.session_state.simulation_detail_report_path = _open_sim
        st.rerun()

    if "simulations_view" not in st.session_state:
        st.session_state.simulations_view = "history"

    if st.session_state.simulations_view == "history":
        _render_simulation_history_view()
    elif st.session_state.simulations_view == "new":
        _render_new_simulation_view()
    elif st.session_state.simulations_view == "detail":
        _render_simulation_detail_view()


def settings_page() -> None:
    st.header("Configurations")
    render_page_intro(
        "settings",
        "Platform Configuration",
        "Inspect runtime defaults for model endpoint, retries, logging, and baseline generation behavior.",
        ["Endpoint", "Reliability", "Governance"],
    )
    settings = get_settings()
    st.text_input("Azure OpenAI endpoint", value=settings.azure_openai_endpoint or "", type="default")
    st.text_input("Azure OpenAI API key", value="***configured***" if settings.azure_openai_api_key else "", type="password")
    st.text_input("Deployment name", value=settings.azure_openai_deployment or "")
    st.text_input("API version", value=settings.azure_openai_api_version)
    st.slider("Default temperature", 0.0, 2.0, settings.default_temperature, 0.05)
    st.selectbox("Logging level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], index=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"].index(settings.log_level))
    st.number_input("Retry configuration", min_value=0, max_value=5, value=settings.default_retry_count)
    st.caption(".env is loaded at application startup. API keys are never displayed or written to logs.")


def main() -> None:
    st.markdown(APP_STYLES, unsafe_allow_html=True)
    st.sidebar.markdown(
        """
        <div class="sidebar-brand">
            <span class="sidebar-brand-badge"></span>
            <span>H-ATLAS</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    nav_options = {
        "�  Dashboard": "Dashboard",
        "🎯  Targets": "Targets",
        "🧪  Simulations": "Simulations",
        "📋  Reports": "Reports",
        "⚙️  Configurations": "Configurations",
    }
    has_open_sim = bool(st.query_params.get("open_sim", None))
    has_sim_back = bool(st.query_params.get("sim_back", None))
    has_open_target = bool(st.query_params.get("open_target", None))
    has_target_back = bool(st.query_params.get("target_back", None))
    if has_open_sim or has_sim_back:
        st.session_state["main_navigation"] = "🧪  Simulations"
    elif has_open_target or has_target_back:
        st.session_state["main_navigation"] = "🎯  Targets"

    selected_nav = st.sidebar.radio(
        "Main Navigation",
        list(nav_options),
        label_visibility="collapsed",
        key="main_navigation",
    )
    page = nav_options[selected_nav]

    previous_page = st.session_state.get("_last_page")
    if page == "Simulations" and previous_page != "Simulations":
        st.session_state.simulations_view = "history"
    st.session_state["_last_page"] = page

    if page == "Dashboard":
        dashboard_page()
    elif page == "Targets":
        targets_page()
    elif page == "Simulations":
        simulations_page()
    elif page == "Reports":
        results_page()
    else:
        settings_page()


if __name__ == "__main__":
    main()

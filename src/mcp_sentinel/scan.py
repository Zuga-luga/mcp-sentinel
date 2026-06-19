"""Static manifest scanner — analyse a server's published tool definitions for
prompt-injection / tool-poisoning without ever running the server.

This is the safe way to audit real-world servers at scale: registries publish
each server's tool list (name + description + input schema), and the poisoning
attack lives *in that prose* — adversarial instructions the agent reads. We scan
the text; we never spawn the server.

Findings reuse `anomaly.Finding` so they flow through the same `grade()` path as
the runtime rules.
"""

from __future__ import annotations

import re
from typing import Any

from .anomaly import Finding, Severity
from .pinning import ToolDef

# Zero-width and bidirectional control characters — used to hide instructions.
_HIDDEN = re.compile(r"[​-‏‪-‮⁠⁦-⁩﻿]")

_INJECTION = re.compile(
    r"\b(ignore\s+(all\s+|the\s+)?(previous|above|prior)|disregard\s+(the\s+)?(previous|above|instructions)"
    r"|system\s+prompt|you\s+are\s+now|act\s+as|jailbreak|do\s+not\s+(tell|inform|mention|reveal)"
    r"|without\s+(telling|informing)\s+the\s+user|override\s+(the\s+)?(rules|instructions))\b",
    re.IGNORECASE,
)

_SECRETS = re.compile(
    r"(~/\.ssh|id_rsa|/etc/passwd|\.aws/credentials|\.env\b|api[_\s-]?key|password|secret\s*key|access[_\s-]?token|private\s+key)",
    re.IGNORECASE,
)

_CROSS_TOOL = re.compile(
    r"\b(also\s+(call|invoke|use|run)|before\s+(using|calling|responding)|after\s+(you\s+)?(call|use)"
    r"|then\s+(call|invoke)|use\s+the\s+\w+\s+tool\s+to)\b",
    re.IGNORECASE,
)

_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _text(tool: ToolDef) -> str:
    return f"{tool.name}\n{tool.description}\n{tool.input_schema}"


def scan_tool(tool: ToolDef) -> list[Finding]:
    findings: list[Finding] = []
    text = _text(tool)

    if _HIDDEN.search(text):
        findings.append(Finding("MCPP001", Severity.HIGH,
            f"Tool '{tool.name}' description contains hidden/zero-width or bidi control characters."))
    if _INJECTION.search(text):
        findings.append(Finding("MCPP002", Severity.HIGH,
            f"Tool '{tool.name}' description contains prompt-injection / override language."))
    if _SECRETS.search(text):
        findings.append(Finding("MCPP003", Severity.HIGH,
            f"Tool '{tool.name}' description references secrets/credentials (e.g. SSH keys, .env, tokens)."))
    if _CROSS_TOOL.search(text):
        findings.append(Finding("MCPP004", Severity.MEDIUM,
            f"Tool '{tool.name}' description instructs the agent to call OTHER tools (cross-tool steering)."))
    for url in _URL.findall(tool.description or ""):
        findings.append(Finding("MCPP005", Severity.LOW,
            f"Tool '{tool.name}' description embeds a URL ({url}) — possible exfil/instruction sink."))
    return findings


def scan_manifest(tools: list[ToolDef]) -> list[Finding]:
    out: list[Finding] = []
    for t in tools:
        out.extend(scan_tool(t))
    return out


def tools_from_json(data: list[dict[str, Any]]) -> list[ToolDef]:
    return [
        ToolDef(t.get("name", ""), t.get("description", ""), t.get("inputSchema", t.get("input_schema", {})) or {})
        for t in data
    ]

# MCP Sentinel — Field-Test Findings

Static scan of published tool manifests (servers are never executed).

**12 servers scanned** · 9 clean (A/B) · 3 flagged · 4 tool(s) with findings

## Per-server

| Server | Tools | Grade | Top finding |
|---|---|---|---|
| translator-HIDDEN | 1 | D | Tool 'translate' description contains hidden/zero-width or bidi control characters. |
| helpful-assistant-POISONED | 1 | D | Tool 'summarize' description contains prompt-injection / override language. |
| calc-RUGPULLER | 1 | C | Tool 'add' description contains prompt-injection / override language. |
| notes-borderline | 1 | A | Tool 'save_note' description embeds a URL (https://notes.example/docs) — possible exfil... |
| filesystem | 3 | A | — |
| github | 2 | A | — |
| time | 1 | A | — |
| fetch | 1 | A | — |
| sqlite | 2 | A | — |
| weather | 1 | A | — |
| memory | 2 | A | — |
| slack | 1 | A | — |

## Findings by rule

| Rule | Count | Meaning |
|---|---|---|
| MCPP001 | 1 | hidden/zero-width or bidi control chars |
| MCPP002 | 2 | prompt-injection / override language |
| MCPP003 | 2 | references secrets/credentials |
| MCPP004 | 1 | cross-tool steering |
| MCPP005 | 2 | embedded URL (exfil/instruction sink) |

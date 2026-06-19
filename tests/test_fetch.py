"""Field-mapping guard for the registry fetcher (no network)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fieldtest"))

from fetch import _tool  # noqa: E402


def test_tool_normalizes_camel_and_snake_case():
    assert _tool({"name": "t", "description": "d", "inputSchema": {"x": 1}}) == {
        "name": "t", "description": "d", "inputSchema": {"x": 1}
    }
    # snake_case input schema and missing fields fall back cleanly
    out = _tool({"name": "t", "input_schema": {"y": 2}})
    assert out["inputSchema"] == {"y": 2} and out["description"] == ""


def test_tool_handles_null_fields():
    out = _tool({"name": "t", "description": None, "inputSchema": None})
    assert out["description"] == "" and out["inputSchema"] == {}

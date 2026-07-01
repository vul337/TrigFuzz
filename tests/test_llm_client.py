from __future__ import annotations

from types import SimpleNamespace

from trigfuzz.llm_client import LLMClient


def test_extract_response_output_text():
    resp = SimpleNamespace(output_text="hello")
    assert LLMClient._extract_text(resp) == "hello"


def test_extract_response_content_parts():
    resp = SimpleNamespace(output=[
        SimpleNamespace(content=[
            SimpleNamespace(text="hel"),
            SimpleNamespace(text="lo"),
        ])
    ])
    assert LLMClient._extract_text(resp) == "hello"


def test_extract_chat_completion_text():
    resp = SimpleNamespace(choices=[
        SimpleNamespace(message=SimpleNamespace(content="hel")),
        SimpleNamespace(message=SimpleNamespace(content="lo")),
    ])
    assert LLMClient._extract_chat_text(resp) == "hello"


def test_developer_role_maps_to_chat_system():
    messages = LLMClient._to_chat_messages([
        {"role": "developer", "content": "policy"},
        {"role": "unknown", "content": "question"},
    ])
    assert messages == [
        {"role": "system", "content": "policy"},
        {"role": "user", "content": "question"},
    ]

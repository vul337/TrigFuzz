"""Thin wrapper over OpenAI-compatible APIs.

The TC generation agent only needs one interface:

    query(messages) -> str

`messages` is a list of OpenAI-compatible chat messages with `role` and
`content`. The default path uses the Responses API. OpenAI-compatible
chat-completions endpoints are also supported by setting
`OPENAI_API_BASE_URL` or `OPENAI_BASE_URL` to a chat-completions style
endpoint.
"""

from __future__ import annotations

import os
from typing import Any

from .prompts import SYSTEM_PROMPT

_DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.5")
_DEFAULT_MAX_OUTPUT_TOKENS = int(os.environ.get("OPENAI_MAX_OUTPUT_TOKENS", "4096"))
_CHAT_ENDPOINT_TAIL = ("chat", "completions")


class LLMClient:
    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        # Import lazily so the package is importable in test environments
        # without the OpenAI SDK installed.
        from openai import OpenAI

        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Export an API key before running TCgen."
            )

        raw_base_url = (
            base_url
            or os.environ.get("OPENAI_API_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
        )
        sdk_base_url = raw_base_url
        self._use_chat_completions = False
        if raw_base_url:
            trimmed = raw_base_url.rstrip("/")
            parts = trimmed.split("/")
            if len(parts) >= 2 and tuple(parts[-2:]) == _CHAT_ENDPOINT_TAIL:
                self._use_chat_completions = True
                sdk_base_url = "/".join(parts[:-2])

        kwargs: dict[str, Any] = {
            "api_key": key,
        }
        if sdk_base_url:
            kwargs["base_url"] = sdk_base_url

        self._client = OpenAI(**kwargs)
        self._model = model

    def query(self, messages: list[dict[str, Any]]) -> str:
        """Send one conversation turn. Returns the final text."""
        if self._use_chat_completions:
            return self._query_chat_completions(messages)

        resp = self._client.responses.create(
            model=self._model,
            instructions=SYSTEM_PROMPT,
            input=self._to_response_input(messages),
            max_output_tokens=_DEFAULT_MAX_OUTPUT_TOKENS,
        )
        return self._extract_text(resp)

    def _query_chat_completions(self, messages: list[dict[str, Any]]) -> str:
        chat_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        chat_messages.extend(self._to_chat_messages(messages))
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=chat_messages,
            max_tokens=_DEFAULT_MAX_OUTPUT_TOKENS,
        )
        return self._extract_chat_text(resp)

    @staticmethod
    def _to_response_input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            if role not in {"user", "assistant", "system", "developer"}:
                role = "user"
            out.append({"role": role, "content": str(content)})
        return out

    @staticmethod
    def _to_chat_messages(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            if role == "developer":
                role = "system"
            elif role not in {"user", "assistant", "system"}:
                role = "user"
            out.append({"role": role, "content": str(content)})
        return out

    @staticmethod
    def _extract_text(resp: Any) -> str:
        text = getattr(resp, "output_text", None)
        if text:
            return str(text)

        chunks: list[str] = []
        for item in getattr(resp, "output", []) or []:
            for part in getattr(item, "content", []) or []:
                part_text = getattr(part, "text", None)
                if part_text:
                    chunks.append(str(part_text))
        return "".join(chunks)

    @staticmethod
    def _extract_chat_text(resp: Any) -> str:
        chunks: list[str] = []
        for choice in getattr(resp, "choices", []) or []:
            message = getattr(choice, "message", None)
            content = getattr(message, "content", None)
            if content:
                chunks.append(str(content))
        return "".join(chunks)

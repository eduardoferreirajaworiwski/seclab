"""Shared LLM access for every module: tries Gemini first, then OpenAI, then
gives up. Centralizing this here means a module that wants AI-generated
suggestions/summaries doesn't reimplement provider selection, HTTP payload
shapes, or fallback ordering - it just calls generate_json() and always has
a deterministic fallback ready for when this returns None (offline, no key
configured, or both providers failed)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

logger = logging.getLogger(__name__)


class AIProviderName(StrEnum):
    GEMINI = "gemini"
    OPENAI = "openai"


@dataclass
class AIResult:
    """Structured result of an AI JSON-generation call.

    `text` is the raw model output (already extracted from the
    provider-specific response envelope); `provider` records which backend
    actually answered so callers can stamp their own `model_source` field.
    """

    text: str
    provider: AIProviderName


class _HttpLike(Protocol):
    async def post_json(
        self, url: str, json_body: dict[str, object], headers: dict[str, str] | None = None
    ) -> dict[str, object]: ...


class AIProviderService:
    """Single entry point for every module that wants an LLM-generated JSON
    object. Tries Gemini first, then OpenAI, then gives up - callers are
    expected to always have a deterministic fallback ready and never block
    user-facing behavior on this succeeding (see phantom/threatlens ai_*
    modules for the established pattern). offline_mode always skips both
    providers, matching the rest of the codebase's offline-first posture."""

    def __init__(self, settings: Settings, http: _HttpLike | None = None) -> None:
        self.settings = settings
        self.http = http or HttpProvider(settings)

    async def generate_json(
        self, *, system_prompt: str, user_prompt: str, offline_mode: bool
    ) -> AIResult | None:
        if offline_mode:
            return None
        if self.settings.gemini_api_key:
            result = await self._try_gemini(system_prompt, user_prompt)
            if result is not None:
                return result
        if self.settings.openai_api_key:
            result = await self._try_openai(system_prompt, user_prompt)
            if result is not None:
                return result
        return None

    async def _try_gemini(self, system_prompt: str, user_prompt: str) -> AIResult | None:
        url = (
            f"{self.settings.gemini_base_url}/models/"
            f"{self.settings.gemini_model}:generateContent"
            f"?key={self.settings.gemini_api_key.get_secret_value()}"
        )
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}
            ],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
        }
        try:
            response = await self.http.post_json(url, json_body=body)
        except Exception as exc:
            logger.warning("ai_provider_gemini_failed", extra={"error": str(exc)})
            return None
        candidates = response.get("candidates", [])
        if not isinstance(candidates, list) or not candidates:
            return None
        first = candidates[0]
        content = first.get("content", {}) if isinstance(first, dict) else {}
        parts = content.get("parts", []) if isinstance(content, dict) else []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        if not text:
            return None
        return AIResult(text=text, provider=AIProviderName.GEMINI)

    async def _try_openai(self, system_prompt: str, user_prompt: str) -> AIResult | None:
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.settings.openai_model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        try:
            response = await self.http.post_json(
                f"{self.settings.openai_base_url}/chat/completions",
                json_body=body,
                headers=headers,
            )
        except Exception as exc:
            logger.warning("ai_provider_openai_failed", extra={"error": str(exc)})
            return None
        choices = response.get("choices", [])
        if not isinstance(choices, list) or not choices:
            return None
        first = choices[0]
        message = first.get("message", {}) if isinstance(first, dict) else {}
        content = message.get("content", "") if isinstance(message, dict) else ""
        if not isinstance(content, str) or not content:
            return None
        return AIResult(text=content, provider=AIProviderName.OPENAI)

    @staticmethod
    def parse_json(text: str) -> dict | None:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

import json

import pytest
from seclab.core.ai_provider import AIProviderName, AIResult
from seclab.core.config import Settings

from seclab_recon.ai_tactics import TacticsAdvisorService
from seclab_recon.models import Target


def _settings() -> Settings:
    return Settings(api_key_pepper="test-pepper-not-for-prod", database_url="sqlite:///:memory:")


def _target() -> Target:
    return Target(
        id=1,
        program_id=1,
        identifier="example.com",
        target_type="domain",
        created_by="tester",
        in_scope=True,
        scope_reason="ok",
    )


class _FakeAI:
    def __init__(self, result):
        self._result = result

    async def generate_json(self, **kwargs):
        return self._result

    @staticmethod
    def parse_json(text):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


@pytest.mark.asyncio
async def test_offline_mode_returns_deterministic_suggestions():
    service = TacticsAdvisorService(_settings(), ai=_FakeAI(None))
    result = await service.suggest(_target(), existing=[], offline_mode=True)
    assert result.model_source == "deterministic-fallback"
    assert len(result.suggestions) > 0


@pytest.mark.asyncio
async def test_ai_result_is_parsed_into_suggestions():
    ai_text = (
        '{"suggestions": [{"title": "t", "description": "d", '
        '"technique": "idor", "suggested_next_step": "n", '
        '"severity": "high", "confidence": 0.8}]}'
    )
    fake = _FakeAI(AIResult(text=ai_text, provider=AIProviderName.GEMINI))
    service = TacticsAdvisorService(_settings(), ai=fake)
    result = await service.suggest(_target(), existing=[], offline_mode=False)
    assert result.model_source == "gemini"
    assert result.suggestions[0].technique == "idor"


@pytest.mark.asyncio
async def test_malformed_ai_json_falls_back_to_deterministic():
    fake = _FakeAI(AIResult(text="not json", provider=AIProviderName.GEMINI))
    service = TacticsAdvisorService(_settings(), ai=fake)
    result = await service.suggest(_target(), existing=[], offline_mode=False)
    assert result.model_source == "deterministic-fallback"

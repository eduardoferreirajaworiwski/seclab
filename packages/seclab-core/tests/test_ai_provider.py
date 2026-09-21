import pytest
from seclab.core.ai_provider import AIProviderName, AIProviderService
from seclab.core.config import Settings


def _settings(**overrides) -> Settings:
    base = {"api_key_pepper": "test-pepper-not-for-prod", "database_url": "sqlite:///:memory:"}
    base.update(overrides)
    return Settings(**base)


class _FakeHttp:
    def __init__(self, gemini_response=None, openai_response=None, raise_gemini=False):
        self.gemini_response = gemini_response
        self.openai_response = openai_response
        self.raise_gemini = raise_gemini
        self.calls: list[str] = []

    async def post_json(self, url, json_body, headers=None):
        if "generativelanguage" in url:
            self.calls.append("gemini")
            if self.raise_gemini:
                raise RuntimeError("boom")
            return self.gemini_response or {}
        self.calls.append("openai")
        return self.openai_response or {}


@pytest.mark.asyncio
async def test_prefers_gemini_when_both_configured():
    settings = _settings(gemini_api_key="g", openai_api_key="o")
    fake = _FakeHttp(
        gemini_response={"candidates": [{"content": {"parts": [{"text": '{"ok": true}'}]}}]}
    )
    service = AIProviderService(settings, http=fake)
    result = await service.generate_json(system_prompt="sys", user_prompt="usr", offline_mode=False)
    assert result is not None
    assert result.provider == AIProviderName.GEMINI
    assert fake.calls == ["gemini"]


@pytest.mark.asyncio
async def test_falls_back_to_openai_when_gemini_fails():
    settings = _settings(gemini_api_key="g", openai_api_key="o")
    fake = _FakeHttp(
        raise_gemini=True,
        openai_response={"choices": [{"message": {"content": '{"ok": true}'}}]},
    )
    service = AIProviderService(settings, http=fake)
    result = await service.generate_json(system_prompt="sys", user_prompt="usr", offline_mode=False)
    assert result is not None
    assert result.provider == AIProviderName.OPENAI
    assert fake.calls == ["gemini", "openai"]


@pytest.mark.asyncio
async def test_offline_mode_skips_every_provider():
    settings = _settings(gemini_api_key="g")
    fake = _FakeHttp()
    service = AIProviderService(settings, http=fake)
    result = await service.generate_json(system_prompt="sys", user_prompt="usr", offline_mode=True)
    assert result is None
    assert fake.calls == []


@pytest.mark.asyncio
async def test_no_keys_configured_returns_none():
    settings = _settings()
    fake = _FakeHttp()
    service = AIProviderService(settings, http=fake)
    result = await service.generate_json(system_prompt="sys", user_prompt="usr", offline_mode=False)
    assert result is None
    assert fake.calls == []

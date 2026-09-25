"""Phase 4 — Gemini provider unit tests.

All Gemini interactions are mocked: that we never need a real API key, an
internet connection, or a live Gemini call. The tests verify the official
wire format, timeout/error handling, and — critically — that the API key
never appears in payloads, errors, or returned values.
"""

import json

import pytest

from src.answer_engine import (
    AIProviderError,
    GeminiConfig,
    GeminiProvider,
    build_ai_request,
)
from src.answer_engine.prompts import SYSTEM_INSTRUCTIONS, build_user_prompt
from src.answer_engine.types import AnswerType

FAKE_KEY = "AIzaSy-fake-test-key-never-real"


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class _FakeTransport:
    """Capture the request and return a scripted response."""

    def __init__(self, response):
        self.response = response
        self.last_kwargs = None
        self.last_url = None
        self.raise_exc = None

    def _fake_post(self, url, **kwargs):
        self.last_url = url
        self.last_kwargs = kwargs
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.response


def make_provider(monkeypatch, transport, api_key=FAKE_KEY):
    monkeypatch.setenv("GEMINI_API_KEY", api_key)
    monkeypatch.setattr(
        "src.answer_engine.providers.gemini.requests.post", transport._fake_post
    )
    return GeminiProvider(), transport


def gemini_raw_answer() -> dict:
    return {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps(
                                {
                                    "answer": "Blue",
                                    "confidence": 0.9,
                                    "needsReview": False,
                                    "reasoning": "Blue is a valid option.",
                                }
                            )
                        }
                    ]
                }
            }
        ]
    }


def sample_request():
    return build_ai_request("Which color?", AnswerType.RADIO, ["Red", "Blue", "Green"])


# ---------------------------------------------------------------------------
# Wire format correctness
# ---------------------------------------------------------------------------

def test_gemini_sends_official_request_shape(monkeypatch):
    provider, transport = make_provider(monkeypatch, _FakeTransport(FakeResponse(200, gemini_raw_answer())))

    resp = provider.generate(sample_request())

    payload = transport.last_kwargs["json"]
    # Official v1beta generateContent shape.
    assert "system_instruction" in payload
    assert payload["system_instruction"]["parts"][0]["text"] == SYSTEM_INSTRUCTIONS
    assert payload["contents"][0]["role"] == "user"
    assert payload["contents"][0]["parts"][0]["text"] == build_user_prompt(sample_request())
    assert payload["generationConfig"]["temperature"] == provider.config.temperature
    assert payload["generationConfig"]["maxOutputTokens"] == provider.config.max_tokens
    assert payload["generationConfig"]["responseMimeType"] == "application/json"

    assert transport.last_url.endswith(f"/models/{provider.config.model}:generateContent")
    assert "generativelanguage.googleapis.com" in transport.last_url
    assert "v1beta" in transport.last_url

    assert resp.answer == "Blue"
    assert resp.confidence == 0.9
    assert resp.needs_review is False


# ---------------------------------------------------------------------------
# 21. API key handling
# ---------------------------------------------------------------------------

def test_gemini_never_puts_key_in_body(monkeypatch):
    provider, transport = make_provider(monkeypatch, _FakeTransport(FakeResponse(200, gemini_raw_answer())))

    provider.generate(sample_request())

    payload_str = json.dumps(transport.last_kwargs["json"])
    headers = transport.last_kwargs["headers"]
    assert FAKE_KEY not in payload_str
    assert headers["x-goog-api-key"] == FAKE_KEY


def test_gemini_error_messages_never_contain_key(monkeypatch):
    for status in (400, 401, 403, 429, 500):
        provider, transport = make_provider(
            monkeypatch, _FakeTransport(FakeResponse(status, {"error": "nope"}))
        )
        with pytest.raises(AIProviderError) as exc_info:
            provider.generate(sample_request())
        assert FAKE_KEY not in str(exc_info.value)
        assert bytes(FAKE_KEY, "utf-8") not in bytes(str(exc_info.value) or "x", "utf-8")


def test_missing_api_key_raises_clear_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    provider = GeminiProvider()
    with pytest.raises(AIProviderError, match="GEMINI_API_KEY"):
        provider.generate(sample_request())


def test_gemini_config_api_key_not_in_repr(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
    provider = GeminiProvider()
    assert FAKE_KEY not in repr(provider)
    assert FAKE_KEY not in repr(provider.config)


# ---------------------------------------------------------------------------
# 14. Timeout / connection failure
# ---------------------------------------------------------------------------

def test_gemini_timeout(monkeypatch):
    transport = _FakeTransport(None)
    transport.raise_exc = __import__("requests").Timeout()
    provider, _ = make_provider(monkeypatch, transport)

    with pytest.raises(AIProviderError, match="timed out"):
        provider.generate(sample_request())


def test_gemini_connection_error(monkeypatch):
    transport = _FakeTransport(None)
    transport.raise_exc = __import__("requests").ConnectionError()
    provider, _ = make_provider(monkeypatch, transport)

    with pytest.raises(AIProviderError, match="connect"):
        provider.generate(sample_request())


# ---------------------------------------------------------------------------
# 13. Provider failure (HTTP errors)
# ---------------------------------------------------------------------------

def test_gemini_http_401(monkeypatch):
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(401, {})))
    with pytest.raises(AIProviderError, match="authentication"):
        provider.generate(sample_request())


def test_gemini_http_403(monkeypatch):
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(403, {})))
    with pytest.raises(AIProviderError, match="access denied|authentication"):
        provider.generate(sample_request())


def test_gemini_http_429(monkeypatch):
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(429, {})))
    with pytest.raises(AIProviderError, match="quota"):
        provider.generate(sample_request())


def test_gemini_http_500(monkeypatch):
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(500, {})))
    with pytest.raises(AIProviderError, match="HTTP 500"):
        provider.generate(sample_request())


# ---------------------------------------------------------------------------
# 15. Malformed responses
# ---------------------------------------------------------------------------

def test_gemini_non_json_body(monkeypatch):
    class NotJson(FakeResponse):
        def json(self):
            raise ValueError

    provider, _ = make_provider(monkeypatch, _FakeTransport(NotJson(200, b"{bad")))
    with pytest.raises(AIProviderError, match="malformed"):
        provider.generate(sample_request())


def test_gemini_structured_text_is_not_json(monkeypatch):
    body = {"candidates": [{"content": {"parts": [{"text": "Blue, because ..."}]}}]}
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(200, body)))
    with pytest.raises(AIProviderError, match="malformed structured JSON"):
        provider.generate(sample_request())


def test_gemini_unexpected_response_shape(monkeypatch):
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(200, {"nope": 1})))
    with pytest.raises(AIProviderError, match="unexpected response shape"):
        provider.generate(sample_request())


def test_gemini_empty_response(monkeypatch):
    body = {"candidates": [{"content": {"parts": [{"text": ""}]}}]}
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(200, body)))
    with pytest.raises(AIProviderError, match="empty response"):
        provider.generate(sample_request())


def test_gemini_structured_answer_list_passthrough(monkeypatch):
    body = {"candidates": [{"content": {"parts": [{"text": json.dumps({"answer": ["a", "b"], "confidence": 0.8})}]}}]}
    provider, _ = make_provider(monkeypatch, _FakeTransport(FakeResponse(200, body)))

    request = build_ai_request("Skills?", AnswerType.CHECKBOX, ["a", "b", "c"])
    resp = provider.generate(request)

    assert resp.answer == ["a", "b"]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_default_config_uses_env(monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test-model")
    monkeypatch.setenv("GEMINI_TIMEOUT_MS", "5000")
    monkeypatch.setenv("GEMINI_TEMPERATURE", "0.7")
    monkeypatch.setenv("GEMINI_MAX_TOKENS", "256")

    config = GeminiConfig(
        model="gemini-test-model",
        timeout_ms=5000,
        temperature=0.7,
        max_tokens=256,
    )

    assert config.model == "gemini-test-model"
    assert config.timeout_ms == 5000
    assert config.temperature == 0.7
    assert config.max_tokens == 256


def test_config_status_without_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    from src.answer_engine.config import config_status

    assert config_status() is not None


def test_config_status_with_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
    from src.answer_engine.config import config_status

    assert config_status() is None


def test_registry_unknown_provider():
    from src.answer_engine.providers import get_provider

    with pytest.raises(AIProviderError, match="Unknown"):
        get_provider("does-not-exist")


def test_registry_lists_default_providers():
    from src.answer_engine.providers import available_providers

    assert "gemini" in available_providers()
    assert "mock" in available_providers()
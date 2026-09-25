"""
Phase 4 — Google Gemini provider.

Implements the :class:`AIProvider` protocol for the current official
Gemini REST API (v1beta ``generateContent``). The endpoint and payload
match the verified integration that already exists in this workspace
(``src/ai/assistant.py``).

Security behaviour:
- The API key comes from ``GeminiConfig`` (read from the environment) and
  is never logged, never included in errors, and never stored.
- Errors describe the problem without exposing the key.
- Malformed responses raise :class:`AIProviderError` instead of crashing.
- A timeout is enforced on every request.
"""

from __future__ import annotations

import json

import requests

from src.answer_engine.config import GeminiConfig
from src.answer_engine.prompts import build_prompt
from src.answer_engine.providers import AIProvider, AIProviderError
from src.answer_engine.types import AIRequest, AIResponse


class GeminiProvider:
    """A provider-agnostic-looking Gemini implementation. Only the wire
    format is Gemini-specific; the answer engine only sees AIRequest /
    AIResponse."""

    id = "gemini"

    def __init__(self, config: GeminiConfig | None = None):
        self.config = config or GeminiConfig()

    def _require_api_key(self) -> str:
        key = self.config.api_key
        if not key:
            raise AIProviderError(
                "Gemini is not configured. Set GEMINI_API_KEY in your "
                "environment (see https://aistudio.google.com/apikey)."
            )
        return key

    def generate(self, request: AIRequest) -> AIResponse:
        api_key = self._require_api_key()
        prompt = build_prompt(request)

        payload = {
            "system_instruction": {
                "parts": [{"text": prompt["system_instructions"]}]
            },
            "contents": [
                {"role": "user", "parts": [{"text": prompt["user_message"]}]}
            ],
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
                "responseMimeType": "application/json",
            },
        }
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        }
        timeout_seconds = self.config.timeout_ms / 1000.0
        url = self.config.endpoint_for()

        try:
            resp = requests.post(
                url, json=payload, headers=headers, timeout=timeout_seconds
            )
        except requests.ConnectionError as exc:
            raise AIProviderError(
                "Could not connect to the Gemini API. Check your internet connection."
            ) from exc
        except requests.Timeout as exc:
            raise AIProviderError(
                "The Gemini API request timed out. The service may be temporarily "
                "unavailable or too slow."
            ) from exc
        except requests.RequestException as exc:
            raise AIProviderError(
                f"Network error reaching the Gemini API: {type(exc).__name__}"
            ) from exc

        if resp.status_code == 401 or resp.status_code == 403:
            raise AIProviderError(
                "Gemini authentication failed. Check that your GEMINI_API_KEY is "
                "valid and has not expired or been revoked."
            )
        if resp.status_code == 429:
            raise AIProviderError(
                "Gemini API quota exceeded. Please wait and try again."
            )
        if resp.status_code != 200:
            raise AIProviderError(
                f"Gemini API error (HTTP {resp.status_code}). Please try again."
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise AIProviderError(
                "Gemini returned a malformed (non-JSON) response."
            ) from exc

        return self._extract(data)

    @staticmethod
    def _extract(data: object) -> AIResponse:
        """Extract the structured text response from Gemini's JSON, then
        return it wrapped as an AIResponse. Structured content is expected
        because we request ``responseMimeType=application/json``."""
        try:
            candidates = data["candidates"]  # type: ignore[index]
            parts = candidates[0]["content"]["parts"]
            raw_text = parts[0]["text"]
        except (KeyError, IndexError, TypeError):
            raise AIProviderError(
                "Gemini returned an unexpected response shape."
            )

        if not isinstance(raw_text, str) or not raw_text.strip():
            raise AIProviderError("Gemini returned an empty response.")

        return _parse_structured(raw_text)


def _parse_structured(raw_text: str) -> AIResponse:
    """Parse the structured JSON that Gemini was asked to return, mapping
    it onto a normalised :class:`AIResponse`. The answer engine performs
    the authoritative validation afterwards; this only does a light
    structural parse so malformed JSON becomes an AIProviderError rather
    than a crash."""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise AIProviderError("Gemini returned malformed structured JSON.") from exc

    if not isinstance(data, dict):
        raise AIProviderError("Gemini structured output must be a JSON object.")

    answer = data.get("answer", None)
    confidence = data.get("confidence", 0.0)
    needs_review = bool(data.get("needsReview", False))
    reasoning = data.get("reasoning", "")
    if isinstance(reasoning, str):
        reasoning = reasoning.strip()

    # The answer engine fully validates types/options/confidence/range;
    # here we only normalise so a provider-level response is well formed.
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0

    return AIResponse(
        answer=answer,
        confidence=confidence,
        needs_review=needs_review,
        reasoning=reasoning,
    )

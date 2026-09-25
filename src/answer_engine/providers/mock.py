"""
Phase 4 — Mock AI provider for tests.

A configurable, in-memory :class:`AIProvider` so the answer engine can be
tested without any real API key, internet access, or external service.

The mock is data-driven: tests control exactly which :class:`AIResponse`
(or :class:`AIProviderError`) it returns through ``handler``. By default it
produces a plausible structured answer derived from the request.
"""

from __future__ import annotations

from typing import Any, Callable

from src.answer_engine.providers import AIProviderError
from src.answer_engine.types import AIRequest, AIResponse

# A handler maps an AIRequest to an AIResponse, or raises AIProviderError
# to simulate provider failure / timeout.
Handler = Callable[[AIRequest], AIResponse]


class MockAIProvider:
    """Deterministic fake provider. ``handler`` may be replaced per test."""

    id = "mock"

    def __init__(self):
        self.handler: Handler | None = None
        self.last_request: AIRequest | None = None

    def generate(self, request: AIRequest) -> AIResponse:
        self.last_request = request
        if self.handler is not None:
            return self.handler(request)
        return default_response(request)


def _pick(request: AIRequest) -> str | list[str]:
    if request.type.value == "CHECKBOX":
        return request.options[:2] if request.options else []
    if request.type.value in ("RADIO", "DROPDOWN"):
        return request.options[0] if request.options else ""
    return f"Answered: {request.question}"


def default_response(request: AIRequest) -> AIResponse:
    """Return a plausible structured answer for the request."""
    return AIResponse(
        answer=_pick(request),
        confidence=0.9 if request.context else 0.4,
        needs_review=not request.context,
        reasoning="Answer derived from supplied data.",
    )


def structured_response(
    answer: str | list[str] | None,
    confidence: float = 0.92,
    needs_review: bool = False,
    reasoning: str = "",
) -> Handler:
    """Build a handler that always returns a pre-set AIResponse."""

    def _handler(request: AIRequest) -> AIResponse:
        return AIResponse(
            answer=answer,
            confidence=confidence,
            needs_review=needs_review,
            reasoning=reasoning,
        )

    return _handler


def failing_handler(error: Exception) -> Handler:
    """Build a handler that always raises ``error`` (simulates provider
    failure and timeout)."""

    def _handler(request: AIRequest) -> AIResponse:
        raise error

    return _handler
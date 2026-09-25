"""
Phase 4 — AI provider abstraction and registry.

The answer engine depends only on the :class:`AIProvider` protocol, never
on Gemini-specific details. Any provider (Gemini today; DeepSeek,
OpenRouter, Ollama later) can be registered and selected without touching
the engine.

Providers raise :class:`AIProviderError` on any failure. Providers must
never include the API key (or anything derived from it) in error messages,
logs, or returned responses.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from src.answer_engine.types import AIRequest, AIResponse


class AIProviderError(Exception):
    """Raised when a provider fails: not configured, network/timeout
    errors, HTTP errors, or malformed responses. Messages never expose
    credentials or API keys."""


@runtime_checkable
class AIProvider(Protocol):
    """Generic provider contract. Implementations map their native wire
    format to/from :class:`AIRequest` / :class:`AIResponse`."""

    id: str

    def generate(self, request: AIRequest) -> AIResponse:
        ...


_REGISTRY: dict[str, callable] = {}


def register_provider(provider_id: str, factory: callable) -> None:
    """Register a provider factory under ``provider_id``. A factory is a
    zero-argument callable returning an :class:`AIProvider` instance."""
    _REGISTRY[provider_id] = factory


def ensure_default_providers() -> None:
    """Register the built-in providers (Gemini and Mock) if not already
    registered. Lazy-imports to avoid a cycle (providers import the base
    protocol from this package)."""
    if "gemini" not in _REGISTRY:
        from src.answer_engine.providers.gemini import GeminiProvider

        _REGISTRY["gemini"] = GeminiProvider
    if "mock" not in _REGISTRY:
        from src.answer_engine.providers.mock import MockAIProvider

        _REGISTRY["mock"] = MockAIProvider


def get_provider(provider_id: str) -> AIProvider:
    """Return an instance of the registered provider, or raise
    AIProviderError if it is unknown."""
    ensure_default_providers()
    factory = _REGISTRY.get(provider_id)
    if factory is None:
        raise AIProviderError(
            f"Unknown AI provider '{provider_id}'. "
            f"Supported providers: {', '.join(sorted(_REGISTRY)) or 'none'}"
        )
    return factory()


def available_providers() -> list[str]:
    """Return the ids of all registered providers (sorted)."""
    ensure_default_providers()
    return sorted(_REGISTRY)

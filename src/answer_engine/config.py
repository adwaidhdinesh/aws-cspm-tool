"""
Phase 4 — Provider configuration.

Configuration is deliberately separated from profile/data concerns. In the
CSPM project AI keys come from environment variables (see
``src/ai/assistant.py``), so Phase 4 follows the same convention.

An API key is never hardcoded in source, never logged, and never included
in a GeneratedAnswer or error message.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Current official Gemini API endpoint (v1beta REST). Verified against the
# existing workspace integration (src/ai/assistant.py) which already uses
# this endpoint format.
GEMINI_URL_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

# Current free-tier-eligible default model. Overridable via env/config.
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_TIMEOUT_MS = 30_000
DEFAULT_TEMPERATURE = 0.2
DEFAULT_MAX_TOKENS = 1024

# Data-minimisation / safety thresholds for the answer engine.
CONFIDENCE_THRESHOLD = 0.5


@dataclass
class GeminiConfig:
    """Settings for the Gemini provider. ``api_key`` must come from the
    environment (``GEMINI_API_KEY``) — never constructed inline."""

    model: str = DEFAULT_GEMINI_MODEL
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS

    @property
    def api_key(self) -> str:
        """Return the Gemini API key from the environment.

        Read lazily so tests can set/unset the environment variable. The
        key is never stored, serialised, or logged.
        """
        return os.environ.get("GEMINI_API_KEY", "")

    @property
    def enabled(self) -> bool:
        """Whether Gemini is enabled: an API key is configured."""
        return bool(self.api_key)

    def endpoint_for(self, model: str | None = None) -> str:
        """Return the full URL for the given (or default) model."""
        return GEMINI_URL_TEMPLATE.format(model=model or self.model)


def default_config() -> GeminiConfig:
    """Return a GeminiConfig with environment-driven defaults."""
    return GeminiConfig(
        model=os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
        timeout_ms=int(
            os.environ.get("GEMINI_TIMEOUT_MS", str(DEFAULT_TIMEOUT_MS))
        ),
        temperature=float(
            os.environ.get("GEMINI_TEMPERATURE", str(DEFAULT_TEMPERATURE))
        ),
        max_tokens=int(os.environ.get("GEMINI_MAX_TOKENS", str(DEFAULT_MAX_TOKENS))),
    )


def _api_key_configured() -> bool:
    """Whether a Gemini API key is present in the environment (never the
    key itself)."""
    return bool(os.environ.get("GEMINI_API_KEY", ""))


def config_status() -> str | None:
    """Return a human-readable setup hint if Gemini isn't configured, or
    None if all required settings are present (mirrors
    ``provider_config_status`` in src/ai/assistant.py). Never reveals the
    key itself."""
    if not _api_key_configured():
        return (
            "Gemini AI answer engine not configured. Set GEMINI_API_KEY "
            "in your environment. Get a free key at "
            "https://aistudio.google.com/apikey"
        )
    return None

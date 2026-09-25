"""
Phase 4 — AI Answer Engine.

A provider-agnostic answer engine that turns a question into a validated
:class:`GeneratedAnswer` using, in order: deterministic profile answers,
relevant user context, and — only when needed — an external AI provider
(currently Google Gemini).

See README "Phase 4 — AI Answer Engine" for architecture and configuration.
"""

from src.answer_engine.config import (
    GeminiConfig,
    default_config,
    config_status,
    CONFIDENCE_THRESHOLD,
)
from src.answer_engine.engine import AnswerEngine
from src.answer_engine.providers import (
    AIProvider,
    AIProviderError,
    available_providers,
    get_provider,
    register_provider,
)
from src.answer_engine.providers.gemini import GeminiProvider
from src.answer_engine.providers.mock import MockAIProvider
from src.answer_engine.prompts import (
    SYSTEM_INSTRUCTIONS,
    build_ai_request,
    build_prompt,
    build_user_prompt,
)
from src.answer_engine.types import (
    AIRequest,
    AIResponse,
    AnswerType,
    GeneratedAnswer,
    RelevantContext,
    UserProfile,
)
from src.answer_engine.validation import (
    ValidationError,
    clamp_confidence,
    parse_structured_json,
    validate_options_against,
    validate_response,
)

__all__ = [
    "AIProvider",
    "AIProviderError",
    "AIRequest",
    "AIResponse",
    "AnswerEngine",
    "AnswerType",
    "CONFIDENCE_THRESHOLD",
    "GeminiConfig",
    "GeminiProvider",
    "GeneratedAnswer",
    "MockAIProvider",
    "RelevantContext",
    "SYSTEM_INSTRUCTIONS",
    "UserProfile",
    "ValidationError",
    "available_providers",
    "build_ai_request",
    "build_prompt",
    "build_user_prompt",
    "clamp_confidence",
    "config_status",
    "default_config",
    "get_provider",
    "parse_structured_json",
    "register_provider",
    "validate_options_against",
    "validate_response",
]
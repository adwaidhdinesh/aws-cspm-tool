"""
Phase 4 — AI Answer validation.

Validates structured provider output before it is trusted by the Answer
Engine. The engine must never blindly accept what an AI provider returns,
so this module:

- parses strict-JSON responses safely (malformed JSON never crashes),
- checks expected fields and answer shape,
- clamps/rejects confidence values outside 0..1,
- enforces exact option matching for RADIO / DROPDOWN / CHECKBOX,
- rejects invalid answers instead of silently picking a wrong option.

All functions are pure and raise :class:`ValidationError` on malformed
input; higher-level callers decide how to surface that (normally as a
low-confidence, needs-review result).
"""

from __future__ import annotations

import json
from typing import Any

from src.answer_engine.types import (
    AIResponse,
    AnswerType,
    MULTI_SELECT_TYPES,
    SINGLE_SELECT_TYPES,
)


class ValidationError(Exception):
    """Raised when provider output is malformed or invalid."""


def _require_field(data: dict, name: str) -> Any:
    if name not in data or data[name] is None:
        raise ValidationError(f"Missing required field '{name}' in provider output")
    return data[name]


def clamp_confidence(value: Any) -> float:
    """Return *value* as a float clamped to [0.0, 1.0], or raise
    ValidationError if it is not a finite number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError("Confidence must be a number")
    conf = float(value)
    if conf != conf or conf in (float("inf"), float("-inf")):
        raise ValidationError("Confidence must be a finite number")
    return max(0.0, min(1.0, conf))


def _normalise(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("Answer field must be a string")
    return value.strip()


def _normalise_option(value: Any) -> str:
    """Normalise a single option value to a stripped string for comparison."""
    if not isinstance(value, str):
        raise ValidationError("Options must be strings")
    return value.strip()


def validate_options_against(
    answer: str | list[str] | None,
    answer_type: AnswerType,
    options: list[str] | None,
) -> str | list[str] | None:
    """Validate an answer against the supplied options.

    For RADIO/DROPDOWN the answer must be exactly one option.
    For CHECKBOX every returned value must be a supplied option.
    For non-select types, options are not applicable and anything provided
    is ignored.

    Raises ValidationError if any returned value is not a supplied option.
    """
    if answer_type in SINGLE_SELECT_TYPES:
        if options is None or not options:
            raise ValidationError("No options supplied for single-select question")
        if isinstance(answer, list):
            raise ValidationError("Single-select answer must not be a list")
        norm = _normalise(answer) if answer is not None else ""
        allowed = [_normalise_option(o) for o in options]
        if norm not in allowed:
            raise ValidationError("Answer does not match any supplied option")
        return norm

    if answer_type in MULTI_SELECT_TYPES:
        if options is None or not options:
            raise ValidationError("No options supplied for multi-select question")
        if not isinstance(answer, list):
            raise ValidationError("Checkbox answer must be a list of options")
        allowed = [_normalise_option(o) for o in options]
        normalised = [_normalise_option(a) for a in answer]
        for item in normalised:
            if item not in allowed:
                raise ValidationError("Checkbox answer contains an invalid option")
        return normalised

    if isinstance(answer, list):
        raise ValidationError("Answer must not be a list for non-select question type")
    return _normalise(answer) if answer is not None else None


def parse_structured_json(
    raw: str, answer_type: AnswerType, options: list[str] | None = None
) -> tuple[str | list[str] | None, float, bool, str]:
    """Parse and validate a strict-JSON provider response string.

    Expected conceptual shape::

        {"answer": "...", "confidence": 0.92, "needsReview": false,
         "reasoning": "short factual justification"}

    Returns ``(answer, confidence, needs_review, reasoning)`` after:
    - JSON syntax checking
    - required-field checks
    - option validity (select types) / answer shape sanity
    - confidence clamping to [0, 1]

    Raises ValidationError on any malformed/invalid output.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValidationError("Provider returned malformed JSON") from exc

    if not isinstance(data, dict):
        raise ValidationError("Provider output must be a JSON object")

    answer = _require_field(data, "answer")
    confidence = clamp_confidence(_require_field(data, "confidence"))
    needs_review = bool(data.get("needsReview", False))
    reasoning = data.get("reasoning", "")
    if not isinstance(reasoning, str):
        raise ValidationError("reasoning must be a string")

    validated_answer = validate_options_against(answer, answer_type, options)
    return validated_answer, confidence, needs_review, reasoning.strip()


def validate_response(
    response: AIResponse,
    answer_type: AnswerType,
    options: list[str] | None = None,
) -> tuple[str | list[str] | None, float, bool]:
    """Validate a normalised :class:`AIResponse` from a provider.

    Returns ``(validated_answer, confidence, is_valid)``. On invalid output
    the answer is ``None``, confidence clamps to [0,1], and ``is_valid``
    is False.

    A response is invalid if:
    - the confidence is not a valid finite number,
    - the answer does not match supplied options (select types), or
    - the answer has the wrong shape for the type.
    """
    try:
        clamped = clamp_confidence(response.confidence)
    except ValidationError:
        return None, 0.0, False

    try:
        validated = validate_options_against(response.answer, answer_type, options)
        return validated, clamped, True
    except ValidationError:
        return None, clamped, False

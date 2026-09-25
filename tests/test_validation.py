"""Phase 4 — Validation unit tests.

Covers JSON parsing, required-field checks, confidence clamping, answer
shape checks, and option matching for radio / dropdown / checkbox.
"""

import pytest

from src.answer_engine import (
    AIResponse,
    AnswerType,
    ValidationError,
)
from src.answer_engine.validation import (
    clamp_confidence,
    parse_structured_json,
    validate_options_against,
    validate_response,
)


def test_clamp_confidence_in_range():
    assert clamp_confidence(0.5) == 0.5
    assert clamp_confidence(0) == 0.0
    assert clamp_confidence(1) == 1.0


# ---------------------------------------------------------------------------
# 17. Confidence outside 0–1 → clamped
# ---------------------------------------------------------------------------

def test_clamp_confidence_above_one():
    assert clamp_confidence(1.7) == 1.0
    assert clamp_confidence(99) == 1.0


def test_clamp_confidence_below_zero():
    assert clamp_confidence(-0.4) == 0.0


# ---------------------------------------------------------------------------
# 16. Invalid confidence
# ---------------------------------------------------------------------------

def test_clamp_confidence_non_numeric():
    with pytest.raises(ValidationError):
        clamp_confidence("high")
    with pytest.raises(ValidationError):
        clamp_confidence(None)
    with pytest.raises(ValidationError):
        clamp_confidence(True)


def test_clamp_confidence_nan_or_inf():
    with pytest.raises(ValidationError):
        clamp_confidence(float("nan"))
    with pytest.raises(ValidationError):
        clamp_confidence(float("inf"))


# ---------------------------------------------------------------------------
# Option matching — RADIO / DROPDOWN
# ---------------------------------------------------------------------------

def test_radio_valid_option():
    assert validate_options_against("Blue", AnswerType.RADIO, ["Red", "Blue", "Green"]) == "Blue"


def test_radio_answer_with_whitespace_valid():
    assert (
        validate_options_against("  Blue  ", AnswerType.RADIO, ["Red", "Blue", "Green"])
        == "Blue"
    )


def test_radio_invalid_option():
    with pytest.raises(ValidationError):
        validate_options_against("Purple", AnswerType.RADIO, ["Red", "Blue", "Green"])


def test_radio_list_answer_rejected():
    with pytest.raises(ValidationError):
        validate_options_against(["Red", "Blue"], AnswerType.RADIO, ["Red", "Blue", "Green"])


def test_dropdown_valid_option():
    assert (
        validate_options_against("Bachelor", AnswerType.DROPDOWN, ["Associate", "Bachelor", "Master"])
        == "Bachelor"
    )


def test_dropdown_invalid_option():
    with pytest.raises(ValidationError):
        validate_options_against("Masters", AnswerType.DROPDOWN, ["Associate", "Bachelor", "Master"])


# ---------------------------------------------------------------------------
# Option matching — CHECKBOX
# ---------------------------------------------------------------------------

def test_checkbox_valid_options():
    assert (
        validate_options_against(["Python", "SQL"], AnswerType.CHECKBOX, ["Python", "SQL", "Java"])
        == ["Python", "SQL"]
    )


def test_checkbox_empty_selection_valid():
    assert validate_options_against([], AnswerType.CHECKBOX, ["Python", "SQL"]) == []


def test_checkbox_invalid_option_rejected():
    with pytest.raises(ValidationError):
        validate_options_against(["Python", "COBOL"], AnswerType.CHECKBOX, ["Python", "SQL"])


def test_checkbox_scalar_answer_rejected():
    with pytest.raises(ValidationError):
        validate_options_against("Python", AnswerType.CHECKBOX, ["Python", "SQL"])


def test_checkbox_values_trimmed_for_comparison():
    """Whitespace is trimmed, but matching is case-exact."""
    assert (
        validate_options_against([" Python ", "SQL"], AnswerType.CHECKBOX, ["Python", "SQL"])
        == ["Python", "SQL"]
    )


def test_checkbox_case_mismatch_rejected():
    with pytest.raises(ValidationError):
        validate_options_against(["python", "SQL"], AnswerType.CHECKBOX, ["Python", "SQL"])


# ---------------------------------------------------------------------------
# Non-select types
# ---------------------------------------------------------------------------

def test_text_answer_passthrough():
    assert validate_options_against("  hello ", AnswerType.TEXT, None) == "hello"


def test_email_type_passthrough():
    assert (
        validate_options_against("ada@example.com", AnswerType.EMAIL, None)
        == "ada@example.com"
    )


def test_list_answer_rejected_for_text():
    with pytest.raises(ValidationError):
        validate_options_against(["a", "b"], AnswerType.TEXT, None)


def test_null_answer_allowed():
    assert validate_options_against(None, AnswerType.TEXT, None) is None


# ---------------------------------------------------------------------------
# parse_structured_json — malformed / invalid provider output
# ---------------------------------------------------------------------------

def valid_json() -> str:
    return (
        '{"answer": "Blue", "confidence": 0.92, "needsReview": false, '
        '"reasoning": "Majors match the colour options."}'
    )


def test_parse_structured_json_valid():
    answer, conf, needs_review, reasoning = parse_structured_json(
        valid_json(), AnswerType.RADIO, ["Red", "Blue"]
    )
    assert answer == "Blue"
    assert conf == 0.92
    assert needs_review is False
    assert "colour options" in reasoning


# 15. malformed JSON
def test_parse_malformed_json_raises():
    with pytest.raises(ValidationError, match="malformed JSON"):
        parse_structured_json("{not json", AnswerType.TEXT)


def test_parse_non_object_json_raises():
    with pytest.raises(ValidationError, match="JSON object"):
        parse_structured_json("[1,2,3]", AnswerType.TEXT)


def test_parse_requires_answer_field():
    with pytest.raises(ValidationError, match="answer"):
        parse_structured_json('{"confidence": 0.9}', AnswerType.TEXT)


def test_parse_requires_confidence_field():
    with pytest.raises(ValidationError, match="confidence"):
        parse_structured_json('{"answer": "x"}', AnswerType.TEXT)


def test_parse_invalid_confidence_string():
    with pytest.raises(ValidationError, match="Confidence"):
        parse_structured_json('{"answer": "x", "confidence": "high"}', AnswerType.TEXT)


def test_parse_confidence_outside_range_clamped():
    _, conf_hi, _, _ = parse_structured_json(
        '{"answer": "x", "confidence": 2.5}', AnswerType.TEXT
    )
    _, conf_lo, _, _ = parse_structured_json(
        '{"answer": "x", "confidence": -1.0}', AnswerType.TEXT
    )
    assert conf_hi == 1.0
    assert conf_lo == 0.0


def test_parse_menu_invalid_option_rejected():
    with pytest.raises(ValidationError, match="does not match"):
        parse_structured_json(valid_json(), AnswerType.RADIO, ["Red", "Green"])


# ---------------------------------------------------------------------------
# validate_response — engine-level gate on a normalised AIResponse
# ---------------------------------------------------------------------------

def test_validate_response_valid():
    resp = AIResponse(answer="Blue", confidence=0.9, needs_review=False)
    answer, conf, is_valid = validate_response(resp, AnswerType.RADIO, ["Red", "Blue"])
    assert (answer, conf, is_valid) == ("Blue", 0.9, True)


def test_validate_response_invalid_option():
    resp = AIResponse(answer="Purple", confidence=0.9, needs_review=False)
    answer, _, is_valid = validate_response(resp, AnswerType.RADIO, ["Red", "Blue"])
    assert answer is None
    assert is_valid is False


def test_validate_response_non_numeric_confidence_invalid():
    resp = AIResponse(answer="Blue", confidence="high", needs_review=False)
    answer, conf, is_valid = validate_response(resp, AnswerType.RADIO, ["Red", "Blue"])
    assert answer is None
    assert conf == 0.0
    assert is_valid is False


def test_validate_response_out_of_range_confidence_clamps_but_valid():
    resp = AIResponse(answer="Blue", confidence=1.8, needs_review=False)
    answer, conf, is_valid = validate_response(resp, AnswerType.RADIO, ["Red", "Blue"])
    assert answer == "Blue"
    assert conf == 1.0
    assert is_valid is True
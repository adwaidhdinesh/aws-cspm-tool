"""
Phase 4 — AI Answer Engine types.

Strongly-typed, provider-agnostic data structures shared across the
answer engine, its providers, and its validators. Following the CSPM
project convention of using ``dataclasses`` for structured data (see
``src/inventory/inventory.py``).

These types deliberately contain only what a single answer requires:

- the current question,
- the question type,
- the available options (if any),
- the relevant context (Phase 3 analog),
- minimal answer-format instructions.

They must never carry the full user profile, unrelated questions, browser
state, credentials, or API keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AnswerType(Enum):
    """Kinds of answers the engine can produce.

    Mirrors the form field types supported downstream (radio, checkbox,
    dropdown, free-text, date, time, number, email, and unknown).
    """

    TEXT = "TEXT"
    PARAGRAPH = "PARAGRAPH"
    RADIO = "RADIO"
    DROPDOWN = "DROPDOWN"
    CHECKBOX = "CHECKBOX"
    DATE = "DATE"
    TIME = "TIME"
    NUMBER = "NUMBER"
    EMAIL = "EMAIL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_value(cls, value: str | None) -> "AnswerType":
        """Return the AnswerType for a string value, defaulting to
        UNKNOWN for anything unrecognised (never raise on bad input)."""
        if not value:
            return cls.UNKNOWN
        try:
            return cls(str(value).upper())
        except ValueError:
            return cls.UNKNOWN


# Answer types where the model may only pick from the supplied options.
SINGLE_SELECT_TYPES = (AnswerType.RADIO, AnswerType.DROPDOWN)
# Answer types where the model may pick any subset of the supplied options.
MULTI_SELECT_TYPES = (AnswerType.CHECKBOX,)


@dataclass
class RelevantContext:
    """A single, scoped piece of relevant information about the user.

    ``source`` describes why this context is trustworthy (e.g. "profile",
    "education", "employment") so the engine and provider can reason about
    provenance without receiving the entire profile.
    """

    key: str
    value: str
    source: str = "profile"


@dataclass
class AIRequest:
    """The minimal, strongly-typed request payload sent to an AI provider.

    This is the data-minimisation boundary: only the current question,
    its type, the supplied options, the relevant context, and minimal
    generation instructions are ever transmitted. There is deliberately
    no field for the full profile, other questions, or credentials.
    """

    question: str
    type: AnswerType
    options: list[str] = field(default_factory=list)
    context: list[RelevantContext] = field(default_factory=list)
    instructions: str = ""


@dataclass
class AIResponse:
    """A normalised, provider-agnostic structured answer from an AI
    provider. Providers must return this shape regardless of wire format.
    """

    answer: str | list[str] | None
    confidence: float
    needs_review: bool
    reasoning: str = ""


@dataclass
class GeneratedAnswer:
    """The final, validated answer produced by the Answer Engine.

    ``source`` records where the answer came from:
    - "local": answered deterministically from profile data (no AI call)
    - "user_context": answered from relevant user context
    - "ai": answered through the AI provider
    - "none": could not produce an answer (missing context, provider
      failure, low confidence, invalid output, unsupported type, etc.)

    If ``reasoning`` is included it is a short, factual justification —
    never hidden chain-of-thought.
    """

    question_id: str
    type: AnswerType
    answer: str | list[str] | None
    confidence: float
    source: str  # "local" | "user_context" | "ai" | "none"
    needs_review: bool
    reasoning: str = ""


@dataclass
class UserProfile:
    """The collection of known facts about the user that the engine may
    consult. This is read-only input to the engine — it is never passed to
    an AI provider wholesale. Only the specific, relevant ``RelevantContext``
    values derived from it are ever passed on.

    Fields are intentionally limited to the explicit profile attributes
    the engine understands. Unknown/missing fields are simply absent
    (``None``/empty), so the engine and model never guess.
    """

    full_name: str = ""
    email: str = ""
    phone: str = ""
    college: str = ""
    university: str = ""
    degree: str = ""
    major: str = ""
    city: str = ""
    country: str = ""
    current_employer: str = ""
    job_title: str = ""
    years_of_experience: str = ""
    writing_style: str = ""
    answer_length: str = ""

    def as_context(self, keys: list[str] | None = None) -> list[RelevantContext]:
        """Return the requested fields as a list of RelevantContext values.

        ``keys`` limits which fields are exposed (default: all populated
        fields). This is the boundary that prevents the full profile from
        being shipped to a provider — callers select only what a question
        actually needs.
        """
        allowed = keys if keys is not None else [f.name for f in self.__dataclass_fields__.values()]
        result: list[RelevantContext] = []
        for key in allowed:
            value = getattr(self, key, "")
            if not value:
                continue
            result.append(RelevantContext(key=key, value=str(value), source="profile"))
        return result

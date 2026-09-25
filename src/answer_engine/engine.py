"""
Phase 4 — AI Answer Engine.

Transforms a question into a validated :class:`GeneratedAnswer` using the
following pipeline, in order:

1. **Deterministic / local answer** — if the question can be answered
   directly from known profile fields (name, email, phone, college,
   university, degree, ...), answer locally and never call a provider.
2. **User-context answer** — if the question asks about the user, pass
   ONLY the relevant context to the provider so it can summarise, combine,
   or transform it. The provider must never invent personal facts.
3. **AI answer** — otherwise build a minimal AIRequest and call the
   configured provider, then parse and validate the structured response.
4. **None** — if context is missing, the provider fails, the output is
   invalid, or the confidence is too low, return ``source="none"`` with
   ``needs_review=True``. Never fabricate or auto-select.

The engine depends only on the :class:`AIProvider` protocol — never on
Gemini-specific details — so additional providers can be added later
without touching this module.
"""

from __future__ import annotations

import re
from typing import Any

from src.answer_engine.config import CONFIDENCE_THRESHOLD
from src.answer_engine.prompts import build_ai_request
from src.answer_engine.providers import AIProvider, AIProviderError
from src.answer_engine.types import (
    AIRequest,
    AnswerType,
    GeneratedAnswer,
    MULTI_SELECT_TYPES,
    RelevantContext,
    SINGLE_SELECT_TYPES,
    UserProfile,
)
from src.answer_engine.validation import validate_response


class AnswerEngine:
    """Provider-agnostic answer engine.

    ``provider`` must implement the :class:`AIProvider` protocol.
    """

    def __init__(
        self,
        provider: AIProvider,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ):
        self.provider = provider
        self.confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def answer(
        self,
        question_id: str,
        question: str,
        question_type: AnswerType | str,
        profile: UserProfile,
        options: list[str] | None = None,
        provider: AIProvider | None = None,
    ) -> GeneratedAnswer:
        """Produce a validated answer for one question.

        ``profile`` is the user's known-facts store; only relevant slices
        are ever passed to a provider. ``provider`` optionally overrides the
        engine's default provider (used by tests).
        """
        answer_type = self._coerce_type(question_type)

        # 1. Deterministic local answer from profile fields.
        local = self._try_local_answer(question, answer_type, profile)
        if local is not None and self._local_matches_options(local, answer_type, options):
            return self._local_result(question_id, answer_type, local)

        # 2. User-context path — build the relevant context slice.
        context = self._relevant_context(question, profile)

        # 3. If the question needs user context and we have none, never
        #    guess or fabricate — return "none" without calling a provider.
        #    Exception: select-type questions with options can be answered
        #    purely from the supplied options, so they may proceed to AI.
        if (
            self._requires_user_context(question, answer_type)
            and not context
            and not (answer_type in (SINGLE_SELECT_TYPES + MULTI_SELECT_TYPES) and options)
        ):
            return self._missing_context_result(question_id, answer_type, question)

        # 4. AI path.
        request = build_ai_request(
            question=question,
            answer_type=answer_type,
            options=options,
            context=context,
        )
        active = provider or self.provider
        return self._run_ai(question_id, question, answer_type, options, request, active)

    @staticmethod
    def _local_matches_options(
        local: str, answer_type: AnswerType, options: list[str] | None
    ) -> bool:
        """Whether a deterministic local value is a valid choice for a
        select-type question. If it is not, the AI path (with validation)
        is used instead — we never force an invalid option. When no options
        are supplied there is nothing to validate against, so local answers
        are allowed."""
        if answer_type not in (SINGLE_SELECT_TYPES + MULTI_SELECT_TYPES):
            return True
        if not options:
            return True
        allowed = {o.strip().lower() for o in options}
        return local.strip().lower() in allowed

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_type(question_type: AnswerType | str) -> AnswerType:
        if isinstance(question_type, AnswerType):
            return question_type
        return AnswerType.from_value(question_type)

    @staticmethod
    def _requires_user_context(question: str, answer_type: AnswerType) -> bool:
        """Whether answering this question needs personal user context.

        Returns True when the question text clearly asks about the user
        (name, email, education, employer, ...) or the answer type only
        makes sense with personal data (email). Generic multi-choice
        questions that a model can answer from its options alone (e.g.
        "favourite colour", "which of these...") do NOT require context.
        """
        lowered = question.lower()
        for signal in AnswerEngine._PERSONAL_SIGNALS:
            if signal in lowered:
                return True
        if answer_type == AnswerType.EMAIL:
            return True
        return False

    # Strong signals that a question is asking for personal information.
    _PERSONAL_SIGNALS: tuple[str, ...] = (
        "name",
        "email",
        "phone",
        "college",
        "university",
        "degree",
        "major",
        "city",
        "country",
        "employer",
        "work",
        "company",
        "job title",
        "experience",
        "your skills",
        "yourself",
        "about you",
        "your background",
    )

    @staticmethod
    def _profile_fields(profile: UserProfile) -> dict[str, str]:
        """The explicit, known profile fields (name, email, college, ...)
        keyed by the natural-language phrases a form question might use."""
        return {
            "name": profile.full_name,
            "full name": profile.full_name,
            "full_name": profile.full_name,
            "email": profile.email,
            "email address": profile.email,
            "phone": profile.phone,
            "phone number": profile.phone,
            "mobile": profile.phone,
            "college": profile.college,
            "university": profile.university,
            "degree": profile.degree,
            "education": profile.degree or profile.college,
        }

    def _try_local_answer(
        self, question: str, answer_type: AnswerType, profile: UserProfile
    ) -> str | None:
        """Answer deterministically from profile fields when the question
        is an explicit request for a known fact. Returns None if the
        question is not a deterministic match.

        Uses word-level phrase matching so natural form phrasing such as
        "What is your email?", "Phone number", or "Which college did you
        attend?" resolves to the stored profile value."""
        lowered = question.lower().strip().rstrip("?")
        words = re.split(r"\W+", lowered)
        fields = self._profile_fields(profile)

        for phrase, value in fields.items():
            if not value:
                continue
            if not phrase:
                continue
            phrase_words = phrase.split()

            # Exact single-token match ("email", "college", ...).
            if len(phrase_words) == 1 and phrase in words:
                return value

            # Multi-word phrase match ("phone number", "email address").
            if all(w in words for w in phrase_words):
                return value

            # "your <phrase>" / "what is your <phrase>" phrasing.
            if phrase_words and f"your {phrase}" in lowered:
                return value

        return None

    def _local_result(
        self,
        question_id: str,
        answer_type: AnswerType,
        value: str,
    ) -> GeneratedAnswer:
        return GeneratedAnswer(
            question_id=question_id,
            type=answer_type,
            answer=value,
            confidence=1.0,
            source="local",
            needs_review=False,
            reasoning=f"Answered directly from the stored profile field '{value}'.",
        )

    def _relevant_context(
        self, question: str, profile: UserProfile
    ) -> list[RelevantContext]:
        """Return ONLY the profile fields relevant to the question.

        This is the data-minimisation boundary: the full profile is never
        exposed. If the question is a general "about you" request, a broad
        but still intentional set of fields is used; if it asks about a
        specific attribute, only that attribute is exposed; if it is not
        personal at all, no context is sent.
        """
        lowered = question.lower()

        if re.search(r"\babout you\b", lowered) or "yourself" in lowered or "background" in lowered:
            keys = [f.name for f in UserProfile.__dataclass_fields__.values()]
            return profile.as_context(keys)

        priority_keys: list[str] = []
        for keyword, key in self._CONTEXT_KEYWORDS:
            if keyword in lowered:
                if key not in priority_keys:
                    priority_keys.append(key)
        if not priority_keys:
            return []
        return profile.as_context(priority_keys)

    _CONTEXT_KEYWORDS: list[tuple[str, str]] = [
        ("name", "full_name"),
        ("email", "email"),
        ("phone", "phone"),
        ("college", "college"),
        ("university", "university"),
        ("degree", "degree"),
        ("major", "major"),
        ("city", "city"),
        ("country", "country"),
        ("work", "current_employer"),
        ("employer", "current_employer"),
        ("company", "current_employer"),
        ("job", "job_title"),
        ("experience", "years_of_experience"),
        ("write", "writing_style"),
        ("length", "answer_length"),
        ("answer", "answer_length"),
    ]

    @staticmethod
    def _missing_context_result(
        question_id: str, answer_type: AnswerType, question: str
    ) -> GeneratedAnswer:
        return GeneratedAnswer(
            question_id=question_id,
            type=answer_type,
            answer=None,
            confidence=0.0,
            source="none",
            needs_review=True,
            reasoning=f"Required user context is missing for '{question}'.",
        )

    def _run_ai(
        self,
        question_id: str,
        question: str,
        answer_type: AnswerType,
        options: list[str] | None,
        request: AIRequest,
        provider: AIProvider,
    ) -> GeneratedAnswer:
        try:
            response = provider.generate(request)
        except AIProviderError as exc:
            return self._provider_failure_result(
                question_id, answer_type, question, str(exc)
            )
        except Exception as exc:  # provider must never crash the engine
            return self._provider_failure_result(
                question_id, answer_type, question, f"Unexpected provider error: {type(exc).__name__}"
            )

        return self._validate_ai_response(
            question_id, question, answer_type, options, request, response
        )

    def _provider_failure_result(
        self, question_id: str, answer_type: AnswerType, question: str, reason: str
    ) -> GeneratedAnswer:
        return GeneratedAnswer(
            question_id=question_id,
            type=answer_type,
            answer=None,
            confidence=0.0,
            source="none",
            needs_review=True,
            reasoning=f"AI provider unavailable for '{question}': {reason}",
        )

    def _validate_ai_response(
        self,
        question_id: str,
        question: str,
        answer_type: AnswerType,
        options: list[str] | None,
        request: AIRequest,
        response: Any,
    ) -> GeneratedAnswer:
        """Validate a provider AIResponse and fold the result into a
        GeneratedAnswer. Never trusts provider output blindly."""
        if response is None or not hasattr(response, "answer") or not hasattr(response, "confidence"):
            return self._invalid_result(
                question_id, answer_type, question, "Provider returned a malformed response object."
            )

        validated, confidence, is_valid = validate_response(
            response, answer_type, options
        )
        if not is_valid:
            return self._invalid_result(
                question_id,
                answer_type,
                question,
                "Provider output did not validate against the question",
            )

        confidence = max(0.0, min(1.0, confidence))
        needs_review = bool(getattr(response, "needs_review", False))
        if confidence < self.confidence_threshold:
            needs_review = True
        if answer_type == AnswerType.UNKNOWN:
            needs_review = True

        source = "user_context" if request.context else "ai"
        return GeneratedAnswer(
            question_id=question_id,
            type=answer_type,
            answer=validated,
            confidence=confidence,
            source=source,
            needs_review=needs_review,
            reasoning=getattr(response, "reasoning", "") or "",
        )

    @staticmethod
    def _invalid_result(
        question_id: str, answer_type: AnswerType, question: str, reason: str
    ) -> GeneratedAnswer:
        return GeneratedAnswer(
            question_id=question_id,
            type=answer_type,
            answer=None,
            confidence=0.0,
            source="none",
            needs_review=True,
            reasoning=f"Answer rejected for '{question}': {reason}",
        )
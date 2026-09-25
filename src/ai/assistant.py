"""
AI Security Copilot backend.

Sends the scan context built by context_builder.py, plus the user's
question, to either DeepSeek or Google Gemini, and returns the answer.
Which provider is used is controlled by the AI_PROVIDER environment
variable — everything else in the AI module (context building, the
system prompt) is identical regardless of provider.

Setup (pick one):

    Gemini (recommended — genuine free tier, no credit card):
        1. Get a free API key at https://aistudio.google.com/apikey
        2. export AI_PROVIDER=gemini
        3. export GEMINI_API_KEY=your_key_here

    DeepSeek (cheap, but not free — needs prepaid credit):
        1. Get an API key at https://platform.deepseek.com
        2. export AI_PROVIDER=deepseek
        3. export DEEPSEEK_API_KEY=your_key_here

If AI_PROVIDER isn't set, Gemini is used by default. Requires the
`requests` package (see requirements.txt).

Security notes:
- API keys are read from environment variables only and never appear in
  UI, logs, or exception messages.
- Error messages describe the problem without exposing credentials.
"""

import os

import requests

from src.ai.prompts import SYSTEM_PROMPT, build_user_prompt

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
GEMINI_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"  # free-tier eligible as of 2026
REQUEST_TIMEOUT_SECONDS = 30


class AssistantError(Exception):
    """Raised when the configured AI provider can't be reached, isn't
    configured, or returns something unexpected. Callers (the dashboard)
    should catch this and show the message to the user instead of
    crashing the app."""


def provider_config_status() -> str | None:
    """Return a human-readable message if the selected provider isn't
    properly configured, or None if everything needed is present.

    This lets the dashboard display a setup hint before the user types
    any question, without requiring an API call.
    """
    provider_name = os.environ.get("AI_PROVIDER", "gemini").lower()

    if provider_name == "gemini":
        if not os.environ.get("GEMINI_API_KEY"):
            return (
                "AI Copilot not configured. Set your Gemini API key:\n\n"
                "    export GEMINI_API_KEY=your_key_here\n\n"
                "Get a free key at https://aistudio.google.com/apikey"
            )
        return None

    if provider_name == "deepseek":
        if not os.environ.get("DEEPSEEK_API_KEY"):
            return (
                "AI Copilot not configured. Set your DeepSeek API key:\n\n"
                "    export DEEPSEEK_API_KEY=your_key_here\n\n"
                "Get a key at https://platform.deepseek.com"
            )
        return None

    return (
        f"AI Copilot not configured correctly. Unknown AI_PROVIDER: '{provider_name}'. "
        "Supported providers: gemini, deepseek"
    )


def _extract_content(data: dict, provider: str) -> str:
    """Safely extract the text response from a provider's JSON reply,
    raising a clear error if the shape is unexpected."""
    try:
        if provider == "gemini":
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        else:
            text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise AssistantError(
            f"Received an unexpected response format from {provider}. "
            "Please try again or use a different provider."
        )

    if not text or not text.strip():
        raise AssistantError(
            f"The {provider} provider returned an empty response. "
            "Please try rephrasing your question."
        )
    return text.strip()


def _call_deepseek(question: str, context: dict) -> str:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise AssistantError(
            "DEEPSEEK_API_KEY is not set. Export it, then restart the dashboard."
        )

    payload = {
        "model": os.environ.get("DEEPSEEK_MODEL", DEFAULT_DEEPSEEK_MODEL),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(question, context)},
        ],
        "temperature": 0.2,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        resp = requests.post(
            DEEPSEEK_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.ConnectionError:
        raise AssistantError(
            "Could not connect to DeepSeek API. Check your internet connection."
        )
    except requests.Timeout:
        raise AssistantError(
            "DeepSeek API request timed out. The service may be temporarily unavailable."
        )
    except requests.RequestException as e:
        raise AssistantError(f"Network error reaching DeepSeek API: {type(e).__name__}")

    if resp.status_code == 401 or resp.status_code == 403:
        raise AssistantError(
            "DeepSeek API authentication failed. "
            "Check that your DEEPSEEK_API_KEY is correct and has not expired."
        )
    if resp.status_code == 429:
        raise AssistantError(
            "DeepSeek API rate limit exceeded. Please wait and try again."
        )
    if resp.status_code != 200:
        raise AssistantError(f"DeepSeek API error (HTTP {resp.status_code}). Please try again.")

    data = resp.json()
    return _extract_content(data, "DeepSeek")


def _call_gemini(question: str, context: dict) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise AssistantError(
            "GEMINI_API_KEY is not set. Export it, then restart the dashboard."
        )

    model = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    url = GEMINI_URL_TEMPLATE.format(model=model)

    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [
            {"role": "user", "parts": [{"text": build_user_prompt(question, context)}]}
        ],
        "generationConfig": {"temperature": 0.2},
    }
    headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.ConnectionError:
        raise AssistantError(
            "Could not connect to Gemini API. Check your internet connection."
        )
    except requests.Timeout:
        raise AssistantError(
            "Gemini API request timed out. The service may be temporarily unavailable."
        )
    except requests.RequestException as e:
        raise AssistantError(f"Network error reaching Gemini API: {type(e).__name__}")

    if resp.status_code == 400:
        raise AssistantError(
            "Gemini API rejected the request. "
            "Check that your GEMINI_API_KEY is valid."
        )
    if resp.status_code == 403:
        raise AssistantError(
            "Gemini API access denied. "
            "Check that your GEMINI_API_KEY has not expired or been revoked."
        )
    if resp.status_code == 429:
        raise AssistantError(
            "Gemini API quota exceeded. Please wait and try again."
        )
    if resp.status_code != 200:
        raise AssistantError(f"Gemini API error (HTTP {resp.status_code}). Please try again.")

    data = resp.json()
    return _extract_content(data, "Gemini")


PROVIDERS = {
    "deepseek": _call_deepseek,
    "gemini": _call_gemini,
}


def ask_ai(question: str, context: dict) -> str:
    """Answer a question using the configured provider's model, given a
    scan context dict (see context_builder.build_context). Raises
    AssistantError on any failure — callers decide how to display that.
    """
    if not context or not context.get("failing_findings"):
        raise AssistantError(
            "No scan findings available to analyze. "
            "Run a scan first with: python main.py"
        )

    provider_name = os.environ.get("AI_PROVIDER", "gemini").lower()
    provider_fn = PROVIDERS.get(provider_name)

    if provider_fn is None:
        raise AssistantError(
            f"Unknown AI_PROVIDER '{provider_name}'. "
            f"Supported providers: {', '.join(PROVIDERS)}"
        )

    return provider_fn(question, context)

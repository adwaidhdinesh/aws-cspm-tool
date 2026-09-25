# CSPM Tool — AWS Cloud Security Posture Management

[![CI](https://github.com/adwaidhdinesh/aws-cspm-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/adwaidhdinesh/aws-cspm-tool/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![React 19](https://img.shields.io/badge/frontend-React%2019-61dafb.svg)](frontend/)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688.svg)](api/)

An intelligent AWS Cloud Security Posture Management tool that discovers
your AWS resources into an asset inventory, runs 15 security checks
mapped to the CIS AWS Foundations Benchmark, scores your account's
posture, detects drift between scans, maps findings to NIST 800-53,
PCI DSS v4.0, and ISO/IEC 27001:2022, and displays everything in an
interactive React dashboard with an AI Security Copilot.

## Architecture

For a source-verified index of features, entry points, tests, and configuration,
see [FEATURE_MAP.md](FEATURE_MAP.md). Keep it current whenever a feature, check,
API route, or dashboard section changes.

```
AWS Account
    │
    ▼
Asset Discovery          (src/inventory/) — all boto3 calls happen here
    │
    ▼
Normalized Asset Objects  (src/inventory/inventory.py)
    │
    ▼
15 Security Rule Checks   (src/rules/) — pure functions, never call AWS
    │
    ▼
Findings                  (linked to the asset that produced them)
    │
    ▼
Scoring + Compliance Mapping + Drift Detection
    │
    ▼
PostgreSQL Database       (src/db.py — assets, scans, findings tables)
    │
    ▼
FastAPI JSON API          (api/main.py)
    │
    ▼
React Dashboard           (frontend/) + AI Security Copilot (src/ai/)
```

The key design boundary: **boto3 calls only happen in `src/inventory/aws_inventory.py`**.
Rules only ever read `Asset.metadata` — they can be unit-tested without AWS credentials
and adding a new check never means adding a boto3 call somewhere unexpected.

## Features

- Discovers assets across **8 AWS services**: IAM, S3, EC2, CloudTrail, RDS, KMS, VPC, Lambda
- **15 security checks**, each mapped to a CIS AWS Foundations Benchmark control ID, each linked to the specific asset it evaluated
- **Soft-deleted resources** — resources that disappear from a scan are kept as `DELETED` rather than removed, preserving historical visibility
- Posture **scoring** (0–100) by severity weight with letter grades A–F
- **Compliance mapping** to NIST 800-53 Rev. 5, PCI DSS v4.0, and ISO/IEC 27001:2022 with per-framework control tables and CSV export
- **Drift detection** — detects NEW_FAIL, RESOLVED, NEW_RESOURCE, and REMOVED_RESOURCE between consecutive scans
- **AI Security Copilot** — context-grounded Q&A about your scan results using Google Gemini or DeepSeek
- **Phase 4 — AI Answer Engine** — provider-agnostic, validated answer generation (Gemini only, see below)
- Dashboard tabs: **Assets**, **Findings**, **Compliance**, **Drift**, **AI Copilot**

## Project Structure

```
cspm-project/
├── AGENTS.md                   # Agent workflow and feature-map maintenance rule
├── FEATURE_MAP.md              # Source-verified feature/module routing index
├── main.py                     # CLI entry point — runs a scan
├── api/main.py                 # FastAPI dashboard API
├── frontend/                   # Vite + React dashboard
├── docker-compose.yml          # Local PostgreSQL environment
├── pytest.ini                  # Pytest marker configuration
├── requirements.txt            # Runtime dependencies
├── requirements-dev.txt        # Development-only dependencies (pytest)
├── latest_findings.json        # JSON snapshot of last scan
├── tests/
│   ├── test_*.py               # Unit tests (no Docker or AWS required)
│   └── contract/               # Real AWS contract tests (opt-in only)
│       └── test_real_aws.py
├── scripts/
│   └── migrate_sqlite_to_postgres.py  # One-time history migration
└── src/
    ├── __init__.py
    ├── aws_client.py            # boto3 session/client helpers
    ├── scanner.py               # Orchestrates rule checks over assets
    ├── scoring.py               # Posture score calculation
    ├── compliance.py            # CIS → NIST/PCI/ISO control mapping
    ├── drift.py                 # Compares findings between scans
    ├── db.py                    # PostgreSQL: assets, scans, findings
    ├── inventory/
    │   ├── inventory.py         # Asset dataclass
    │   └── aws_inventory.py     # All boto3 calls — discovers assets
    ├── rules/                   # Pure functions: Asset list → findings
    │   ├── iam_rules.py
    │   ├── s3_rules.py
    │   ├── ec2_rules.py
    │   ├── cloudtrail_rules.py
    │   ├── rds_rules.py
    │   ├── kms_rules.py
    │   ├── vpc_rules.py
    │   └── lambda_rules.py
    └── ai/                      # AI Security Copilot
        ├── prompts.py           # System prompt (anti-hallucination)
        ├── context_builder.py   # Builds compact scan summary for LLM
        └── assistant.py         # Gemini / DeepSeek provider interface
    └── answer_engine/           # Phase 4 — AI Answer Engine
        ├── types.py             # AnswerType, AIRequest, AIResponse, GeneratedAnswer
        ├── config.py            # Gemini provider configuration (env-based)
        ├── engine.py            # AnswerEngine pipeline (local → context → AI)
        ├── prompts.py           # Prompt builder (prompt-injection hardened)
        ├── validation.py        # Structured-output validation
        └── providers/
            ├── __init__.py      # AIProvider protocol + provider registry
            ├── gemini.py        # GeminiProvider (current v1beta API)
            └── mock.py          # MockAIProvider (tests only)
```

## Setup

### 1. Create a virtual environment

**Linux / macOS:**
```bash
python -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
# Runtime dependencies
pip install -r requirements.txt

# For running tests (development only)
pip install -r requirements-dev.txt
```

Runtime dependencies: `boto3`, `psycopg`, `fastapi`, `uvicorn`, `requests`.

The React dashboard additionally requires Node.js 20 or later.

### 3. Start PostgreSQL

```bash
docker compose up -d postgres
export DATABASE_URL=postgresql://cspm:cspm@localhost:5432/cspm
```

The scanner and API create the required tables on startup. If you copy
`.env.example` to `.env`, load it before running the scanner:

```bash
set -a; source .env; set +a
```

To preserve existing local SQLite history, import it once after PostgreSQL starts:

```bash
python scripts/migrate_sqlite_to_postgres.py --sqlite-path cspm.db
```

### 4. Configure AWS credentials

Use any standard boto3 credential method:

```bash
aws configure
# or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
```

The IAM identity needs **read-only** permissions. The `SecurityAudit`
AWS managed policy covers everything this tool needs.

### 5. Run a scan

```bash
python main.py

# Optional: specify a named profile and/or region
python main.py --profile my-aws-profile --region us-west-2
```

This discovers your asset inventory, runs every rule against it, prints
a summary, saves everything to PostgreSQL, and writes `latest_findings.json`.

### 6. Launch the dashboard

```bash
# Terminal 1: API
uvicorn api.main:app --reload

# Terminal 2: React client
cd frontend
npm install
npm run dev
```

### 7. Run tests

```bash
# Unit tests (no Docker or AWS needed)
pytest tests/test_*.py

# Optional real AWS contract tests (requires AWS credentials + CSPM_RUN_AWS_TESTS=1)
pytest -m aws
```

The standard unit suite runs without AWS credentials — they use manually
created Asset objects to test rules, scoring, drift detection, and
compliance mapping. The Phase 4 engine tests use a `MockAIProvider` and
never require a Gemini key, internet access, or a live API.

## AI Security Copilot

The AI Copilot is a context-grounded assistant that answers questions
about your scan results. It does **not** have access to your AWS account,
cannot run new scans, and will clearly say so when asked about
information not in the provided scan context.

### Provider setup (pick one)

**Google Gemini (recommended — free tier):**
1. Get a free API key at https://aistudio.google.com/apikey
2. Export the environment variable:
   ```bash
   export AI_PROVIDER=gemini
   export GEMINI_API_KEY=your_key_here
   ```

**DeepSeek (paid, low cost):**
1. Get an API key at https://platform.deepseek.com
2. Export the environment variables:
   ```bash
   export AI_PROVIDER=deepseek
   export DEEPSEEK_API_KEY=your_key_here
   ```

If `AI_PROVIDER` is not set, Gemini is used by default.

API keys are read from environment variables only and are never exposed
in the UI, logs, or JSON output.

### Suggested questions

- What are my most critical security issues?
- What should I fix first?
- Explain the most severe finding in simple terms.
- Which services have the most issues?
- How has my security posture changed?

## Phase 4 — AI Answer Engine

Adapted to this project's Python architecture. The Answer Engine is a
**provider-agnostic** component that turns a question into a **validated**
``GeneratedAnswer``. It answers from three sources, in order of preference:

```
Question
   ↓
1. Deterministic / local answer   (explicit profile fields — no AI call)
   ↓
2. Relevant user context          (profile slice passed to the provider)
   ↓
3. AI provider call               (GeminiProvider — structured JSON out)
   ↓
Answer validation                 (options, confidence, JSON shape)
   ↓
Validated GeneratedAnswer
```

Only **Google Gemini** is implemented as an external provider. The
provider interface (``AIProvider``) is provider-agnostic by design so
DeepSeek / OpenRouter / Ollama can be added later without rewriting the
engine.

### Module layout

| File | Responsibility |
|------|----------------|
| `src/answer_engine/types.py` | `AnswerType`, `AIRequest`, `AIResponse`, `GeneratedAnswer`, `UserProfile`, `RelevantContext` |
| `src/answer_engine/engine.py` | `AnswerEngine` — the local → context → AI pipeline |
| `src/answer_engine/providers/` | `AIProvider` protocol, provider registry, `GeminiProvider`, `MockAIProvider` |
| `src/answer_engine/prompts.py` | Prompt builder — untrusted-data boundaries + injection hardening |
| `src/answer_engine/validation.py` | JSON / option / confidence validation (never trusts the model) |
| `src/answer_engine/config.py` | Gemini configuration (env-based, like `src/ai/assistant.py`) |

### Gemini configuration

The API key comes from the environment only — never hardcoded, never
logged, never stored in a file:

```bash
export GEMINI_API_KEY=your_key_here        # required
export GEMINI_MODEL=gemini-2.5-flash       # optional (current default)
export GEMINI_TIMEOUT_MS=30000             # optional
export GEMINI_TEMPERATURE=0.2              # optional
export GEMINI_MAX_TOKENS=1024              # optional
```

Get a free key at https://aistudio.google.com/apikey. The provider uses
the current official `v1beta` `generateContent` endpoint with
`responseMimeType: application/json` for structured output.

### Privacy & data minimization

The engine ships only the minimum data needed to answer one question:

- **Never** sends the full profile, unrelated questions, form metadata,
  DOM, browser state, or credentials.
- For a *specific* question ("Which college did you attend?") only that
  profile field is sent.
- For a *general* "about you" question a broad-but-intentional slice is
  sent; for non-personal questions no context is sent at all.
- The API key is never included in requests' body, generated answers,
  error messages, or logs.
- The model is instructed that question/options/context are **untrusted
  data** — embedded instructions inside a question are treated as data,
  not followed.

### Supported answer types

`TEXT`, `PARAGRAPH`, `RADIO`, `DROPDOWN`, `CHECKBOX`, `DATE`, `TIME`,
`NUMBER`, `EMAIL`, `UNKNOWN`.

- RADIO/DROPDOWN: Gemini must return exactly one of the supplied options;
  anything else is rejected (`answer = None`, `needs_review = True`).
- CHECKBOX: every returned value must be a supplied option; any invalid
  value rejects the whole answer.
- TEXT/PARAGRAPH: concise / context-grounded free text. When a personal
  question lacks context, the engine returns `source="none"` rather than
  fabricating.
- Confidence is clamped to 0–1; low-confidence, invalid, or malformed
  output always sets `needs_review`.

### Usage

```python
from src.answer_engine import AnswerEngine, GeminiProvider, GeminiConfig, UserProfile, AnswerType

profile = UserProfile(full_name="Ada Lovelace", email="ada@example.com", ...)
engine = AnswerEngine(GeminiProvider(GeminiConfig()))
result = engine.answer("q1", "What is your email?", AnswerType.EMAIL, profile)
# GeneratedAnswer(question_id="q1", type=EMAIL, answer="ada@example.com",
#                 confidence=1.0, source="local", needs_review=False, ...)
```

### Current limitations

- **Gemini only** — DeepSeek / OpenRouter / Ollama providers are *not*
  implemented yet, though the registry makes them straightforward to add.
- **No web research** — the engine never searches the web.
- **No automatic form submission or browser autofill** — engine produces
  a `GeneratedAnswer` only.
- **No DOM interaction** — this module is independent of any UI.
- **No API key UI/storage** — following this project's convention, the key
  is read from the environment rather than stored in a browser.

## Security Checks (15 total)

| Rule ID    | CIS Control | Severity | Check |
|-----------|-------------|----------|-------|
| IAM-001   | 1.5         | Critical | Root account MFA enabled |
| IAM-002   | 1.10        | High     | IAM users with console access have MFA |
| IAM-003   | 1.16        | Critical | Customer-managed policies with wildcard admin |
| S3-001    | 2.1.5       | Critical | S3 buckets not publicly accessible |
| S3-002    | 2.1.1       | Medium   | S3 default encryption enabled |
| EC2-001   | 5.2         | Critical | Security groups don't allow unrestricted sensitive port access |
| EC2-002   | CUSTOM-2    | Medium   | EC2 instances with public IP flagged for review |
| CT-001    | 3.1         | High     | Active multi-region CloudTrail exists |
| CT-002    | 3.2         | Medium   | CloudTrail log file validation enabled |
| RDS-001   | 2.3.2       | Critical | RDS instances not publicly accessible |
| RDS-002   | 2.3.1       | High     | RDS storage encryption enabled |
| KMS-001   | 2.8         | Medium   | Customer-managed symmetric KMS key rotation |
| VPC-001   | 5.3         | Medium   | Default security group has no inbound rules |
| VPC-002   | 3.9         | Medium   | VPC flow logging enabled |
| LAMBDA-001| CUSTOM-1    | Critical | Lambda function resource policy not public |

## Compliance Framework Mapping

Every CIS finding is mapped to equivalent controls in:

- **NIST 800-53 Rev. 5**
- **PCI DSS v4.0**
- **ISO/IEC 27001:2022**

These mappings are simplified for illustrative/educational use and are
**not** an official crosswalk. For real compliance audits, use your
framework's published control mapping documentation or a certified GRC tool.

## Drift Detection

Findings are matched across scans by `(rule_id, service, resource)`.
The dashboard's Drift tab compares the selected scan against the
immediately preceding scan for the same account and classifies every
change:

- **NEW_FAIL** — a check that used to pass now fails (regression)
- **RESOLVED** — a check that used to fail now passes
- **NEW_RESOURCE** — a resource that wasn't seen in the previous scan
- **REMOVED_RESOURCE** — a resource from the previous scan no longer exists

Only requires running `python main.py` more than once against the same
account — no extra setup needed.

## Testing strategy

Unit tests cover discovery-independent rules, scoring, compliance, drift,
AI context construction, and answer validation using deterministic fixtures.
They run without Docker or AWS credentials:

```bash
pytest tests/test_*.py
```

The opt-in real-AWS contract suite validates selected discovery behavior
against an authenticated account:

```bash
CSPM_RUN_AWS_TESTS=1 pytest -m aws
```

## Adding a New Service

1. Add a `discover_<service>_assets(session, account_id)` function to
   `src/inventory/aws_inventory.py` that returns a `list[Asset]`, with
   whatever config the rules will need in `Asset.metadata`. Register it
   in `ALL_DISCOVERERS`.
2. Add a new `src/rules/<service>_rules.py` with functions that take
   `assets: list[Asset]`, filter by `resource_type`, and return finding
   dicts. Register each in `scanner.py`'s `ALL_RULES`.
3. Add the CIS control mapping to `compliance.py`'s `CIS_TO_FRAMEWORKS`.

## Limitations

- **Single AWS account per scan** — multi-account support would require
  an assumed-role credential flow and an accounts table.
- **Single-region resource discovery** — EC2, RDS, VPC, Lambda, and KMS
  discoverers currently scan only the configured/session region.
  Resources in other regions are not found. A future enhancement would
  automatically discover and scan across all enabled AWS regions.
- **Read-only scanning** — the tool never modifies any AWS resource.
- **No automatic remediation** — findings include remediation guidance
  but the tool does not apply fixes.
- **No built-in scheduler** — run scans manually or schedule via
  cron/Lambda externally.
- **No multi-cloud support** — AWS only.
- **Compliance mappings are illustrative** — not official audit-grade
  control crosswalks.
- **AI Copilot analyzes provided scan context only** — it does not
  independently access AWS or run new scans.

## Suggested Next Steps

- Asset search/filtering by tag (e.g. "everything owned by team X")
- Scheduled scanning (cron / Lambda) for continuous monitoring
- Slack/email alerting on new Critical findings
- Multi-account support with assumed-role credential flow

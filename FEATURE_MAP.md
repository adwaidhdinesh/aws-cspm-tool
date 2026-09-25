# CSPM feature map

Source-verified reference map for routing implementation and review work. Read this file before broad repository exploration, then inspect the linked source and tests before changing behavior.

## Architecture and entry points

| Feature / code path | Entry point and implementation | Trigger | Tests | Config / dependencies |
| --- | --- | --- | --- | --- |
| Run an AWS posture scan | `main.py:main()` coordinates authentication, discovery, `db.save_assets()`, `scanner.run_scan()`, `calculate_score()`, and `db.save_scan()` | `python main.py`; optional `--profile`, `--region`, and `--endpoint-url` flags | The rule, scoring, and discovery layers are covered below; end-to-end persistence is in `tests/integration/test_end_to_end_floci.py` | AWS credentials supplied through standard boto3 resolution; `AWS_ENDPOINT_URL`; `DATABASE_URL`; `boto3`, `psycopg` |
| Create AWS session and determine account | `src/aws_client.py:get_session()`, `get_client()`, `get_account_id()` | Called by `main.py`; Floci scripts and tests use the same AWS conventions | Real-account smoke coverage: `tests/contract/test_real_aws.py`; discovery coverage: `tests/integration/` | boto3 profile/credential chain, CLI region, optional endpoint override; botocore retry config |
| Normalize AWS resources | `src/inventory/inventory.py:Asset` dataclass; `Asset.key()` defines cross-scan identity | Every discovery function returns these objects; every rule receives them | Rule unit tests construct `Asset` data in `tests/test_*_rules.py` | Python dataclasses only |
| Discover AWS inventory | `src/inventory/aws_inventory.py:discover_assets()` dispatches to `discover_iam_assets()`, `discover_s3_assets()`, `discover_ec2_assets()`, `discover_cloudtrail_assets()`, `discover_rds_assets()`, `discover_kms_assets()`, `discover_vpc_assets()`, and `discover_lambda_assets()` | Called once per CLI scan before any rules run | `tests/integration/test_iam_discovery_floci.py`, `test_s3_discovery_floci.py`, `test_ec2_discovery_floci.py`, `test_other_services_floci.py`; real AWS: `tests/contract/test_real_aws.py` | boto3 clients via `src/aws_client.py`; AWS/Floci endpoint and credentials |
| Run all registered security checks | `src/scanner.py:ALL_RULES` registers 15 checks; `run_scan()` invokes each and isolates a failing rule from the rest of a scan | Called by `main.py` after discovery | Individual rule tests below; complete scan: `tests/integration/test_end_to_end_floci.py` | Pure Python after discovery; no rule calls boto3 directly |
| Build a standard finding | `src/rules/_helpers.py:make_finding()` | Called by security-check functions | Indirectly covered by every rule test | Finding dictionaries carry rule, CIS, severity, resource, status, description, and remediation fields |

## Security checks

All checks are triggered together by `src/scanner.py:run_scan()` during `python main.py`. They read normalized `Asset.metadata`, never boto3 directly.

| Feature (plain language) | Implementation | Tests | Key inputs / dependencies |
| --- | --- | --- | --- |
| Root account MFA | `src/rules/iam_rules.py:check_root_mfa()` | `tests/test_iam_rules.py` | IAM `RootAccount` asset metadata |
| IAM console-user MFA | `src/rules/iam_rules.py:check_iam_user_mfa()` | `tests/test_iam_rules.py` | IAM `User` metadata, including console access and MFA state |
| Wildcard administrator policy | `src/rules/iam_rules.py:check_wildcard_admin_policies()` | `tests/test_iam_rules.py` | IAM policy metadata; discovery helper `_has_full_wildcard()` |
| S3 public access | `src/rules/s3_rules.py:check_public_buckets()` | `tests/test_s3_rules.py` | S3 bucket public-access metadata |
| S3 default encryption | `src/rules/s3_rules.py:check_bucket_encryption()` | `tests/test_s3_rules.py` | S3 bucket encryption metadata |
| EC2 security groups open to sensitive ports | `src/rules/ec2_rules.py:check_open_security_groups()` | `tests/test_ec2_rules.py` | EC2 security-group metadata; discovery helper `_find_open_sensitive_ports()` |
| EC2 instances with public IPs | `src/rules/ec2_rules.py:check_instance_public_ip()` | `tests/test_ec2_rules.py` | EC2 instance state and public-IP metadata |
| Multi-region CloudTrail logging | `src/rules/cloudtrail_rules.py:check_cloudtrail_enabled()` | `tests/test_cloudtrail_rules.py` | CloudTrail inventory metadata |
| CloudTrail log-file validation | `src/rules/cloudtrail_rules.py:check_cloudtrail_log_validation()` | `tests/test_cloudtrail_rules.py` | CloudTrail validation metadata |
| Publicly accessible RDS instances | `src/rules/rds_rules.py:check_rds_public_access()` | `tests/test_rds_rules.py` | RDS instance public-access metadata |
| RDS storage encryption | `src/rules/rds_rules.py:check_rds_encryption()` | `tests/test_rds_rules.py` | RDS instance encryption metadata |
| KMS key rotation | `src/rules/kms_rules.py:check_kms_key_rotation()` | `tests/test_kms_rules.py` | Symmetric KMS key rotation metadata |
| Default security-group traffic restriction | `src/rules/vpc_rules.py:check_default_sg_restricts_traffic()` | `tests/test_vpc_rules.py` | VPC default security-group ingress metadata |
| VPC flow logs | `src/rules/vpc_rules.py:check_vpc_flow_logs_enabled()` | `tests/test_vpc_rules.py` | VPC flow-log metadata |
| Public Lambda function access | `src/rules/lambda_rules.py:check_lambda_public_access()` | `tests/test_lambda_rules.py` | Lambda resource-policy/public-access metadata |

## Results, history, and compliance

| Feature / code path | Entry point and implementation | Trigger | Tests | Config / dependencies |
| --- | --- | --- | --- |
| Posture score and grade | `src/scoring.py:calculate_score()` and `score_grade()` | CLI scan and React overview/API responses | `tests/test_scoring.py` | Finding severities and statuses; no external dependency |
| CIS-to-framework mapping | `src/compliance.py:CIS_TO_FRAMEWORKS`, `get_mapped_controls()`, `format_mapped_controls()`, `compliance_summary()`, and `framework_score()` | Findings are persisted with mappings; Compliance tab requests `GET /api/scans/{scan_id}/compliance` | `tests/test_compliance.py` | Built-in illustrative mappings for NIST 800-53, PCI DSS v4.0, and ISO 27001:2022 |
| PostgreSQL schema and scan history | `src/db.py:init_db()`, `save_assets()`, `save_scan()`, `get_all_scans()`, `get_scan()`, `get_assets_for_account()`, `get_findings_for_scan()`, and related asset/finding lookups | `main.py` persists scans; API reads them; API lifespan initializes schema | `tests/integration/test_end_to_end_floci.py` exercises persistence as part of the Floci suite | `DATABASE_URL`; `psycopg`; PostgreSQL service in `docker-compose.yml` |
| Soft-deleted assets | `src/db.py:save_assets()` marks previously active but undiscovered resources as `DELETED` rather than removing them | Each successful CLI discovery/save operation; visible in React Assets tab | Covered indirectly by persistence flow; no dedicated unit test currently | PostgreSQL `assets.status`; current account inventory |
| SQLite history import (one-time migration) | `scripts/migrate_sqlite_to_postgres.py:main()` | Manual command: `python scripts/migrate_sqlite_to_postgres.py --sqlite-path cspm.db` | No dedicated test currently | Legacy SQLite file, `DATABASE_URL`, `sqlite3`, and `psycopg` |
| Historical drift comparison | `src/drift.py:compare_scans()` and `summarize_drift()`; `src/db.py:get_previous_scan()` | React Drift tab requests `GET /api/scans/{scan_id}/drift` | `tests/test_drift.py` | Two persisted scans for the same account; findings match by rule, service, and resource |

## API and React dashboard

| Feature / code path | Entry point and implementation | Trigger | Tests | Key config / dependencies |
| --- | --- | --- | --- |
| Dashboard API | `api/main.py`; FastAPI routes: `/health`, `/api/scans`, scan/findings/assets routes, compliance, drift, and copilot routes | `uvicorn api.main:app --reload`; React calls it over HTTP | No dedicated API endpoint test currently | `DATABASE_URL`; `CORS_ORIGINS`; FastAPI, Uvicorn |
| React application shell and scan selector | `frontend/src/main.jsx`; `frontend/src/App.jsx:App()` initial scan-loading effects; `frontend/src/api.js:api()` | `cd frontend && npm run dev` | Production build: `npm --prefix frontend run build`; no frontend test suite currently | React, Vite; `VITE_API_URL` or Vite's API proxy |
| Legacy Streamlit dashboard (inactive) | `dashboard.py` | Manual `streamlit run dashboard.py` only after separately installing its historical Streamlit/pandas dependencies | No dedicated test currently | Retained for reference; it is not installed, documented as supported, or exercised by the current CI |
| Overview at a glance | `frontend/src/App.jsx` `tab === "Overview"`; `Trend()` and `openPriorityFinding()` | React **Overview** tab, default view | No frontend test currently | Scans, findings, and assets API data |
| Asset inventory and details | `frontend/src/App.jsx` `tab === "Assets"` | React **Assets** tab | No frontend test currently | `GET /api/scans/{scan_id}/assets`; asset tags and metadata from PostgreSQL |
| Findings review and CSV export | `frontend/src/App.jsx` `tab === "Findings"`; `FindingRow()` and `csvDownload()` | React **Findings** tab and filter/download controls | No frontend test currently | `GET /api/scans/{scan_id}/findings`; browser Blob download API |
| Compliance mapping view | `frontend/src/App.jsx` `tab === "Compliance"`; lazy-load effect | React **Compliance** tab | No frontend test currently | `GET /api/scans/{scan_id}/compliance` |
| Drift view | `frontend/src/App.jsx` `tab === "Drift"`; lazy-load effect | React **Drift** tab | No frontend test currently | `GET /api/scans/{scan_id}/drift` |
| AI Copilot view | `frontend/src/App.jsx` `tab === "AI Copilot"` and `submitQuestion()` | React **AI Copilot** tab; user submits a question | Context generation: `tests/test_context_builder.py`; provider behavior: `tests/test_gemini_provider.py` | Copilot API routes; `AI_PROVIDER`, provider key/model variables below |
| Dashboard styles and responsiveness | `frontend/src/styles.css` | Imported by `frontend/src/main.jsx` | No frontend test currently | Native CSS; supports reduced motion and responsive layout |

## AI features

| Feature / code path | Entry point and implementation | Trigger | Tests | Config / dependencies |
| --- | --- | --- | --- |
| CSPM Copilot context | `src/ai/context_builder.py:build_context()` limits context to worst failing findings | API `POST /api/scans/{scan_id}/copilot` | `tests/test_context_builder.py` | Persisted scan/findings and `src.compliance.get_mapped_controls()` |
| CSPM Copilot provider calls | `src/ai/assistant.py:provider_config_status()` and `ask_ai()` delegate to `_call_gemini()` or `_call_deepseek()`; prompts in `src/ai/prompts.py` | API copilot status/question routes | Gemini provider tests: `tests/test_gemini_provider.py` | `AI_PROVIDER` (`gemini` default or `deepseek`), `GEMINI_API_KEY`/`GEMINI_MODEL`, `DEEPSEEK_API_KEY`/`DEEPSEEK_MODEL`, `requests` |
| Provider-agnostic Answer Engine | `src/answer_engine/engine.py:AnswerEngine.answer()`; types in `types.py`, prompt construction in `prompts.py`, validation in `validation.py`, providers in `providers/` | Not exposed by `main.py` or the React dashboard currently; usable by Python callers | `tests/test_answer_engine.py`, `tests/test_validation.py`, `tests/test_prompts.py`, `tests/test_gemini_provider.py` | Gemini configuration in `src/answer_engine/config.py`; provider registry in `src/answer_engine/providers/__init__.py` |

## Development and test support

| Feature / code path | Entry point and implementation | Trigger | Tests / verification | Key config / dependencies |
| --- | --- | --- | --- |
| Local AWS emulator fixtures | `docker-compose.floci.yml`; `scripts/seed_floci.py:main()`; `scripts/reset_floci.py:main()` | Start Floci with Docker Compose, then seed/reset scripts | `tests/integration/` | Floci endpoint (normally `http://localhost:4566`), test AWS credentials, Docker |
| Unit suite | `tests/test_*.py` | `pytest tests/test_*.py` | 164 tests at the time this map was written | pytest and pure-Python/mocked dependencies |
| GitHub Actions CI | `.github/workflows/ci.yml` runs Python unit/compile checks, the React production build, and the Floci integration flow | Pushes and pull requests targeting `main` | Executes the suites and build listed in adjacent rows | GitHub Actions; Python 3.11, Node 20, Floci Docker service, and PostgreSQL service |
| Floci integration suite | `tests/integration/conftest.py` and test modules | `pytest -m integration` with Floci running and PostgreSQL configured for persistence coverage | Discovery and scan pipeline integration tests | Docker/Floci, boto3 test credentials, `DATABASE_URL` for persistence test |
| Real AWS contract suite | `tests/contract/test_real_aws.py` | `CSPM_RUN_AWS_TESTS=1 pytest -m aws` | Opt-in live AWS discovery contracts | Real AWS credentials and explicit opt-in variable |

## Current architecture note

The active application uses **PostgreSQL**, **FastAPI**, and a **React/Vite** dashboard. SQLite is retained only as an optional import source in `scripts/migrate_sqlite_to_postgres.py`. `dashboard.py` is retained as an inactive Streamlit reference, but Streamlit is not part of the supported runtime requirements or CI path.

## Maintenance rule

Update this map as the final step whenever a task adds, removes, or materially changes a user-facing feature, security check, dashboard section, API route, configuration input, test location, or major module. Verify paths and names from source before editing; if a relationship is uncertain, label it as uncertain instead of inferring it.

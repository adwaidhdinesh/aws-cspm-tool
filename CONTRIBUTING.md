# Contributing to AWS CSPM Tool

Thank you for considering contributing! This project aims to be a practical, recruiter-visible demonstration of cloud security engineering — and real contributions make it better.

## Ways to Contribute

- 🐛 **Bug reports** — open an issue with clear reproduction steps
- ✨ **New security checks** — add a rule module following the pattern below
- 📝 **Documentation** — improve README, add examples, fix typos
- 🧪 **Tests** — increase coverage, especially for rules and scoring
- 🎨 **Dashboard** — improve the React UI / visualizations

## Adding a New Security Check

1. Create or edit a rule module in `src/rules/<service>_rules.py`
2. Each rule is a pure function that:
   - Takes a list of normalized `Asset` objects as input: `assets: list[Asset]`
   - Filters by `resource_type` (e.g. `asset.resource_type == "s3_bucket"`)
   - Evaluates `asset.metadata` without making any external AWS API calls
   - Returns a list of standard finding dicts created with `make_finding()`:

```python
{
    "rule_id": "S3-001",
    "cis_control": "2.1.5",
    "title": "S3 bucket allows public read access",
    "severity": "Critical",      # Critical | High | Medium | Low
    "resource": "my-bucket-name",
    "status": "FAIL",            # FAIL | PASS
    "description": "...",
    "remediation": "..."
}
```

3. Register the function in `src/scanner.py`'s `ALL_RULES` list
4. If the rule maps to a new CIS control, add it to `src/compliance.py`'s `CIS_TO_FRAMEWORKS`
5. **Add tests** — every rule should have unit tests in `tests/test_<service>_rules.py` using mock `Asset` objects (no AWS credentials required)

## Development Setup

```bash
git clone https://github.com/adwaidhdinesh/aws-cspm-tool.git
cd aws-cspm-tool
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-mock
```

## Before Submitting a PR

- ✅ Run `pytest` — all tests pass
- ✅ Run `python main.py` against a test account or local emulator
- ✅ Update README if behavior changes
- ✅ No real credentials, hardcoded secrets, or personal data in code

## Code Style

- Follow PEP 8
- Keep functions focused and single-purpose
- Add docstrings to new functions
- Any feature that adds new rule families/checks should also include the roadmap doc (README) note

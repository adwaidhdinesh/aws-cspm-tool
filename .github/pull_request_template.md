## Description

Briefly describe what this PR changes and why.

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change fixing an issue)
- [ ] ✨ New security check / rule
- [ ] 🚀 New feature (API, dashboard, inventory)
- [ ] 📝 Documentation update
- [ ] 🧪 Tests / CI improvement
- [ ] 🔧 Refactoring / Maintenance

## Checklist

- [ ] All tests pass locally (`pytest tests/test_*.py` and `npm --prefix frontend run build`)
- [ ] New security checks follow the pure-function architecture (no boto3 calls in rules)
- [ ] Added unit tests covering new rules, edge cases, and compliance mappings
- [ ] Updated `FEATURE_MAP.md` if adding, removing, or modifying features/rules/endpoints
- [ ] Updated `README.md` / `CONTRIBUTING.md` if applicable
- [ ] No hardcoded secrets, personal tokens, or live AWS credentials included

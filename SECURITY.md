# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x | ✅ |
| < 2.0 | ❌ |

## Reporting a Vulnerability

This project involves scanning cloud infrastructure, so security is taken seriously.

**Please do NOT open a public issue for security vulnerabilities.**

To report a vulnerability:

1. **Email:** adwaidhdinesh2006@gmail.com
2. Include:
   - Description of the vulnerability
   - Affected component/module
   - Steps to reproduce (if possible)
   - Impact assessment

You should receive a response within **48 hours**. If the issue is confirmed, a fix will be released as soon as possible, and you'll be credited (if desired).

## Security Notes

- This tool requires **read-only** IAM permissions. Never run it with write/administrative credentials.
- Never commit real AWS credentials to this repository — use environment variables or AWS SSO.
- Test findings are generated from the free/public EC2 instances list for legitimate testing purposes only.
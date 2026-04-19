# Security Policy

## Supported Versions

Security fixes are prioritized for the latest version of the project on the default branch.

If you maintain a private fork or older deployment, please upgrade to the latest version before requesting support.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Instead, report them privately to the project maintainer.

Suggested contact line for you to customize:

- Security contact: geniusg@live.com

If possible, include:

- A clear description of the issue
- Steps to reproduce
- The affected area of the application
- Potential impact
- Suggested remediation, if you have one

You can expect:

- An acknowledgement after the report is received
- A good-faith review of the report
- Reasonable effort to confirm and address valid issues
- Coordination on disclosure timing where appropriate

## What Counts as a Security Issue

Examples include:

- Authentication bypass
- Authorization or role escalation issues
- Exposure of encrypted or plaintext device passwords
- Session, JWT, or cookie handling flaws
- SQL injection or unsafe database access
- Backup or restore abuse
- Sensitive data leakage
- Vulnerabilities caused by insecure default configuration

## Disclosure Policy

Please allow time for investigation and remediation before any public disclosure. Public disclosure before a fix is available may put users at risk.

## Security Best Practices for Contributors

- Never commit secrets or `.env` files
- Never post credentials, tokens, or database dumps in issues or pull requests
- Sanitize logs, screenshots, and sample data
- Review auth and permission changes carefully
- Prefer private reporting for anything that could put deployments or data at risk

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older releases | No |

Only the latest version on the `main` branch receives updates. If you are using
a pinned release, upgrade to the latest before reporting.

## Reporting a Vulnerability

If you discover a security issue in this tool, please report it privately.

**Contact:** [soroka.tech/contact](https://www.soroka.tech/contact)

Do **not** open a public GitHub issue for security reports.

### What counts as a security issue

- **False negatives** -- a real vulnerability pattern that the scanner fails to detect
- **Pattern bypasses** -- a way to write vulnerable code that evades an existing grep pattern
- **Malicious pattern injection** -- a crafted input that causes the scanner to execute unintended commands
- **Information disclosure** -- the scanner leaking sensitive data from the scanned project into logs or reports

### What does not count

- False positives (use the False Positive issue template instead)
- Feature requests for new patterns
- Documentation errors

## Response Timeline

- **Acknowledge:** within 48 hours
- **Triage:** within 5 business days
- **Fix (critical):** within 7 days
- **Fix (non-critical):** included in the next release

We will credit you in the CHANGELOG unless you prefer to remain anonymous.

## Scope

This tool performs static analysis only. It does not execute the code it scans,
make network requests against target systems, or modify any files in the scanned
project. It is not a substitute for professional penetration testing.

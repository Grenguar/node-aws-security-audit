# Contributing to Node.js AWS Security Audit

Thank you for your interest in improving this security audit skill. Contributions from the community help make this tool more effective at catching real-world vulnerabilities.

## Getting Started

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/Grenguar/node-aws-security-audit.git
   cd node-aws-security-audit
   ```

2. There is no build step. The project consists of shell scripts and markdown files. You need:
   - Bash 4+ (macOS users: `brew install bash`)
   - `grep` (GNU grep recommended)
   - A Node.js project to test against

3. Familiarize yourself with the project structure:
   - `SKILL.md` -- the main skill definition consumed by AI coding agents
   - `scripts/` -- shell scripts that perform the actual checks
   - `references/` -- vulnerability catalog and supporting data

## Types of Contributions Welcome

- **New vulnerability patterns** -- grep patterns that detect insecure code in Node.js/AWS projects
- **Framework-specific rules** -- checks for Express, NestJS, Fastify, Koa, Bun, and other frameworks
- **False positive fixes** -- refining patterns to reduce noise
- **Documentation improvements** -- clarifying instructions, adding examples, fixing typos
- **Infrastructure checks** -- new rules for AWS Lambda, Docker, Terraform, CloudFormation, or Serverless configs

## How to Add a New Vulnerability Pattern

1. **Identify the vulnerability.** Reference a CVE, OWASP category, or known insecure pattern. Document why it is dangerous.

2. **Add the grep pattern** to the vulnerability catalog in `references/`. Include:
   - The pattern itself
   - A description of what it catches
   - The severity level
   - A reference link (CVE, OWASP, or advisory URL)

3. **If the vulnerability is tied to a built-in Node.js API**, add a corresponding check to `scripts/node-version-check.sh`.

4. **Test against a sample project.** Run the audit against at least one real Node.js project that contains the vulnerable pattern. Confirm the pattern triggers correctly and does not produce false positives on safe code.

5. **Submit a pull request** following the PR expectations below.

## How to Report False Positives

If the tool flags code that is not actually vulnerable, please open an issue using the **False Positive** issue template:

[Open a false positive report](https://github.com/Grenguar/node-aws-security-audit/issues/new)

Include the code snippet that was flagged, the pattern that matched, and an explanation of why the code is safe.

## Code Style

- All bash scripts must use `set -uo pipefail` at the top.
- Grep patterns belong in the vulnerability catalog markdown files under `references/`, not hardcoded in scripts where avoidable.
- Keep `SKILL.md` under 200 lines. It is the primary interface for AI agents and must remain focused.
- Use consistent formatting in markdown: ATX-style headers, fenced code blocks with language tags, and one sentence per line where practical.

## Pull Request Expectations

Every PR should include:

1. **A description of what the pattern catches.** Name the vulnerability class, affected API or framework, and severity.
2. **A vulnerable code example.** Show a minimal snippet that the new pattern detects.
3. **Evidence of testing.** Confirm you ran the check against at least one real project. Mention the project name or describe the test setup.
4. **No unrelated changes.** Keep PRs focused on a single vulnerability pattern or fix.

## Good First Issues

Looking for a place to start? Check the issues labeled as good first issues:

[Good first issues](https://github.com/Grenguar/node-aws-security-audit/labels/good%20first%20issue)

## Questions?

Open a discussion or issue on the repository. For security-sensitive matters, see [SECURITY.md](SECURITY.md).

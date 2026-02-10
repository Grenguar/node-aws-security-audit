# Node.js Security Audit Skill

OWASP Top 10 security audits for Node.js -- right inside your AI coding agent.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent_Skills-Compatible-blue)](https://agentskills.io)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top_10:2021-orange)](https://owasp.org/Top10/)

Ask your agent to audit your code. Get a scored report with findings, file locations, and fix suggestions. No dashboards, no separate tools.

See a [sample audit report](examples/sample-report.md) to preview the output.

---

## Quick Start

```bash
npx skills add Grenguar/node-aws-security-audit
```

Then ask your agent:

```
> audit my project for security vulnerabilities
```

That's it. You'll get a `security-audit-report.md` with a score (0-100), findings by severity, and quick wins.

---

## What You Get

- **Security score (0-100)** with letter grade (A+ to F) and visual progress bar
- **Findings by severity** -- Critical, High, Medium, Low -- each with file locations, vulnerable code, and fix
- **Quick Wins** -- top 3-5 easiest fixes ranked by score impact
- **Dependency scan** -- `npm audit` integration with outdated/unpinned/deprecated package detection
- **OWASP Top 10:2021** full coverage mapped to Node.js patterns

---

## Try It

Clone the [sample vulnerable app](examples/sample-vulnerable-app/) and run an audit to see it in action:

```bash
cd examples/sample-vulnerable-app
# Ask your agent: "audit this project for security vulnerabilities"
```

The sample app contains intentional vulnerabilities across Express, Lambda, Docker, Serverless Framework, and webpack configurations. The [sample audit report](examples/sample-report.md) shows what the output looks like.

---

## Example Output

<details>
<summary>Show example audit output</summary>

```
Security Score: 58 / 100 (C) -- Concerning
[███████████░░░░░░░░░] 58/100

| Severity | Count | Top Finding                              |
|----------|-------|------------------------------------------|
| Critical | 1     | SQL Injection in src/routes/users.js:42  |
| High     | 2     | Missing CSRF protection across 5 routes  |
| Medium   | 4     | No rate limiting on auth endpoints       |
| Low      | 2     | console.log with PII in src/utils/log.js |

Quick Wins:
1. Install helmet middleware (+5 pts)
2. Parameterize SQL queries (+15 pts)
3. Add rate limiting (+5 pts)

Projected score after Quick Wins: 83 / 100 (B)
```

Each finding includes the vulnerable code snippet, attack vector explanation, and remediation code.

</details>

---

## Install

### Using the `skills` CLI (recommended)

```bash
npx skills add Grenguar/node-aws-security-audit
```

Target a specific agent:

```bash
npx skills add Grenguar/node-aws-security-audit -a codex
npx skills add Grenguar/node-aws-security-audit -a cursor
npx skills add Grenguar/node-aws-security-audit -a windsurf
npx skills add Grenguar/node-aws-security-audit -a auto      # auto-detect
```

Add `-g` for global install (all projects) or omit for project-level.

### Quick install script

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Grenguar/node-aws-security-audit/main/install.sh)
```

### Manual

<details>
<summary>Clone to your agent's skill directory</summary>

| Agent | Path |
|-------|------|
| Claude Code | `~/.claude/skills/nodejs-security-audit` |
| Codex | `~/.agents/skills/nodejs-security-audit` |
| Cursor | `~/.cursor/skills/nodejs-security-audit` |
| Windsurf | `~/.codeium/windsurf/skills/nodejs-security-audit` |
| Project-level | `.claude/skills/nodejs-security-audit` |

```bash
git clone https://github.com/Grenguar/node-aws-security-audit.git <path-from-table>
```

</details>

---

## Usage

```
> audit my project for security vulnerabilities
> run a security review
> check for OWASP vulnerabilities
> is my code secure?
> scan for injection vulnerabilities
> check my dependencies
```

In Claude Code you can also run `/nodejs-security-audit` directly.

---

## Supported Frameworks and Platforms

### Web Frameworks

| Framework | Key Checks |
|-----------|-----------|
| **Express** | helmet, CORS, body limits, sessions, trust proxy, error handling, HPP |
| **NestJS** | Guards, ValidationPipe, DTO validation, TypeORM/Prisma injection, Swagger exposure, GraphQL depth limiting |
| **Fastify** | Schema validation, @fastify/helmet, rate limit, CSRF, plugin encapsulation, TypeBox schema injection |
| **Koa** | koa-helmet, CSRF, static files, mass assignment, rate limiting |

### Runtimes

| Runtime | Key Checks |
|---------|-----------|
| **Node.js** | Version-to-CVE mapping, EOL detection, OpenSSL version, built-in API vulnerabilities |
| **Bun** | Bun.serve() headers, Bun shell injection, bun:sqlite injection, Bun.file() path traversal |

### Serverless and Containers

| Platform | Key Checks |
|----------|-----------|
| **AWS Lambda** | Event source injection, IAM over-permission, function URL auth, /tmp abuse, credential caching |
| **Docker / ECS / Fargate** | Running as root, secrets in Dockerfile, .dockerignore, multi-stage builds, ALB/WAF |

### AWS Services

| Service | Key Checks |
|---------|-----------|
| **Amplify Gen 2** | Authorization config, Cognito settings, sandbox/production leaks |
| **AppSync GraphQL** | @auth directives, introspection, resolver injection, query depth/complexity |
| **AppSync Events** | Channel authorization, namespace permissions, WebSocket security |

### Infrastructure as Code

| IaC Tool | Key Checks |
|----------|-----------|
| **Terraform** | IAM wildcards, plaintext secrets, privileged containers, state encryption (Checkov/tfsec cross-ref) |
| **CloudFormation / SAM** | Wildcard IAM, hardcoded secrets, missing VPC/DLQ, ECS Exec (cfn-nag cross-ref) |
| **Serverless Framework** | Wildcard IAM, per-function roles, missing authorizers, cors: true, deployment bucket encryption |

### Build Tools

| Tool | Key Checks |
|------|-----------|
| **webpack** | Source maps in production, eval devtools, DefinePlugin env leaks, dev-server exposure |

---

## Requirements

- **Node.js** and **npm** installed
- **bash** shell (macOS, Linux, or WSL)
- An AI coding agent that supports skills

---

## Limitations

- Static analysis only -- no runtime testing
- Pattern-based -- manual review recommended for Critical/High findings
- Not a substitute for professional penetration testing

---

## Contributing

Contributions welcome -- new vulnerability patterns, framework rules, and false positive improvements.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request expectations. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Looking for a place to start? Check the issues labeled [good first issue](https://github.com/Grenguar/node-aws-security-audit/labels/good%20first%20issue).

Found a false positive? Open an issue using the [false positive template](https://github.com/Grenguar/node-aws-security-audit/issues/new?template=false_positive.yml). Have an idea for a new check? Use the [feature request template](https://github.com/Grenguar/node-aws-security-audit/issues/new?template=feature_request.yml).

---

## Security

Found a false negative or bypass? See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## About

Open-source project by **[Soroka Tech](https://soroka.tech)** -- full-stack cloud consulting.

Need a professional security assessment or remediation? [Contact us](https://soroka.tech).

---

## License

MIT -- see [LICENSE](LICENSE).

---

## References

- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Agent Skills Specification](https://agentskills.io)
- [`skills` CLI by Vercel](https://github.com/vercel-labs/skills)
- [Sample audit report](examples/sample-report.md)

---

[GitHub](https://github.com/Grenguar/node-aws-security-audit) | [Soroka Tech](https://soroka.tech)

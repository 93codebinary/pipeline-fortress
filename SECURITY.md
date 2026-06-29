# Security Policy — PipelineFortress

## Overview

PipelineFortress wraps **OWASP Juice Shop** — an intentionally vulnerable web application — in a secure CI/CD pipeline. While Juice Shop's vulnerabilities are deliberate and expected, we do not want to be surprised by zero-day vulnerabilities in the **pipeline infrastructure itself** (GitHub Actions workflows, Kubernetes manifests, Docker images, gateway services, or LLM integration components).

---

## Supported Versions

Security patches are provided for the latest released version of the pipeline.

| Version | Supported |
|:--------|:----------|
| Latest (master) | ✅ |
| Older commits | ❌ |

For OWASP Juice Shop application versions, refer to the [upstream security policy](https://github.com/juice-shop/juice-shop/security/policy):

| Version | Supported |
|:--------|:----------|
| 20.1.x | ✅ |
| < 20.1 | ❌ |

---

## Scope

### In scope — report these

- Vulnerabilities in the **GitHub Actions pipeline** (`.github/workflows/devsecops-pipeline.yml`)
- Security issues in the **LLM Gateway** (`gateway/llm-gateway/llm_gateway.py`)
- Weaknesses in the **redaction layer** (`scripts/redact.py`) that allow secrets or source code to reach the LLM API
- Misconfigurations in **Kubernetes manifests** (`k8s/`)
- Prompt injection bypasses in the **LLM triage tool**
- Secrets exposed in pipeline logs, artifacts, or commit history
- Authentication or rate-limiting bypass in the **API Gateway** (Kong config)

### Out of scope — these are intentional

- Vulnerabilities **inside OWASP Juice Shop** — these are deliberate challenges by design
- CVEs in Juice Shop's `node_modules` — tracked by Trivy SCA with a known threshold of 5
- ZAP DAST findings against the running Juice Shop instance — expected and documented in `docs/baseline-vulnerabilities.md`

---

## Reporting a Vulnerability

For vulnerabilities in the **pipeline infrastructure** that are not part of any challenge or known baseline finding, please report via the repository:

**GitHub:** [github.com/93codebinary/pipeline-fortress](https://github.com/93codebinary/pipeline-fortress)

Open a **private security advisory**:
1. Go to the repo → **Security** tab → **Advisories** → **New draft security advisory**
2. Describe the vulnerability, affected component, and reproduction steps
3. Do **not** open a public GitHub issue for security vulnerabilities

For OWASP Juice Shop application vulnerabilities unrelated to hacking challenges, contact the upstream project leads at [bjoern.kimminich@owasp.org](mailto:bjoern.kimminich@owasp.org).

> Reported pipeline vulnerabilities that demonstrate a genuine security weakness may be incorporated as new pipeline hardening controls with credit to the reporter.

---

## Responsible Disclosure Guidelines

- All testing must be confined to your **own local lab or sandbox environment**
- Do **not** test against any shared or production instance
- Do **not** use automated scanners against infrastructure you do not own
- Do **not** exfiltrate data, modify production manifests, or disrupt CI/CD runs
- Allow reasonable time for a fix before any public disclosure

---

## Whistleblower Policy

For concerns that cannot be resolved through standard reporting channels, the [OWASP Whistleblower Policy](https://policy.owasp.org/operational/whistleblower.html) provides additional guidance and protection for reporters.

---

## Security Controls Already in Place

The following controls are active in this pipeline. If you find a bypass for any of these, please report it:

| Control | Implementation | Location |
|---|---|---|
| Secrets scanning | Gitleaks (full git history) | Job 1 — pipeline |
| SAST | Semgrep OWASP Top 10 rulesets | Job 2 — pipeline |
| Dependency CVE scan | Trivy FS | Job 3 — pipeline |
| Container image scan | Trivy image tarball | Job 5 — pipeline |
| IaC misconfiguration | Checkov CIS Kubernetes | Job 6 — pipeline |
| DAST | OWASP ZAP baseline | Job 8 — pipeline |
| LLM redaction layer | 9-category pattern stripping | `scripts/redact.py` |
| Prompt injection detection | 8 injection patterns | `gateway/llm-gateway/llm_gateway.py` |
| API authentication | Kong key-auth plugin | `gateway/api-gateway/kong.yaml` |
| Rate limiting | 20 req/min per consumer | Kong + Redis |
| Network policy | Default-deny + allowlist | `k8s/networkpolicy.yaml` |
| Non-root containers | `runAsNonRoot: true` | `k8s/deployment.yaml` |

---

## Attribution

This security policy is based on the [OWASP Juice Shop Security Policy](https://github.com/juice-shop/juice-shop/security/policy) and extended to cover the PipelineFortress DevSecOps pipeline infrastructure.

**GitHub:** [@93codebinary](https://github.com/93codebinary)

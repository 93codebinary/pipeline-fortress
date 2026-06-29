# 🛡️ PipelineFortress — Secure CI/CD DevSecOps Pipeline

[![Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?logo=githubactions)](https://github.com/features/actions)
[![Secrets](https://img.shields.io/badge/Secrets-Gitleaks-red)](https://github.com/gitleaks/gitleaks)
[![SAST](https://img.shields.io/badge/SAST-Semgrep-blue)](https://semgrep.dev)
[![SCA](https://img.shields.io/badge/SCA-Trivy-1904DA)](https://trivy.dev)
[![IaC](https://img.shields.io/badge/IaC-Checkov-brightgreen)](https://www.checkov.io)
[![DAST](https://img.shields.io/badge/DAST-OWASP%20ZAP-purple)](https://www.zaproxy.org)
[![SBOM](https://img.shields.io/badge/SBOM-Syft-yellow)](https://github.com/anchore/syft)
[![Docker](https://img.shields.io/badge/Registry-Docker%20Hub-2496ED?logo=docker)](https://hub.docker.com)
[![GitOps](https://img.shields.io/badge/GitOps-ArgoCD-EF7B4D?logo=argo)](https://argo-cd.readthedocs.io)

## Overview

**PipelineFortress** is a production-grade DevSecOps CI/CD pipeline wrapping **OWASP Juice Shop** — a deliberately vulnerable web application — with 8 automated security gates. Every push to `master` triggers the full pipeline: secrets scanning, static analysis, dependency scanning, container build, image scanning, IaC scanning, SBOM generation, dynamic application testing, and a GitOps manifest update.

> ⚠️ OWASP Juice Shop is intentionally vulnerable. This pipeline exists to detect, report, and gate on those vulnerabilities. Never deploy Juice Shop to a public-facing production environment.

---

## Pipeline Architecture

```
git push → master
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   GITHUB ACTIONS PIPELINE                       │
│                                                                 │
│  Job 1 ──▶ 🔑 Gitleaks       Secrets scan (full git history)   │
│                │               Gate: 0 secrets — HARD FAIL     │
│          ┌─────┴─────┐                                          │
│  Job 2 ──▶ Semgrep   │  Job 3 ──▶ Trivy FS (SCA)              │
│  (SAST)  │ OWASP Top │           Dependency CVE scan           │
│          │ 10 + JWT  │           Gate: CRITICAL CVEs > 5       │
│          └─────┬─────┘                │                         │
│                └──────────┬───────────┘                         │
│  Job 4 ──▶ 🐳 Docker Build + Push to Docker Hub                │
│                │                                                │
│     ┌──────────┼──────────┐                                     │
│     ▼          ▼          ▼                                     │
│  Job 5      Job 6      Job 7                                    │
│  Trivy      Checkov    Syft                                     │
│  Image      IaC Scan   SBOM                                     │
│  Scan       k8s/       JSON +                                   │
│             manifests  SPDX                                     │
│     └──────────┼──────────┘                                     │
│                ▼                                                │
│  Job 8 ──▶ 🕷️ OWASP ZAP DAST Baseline Scan                    │
│                │               Gate: 0 HIGH alerts             │
│                ▼                                                │
│  Job 9 ──▶ ☸️ GitOps Update                                    │
│              Update deployment.yaml + version.txt              │
│              git commit + push → ArgoCD syncs cluster          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Gates

| Job | Tool | Type | Gate Condition | On Fail |
|---|---|---|---|---|
| 1 | Gitleaks | Secrets | Any secret in git history | ❌ Hard fail |
| 2 | Semgrep | SAST | Any ERROR-level finding | ❌ Hard fail |
| 3 | Trivy FS | SCA | CRITICAL CVEs > 5 | ❌ Hard fail |
| 4 | Docker | Build | Build failure | ❌ Hard fail |
| 5 | Trivy Image | Container | Any CRITICAL OS CVE | ❌ Hard fail |
| 6 | Checkov | IaC | Any CRITICAL/HIGH misconfiguration | ❌ Hard fail |
| 7 | Syft | SBOM | Generation failure | ⚠️ Warn only |
| 8 | OWASP ZAP | DAST | Any HIGH risk alert | ❌ Hard fail |

> The SCA gate threshold is 5 (not 0) because Juice Shop intentionally ships vulnerable packages (`node-serialize` RCE, `vm2` sandbox escape) as part of its challenge design. For a real production app this must be 0.

---

## Pipeline Flow — Job by Job

### Job 1 — 🔑 Secrets Scan (Gitleaks)

Runs **first** across the full git commit history (`fetch-depth: 0`). Uses Gitleaks built-in ruleset to detect 150+ secret types — API keys, JWT tokens, passwords, private keys, connection strings. Hard fails on any detection. Results saved as SARIF artifact.

### Job 2 — 🔍 SAST (Semgrep) ← parallel with Job 3

Static Application Security Testing using six Semgrep rulesets:

| Ruleset | What it catches |
|---|---|
| `p/javascript` | General JS security issues |
| `p/nodejs` | Node.js specific vulnerabilities |
| `p/owasp-top-ten` | OWASP A01–A10 patterns |
| `p/jwt` | JWT algorithm confusion, weak secrets |
| `p/xss` | Reflected, stored, DOM XSS |
| `p/sql-injection` | SQLi and ORM injection |

Gate: Hard fail on any `ERROR`-level finding. File-exists and empty-file guards prevent crashes if Semgrep exits without writing output.

### Job 3 — 📦 SCA / Dependency Scan (Trivy FS) ← parallel with Job 2

Scans `package.json` and `node_modules` for known CVEs using Trivy in filesystem mode. Reports CRITICAL and HIGH severity only. Gate: fail if CRITICAL CVE count exceeds 5.

### Job 4 — 🐳 Build & Push Docker Image

Only triggers after both Job 2 and Job 3 pass. Key fix applied here: `version.txt` may contain a float (`1.0`) which breaks bash integer arithmetic. The pipeline strips the decimal with `cut -d'.' -f1` before incrementing. Image tagged with auto-incremented version and pushed to Docker Hub. Saved as `.tar` artifact for Jobs 5 and 7 to download (prevents cross-job file loss on separate runners).

### Job 5 — 🛡️ Container Image Scan (Trivy Image) ← parallel with Jobs 6 and 7

Downloads the `.tar` artifact from Job 4 and scans OS and runtime layers for CVEs. Gate: zero tolerance for CRITICAL CVEs in OS/runtime layers. Application dependency CVEs are handled separately by Job 3.

### Job 6 — 🏗️ IaC Scan (Checkov) ← parallel with Jobs 5 and 7

Scans all YAML files in `k8s/` against CIS Kubernetes benchmarks. Checks enforced include non-root containers, resource limits, security contexts, image tag pinning, and capability dropping. Gate: fail on any CRITICAL or HIGH misconfiguration. MEDIUM and LOW are soft-fail (collected but not blocking).

### Job 7 — 📋 SBOM Generation (Syft) ← parallel with Jobs 5 and 6

Generates a Software Bill of Materials in two formats from the Docker image:
- `sbom.json` — Syft native format (full package inventory)
- `sbom.spdx.json` — SPDX industry standard (required for EO 14028 supply chain compliance)

Artifacts retained for 90 days for compliance audit trail. Non-blocking gate.

### Job 8 — 🕷️ DAST (OWASP ZAP Baseline)

Runs only after Jobs 5, 6, and 7 all complete. Loads the Docker image, starts Juice Shop on port 3000, polls until HTTP 200, then runs ZAP baseline scan (passive crawl + limited active probes). Gate: fail on any HIGH risk alert (riskcode=3). Container is always stopped in cleanup regardless of gate result.

### Job 9 — ☸️ GitOps Update

Runs only after all security gates pass. Recalculates version (fresh runner — no GITHUB_ENV from Job 4), updates `deployment.yaml` image tag with `sed`, writes new version to `version.txt`, commits both files, and pushes back to the repo. ArgoCD watches the repo and auto-syncs the Kubernetes cluster when this commit lands.

---

## Repository Structure

```
pipeline-fortress/
│
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml    ← Full 9-job pipeline
│
├── k8s/
│   ├── deployment.yaml               ← Kubernetes Deployment (image tag auto-updated)
│   ├── service.yaml                  ← NodePort / LoadBalancer service
│   └── networkpolicy.yaml            ← Default-deny NetworkPolicy
│
├── scripts/
│   ├── redact.py                     ← LLM redaction layer (Week 3)
│   ├── triage.py                     ← LLM triage orchestrator
│   ├── merge_findings.py             ← Multi-scanner output merger
│   └── prompts/                      ← LLM prompt library
│       ├── triage_system.txt
│       ├── triage_user.txt
│       ├── fix_system.txt
│       ├── fix_user.txt
│       ├── pr_system.txt
│       └── pr_user.txt
│
├── gateway/
│   ├── llm-gateway/
│   │   ├── llm_gateway.py            ← FastAPI LLM Gateway service
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── api-gateway/
│       └── kong.yaml                 ← Kong API Gateway config
│
├── docs/
│   ├── baseline-vulnerabilities.md   ← OWASP Top 10 baseline catalogue
│   ├── sbom/                         ← Generated SBOM outputs
│   └── metrics-dashboard.md          ← Vulnerability metrics
│
├── Dockerfile                        ← Juice Shop container definition
├── deployment.yaml                   ← K8s Deployment (GitOps target)
├── version.txt                       ← Auto-incremented image version
└── README.md
```

---

## Setup Instructions

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Git | 2.40+ | Source control |
| Docker Desktop | 24.0+ | Local build and test |
| kubectl | 1.28+ | Kubernetes CLI |

### GitHub Secrets Required

Go to your repo → **Settings → Secrets and variables → Actions → New repository secret**

| Secret | Description |
|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token (not password) — generate at hub.docker.com → Account Settings → Security |
| `GIT_EMAIL` | Email for automated git commits in Job 9 |
| `GIT_USERNAME` | Username for automated git commits in Job 9 |
| `GITHUB_TOKEN` | Auto-provided by GitHub — do NOT create manually |

### Enable Workflow Write Permissions

Go to **Settings → Actions → General → Workflow permissions**
→ Select **Read and write permissions** → Save

This is required for Job 9 to push the updated `deployment.yaml` back to the repo.

### Trigger the Pipeline

```bash
# Any push to master triggers all 9 jobs
git add .
git commit -m "feat: trigger pipeline"
git push origin master
```

---

## Artifacts — Accessing Reports

After each pipeline run, download reports from:
**GitHub → Actions → click the run → scroll to Artifacts**

| Artifact | File | Contents |
|---|---|---|
| `gitleaks-report` | `results.sarif` | Secrets found in git history |
| `semgrep-report` | `semgrep-results.sarif` | SAST code findings |
| `trivy-fs-report` | `trivy-fs-results.json` | Dependency CVEs |
| `trivy-image-report` | `trivy-image-results.json` | Container image CVEs |
| `checkov-report` | `checkov-results.json` | IaC misconfigurations |
| `sbom-reports` | `sbom.json` + `sbom.spdx.json` | Full package inventory |
| `zap-dast-report` | `zap-report.html` + `zap-report.json` | DAST findings |

> Tip: Download `zap-report.html` and open it directly in a browser for a formatted DAST report with no tools needed.

---

## Version Management

The pipeline uses an auto-incrementing integer version stored in `version.txt`.

**Important:** `version.txt` must contain a plain integer (e.g. `1`), not a float (e.g. `1.0`). If you see the error `invalid arithmetic operator (error token is ".0 + 1")`, edit `version.txt` and change the value to a plain integer.

The pipeline strips any decimal automatically using:
```bash
RAW=$(cat version.txt)
INT=$(echo "$RAW" | cut -d'.' -f1)
VERSION=$(( INT + 1 ))
```

---

## GitOps Flow

```
All 8 security gates pass
        │
        ▼
Job 9 updates deployment.yaml
  image: dockerhub/gitops-juiceshop-devsecops:<NEW_VERSION>
        │
        ▼
git commit + push → master
        │
        ▼
ArgoCD detects manifest drift
        │
        ▼
kubectl apply → rolling update on Kubernetes cluster
```

-
*Secure by default. Automated by design. Deployed with GitOps.*

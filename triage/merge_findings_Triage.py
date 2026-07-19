#!/usr/bin/env python3
"""Merge all scanner outputs into one consolidated_findings.json."""
import json, os, hashlib

def load(path):
    if not os.path.exists(path):
        print(f"[skip] {path} not found"); return None
    try:
        with open(path) as f: return json.load(f)
    except Exception as e:
        print(f"[warn] could not parse {path}: {e}"); return None

findings = []

def add(tool, severity, title, file="", line=0, cve="", description=""):
    fid = hashlib.md5(f"{tool}|{title}|{file}|{line}|{cve}".encode()).hexdigest()[:10]
    findings.append({
        "id": fid, "tool": tool,
        "severity": (severity or "UNKNOWN").upper(),
        "title": title, "file": file, "line": line, "cve": cve,
        "description": (description or "")[:500],
    })

# --- Semgrep (SARIF format) ---
data = load("semgrep-results.sarif")
if data:
    for r in data.get("runs", [{}])[0].get("results", []):
        loc = r.get("locations", [{}])[0].get("physicalLocation", {})
        add("semgrep", "HIGH" if r.get("level") == "error" else "MEDIUM",
            r.get("ruleId", "semgrep-finding"),
            loc.get("artifactLocation", {}).get("uri", ""),
            loc.get("region", {}).get("startLine", 0),
            "", r.get("message", {}).get("text", ""))

# --- gitleaks (SARIF). NOTE: gitleaks output can contain the ACTUAL secret,
# so we deliberately write a fixed description and never copy its message. ---
data = load("results.sarif")
if data:
    for r in data.get("runs", [{}])[0].get("results", []):
        loc = r.get("locations", [{}])[0].get("physicalLocation", {})
        add("gitleaks", "CRITICAL", r.get("ruleId", "secret-detected"),
            loc.get("artifactLocation", {}).get("uri", ""),
            loc.get("region", {}).get("startLine", 0),
            "", "Hard-coded secret detected (value withheld)")

# --- Trivy: dependency scan + image scan ---
for path, tool in [("trivy-fs-results.json", "trivy-sca"),
                   ("trivy-image-results.json", "trivy-image")]:
    data = load(path)
    if data:
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                add(tool, v.get("Severity", ""),
                    f"{v.get('PkgName','?')} {v.get('InstalledVersion','')}",
                    result.get("Target", ""), 0,
                    v.get("VulnerabilityID", ""), v.get("Title", ""))

# --- Checkov ---
data = load("checkov-results.json")
if data:
    for r in (data if isinstance(data, list) else [data]):
        for c in r.get("results", {}).get("failed_checks", []):
            add("checkov", c.get("severity") or "MEDIUM", c.get("check_id", ""),
                c.get("file_path", ""), 0, "", c.get("check_name", ""))

# --- OWASP ZAP ---
data = load("zap-report.json")
if data:
    riskmap = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for alert in data.get("site", [{}])[0].get("alerts", []):
        add("zap", riskmap.get(str(alert.get("riskcode", "")), "MEDIUM"),
            alert.get("name", ""), alert.get("site", ""), 0,
            "", alert.get("desc", ""))

with open("consolidated_findings.json", "w") as f:
    json.dump(findings, f, indent=2)
print(f"Consolidated {len(findings)} findings -> consolidated_findings.json")

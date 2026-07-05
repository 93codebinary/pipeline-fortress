#!/usr/bin/env python3
"""
merge_findings.py — PipelineFortress finding consolidator

Reads the raw output files from every scanner in the pipeline
(Gitleaks, Semgrep, Trivy FS, Trivy Image, Checkov, ZAP) and merges
them into a single JSON file using DefectDojo's "Generic Findings
Import" schema, so the whole run can be imported into DefectDojo
with one API call.

Usage:
    python3 merge_findings.py --outdir . --output all-findings.json

All input files are optional — if a report doesn't exist (e.g. a
job was skipped or produced no artifact), it's silently skipped
rather than failing the whole run.
"""

import argparse
import json
import os
import sys

# Severity mapping -> DefectDojo's expected values
DOJO_SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium",
                    "low": "Low", "info": "Info", "informational": "Info",
                    "warning": "Medium", "error": "High"}


def sev(s):
    return DOJO_SEVERITIES.get(str(s).strip().lower(), "Info")


def safe_load(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [warn] could not parse {path}: {e}", file=sys.stderr)
        return None


def parse_sarif(path, tool_name):
    """Generic SARIF parser — covers Gitleaks and Semgrep SARIF output."""
    data = safe_load(path)
    if not data:
        return []
    findings = []
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule = rules.get(result.get("ruleId"), {})
            level = result.get("level", "warning")
            locations = result.get("locations", [])
            file_path, line = None, None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            findings.append({
                "title": f"[{tool_name}] {result.get('ruleId', 'finding')}",
                "description": result.get("message", {}).get("text", "") or rule.get("shortDescription", {}).get("text", ""),
                "severity": sev(level),
                "file_path": file_path,
                "line": line,
                "vuln_id_from_tool": result.get("ruleId"),
                "static_finding": True,
                "dynamic_finding": False,
            })
    return findings


def parse_trivy(path, tool_name):
    """Trivy filesystem or image scan JSON (vuln scanner output)."""
    data = safe_load(path)
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        for v in result.get("Vulnerabilities", []) or []:
            findings.append({
                "title": f"[{tool_name}] {v.get('VulnerabilityID', 'CVE')} in {v.get('PkgName', target)}",
                "description": v.get("Description", "") or v.get("Title", ""),
                "severity": sev(v.get("Severity", "UNKNOWN")),
                "file_path": target,
                "component_name": v.get("PkgName"),
                "component_version": v.get("InstalledVersion"),
                "cve": v.get("VulnerabilityID"),
                "vuln_id_from_tool": v.get("VulnerabilityID"),
                "mitigation": f"Upgrade to {v.get('FixedVersion')}" if v.get("FixedVersion") else "",
                "references": v.get("PrimaryURL", ""),
                "static_finding": True,
                "dynamic_finding": False,
            })
    return findings


def parse_checkov(path):
    """Checkov JSON output (IaC misconfigurations)."""
    data = safe_load(path)
    if not data:
        return []
    results = data if isinstance(data, list) else [data]
    findings = []
    for r in results:
        for check in r.get("results", {}).get("failed_checks", []):
            cr = check.get("check_result", {})
            findings.append({
                "title": f"[Checkov] {check.get('check_id')} - {check.get('check_name', '')}",
                "description": check.get("description", "") or check.get("check_name", ""),
                "severity": sev(cr.get("severity", "medium")),
                "file_path": check.get("file_path"),
                "line": (check.get("file_line_range") or [None])[0],
                "vuln_id_from_tool": check.get("check_id"),
                "mitigation": check.get("guideline", ""),
                "static_finding": True,
                "dynamic_finding": False,
            })
    return findings


def parse_zap(path):
    """OWASP ZAP baseline JSON report."""
    data = safe_load(path)
    if not data:
        return []
    findings = []
    risk_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])
            url = instances[0].get("uri") if instances else site.get("@name")
            findings.append({
                "title": f"[ZAP] {alert.get('alert', alert.get('name', 'finding'))}",
                "description": alert.get("desc", ""),
                "severity": risk_map.get(str(alert.get("riskcode")), "Info"),
                "file_path": url,
                "mitigation": alert.get("solution", ""),
                "references": alert.get("reference", ""),
                "vuln_id_from_tool": alert.get("pluginid"),
                "static_finding": False,
                "dynamic_finding": True,
            })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=".", help="Directory containing the downloaded report artifacts")
    ap.add_argument("--output", default="all-findings.json", help="Path to write the merged JSON")
    args = ap.parse_args()

    def p(name):
        return os.path.join(args.outdir, name)

    print("Merging findings from all scanners...")
    all_findings = []

    jobs = [
        ("Gitleaks",  lambda: parse_sarif(p("results.sarif"), "Gitleaks")),
        ("Semgrep",   lambda: parse_sarif(p("semgrep-results.sarif"), "Semgrep")),
        ("Trivy-FS",  lambda: parse_trivy(p("trivy-fs-results.json"), "Trivy-FS")),
        ("Trivy-Image", lambda: parse_trivy(p("trivy-image-results.json"), "Trivy-Image")),
        ("Checkov",   lambda: parse_checkov(p("checkov-results.json"))),
        ("ZAP",       lambda: parse_zap(p("zap-report.json"))),
    ]

    summary = {}
    for name, fn in jobs:
        try:
            found = fn()
        except Exception as e:
            print(f"  [warn] {name} parser failed: {e}", file=sys.stderr)
            found = []
        summary[name] = len(found)
        all_findings.extend(found)
        print(f"  {name}: {len(found)} finding(s)")

    output = {"findings": all_findings}
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nTotal findings merged: {len(all_findings)}")
    print(f"Written to: {args.output}")
    print("Summary by tool:", json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

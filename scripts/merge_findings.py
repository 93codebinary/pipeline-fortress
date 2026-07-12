#!/usr/bin/env python3
"""
merge_findings.py  —  PipelineFortress
───────────────────────────────────────
Consolidates all scan reports from the PipelineFortress CI pipeline
into a single DefectDojo-compatible Generic Findings Import JSON.

Supported inputs (auto-detected by filename inside --outdir):
  results.sarif              →  Gitleaks secrets scan
  semgrep-results.sarif      →  Semgrep SAST
  trivy-fs-results.json      →  Trivy SCA (filesystem)
  trivy-image-results.json   →  Trivy container image scan
  checkov-results.json       →  Checkov IaC scan
  zap-report.json            →  OWASP ZAP DAST

Usage:
  python3 scripts/merge_findings.py \
    --outdir reports \
    --output all-findings.json \
    --verbose
"""

import json
import os
import argparse
import sys
from datetime import date
from collections import Counter

TODAY = str(date.today())


# ── Severity maps ─────────────────────────────────────────────────────────────

SARIF_LEVEL_MAP = {
    "error":   "High",
    "warning": "Medium",
    "note":    "Low",
    "none":    "Info",
}

ZAP_RISK_MAP = {
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "Info",
}

TRIVY_SEV_MAP = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "UNKNOWN":  "Info",
}

CHECKOV_SEV_MAP = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
}


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_sarif(path, tool_hint="SARIF Tool"):
    """
    Parse a SARIF 2.1.0 file.
    Works for Gitleaks (results.sarif) and Semgrep (semgrep-results.sarif).
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [WARN] Could not parse {path}: {e}")
        return findings

    for run in data.get("runs", []):
        # Tool name from SARIF driver
        tool_name = (
            run.get("tool", {})
               .get("driver", {})
               .get("name", tool_hint)
        )

        # Build rule lookup for richer descriptions
        rules = {
            r["id"]: r
            for r in run.get("tool", {})
                        .get("driver", {})
                        .get("rules", [])
        }

        for result in run.get("results", []):
            rule_id   = result.get("ruleId", "unknown-rule")
            rule_info = rules.get(rule_id, {})

            # Message text
            message  = result.get("message", {})
            msg_text = (
                message.get("text", "")
                if isinstance(message, dict)
                else str(message)
            )

            # Physical location
            locs      = result.get("locations", [])
            file_path = ""
            line      = None
            if locs:
                phys      = locs[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                line      = phys.get("region", {}).get("startLine")

            severity = SARIF_LEVEL_MAP.get(
                result.get("level", "note"), "Info"
            )

            # Prefer full description from rule metadata
            full_desc = (
                rule_info.get("fullDescription", {}).get("text", "")
                or rule_info.get("shortDescription", {}).get("text", "")
                or msg_text
            )

            findings.append({
                "title":       f"[{tool_name}] {rule_id}",
                "severity":    severity,
                "description": full_desc,
                "tool":        tool_name,
                "file_path":   file_path,
                "line":        line,
                "date":        TODAY,
                "static_finding":  True,
                "dynamic_finding": False,
                "unique_id_from_tool": (
                    f"{tool_name}:{rule_id}:{file_path}:{line}"
                ),
            })

    return findings


def load_trivy(path, label="Trivy"):
    """
    Parse a Trivy JSON report.
    Handles both filesystem (trivy-fs-results.json)
    and image (trivy-image-results.json) output formats.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [WARN] Could not parse {path}: {e}")
        return findings

    for result in data.get("Results", []):
        target   = result.get("Target", "unknown")
        pkg_type = result.get("Type", "")

        for v in result.get("Vulnerabilities", []):
            cve_id    = v.get("VulnerabilityID", "UNKNOWN")
            pkg_name  = v.get("PkgName", "unknown")
            installed = v.get("InstalledVersion", "")
            fixed     = v.get("FixedVersion", "not fixed")
            title     = v.get("Title", "")
            desc      = v.get("Description", "") or title
            refs      = v.get("References", [])[:3]
            cvss      = v.get("CVSS", {})

            # Build CVSS score string if available
            cvss_str = ""
            for source, scores in cvss.items():
                v3 = scores.get("V3Score")
                if v3:
                    cvss_str = f"CVSS v3 ({source}): {v3}"
                    break

            findings.append({
                "title": f"{cve_id} in {pkg_name} ({installed})",
                "severity": TRIVY_SEV_MAP.get(
                    v.get("Severity", "UNKNOWN"), "Info"
                ),
                "description": (
                    f"{desc}\n\n"
                    f"Package      : {pkg_name} {installed}\n"
                    f"Fixed in     : {fixed}\n"
                    f"Target       : {target} [{pkg_type}]\n"
                    f"{cvss_str}\n"
                    f"References   : {', '.join(refs)}"
                ).strip(),
                "tool":            label,
                "file_path":       target,
                "line":            None,
                "date":            TODAY,
                "cve":             cve_id if cve_id.startswith("CVE-") else None,
                "static_finding":  True,
                "dynamic_finding": False,
                "unique_id_from_tool": f"{label}:{cve_id}:{pkg_name}:{installed}",
            })

    return findings


def load_checkov(path):
    """
    Parse a Checkov JSON report.
    Handles both list output (one block per framework) and dict output.
    """
    findings = []
    try:
        with open(path) as f:
            raw = json.load(f)
    except Exception as e:
        print(f"  [WARN] Could not parse {path}: {e}")
        return findings

    blocks = raw if isinstance(raw, list) else [raw]

    for block in blocks:
        for check in block.get("results", {}).get("failed_checks", []):
            check_id = check.get("check_id", "UNKNOWN")

            # check_type varies across Checkov versions
            check_obj  = check.get("check", {})
            check_name = (
                check_obj.get("name", check_id)
                if isinstance(check_obj, dict)
                else check.get("check_id", check_id)
            )

            resource    = check.get("resource", "")
            file_path   = check.get("file_path", "")
            line_range  = check.get("file_line_range", [None, None])
            start_line  = line_range[0] if line_range else None
            guideline   = check.get("guideline", "")
            code_block  = check.get("code_block", [])

            # Severity: check multiple locations Checkov uses
            sev_raw = (
                check.get("severity")
                or check.get("check_result", {}).get("severity", "")
                or "MEDIUM"
            )
            severity = CHECKOV_SEV_MAP.get(
                str(sev_raw).upper(), "Medium"
            )

            # Build code snippet preview
            code_preview = ""
            if code_block:
                lines = [f"  {ln}: {txt}" for ln, txt in code_block[:5]]
                code_preview = "\nCode snippet:\n" + "\n".join(lines)

            findings.append({
                "title": f"[Checkov] {check_id} — {check_name}",
                "severity":    severity,
                "description": (
                    f"Resource  : {resource}\n"
                    f"File      : {file_path}\n"
                    f"Check     : {check_name}\n"
                    f"Guideline : {guideline}"
                    f"{code_preview}"
                ).strip(),
                "tool":            "Checkov",
                "file_path":       file_path,
                "line":            start_line,
                "date":            TODAY,
                "static_finding":  True,
                "dynamic_finding": False,
                "unique_id_from_tool": f"Checkov:{check_id}:{resource}",
            })

    return findings


def load_zap(path):
    """
    Parse an OWASP ZAP JSON report (zap-report.json).
    Extracts all alerts with affected URLs and remediation.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [WARN] Could not parse {path}: {e}")
        return findings

    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            risk_code  = str(alert.get("riskcode", "0"))
            plugin_id  = alert.get("pluginid", "")
            name       = alert.get("name", "ZAP Alert")
            desc       = alert.get("desc", "")
            solution   = alert.get("solution", "")
            other_info = alert.get("otherinfo", "")
            reference  = alert.get("reference", "")
            cweid      = alert.get("cweid", "")
            wascid     = alert.get("wascid", "")

            # Collect affected URLs from instances
            instances = alert.get("instances", [])
            urls      = [i.get("uri", "") for i in instances[:10]]
            methods   = list(set(i.get("method", "") for i in instances))

            findings.append({
                "title":    f"[ZAP] {name}",
                "severity": ZAP_RISK_MAP.get(risk_code, "Info"),
                "description": (
                    f"{desc}\n\n"
                    f"Solution     : {solution}\n"
                    f"Other info   : {other_info}\n"
                    f"Methods      : {', '.join(m for m in methods if m)}\n"
                    f"URLs affected: {chr(10).join(urls[:5])}\n"
                    f"CWE-{cweid} / WASC-{wascid}\n"
                    f"References   : {reference}"
                ).strip(),
                "tool":            "OWASP ZAP",
                "file_path":       site_name,
                "line":            None,
                "date":            TODAY,
                "static_finding":  False,
                "dynamic_finding": True,
                "unique_id_from_tool": f"ZAP:{plugin_id}:{name}",
                "endpoints":       urls,
            })

    return findings


# ── File → loader routing ─────────────────────────────────────────────────────

FILE_LOADERS = {
    "results.sarif":             lambda p: load_sarif(p, "Gitleaks"),
    "semgrep-results.sarif":     lambda p: load_sarif(p, "Semgrep"),
    "trivy-fs-results.json":     lambda p: load_trivy(p, "Trivy-FS"),
    "trivy-image-results.json":  lambda p: load_trivy(p, "Trivy-Image"),
    "checkov-results.json":      load_checkov,
    "zap-report.json":           load_zap,
}


# ── DefectDojo output builder ─────────────────────────────────────────────────

def to_dojo_finding(f):
    """
    Convert internal finding dict to DefectDojo Generic Findings Import format.
    https://defectdojo.github.io/django-DefectDojo/integrations/parsers/file/generic/
    """
    entry = {
        "title":           f["title"][:500],
        "severity":        f["severity"],
        "description":     f.get("description", ""),
        "date":            f["date"],
        "active":          True,
        "verified":        False,
        "false_p":         False,
        "out_of_scope":    False,
        "static_finding":  f.get("static_finding", True),
        "dynamic_finding": f.get("dynamic_finding", False),
    }

    if f.get("file_path"):
        entry["file_path"] = f["file_path"]

    if f.get("line"):
        entry["line"] = int(f["line"])

    if f.get("cve"):
        entry["cve"] = f["cve"]

    if f.get("unique_id_from_tool"):
        entry["unique_id_from_tool"] = f["unique_id_from_tool"][:500]

    # ZAP endpoints
    if f.get("endpoints"):
        entry["endpoints"] = [{"host": u} for u in f["endpoints"] if u]

    return entry


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Merge PipelineFortress scan reports into DefectDojo format"
    )
    p.add_argument(
        "--outdir",  default="reports",
        help="Directory containing downloaded scan artifacts (default: reports)"
    )
    p.add_argument(
        "--output",  default="all-findings.json",
        help="Output file path (default: all-findings.json)"
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Print each finding title as it is processed"
    )
    return p.parse_args()


def main():
    args   = parse_args()
    all_findings = []

    print(f"\n{'═'*62}")
    print(f"  merge_findings.py — PipelineFortress")
    print(f"  Scan date : {TODAY}")
    print(f"  Input dir : {args.outdir}")
    print(f"  Output    : {args.output}")
    print(f"{'═'*62}\n")

    # ── Load each report ──────────────────────────────────────────────────────
    for filename, loader in FILE_LOADERS.items():
        filepath = os.path.join(args.outdir, filename)
        if os.path.exists(filepath):
            findings = loader(filepath)
            sev_summary = Counter(f["severity"] for f in findings)
            sev_str = " | ".join(
                f"{s}:{c}" for s, c in
                sorted(sev_summary.items(),
                       key=lambda x: ["Critical","High","Medium","Low","Info"]
                                      .index(x[0]) if x[0] in
                                      ["Critical","High","Medium","Low","Info"]
                                      else 99)
            )
            print(f"  ✓ {filename:<42} {len(findings):>4} findings  [{sev_str}]")
            if args.verbose:
                for f in findings:
                    print(f"      [{f['severity']:8}] {f['title']}")
            all_findings.extend(findings)
        else:
            print(f"  ✗ {filename:<42} not found — skipped")

    # ── Write output ──────────────────────────────────────────────────────────
    payload = {
        "findings": [to_dojo_finding(f) for f in all_findings]
    }
    with open(args.output, "w") as out:
        json.dump(payload, out, indent=2)

    # ── Summary ───────────────────────────────────────────────────────────────
    sev_counts  = Counter(f["severity"]       for f in all_findings)
    tool_counts = Counter(f.get("tool", "?")  for f in all_findings)

    sev_order = ["Critical", "High", "Medium", "Low", "Info"]

    print(f"\n{'─'*62}")
    print(f"  TOTAL FINDINGS : {len(all_findings)}")
    print(f"  By severity    :")
    for sev in sev_order:
        if sev in sev_counts:
            bar = "█" * min(sev_counts[sev], 40)
            print(f"    {sev:<10} {sev_counts[sev]:>4}  {bar}")
    print(f"  By tool        :")
    for tool, count in sorted(tool_counts.items()):
        print(f"    {tool:<32} {count:>4}")
    print(f"\n  Output written : {args.output}")
    print(f"{'═'*62}\n")

    # Non-zero exit if critical/high found (optional gate)
    critical_high = sev_counts.get("Critical", 0) + sev_counts.get("High", 0)
    if critical_high > 0:
        print(f"  ⚠  {critical_high} Critical/High findings — review before closing.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

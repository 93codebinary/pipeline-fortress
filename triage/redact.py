#!/usr/bin/env python3
"""Redaction layer: no secret, source code, or internal identifier
ever leaves the build runner."""
import json, re

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "[REDACTED_JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}"), r"\1=[REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_API_KEY]"),
]
CODE_BLOCK = re.compile(r"```[\s\S]*?```|`[^`\n]{20,}`")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
URL = re.compile(r"https?://[^\s\"']+")

path_map = {}
def redact_path(p):
    """Replace real file paths with FILE_1, FILE_2... placeholders,
    keeping only the extension so the LLM still knows the language."""
    if not p: return p
    if p not in path_map:
        ext = "." + p.rsplit(".", 1)[-1] if "." in p.rsplit("/", 1)[-1] else ""
        path_map[p] = f"FILE_{len(path_map)+1}{ext}"
    return path_map[p]

def redact_text(t):
    if not t: return t
    for pat, repl in SECRET_PATTERNS:
        t = pat.sub(repl, t)
    t = CODE_BLOCK.sub("[CODE_REMOVED]", t)
    t = EMAIL.sub("[EMAIL]", t)
    t = URL.sub("[URL]", t)
    return t

with open("consolidated_findings.json") as f:
    findings = json.load(f)

for fnd in findings:
    fnd["file"] = redact_path(fnd["file"])
    fnd["title"] = redact_text(fnd["title"])
    fnd["description"] = redact_text(fnd["description"])

with open("redacted_findings.json", "w") as f:
    json.dump(findings, f, indent=2)
with open("path_map.json", "w") as f:   # stays on the runner, never sent to the LLM
    json.dump(path_map, f, indent=2)
print(f"Redacted {len(findings)} findings -> redacted_findings.json")
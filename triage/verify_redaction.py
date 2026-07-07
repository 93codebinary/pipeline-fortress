#!/usr/bin/env python3
"""Prove redaction worked. If any secret pattern survives, FAIL the build."""
import re, sys
PATTERNS = [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{20,}",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."]
text = open("redacted_findings.json").read()
hits = [p for p in PATTERNS if re.search(p, text)]
if hits:
    print(f"REDACTION FAILED — patterns still present: {hits}"); sys.exit(1)
print("Redaction verified: nothing secret in the data leaving the runner.")
#!/usr/bin/env python3
import json, os
os.makedirs("security/remediation", exist_ok=True)
data = json.load(open("triage_report.json"))
for i, t in enumerate(data["triage"][:3], 1):
    with open(f"security/remediation/finding-{i}.md", "w") as f:
        f.write(f"# Finding {i} — {t.get('priority')}\n\n"
                f"**Reason:** {t.get('reason')}\n\n"
                f"**Proposed fix:**\n\n```\n{t.get('fix')}\n```\n\n"
                f"> Drafted by LLM triage. A human must verify before applying.\n")
print("Wrote fix proposals for top 3 findings.")
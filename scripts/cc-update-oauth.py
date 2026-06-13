#!/usr/bin/env python3
# Rewrite cc-gateway config.yaml oauth block from a Claude Code .credentials.json.
# Line-anchored replace so surrounding YAML/comments are untouched.
import json, re, sys, time, shutil

CRED = "/root/.claude/.credentials.json"
CFG  = "/root/cc-gateway/config.yaml"

d = json.load(open(CRED))["claudeAiOauth"]
acc, ref, exp = d["accessToken"], d["refreshToken"], int(d["expiresAt"])

bak = CFG + ".bak." + time.strftime("%Y%m%d-%H%M%S")
shutil.copy2(CFG, bak)

txt = open(CFG).read()
subs = {
    "access_token":  acc,
    "refresh_token": ref,
    "expires_at":    str(exp),
}
for field, val in subs.items():
    new, n = re.subn(rf"^(\s*{field}:\s*).*$", lambda m: m.group(1) + val, txt, flags=re.M)
    if n != 1:
        sys.exit(f"ERROR: expected 1 match for {field}, got {n}")
    txt = new
open(CFG, "w").write(txt)

valid = "VALID" if exp/1000 > time.time() else "EXPIRED"
print(f"backup: {bak}")
print(f"updated oauth: access(len {len(acc)}), refresh(len {len(ref)}), expires_at {exp} -> access {valid}")

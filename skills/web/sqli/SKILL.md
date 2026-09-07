---
name: sqli
description: Focused SQLi checklist — detection differentials, contexts, sqlmap handoff, proof standard.
---

# SQL Injection

## Checklist
- [ ] Test EVERY input: query/body/JSON/cookies/headers (`User-Agent`, `X-Forwarded-For`, `Referer`)
- [ ] Numeric AND string contexts
- [ ] Differential pair: `'` vs `''`; `' AND 1=1-- -` vs `' AND 1=2-- -`
- [ ] Time-based fallback (0s/5s/10s) when errors suppressed
- [ ] Second-order sinks (store then use later)
- [ ] Hand off to **sqlmap** only after a manual positive signal

## Common bypasses
- Comment styles: `-- -`, `#`, `/* */`, balanced quotes
- Encoding / WAF: double URL-encode, case mix, inline comments `UN/**/ION`
- JSON/numeric without quotes: `1 AND 1=1`, `1-0`

## Proof standard
- Repeatable boolean differential, error oracle with DB signature, reproducible time delay (2–3×), or OOB DNS.
- A single 500 on `'` is NOT confirmation.
- Prefer `sqlmap --batch --level=3 --risk=2` for extraction after manual proof.

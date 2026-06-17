---
name: sqli
aliases: [sqli, sql-injection, sqlmap]
tags: [injection, owasp-a03, database, sqlmap]
severity: critical
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/penetration-testing/exploiting-sql-injection-vulnerabilities/SKILL.md -->

# SQL Injection

## When to Use
- Any GET/POST param, JSON field, cookie, or header that may reach a SQL query.
- Validating that parameterized queries are used everywhere (incl. ORDER BY / column names, which are not parameterizable).
- Confirming impact of a suspected injection before reporting.

## Critical Checks Most Often Missed
- **Test EVERY input, not just `?id=`.** Every param, JSON string AND numeric fields, and the `Cookie`, `Referer`, `User-Agent`, `X-Forwarded-For`, `Host` headers. Injections live in headers more often than people expect.
- **Numeric vs string context.** For a numeric param try bare arithmetic (`1 AND 1=1`, `1-0`, `1*1`) — a param that ignores quotes can still be injectable numerically.
- **Comment styles matter.** Try `-- -`, `#`, `/* */`, and a balanced trailing quote with no comment. A payload can fail purely on the wrong comment.
- **Second-order.** Input stored at registration and used later in a different query (profile page). Test the sink, not just the source.

## Validation / Confirm Steps
Always run the **differential pair** and compare status/length/content:
- `'` vs `''` (one quote breaks, two repair → strong signal).
- `' AND 1=1-- -` vs `' AND 1=2-- -` (and the `"`, `)`, `')` context variants).

Always include a **time-based fallback** (error/boolean signals are often suppressed) — test 0s/5s/10s:
- MySQL `' AND SLEEP(5)-- -` · Postgres `';SELECT pg_sleep(5)-- -` · MSSQL `';WAITFOR DELAY '0:0:5'-- -` · Oracle `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -`

A 500 error, a true/false content-length delta, a reproducible time delay, or an OOB DNS hit each **confirm** injection. Re-run 2–3× to defeat caching/jitter before reporting. Hand off to `sqlmap` for extraction only after a manual positive.

## False-Positive Traps
- A single 500 on `'` may be generic WAF/error handling, not injection — require the differential pair or a repeatable time delay.
- Time deltas under load are noisy: compare 0s vs 5s vs 10s payloads and repeat.
- Do **not** conclude "not vulnerable" after one quote on the `id` param returns 200 — you have not tested numeric context, headers, other params, or time-based blind.

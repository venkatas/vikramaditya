# engagements/ — the ONLY home for client/engagement data

**Everything under this directory is git-ignored** (see `.gitignore` allowlist block).
This is the single, durable boundary that keeps real client data out of the public repo.

## Rules
- **All** real client/engagement output lives here: `engagements/<target>/{recon,findings,reports,creds,notes,cloud,har,sessions}`.
- Tracked code, tests, and docs use **synthetic placeholders only** — `*.example.invalid`,
  TEST-NET IPs (`198.51.100.0/24`), `AKIAIOSFODNN7EXAMPLE`, fake PII. Never copy live target
  output, a HAR, a DB dump, a credential, or an admin URL into a tracked file.
- Operator state (the leak-guard blocklist, whitebox config) stays in `~/.config/vikramaditya/`
  or `engagements/_local/`.

Only this `README.md` and `.gitkeep` are tracked here; nothing else ever should be.

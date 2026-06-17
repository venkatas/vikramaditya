---
name: lfi
aliases: [lfi, local-file-inclusion, path-traversal, directory-traversal, file-read, rfi]
tags: [path-traversal, lfi, file-read, owasp-a01]
severity: high
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/performing-directory-traversal-testing/SKILL.md -->

# Local File Inclusion / Path Traversal

## When to Use
- Any param that names or includes a file (download, view, template, log, report, `?page=`, `?file=`, `?lang=`).
- Assessing LFI/RFI in template engines and include() sinks.

## Critical Checks Most Often Missed
Scanners only try `../../../etc/passwd` and give up when a filter blocks it. For **every** file param try the full matrix — one blocked payload does not mean safe:
- **Raw absolute path, NO traversal** — `/etc/passwd`, `etc/passwd`, `file:///etc/passwd`. Works when the app prepends nothing or uses `include($_GET['x'])` directly. **This is the #1 miss.**
- **Leading-slash variants** — `//etc/passwd`, `///etc/passwd`, `/./etc/passwd`, `/%2e/etc/passwd` (loaders normalise multiple slashes).
- **Classic relative traversal at depth 1–12** — `../etc/passwd` … `../../../../../../../../../../../../etc/passwd`.
- **Filter-stripping bypasses** (non-recursive `../` removal) — `....//....//....//etc/passwd`.
- **Encoding** — `%2e%2e%2f`, double-encoding `%252e%252e%252f`, UTF-8 overlong, `..%c0%af`, null byte `%00` on legacy PHP/ASP, and an appended `?`/`#` to defeat suffix appends.
- **PHP wrappers** — `php://filter/convert.base64-encode/resource=index.php` to read source; `data://`, `expect://` for RCE.

## Validation / Confirm Steps
- Confirm a **known file's known content**: `/etc/passwd` returns `root:x:0:0:` lines; on Windows read `C:\windows\win.ini`.
- For source disclosure via `php://filter`, decode the base64 and confirm it is the real script.
- Escalate to RCE only after proving read (log poisoning, session files, `php://input`, wrappers).

## False-Positive Traps
- A 200 with a generic error page is NOT a read — require the file's actual content signature.
- A blocked `../../../etc/passwd` is NOT a negative until you've tried raw absolute path, leading-slash, encoding, wrappers, and a null-byte/`?`-suffix bypass.

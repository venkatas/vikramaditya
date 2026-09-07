---
name: upload-rce
description: Focused upload→RCE checklist — extension/MIME/magic bypasses, proof.
---

# File Upload → RCE

## Checklist
- [ ] Extension matrix: `.phtml`, `.php5`, `.pHp`, `.php.jpg`, `.jpg.php`, null byte, trailing dot/space
- [ ] Content-Type spoof + magic-byte prefix (`GIF89a<?php ...`)
- [ ] Polyglot / SVG XSS / XXE-in-DOCX / ZIP slip
- [ ] Handler enable: `.htaccess` / `web.config`
- [ ] Locate stored path and request it back

## Common bypasses
| Attack | Example |
|---|---|
| Double ext / case | `shell.jpg.php`, `shell.pHp` |
| MIME spoof | body PHP, `Content-Type: image/jpeg` |
| Magic prefix | `GIF89a` + PHP |
| Trailing junk | `shell.php.`, `shell.php ` (Windows) |

## Proof standard
- Upload accepted ≠ RCE. Confirm execution (`uid=` / OOB) after fetching the stored file.
- Source returned without execution → try handler mapping / other extension before claiming RCE.

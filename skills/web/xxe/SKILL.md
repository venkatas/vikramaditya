---
name: xxe
description: Focused XXE checklist — parsers, upload vectors, OOB, proof standard.
---

# XXE — XML External Entity

## Checklist
- [ ] XML upload / SOAP / SAML / Office DOCX/XLSX/SVG/XML feeds
- [ ] Classic file read entity → `/etc/passwd`
- [ ] OOB/parameter entities when inline blocked
- [ ] Content-Type `application/xml` / `text/xml` on JSON APIs that still parse XML
- [ ] SVG and Office ZIP internal XML

## Common bypasses
- Parameter entities + external DTD when SYSTEM inline blocked
- UTF-16 / BOM tricks; XInclude when entities disabled
- SOAP/SAML wrapper still parsed by libxml

## Proof standard
- Retrieved file content signature or OOB HTTP/DNS hit from the parser host.
- Blind XXE without OOB/read = candidate only.

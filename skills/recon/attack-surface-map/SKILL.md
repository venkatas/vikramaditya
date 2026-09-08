---
name: attack-surface-map
description: Attack-surface mapping — hosts, endpoints, params, tech stack, JS/API specs. Portable CAI web-recon methodology ideas.
---

# Attack Surface Map

## Checklist
- [ ] Live hosts from passive enum → httpx titles / tech / status
- [ ] Crawl + historical URLs; retain only in-scope hosts
- [ ] Enumerate methods, content-types, auth walls (guest vs session)
- [ ] Collect JS bundles, source maps, OpenAPI/Swagger, robots, sitemap, `.well-known`
- [ ] Parameter inventory (query/body/JSON/headers/cookies) per interesting route
- [ ] Flag staging/dev/admin panels and third-party embeds

## Methodology (hypothesis-driven)
1. Breadth first: map before deep exploit attempts
2. One bounded probe per hypothesis; record evidence path
3. Prefer safe/read-only requests until a live signal justifies more

## Proof standard
- Surface map cites concrete URLs/methods/params observed (not guessed).
- Tech fingerprints are labels for prioritization — not findings by themselves.
- Out-of-scope discoveries are logged and **not** probed further.

## Vik wiring
- Aligns with `skills/web2-recon` narrative; this pack is the concise loader form for brain injection.

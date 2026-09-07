---
name: deserialization
description: Focused insecure deserialization checklist — gadget hints, safe proof, no blind RCE spray.
---

# Insecure Deserialization

## Checklist
- [ ] Find typed blobs: `Java` (`rO0`), .NET ViewState, PHP `O:`, Python pickle/`pickle.loads`, Ruby Marshal
- [ ] Cookie / hidden field / queue / cache / session store carriers
- [ ] Library fingerprint before gadget choice (ysoserial / phpggc / similar)
- [ ] Prefer sleep/DNS canary over destructive payloads
- [ ] Check signed/encrypted ViewState MAC before claiming forgeability

## Common bypasses
- Base64 / nested encoding; alternate content-types
- Signing key hard-coded or weak → forge ViewState / JWT-like wrappers
- Polymorphic type discriminators trusting client `class` / `@type` (Jackson/`enableDefaultTyping`)

## Proof standard
- Controlled side effect (time delay, OOB DNS/HTTP, file create in temp) attributable to the payload.
- Do NOT spray public RCE gadgets against production without authorization scope; document canary proof first.

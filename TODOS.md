# Vikramaditya — Pending Improvements

## Critical (tool fails on real targets)

### 1. ~~Endpoint Discovery fails on Vite/Next.js/code-split apps~~ DONE
- Fixed: scrapes ALL JS chunks (Vite /assets/, Next.js /_next/, CRA /static/js/)
- Fixed: follows dynamic imports and modulepreload links for code-split chunks
- Fixed: extracts from fetch(), axios, and template literal API calls
- Fixed: OpenAPI/Swagger spec discovery (/docs, /swagger.json, /openapi.json)
- Fixed: noise filter rejects HTTP headers, CSS classes, template artifacts
- Tested on: app.foctta.com (Vite) — found 226 live endpoints from 52 JS files

### 2. ~~Login URL not auto-discovered~~ DONE
- Fixed: probes 18+ common login patterns (auth/login, login-view/, v1/auth/login, etc.)
- Fixed: supports dev/staging token endpoints (/dev/token)
- Fixed: extracts role/tenant from email for dev token login
- Tested on: app.foctta.com — auto-detected v1/auth/login

### 3. ~~API base path not auto-detected~~ DONE
- Fixed: probes /api/, /v1/, /api/v1/, /graphql, /api/organization/, etc.
- Fixed: tries subdomain variants (api.example.com from app.example.com)
- Fixed: validates responses are JSON (not SPA HTML false positives)
- Tested on: app.foctta.com — correctly detected same-origin API

### 4. No GraphQL support
- Many modern apps use GraphQL, not REST
- Need: introspection query, mutation fuzzing, auth bypass on queries

## High (findings missed on real targets)

### 5. IDOR scanner doesn't find cfgold.in view-learner IDOR consistently
- Works when run alone, misses in full autopilot
- Root cause: endpoint count varies between runs (38 vs 149)
- Need: deterministic endpoint list from Phase 1

### 6. Score manipulation not detected consistently
- Works when tested directly, sometimes missed in autopilot
- Root cause: endpoint matching for "generate-live-test-result" depends on keywords

### 7. Learner API not tested
- Autopilot only tests /api/organization/, not /api/learner/
- Need: test ALL API namespaces discovered, not just the base URL

### 8. Video completion bypass not in autopilot
- Confirmed manually but autopilot doesn't test it
- Need: learner API phase that tests video-track-progress

## Medium (quality improvements)

### 9. Brain supervisor always says CONTINUE
- Never injects or skips phases
- Need: more aggressive decision rules with concrete patterns

### 10. Reporter PoC data not auto-generated
- PoC sections need manual .poc files
- Need: autopilot should save curl commands + responses as PoC automatically

### 11. No CSRF testing
### 12. No SSRF testing
### 13. No HTTP method tampering (GET→PUT→DELETE)
### 14. No cleanup of test accounts created during upload bypass
### 15. Finding deduplication (same AWS key reported from upload + info disclosure)

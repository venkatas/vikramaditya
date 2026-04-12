# Vikramaditya — Pending Improvements

## Critical (tool fails on real targets)

### 1. Endpoint Discovery fails on Vite/Next.js/code-split apps
- Current: only extracts from single main.js bundle
- Needed: fetch ALL JS chunks, parse lazy-loaded routes
- Also: brute-force common API paths (/v1/, /api/v1/, /graphql, etc.)
- Also: try OpenAPI/Swagger discovery (/docs, /swagger.json, /openapi.json)
- Tested on: app.foctta.com (Vite) — found 0 endpoints, should find 8+

### 2. Login URL not auto-discovered
- Current: user must specify --login-url
- Needed: try common patterns (auth/login, login, sign-in, api/auth/login, v1/auth/login)
- Also: detect auth type from response (JWT in body vs cookies vs headers)

### 3. API base path not auto-detected
- Current: user must specify exact base URL
- Needed: probe /api/, /v1/, /v2/, /graphql and detect which responds

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

# Caido MCP client config for Vikramaditya

Lets a Claude Code session driving Vikramaditya see the operator's
[Caido](https://caido.io) proxy traffic — read history, send requests
through Caido's Replay, run parallel sweeps, search/filter — without
re-crawling the target.

The actual MCP server is the upstream community project
[`caido-mcp-server`](https://github.com/c0tton-fluff/caido-mcp-server)
by `c0tton-fluff` (MIT-licensed). This directory only ships a config
fragment that points Claude Code at it.

## Why use it

When the operator has already walked through the application in
Caido (login, role switch, business-flow capture), the brain agent
can consume that traffic directly instead of re-discovering endpoints
through `katana`/`waybackurls`/`hakrawler` from scratch. That matters
for engagements where:

- Authentication is multi-step (SSO, MFA, captcha) and unscriptable.
- Endpoints only surface inside an authenticated SPA flow.
- The operator wants the agent's verdicts grounded in *real* observed
  traffic, not re-runs of unauthenticated probes.

## What the MCP exposes

- Read proxy history (every request / response Caido captured)
- Send requests via Caido **Replay** — status, headers, body returned inline
- Send up to 50 parallel requests per batch (BAC sweeps, parameter fuzzing,
  endpoint sweeps)
- Access fuzzing **sessions / results / payloads**
- Search / filter traffic by host, method, status, content type
- Read project state — projects, scopes, sitemaps

The upstream MCP auto-redacts `Authorization`, `Cookie`, `Set-Cookie`
and API-key headers before returning data to the model, so bearers
don't leak into the LLM context.

## Setup (≤ 5 minutes)

### 1. Install the upstream MCP server

```bash
# Recommended installer from the upstream project
curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/caido-mcp-server/main/install.sh | bash
```

Or build from source — see the upstream
[`caido-mcp-server` README](https://github.com/c0tton-fluff/caido-mcp-server).

### 2. Create a Caido Personal Access Token

1. Open Caido (desktop or CLI build).
2. **Settings → Developer → Personal Access Tokens**.
3. Create a token, copy it.

### 3. Set environment variables

```bash
export CAIDO_URL="http://127.0.0.1:8080"
export CAIDO_PAT="<your-personal-access-token>"
```

Persist in `~/.zshrc` / `~/.bashrc`.

> Prefer OAuth? Run `CAIDO_URL=http://localhost:8080 caido-mcp-server login`
> once — the token is cached at `~/.caido-mcp/token.json` and you can
> drop the `CAIDO_PAT` env var.

### 4. Register the MCP server in your Claude Code settings

Merge the contents of `config.json` in this directory into your
`~/.claude/settings.json` under `"mcpServers"`. If you have no other
MCP servers configured yet:

```bash
mkdir -p ~/.claude
cp mcp/caido-mcp-client/config.json ~/.claude/settings.json
```

If you already have other MCP servers (e.g. `hackerone`, `burp`), open
the file and add the `"caido"` block alongside them.

### 5. Verify

Start Caido, then in Claude Code:

```text
/hunt target.com
```

If the MCP is wired, the agent will reference your captured traffic
instead of re-crawling.

## Coexistence with Burp MCP

Both servers can run concurrently — the agent will pick whichever has
traffic for the current target. Most operators run one daily proxy and
configure just that entry; leaving the other out of `mcpServers`
avoids duplicate tool surfaces in the model context.

## Operating without Caido

All Vikramaditya commands still work without this MCP. Falls back to:

- `curl` / `httpx` / `katana` for HTTP discovery (no captured-flow context).
- Manual request/response pasting in the validate step.
- `webhook.site` or Project Discovery `interactsh` for OOB testing
  instead of Caido's collaborator-style hooks.

## Credit

Upstream MCP server: [c0tton-fluff/caido-mcp-server](https://github.com/c0tton-fluff/caido-mcp-server), MIT.
The config pattern in this directory mirrors the same shape used by
other Claude Code MCP toolkits — including the
[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
Caido MCP client, which we drew on when designing the integration.
Please credit those projects when redistributing this directory.

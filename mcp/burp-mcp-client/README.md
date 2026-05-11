# Burp Suite MCP client config for Vikramaditya

Connects a Claude Code session driving Vikramaditya to
[PortSwigger's official Burp Suite MCP server][burp-mcp]. Gives the
brain agent live visibility into the operator's Burp proxy history,
Scanner findings, project files, and Collaborator OOB hooks — the
same way the Caido MCP client (sibling directory) does for Caido users.

This directory only ships a config fragment. The actual MCP server is
shipped by PortSwigger.

## Why use it

Bug-bounty and VAPT operators frequently drive Burp Suite by hand for
the auth / business-flow capture, then expect the autonomous scanner
to pick up from where they left off. Without an MCP bridge the
scanner is blind to that traffic. With it:

- Brain agent reads the request/response pairs the operator already
  captured (auth tokens, role-switched sessions, multi-step wizards).
- Validation step can re-send a captured request via Burp Repeater
  and quote the response — proves a finding without leaving Burp.
- Generates Collaborator payloads for OOB testing (SSRF, blind SQLi,
  XXE, OAST chains) instead of bouncing through `webhook.site`.
- Reads Burp Scanner findings — useful as a second opinion alongside
  Vikramaditya's own Phases 7–11.

## What the MCP exposes

- **Read proxy history** — every request/response captured by Burp,
  filterable by host / method / status / content-type.
- **Send requests** — via the Burp REST API (Repeater equivalent).
- **Generate Collaborator payloads** — for OOB testing.
- **Access Scanner findings** — Burp's active/passive scanner output.
- **Read / write project state** — Burp project files.

## Setup (≤ 5 minutes)

### 1. Install the Burp MCP server

Download the official MCP server `.jar` from PortSwigger:

```bash
# Releases page — pick the latest burp-mcp-server-x.y.z.jar
# https://portswigger.net/burp/releases
curl -L -o ~/burp-mcp-server.jar \
    "https://portswigger.net/burp/releases/download/burp-mcp-server.jar"
sudo install -m 0644 ~/burp-mcp-server.jar /usr/local/lib/burp-mcp-server.jar
```

The `.jar` requires Java 17+:

```bash
java -version 2>&1 | head -1   # must be 17 or newer
```

### 2. Enable the Burp REST API

1. Open Burp Suite Professional.
2. **Settings → Suite → REST API**.
3. Enable the API on port **1337** (default).
4. Copy the API key.

### 3. Set environment variables

```bash
export BURP_API_URL="http://127.0.0.1:1337"
export BURP_API_KEY="<your-api-key>"
export BURP_MCP_JAR="/usr/local/lib/burp-mcp-server.jar"
```

Persist in `~/.zshrc` / `~/.bashrc`.

### 4. Register the MCP server in Claude Code settings

Merge the contents of `config.json` in this directory into your
`~/.claude/settings.json` under `"mcpServers"`. If you have no other
MCP servers yet:

```bash
mkdir -p ~/.claude
cp mcp/burp-mcp-client/config.json ~/.claude/settings.json
```

Otherwise open the file and paste the `"burp"` block alongside the
other server entries.

### 5. Verify

Start Burp, then in Claude Code:

```text
/hunt target.com
```

If wired, the agent will reference the traffic Burp has captured and
won't re-crawl endpoints you've already touched.

## Coexistence with Caido MCP

You can run both at once — the agent picks whichever has traffic for
the current target. Most operators stick to one daily proxy; remove
the other entry from `mcpServers` to keep the model's tool surface
small.

## Operating without Burp

All Vikramaditya commands still work without this MCP. Falls back to:

- `curl` / `httpx` / `katana` for HTTP discovery (no captured-flow context).
- Manual request/response pasting in the validate step.
- `webhook.site` or Project Discovery `interactsh` for OOB testing
  instead of Burp Collaborator.

## Credit

[Burp Suite MCP][burp-mcp] is a PortSwigger property; you must comply
with PortSwigger's Burp Suite licence terms to run the server. This
directory only carries a config fragment, not the server binary.

The config pattern mirrors the same shape used by other Claude Code
MCP toolkits — including the
[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
Burp MCP client, which we drew on when designing the integration.

[burp-mcp]: https://portswigger.net/burp/documentation/desktop/automated-scanning/mcp-server

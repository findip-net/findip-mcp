# FindIP MCP server

Ask your assistant about an IP address or a risky session, and get the answer from FindIP.

`@findip/mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server for [FindIP](https://findip.net). It gives Claude, Cursor and other MCP clients IP intelligence and FindIP Shield risk signals. It runs locally over stdio and only reads data.

## Tools

| Tool | What it does | Key |
| --- | --- | --- |
| `lookup_ip` | Country, city, ISP and ASN for an IP, plus risk signals: VPN, proxy, Tor, relay, hosting, scanner, malicious listings, threat score | API key |
| `verify_session` | Server-side risk check for a Shield session: score, recommendation, challenge status, IP and network rotation | Site secret key |
| `list_shield_sites` | Your Shield sites with today's event and risky-event counts | API key |
| `recent_risky_events` | Recent high-risk events on a site, for example "what risky traffic hit my signup form this week" | API key |
| `explain_event` | One event in plain language: where it came from, which signals fired, what was recommended | API key |

All five tools are read-only. [docs/BACKEND.md](docs/BACKEND.md) lists the FindIP endpoint behind each one.

## Setup

You need Node.js 18.17 or later and a FindIP API key. Keys are free at [findip.net](https://findip.net).

### Claude Code

```bash
claude mcp add findip --env FINDIP_API_KEY=your_api_key -- npx -y @findip/mcp
```

### Claude Desktop

Add this to `claude_desktop_config.json` (Settings, Developer, Edit Config), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "findip": {
      "command": "npx",
      "args": ["-y", "@findip/mcp"],
      "env": {
        "FINDIP_API_KEY": "your_api_key"
      }
    }
  }
}
```

### Cursor

Add this to `~/.cursor/mcp.json`, or to `.cursor/mcp.json` in a project:

```json
{
  "mcpServers": {
    "findip": {
      "command": "npx",
      "args": ["-y", "@findip/mcp"],
      "env": {
        "FINDIP_API_KEY": "your_api_key"
      }
    }
  }
}
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `FINDIP_API_KEY` | Your FindIP API key. Required for `lookup_ip`, `list_shield_sites`, `recent_risky_events` and `explain_event`. |
| `FINDIP_SHIELD_SECRET_KEY` | Secret key (`sec_...`) of one Shield site. Required for `verify_session`. Find it in the site's settings in the Shield dashboard. |
| `FINDIP_SHIELD_ACCOUNT_API` | Set to `0` to turn off the three Shield account tools, so the API key is used for IP lookups only. On by default. |
| `FINDIP_TIMEOUT_MS` | Request timeout. Default 15000. |
| `FINDIP_API_BASE_URL`, `FINDIP_SHIELD_BASE_URL`, `FINDIP_PORTAL_BASE_URL` | Override the FindIP hosts, for testing. |

The Shield account tools allow 60 requests per account per minute. Repeated requests with a wrong key are blocked for 10 minutes.

Keys are read from the environment only. They are never accepted as tool arguments and never appear in tool output or error messages.

## Examples

- "Look up 203.0.113.9. Is it a VPN or a hosting provider?"
- "Verify Shield session sess_8f2c and tell me why it was flagged."
- "What risky traffic hit my signup form this week?"
- "Explain event 5b1e... on shop.example. Should I worry?"

## How to read the results

FindIP reports risk signals. A VPN, a hosting network or a high score tells you about the connection, not about the person behind it. Use the signals to decide who gets a closer look, an extra step or a manual review.

The Shield browser SDK collects signals and can add friction in the page, but a browser can be scripted or bypassed, so it is not a security boundary. Decisions that matter belong on your server: call server verification (the endpoint `verify_session` uses) from your backend before you allow, challenge or block. A session with `risk_status: "unknown"` had no IP intelligence; treat it as unknown, not as safe.

## Privacy

- The server talks only to FindIP: `api.findip.net`, `shield.findip.net` and `www.findip.net`.
- Shield tools never return end-user identity (email, user ID and their hashes). FindIP removes it before the data leaves its servers.
- Site listings are a short summary: no site keys, no settings.
- No telemetry, and nothing is written to disk.

## Development

```bash
npm install
npm run typecheck
npm test        # vitest, all HTTP mocked
npm run build
```

## License

MIT

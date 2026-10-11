# Backend for the Shield tools

Status: proposal. Nothing in this document is built or deployed.

## What exists today

| Tool | Backend | Auth | State |
| --- | --- | --- | --- |
| `lookup_ip` | `GET https://api.findip.net/{ip}/?token={key}` (NewApi `IpController`) | FindIP API key, query parameter only | Live |
| `verify_session` | `POST https://shield.findip.net/v1/shield/sessions/verify` (Shield API `routes/verify.ts`) | Site secret key, `Authorization: Bearer sec_...` | Live |
| `list_shield_sites` | Shield API `GET /v1/shield/sites` | NewWeb cookie session only | Needs the endpoint below |
| `recent_risky_events` | Shield API `GET /v1/shield/sites/{siteId}/events` | NewWeb cookie session only | Needs the endpoint below |
| `explain_event` | Shield API `GET /v1/shield/sites/{siteId}/events/{eventId}` | NewWeb cookie session only | Needs the endpoint below |

Two facts shape the design:

- The verify endpoint takes a **site secret key** and a **session ID**, not the FindIP API key and not a token. `verify_session` therefore reads `FINDIP_SHIELD_SECRET_KEY`. The growth plan's `verify_session(token)` does not match the shipped endpoint.
- The Shield dashboard routes accept only the pair `X-Shield-Proxy-Secret` + `X-Shield-User-Id`, sent by NewWeb's `ShieldController` after it has validated the browser cookie. There is no path from an API key to those routes.

## Proposed endpoint

A new NewWeb controller, `ShieldAccountApiController.cs`. New file, no edits to existing files, no `Program.cs` registration (same self-contained pattern as `ShieldController`: static `HttpClient`, `IConfiguration`).

```
Authorization: Bearer <FindIP API key>

GET https://findip.net/api/shield/v1/sites
GET https://findip.net/api/shield/v1/sites/{siteId}/events?range=&minRiskScore=&eventName=&limit=&cursor=
GET https://findip.net/api/shield/v1/sites/{siteId}/events/{eventId}
```

Responses are the Shield API's JSON, forwarded unchanged except for the identity fields (see Risks). Errors: `401 {"error":"invalid_api_key"}`, `404 {"error":"not_found"}`, `429 {"error":"rate_limited"}`, `502 {"error":"shield_api_unreachable"}`.

`/api/shield/v1` is a new prefix. It stays out of `/shield/api/{**path}`, which is the existing cookie-authenticated catch-all.

### Behaviour

1. Feature flag `ShieldApi:AccountApi:Enabled`, default `false`. When off, every route returns 404, so the controller can ship dark.
2. `[AllowAnonymous]`; the controller does its own auth. Read the bearer value, reject anything empty or longer than 50 characters (NewApi's limit) before any lookup.
3. Resolve the key to a user: one read of `UserData` by `ApiKey`, selecting `Id`, `Email`, `IsActive`, `IsEmailVerified`. Reject unknown, inactive and unverified accounts with the same 401.
4. Apply `ShieldGate.IsAllowedEmail(email, configuration)`, so the pre-launch allowlist covers this path too.
5. Forward to `{ShieldApi:BaseUrl}/v1/shield/...` with `X-Shield-Proxy-Secret` and `X-Shield-User-Id`, exactly as `ShieldController.Api` does. The Shield API already scopes every query by that user ID.
6. GET only, and only the three route shapes above, matched by explicit route templates (`{siteId:guid}`), never a catch-all. Query parameters are an allowlist: `range`, `from`, `to`, `minRiskScore`, `eventName`, `riskLevel`, `limit`, `cursor`.

### What it reuses

- `ShieldApi:BaseUrl` and `ShieldApi:ProxySecret` configuration, and the header contract of `ShieldController`.
- `Infrastructure/ShieldGate`.
- `NewDataDbContext.UserData`, the way `ShieldInternalController.CheckUsers` already reads it.
- The Shield API as is: `listSitesForUser`, `listEvents`, `getEvent`. No Shield change is needed for a first version.

### What it reads

- `findip` database: one `UserData` row per request, read only (`Id`, `Email`, `IsActive`, `IsEmailVerified`). No writes, no schema change.
- Shield data, through the Shield API only: the caller's sites, and events of those sites.

It writes nothing.

## Risks

1. **The API key gains a new power.** Today it only spends lookup quota, and it travels in query strings, so it shows up in access logs, browser history and customer code. With this endpoint a leaked key also reads visitor IPs and risk events. Mitigations: flag off by default; consider a per-account opt-in switch in the dashboard, or a separate read-only Shield token, before turning it on for everyone.
2. **End-user identity.** The Shield event routes decrypt `identity.email` and `identity.userId` on the dashboard read path. An assistant should not receive them. The MCP server drops identity and `customerContext` before returning anything, but that is client-side. The controller should remove `identity` and `customerContext` from event JSON itself, or the Shield API should gain an additive `?identity=none` switch that skips decryption.
3. **`findip` database rule.** The key lookup is a read of the production `findip` database from new feature code. `ShieldInternalController` is a precedent, but the hard rule says the database is off-limits to feature work, so this needs the owner's explicit approval. Check that `"UserData"."ApiKey"` is indexed; the EF configuration declares no index.
4. **Key guessing and load.** NewWeb has no rate limiter. The controller needs its own: a per-IP invalid-key counter (NewApi's `IpController` uses 8 failures per 10 minutes) and a per-key request cap, both in memory. Cache key-to-user results for about a minute to keep load off Postgres, and accept that a rotated key stays valid for that minute.
5. **Wider proxy surface.** A second way to reach the dashboard routes. Kept small by GET only, three fixed routes and a parameter allowlist; no settings, keys, exports, sessions or mutations.
6. **Event listing cost.** `listEvents` runs a `COUNT(*)` plus a page query. Cap `limit` at 100 and require a range of at most 30 days.
7. **Edge behaviour.** `findip.net` sits behind Cloudflare. Confirm `/api/shield/*` is not cached and that bot rules do not block non-browser clients. Send `Cache-Control: no-store`.

## How the MCP server uses it

`list_shield_sites`, `recent_risky_events` and `explain_event` are written against this contract and covered by tests with mocked HTTP. They are gated by `FINDIP_SHIELD_ACCOUNT_API` (default off). While off, each returns `endpoint_not_available` naming the endpoint it needs, and no request is sent, so the API key never goes to a route that does not exist. With the flag on, a 404 from `/sites` is reported the same way.

`explain_event` takes an event ID and an optional site. Event IDs are scoped to a site in the Shield API, so without a site the server asks each of the account's sites in turn (up to 20). A cross-site route `GET /api/shield/v1/events/{eventId}` would remove that loop but needs a new Shield API query, so it is left out of the first version.

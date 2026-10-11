# Backends

Every tool is a read. This page lists what each one calls.

| Tool | Endpoint | Auth |
| --- | --- | --- |
| `lookup_ip` | `GET https://api.findip.net/{ip}/?token={key}` | FindIP API key (query parameter) |
| `verify_session` | `POST https://shield.findip.net/v1/shield/sessions/verify` | Shield site secret key, `Authorization: Bearer sec_...` |
| `list_shield_sites` | `GET https://www.findip.net/api/shield/v1/sites` | FindIP API key, `Authorization: Bearer <key>` |
| `recent_risky_events` | `GET https://www.findip.net/api/shield/v1/sites/{siteId}/events` | same |
| `explain_event` | `GET https://www.findip.net/api/shield/v1/sites/{siteId}/events/{eventId}` | same |

## Shield account API

Live since 2026-10-11. A FindIP portal endpoint that resolves the API key to its account and forwards three GET routes to the Shield API, scoped to that account's sites. It has no write routes.

**Event query parameters used by this server:** `range` (`24h`, `7d`, `14d`, `30d`), `minRiskScore`, `eventName`, `limit` (capped at 100 by the server).

**Responses**

- `/sites` returns full site objects. This server passes on a summary only: `id`, `name`, `domain`, `status`, `last_event_at`, `events_today`, `risky_events_today`. Site keys, the identity key, the owner ID and enforcement settings are not passed to the assistant.
- Event responses arrive with `identity`, `identityContext` and `customerContext` already removed by FindIP. This server also selects fields explicitly, so those would be dropped here in any case.

**Errors**

| Status | `error` | Reported by this server as |
| --- | --- | --- |
| 401 | `invalid_api_key` | `unauthorized`: check `FINDIP_API_KEY` |
| 404 | `not_found` | `not_found`; on `/sites` it means the endpoint is switched off, reported as `endpoint_not_available` |
| 429 | `rate_limited` | `rate_limited` |
| 502 | `shield_api_unreachable` | `upstream_error`: temporary, retry |
| 502 | `key_resolver_unreachable` | `upstream_error`: temporary, retry |

**Limits:** 60 requests per account per minute; 8 failed keys per IP per 10 minutes.

## Notes

- **Host.** The default is `https://www.findip.net`. Redirects are never followed: a redirect to another host would drop the `Authorization` header, so a redirect is reported as an error instead. `FINDIP_PORTAL_BASE_URL` overrides the host.
- **Off switch.** `FINDIP_SHIELD_ACCOUNT_API=0` disables the three account tools locally; they then return `disabled` and send nothing.
- **`verify_session` uses a different key.** The verification endpoint takes a per-site secret key (`FINDIP_SHIELD_SECRET_KEY`) and a session ID, so one server instance verifies sessions for one site.
- **`explain_event` without a site.** Event IDs are scoped to a site, so the server asks each of the account's sites in turn (up to 20, one request each). Pass `site` to make it a single request.
- **The lookup key travels in the URL.** `api.findip.net` accepts the token as a query parameter only. This server keeps request URLs out of every error message.

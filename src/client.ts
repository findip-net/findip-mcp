import { isIP } from 'node:net';
import { VERSION, type Config } from './config.js';

export type FindIPErrorCode =
  | 'missing_api_key'
  | 'missing_secret_key'
  | 'invalid_input'
  | 'endpoint_not_available'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'rate_limited'
  | 'upstream_error'
  | 'network_error';

export class FindIPError extends Error {
  constructor(
    public readonly code: FindIPErrorCode,
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = 'FindIPError';
  }
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

type Json = Record<string, unknown>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACCOUNT_API_PATH = '/api/shield/v1';

export const RANGES = ['24h', '7d', '14d', '30d'] as const;
export type Range = (typeof RANGES)[number];

export interface RiskyEventsOptions {
  site: string;
  range?: Range;
  minRiskScore?: number;
  eventName?: string;
  limit?: number;
}

/** Replaces localized `names` maps with the English name to keep answers short. */
export function compactNames(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(compactNames);
  if (value === null || typeof value !== 'object') return value;
  const out: Json = {};
  for (const [key, inner] of Object.entries(value as Json)) {
    if (key === 'names' && inner !== null && typeof inner === 'object' && !Array.isArray(inner)) {
      const names = inner as Json;
      out.name = names.en ?? Object.values(names)[0] ?? null;
    } else {
      out[key] = compactNames(inner);
    }
  }
  return out;
}

const NETWORK_FLAGS: Array<[field: string, label: string]> = [
  ['isVpn', 'VPN'],
  ['isProxy', 'proxy'],
  ['isTor', 'Tor exit'],
  ['isRelay', 'privacy relay'],
  ['isHosting', 'hosting provider'],
  ['isDatacenter', 'datacenter'],
  ['isMalicious', 'listed as malicious'],
  ['isScanner', 'known scanner'],
  ['isPublicDns', 'public DNS'],
];

function networkSignals(event: Json): string[] {
  return NETWORK_FLAGS.filter(([field]) => event[field] === true).map(([, label]) => label);
}

/**
 * The event fields an assistant needs. End-user identity (email, user ID,
 * hashes) and the raw customer context are left out on purpose.
 */
export function summarizeEvent(event: Json): Json {
  return {
    id: event.id,
    timestamp: event.timestamp,
    event: event.eventName,
    page_path: event.pagePath,
    session_id: event.sessionId,
    visitor_id: event.visitorId,
    ip: event.ipAddress,
    country: event.countryCode,
    asn: event.asn,
    network: event.organization || event.asnName || null,
    network_signals: networkSignals(event),
    risk_status: event.intelOk === false || event.riskScore == null ? 'unknown' : 'available',
    risk_score: event.riskScore ?? null,
    risk_level: event.riskLevel ?? null,
    recommendation: event.recommendation ?? null,
    risk_reasons: Array.isArray(event.riskReasons) ? event.riskReasons : [],
    enforcement_action: event.enforcementAction ?? null,
    enforcement_outcome: event.enforcementOutcome ?? null,
    identified: event.identity != null,
  };
}

export function explainEvent(event: Json): Json {
  const summary = summarizeEvent(event);
  const signals = summary.network_signals as string[];
  const reasons = summary.risk_reasons as string[];
  const lines: string[] = [];

  lines.push(
    `${String(event.eventName ?? 'event')} on ${String(event.pagePath ?? 'unknown page')} at ${String(event.timestamp ?? 'unknown time')}.`,
  );
  const network = [event.organization || event.asnName, event.asn ? `AS${String(event.asn)}` : null]
    .filter(Boolean)
    .join(', ');
  lines.push(
    `Seen from ${String(event.ipAddress ?? 'an unknown IP')}` +
      (event.countryName || event.countryCode ? ` in ${String(event.countryName || event.countryCode)}` : '') +
      (network ? ` (${network})` : '') +
      '.',
  );
  if (summary.risk_status === 'unknown') {
    lines.push('IP intelligence was not available for this event, so it has no score. Treat it as unknown, not as safe.');
  } else {
    lines.push(
      `Risk score ${String(event.riskScore)} of 100 (${String(event.riskLevel ?? 'unrated')}); recommendation: ${String(event.recommendation ?? 'none')}.`,
    );
  }
  lines.push(signals.length ? `Network signals: ${signals.join(', ')}.` : 'No anonymizer or hosting signals on this address.');
  if (reasons.length) lines.push(`Reasons recorded: ${reasons.join(', ')}.`);
  if (event.enforcementAction) {
    lines.push(
      `In-page action: ${String(event.enforcementAction)}` +
        (event.enforcementOutcome ? ` (${String(event.enforcementOutcome)})` : '') +
        '.',
    );
  }
  lines.push(
    'These are risk signals, not a verdict about the person. Confirm with server verification before allowing, challenging or blocking.',
  );

  return {
    explanation: lines.join(' '),
    event: {
      ...summary,
      country_name: event.countryName ?? null,
      page_url: event.pageUrl ?? null,
      referrer_domain: event.referrerDomain ?? null,
      event_source: event.eventSource ?? null,
      event_confidence: event.eventConfidence ?? null,
      form: event.form ?? null,
      sdk_version: event.sdkVersion ?? null,
    },
  };
}

function summarizeSite(site: Json): Json {
  return {
    id: site.id,
    name: site.name,
    domain: site.primaryDomain,
    status: site.status,
    last_event_at: site.lastEventAt ?? null,
    events_today: site.eventsToday ?? 0,
    risky_events_today: site.riskyEventsToday ?? 0,
  };
}

export class FindIPClient {
  constructor(
    private readonly config: Config,
    private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
  ) {}

  // ---- Live today ----

  /** GET https://api.findip.net/{ip}/?token={key} */
  async lookupIp(ip: string): Promise<unknown> {
    const address = ip.trim();
    if (isIP(address) === 0) {
      throw new FindIPError('invalid_input', `"${ip}" is not a valid IPv4 or IPv6 address.`);
    }
    const key = this.requireApiKey();
    const url = `${this.config.lookupBaseUrl}/${encodeURIComponent(address)}/?token=${encodeURIComponent(key)}`;
    const data = await this.request('IP lookup', url, { method: 'GET' });
    return compactNames(data);
  }

  /** POST https://shield.findip.net/v1/shield/sessions/verify with the site secret key. */
  async verifySession(sessionId: string, eventName?: string): Promise<unknown> {
    const id = sessionId.trim();
    if (!id || id.length > 128) {
      throw new FindIPError('invalid_input', 'session_id must be 1 to 128 characters.');
    }
    const secret = this.config.shieldSecretKey;
    if (!secret) {
      throw new FindIPError(
        'missing_secret_key',
        'verify_session needs FINDIP_SHIELD_SECRET_KEY, the secret key (sec_...) of the Shield site the session belongs to. ' +
          'Find it in the FindIP dashboard under Shield, in the site settings.',
      );
    }
    if (!secret.startsWith('sec_')) {
      throw new FindIPError(
        'missing_secret_key',
        'FINDIP_SHIELD_SECRET_KEY must be a Shield site secret key starting with sec_. A public site key (pub_...) or the FindIP API key will not work.',
      );
    }
    const body: Json = { session_id: id };
    if (eventName) body.event = eventName;
    return this.request('Session verification', `${this.config.shieldBaseUrl}/v1/shield/sessions/verify`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  // ---- Proposed Shield account API (docs/BACKEND.md) ----

  async listShieldSites(): Promise<Json[]> {
    return (await this.rawSites()).map(summarizeSite);
  }

  async recentRiskyEvents(options: RiskyEventsOptions): Promise<Json> {
    const range = options.range ?? '7d';
    const minRiskScore = options.minRiskScore ?? 50;
    const limit = options.limit ?? 25;
    const site = await this.resolveSite(options.site);

    const query = new URLSearchParams({ range, minRiskScore: String(minRiskScore), limit: String(limit) });
    if (options.eventName) query.set('eventName', options.eventName);
    const data = (await this.accountApi(
      `/sites/${encodeURIComponent(String(site.id))}/events?${query.toString()}`,
    )) as { events?: Json[]; nextCursor?: string | null };

    const events = (data.events ?? []).map(summarizeEvent);
    return {
      site: { id: site.id, name: site.name, domain: site.primaryDomain },
      range,
      min_risk_score: minRiskScore,
      returned: events.length,
      has_more: data.nextCursor != null,
      events,
    };
  }

  async explainEvent(eventId: string, site?: string): Promise<Json> {
    const id = eventId.trim();
    if (!id || id.length > 128) {
      throw new FindIPError('invalid_input', 'event_id must be 1 to 128 characters.');
    }
    const candidates = site ? [await this.resolveSite(site)] : await this.rawSites();
    if (candidates.length === 0) {
      throw new FindIPError('not_found', 'This account has no Shield sites.');
    }
    // An event ID is scoped to a site, so without one each site is asked in turn.
    for (const candidate of candidates.slice(0, 20)) {
      try {
        const event = (await this.accountApi(
          `/sites/${encodeURIComponent(String(candidate.id))}/events/${encodeURIComponent(id)}`,
        )) as Json;
        return { site: { id: candidate.id, name: candidate.name, domain: candidate.primaryDomain }, ...explainEvent(event) };
      } catch (error) {
        if (error instanceof FindIPError && error.code === 'not_found') continue;
        throw error;
      }
    }
    throw new FindIPError(
      'not_found',
      `No event ${id} was found${site ? ' on that site' : ' on your Shield sites'}. It may be older than the site's event retention.`,
    );
  }

  // ---- Internals ----

  private requireApiKey(): string {
    if (!this.config.apiKey) {
      throw new FindIPError(
        'missing_api_key',
        'FINDIP_API_KEY is not set. Create a free key at https://findip.net and add it to the MCP server environment.',
      );
    }
    return this.config.apiKey;
  }

  private async rawSites(): Promise<Json[]> {
    const data = await this.accountApi('/sites');
    if (!Array.isArray(data)) {
      throw new FindIPError('upstream_error', 'The Shield account API returned an unexpected site list.');
    }
    return data as Json[];
  }

  private async resolveSite(site: string): Promise<Json> {
    const wanted = site.trim().toLowerCase();
    if (!wanted) throw new FindIPError('invalid_input', 'site is required: a site ID, name or domain.');
    const sites = await this.rawSites();
    const matches = UUID_RE.test(wanted)
      ? sites.filter((s) => String(s.id).toLowerCase() === wanted)
      : sites.filter(
          (s) => String(s.primaryDomain ?? '').toLowerCase() === wanted || String(s.name ?? '').toLowerCase() === wanted,
        );
    if (matches.length === 1) return matches[0] as Json;
    const known = sites.map((s) => `${String(s.name)} (${String(s.primaryDomain)}, ${String(s.id)})`).join('; ');
    throw new FindIPError(
      matches.length === 0 ? 'not_found' : 'invalid_input',
      matches.length === 0
        ? `No Shield site matches "${site}". Your sites: ${known || 'none'}.`
        : `"${site}" matches more than one Shield site. Use the site ID. Your sites: ${known}.`,
    );
  }

  private notAvailable(path: string): FindIPError {
    const endpoint = `GET ${this.config.portalBaseUrl}${ACCOUNT_API_PATH}${path.split('?')[0]}`;
    return new FindIPError(
      'endpoint_not_available',
      `This tool requires the FindIP Shield account API (${endpoint}), which is not available yet. ` +
        'Shield dashboard data is currently reachable only from a signed-in browser at https://findip.net/shield. ' +
        'lookup_ip and verify_session work today. Once the endpoint is live, set FINDIP_SHIELD_ACCOUNT_API=1.',
    );
  }

  private async accountApi(path: string): Promise<unknown> {
    if (!this.config.shieldAccountApiEnabled) throw this.notAvailable(path);
    const key = this.requireApiKey();
    try {
      return await this.request('Shield account API', `${this.config.portalBaseUrl}${ACCOUNT_API_PATH}${path}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${key}` },
      });
    } catch (error) {
      // The endpoint is feature-flagged off by default and answers 404 then;
      // only /sites can tell "not deployed" from "no such site or event".
      if (error instanceof FindIPError && error.code === 'not_found' && path === '/sites') {
        throw this.notAvailable(path);
      }
      throw error;
    }
  }

  /** Never puts the request URL in an error: the lookup URL carries the API key. */
  private async request(what: string, url: string, init: RequestInit): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        ...init,
        redirect: 'manual',
        headers: { Accept: 'application/json', 'User-Agent': `findip-mcp/${VERSION}`, ...(init.headers as Record<string, string>) },
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (error) {
      const timedOut = error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError');
      throw new FindIPError('network_error', timedOut ? `${what} timed out.` : `${what} could not reach FindIP.`);
    }

    const text = await response.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }

    if (response.ok) {
      if (body === null) throw new FindIPError('upstream_error', `${what} returned a response that is not JSON.`, response.status);
      return body;
    }

    const detail = upstreamDetail(body);
    const suffix = detail ? ` (${detail})` : '';
    switch (response.status) {
      case 400:
        // api.findip.net answers 400 for a missing or unknown token.
        throw /api ?key|token/i.test(detail)
          ? new FindIPError('unauthorized', `${what}: FindIP did not accept the API key. Check FINDIP_API_KEY.`, 400)
          : new FindIPError('invalid_input', `${what} rejected the request${suffix}.`, 400);
      case 401:
        throw new FindIPError('unauthorized', `${what}: the key was not accepted${suffix}.`, 401);
      case 403:
        throw new FindIPError('forbidden', `${what} was refused${suffix}.`, 403);
      case 404:
        throw new FindIPError('not_found', `${what} found nothing${suffix}.`, 404);
      case 429:
        throw new FindIPError('rate_limited', `${what} is rate limited. Wait a moment and try again.`, 429);
      default:
        throw new FindIPError('upstream_error', `${what} failed with HTTP ${response.status}${suffix}.`, response.status);
    }
  }
}

function upstreamDetail(body: unknown): string {
  if (body === null || typeof body !== 'object') return '';
  const b = body as Json;
  for (const field of ['message', 'detail', 'error', 'code', 'title']) {
    const value = b[field];
    if (typeof value === 'string' && value) return value.slice(0, 200);
  }
  return '';
}

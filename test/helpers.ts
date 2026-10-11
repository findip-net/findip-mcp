import type { Config, FetchLike } from '../src/server.js';

export const KEY = 'test-api-key-123';
export const SECRET = 'sec_test_secret';

export function config(overrides: Partial<Config> = {}): Config {
  return {
    apiKey: KEY,
    shieldSecretKey: SECRET,
    lookupBaseUrl: 'https://api.findip.net',
    shieldBaseUrl: 'https://shield.findip.net',
    portalBaseUrl: 'https://www.findip.net',
    shieldAccountApiEnabled: true,
    timeoutMs: 1000,
    ...overrides,
  };
}

export interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

type Reply = { status?: number; json?: unknown; text?: string } | Error;

/** Mocked HTTP: routes are "METHOD url"; nothing reaches the network. */
export function mockFetch(routes: Record<string, Reply | ((call: Call) => Reply)>): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    const call: Call = {
      url,
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const match = Object.keys(routes)
      .filter((route) => {
        const target = `${call.method} ${url}`;
        // A route ending in "/" is a prefix; any other route is an exact path.
        return route.endsWith('/') ? target.startsWith(route) : target.split('?')[0] === route;
      })
      .sort((a, b) => b.length - a.length)[0];
    if (!match) return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    const entry = routes[match]!;
    const reply = typeof entry === 'function' ? entry(call) : entry;
    if (reply instanceof Error) throw reply;
    return new Response(reply.text ?? JSON.stringify(reply.json ?? null), { status: reply.status ?? 200 });
  };
  return { fetch, calls };
}

export const SITE_A = {
  id: '11111111-1111-4111-8111-111111111111',
  userId: 'user-1',
  name: 'Main shop',
  primaryDomain: 'shop.example',
  status: 'active',
  publicSiteKey: 'pub_abc',
  identityKey: 'fk1.k1.BASE64SPKI',
  enforcement: { enabled: true, blockAction: 'stop', turnstileSiteKey: '0xTURNSTILE' },
  turnstileSecretSet: true,
  lastEventAt: '2026-10-10T10:00:00.000Z',
  eventsToday: 120,
  riskyEventsToday: 7,
};

export const SITE_B = {
  ...SITE_A,
  id: '22222222-2222-4222-8222-222222222222',
  name: 'Blog',
  primaryDomain: 'blog.example',
};

export const EVENT = {
  id: 'evt_1',
  shieldSiteId: SITE_A.id,
  sessionId: 'sess_1',
  visitorId: 'vis_1',
  eventName: 'signup_attempt',
  eventSource: 'auto',
  eventConfidence: 0.9,
  timestamp: '2026-10-09T08:00:00.000Z',
  pageUrl: 'https://shop.example/signup',
  pagePath: '/signup',
  referrerDomain: null,
  ipAddress: '203.0.113.9',
  countryCode: 'NL',
  countryName: 'Netherlands',
  asn: 64500,
  asnName: 'EXAMPLE-NET',
  organization: 'Example Hosting',
  isVpn: true,
  isProxy: false,
  isTor: false,
  isRelay: false,
  isHosting: true,
  isDatacenter: false,
  isMalicious: false,
  isScanner: false,
  isPublicDns: false,
  intelOk: true,
  riskScore: 82,
  riskLevel: 'critical',
  recommendation: 'block',
  riskReasons: ['vpn_detected', 'hosting_provider'],
  browser: {},
  form: { type: 'signup' },
  // The live endpoint strips identity, identityContext and customerContext.
  // They stay in this fixture to prove the client would drop them as well.
  customerContext: { email_hash: 'abc' },
  identity: { email: 'person@example.com', userId: 'u_42', emailDomain: 'example.com', encrypted: true },
  enforcementAction: 'stop',
  enforcementOutcome: 'stopped',
  sdkVersion: '1.11.0',
};

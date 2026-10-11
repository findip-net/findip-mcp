import { describe, expect, it } from 'vitest';
import { FindIPClient, FindIPError } from '../src/client.js';
import { loadConfig } from '../src/config.js';
import { EVENT, KEY, SECRET, SITE_A, SITE_B, config, mockFetch } from './helpers.js';

const API = 'https://findip.net/api/shield/v1';

async function failure(work: Promise<unknown>): Promise<FindIPError> {
  try {
    await work;
  } catch (error) {
    expect(error).toBeInstanceOf(FindIPError);
    return error as FindIPError;
  }
  throw new Error('expected a FindIPError');
}

describe('loadConfig', () => {
  it('uses production defaults and keeps the account API off', () => {
    const c = loadConfig({ FINDIP_API_KEY: ' k ' });
    expect(c).toMatchObject({
      apiKey: 'k',
      lookupBaseUrl: 'https://api.findip.net',
      shieldBaseUrl: 'https://shield.findip.net',
      portalBaseUrl: 'https://findip.net',
      shieldAccountApiEnabled: false,
      timeoutMs: 15000,
    });
  });

  it('reads overrides and rejects a bad URL', () => {
    expect(loadConfig({ FINDIP_SHIELD_ACCOUNT_API: 'true', FINDIP_API_BASE_URL: 'http://localhost:8080/' })).toMatchObject({
      shieldAccountApiEnabled: true,
      lookupBaseUrl: 'http://localhost:8080',
    });
    expect(() => loadConfig({ FINDIP_PORTAL_BASE_URL: 'ftp://x' })).toThrow(/FINDIP_PORTAL_BASE_URL/);
  });
});

describe('lookupIp', () => {
  it('calls api.findip.net with the token and compacts localized names', async () => {
    const { fetch, calls } = mockFetch({
      'GET https://api.findip.net/8.8.8.8/': {
        json: {
          country: { iso_code: 'US', names: { de: 'USA', en: 'United States' } },
          subdivisions: [{ names: { en: 'California', fr: 'Californie' } }],
          traits: { isp: 'Google LLC', autonomous_system_number: 15169 },
          intelligence: { risk: { score: 5 }, flags: { is_vpn: false } },
        },
      },
    });
    const result = await new FindIPClient(config(), fetch).lookupIp(' 8.8.8.8 ');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`https://api.findip.net/8.8.8.8/?token=${KEY}`);
    expect(result).toEqual({
      country: { iso_code: 'US', name: 'United States' },
      subdivisions: [{ name: 'California' }],
      traits: { isp: 'Google LLC', autonomous_system_number: 15169 },
      intelligence: { risk: { score: 5 }, flags: { is_vpn: false } },
    });
  });

  it('encodes IPv6 addresses', async () => {
    const { fetch, calls } = mockFetch({ 'GET https://api.findip.net/': { json: {} } });
    await new FindIPClient(config(), fetch).lookupIp('2001:4860:4860::8888');
    expect(calls[0]!.url).toContain('/2001%3A4860%3A4860%3A%3A8888/?token=');
  });

  it('rejects anything that is not an IP before any request', async () => {
    const { fetch, calls } = mockFetch({});
    const error = await failure(new FindIPClient(config(), fetch).lookupIp('../admin'));
    expect(error.code).toBe('invalid_input');
    expect(calls).toHaveLength(0);
  });

  it('asks for the API key when it is missing', async () => {
    const { fetch, calls } = mockFetch({});
    const error = await failure(new FindIPClient(config({ apiKey: '' }), fetch).lookupIp('1.1.1.1'));
    expect(error.code).toBe('missing_api_key');
    expect(calls).toHaveLength(0);
  });

  it('maps an invalid key, rate limits and outages without leaking the key', async () => {
    const cases: Array<[unknown, number, string]> = [
      [{ title: 'One or more validation errors occurred.', detail: 'Invalid apiKey.' }, 400, 'unauthorized'],
      [{ code: 'email_verification_required', message: 'Verify your email.' }, 403, 'forbidden'],
      [{ message: 'No data found for IP address: 10.0.0.1' }, 404, 'not_found'],
      [{ message: 'Too many requests' }, 429, 'rate_limited'],
      [{}, 502, 'upstream_error'],
    ];
    for (const [json, status, code] of cases) {
      const { fetch } = mockFetch({ 'GET https://api.findip.net/': { status, json } });
      const error = await failure(new FindIPClient(config(), fetch).lookupIp('10.0.0.1'));
      expect(error.code).toBe(code);
      expect(error.message).not.toContain(KEY);
    }
    const { fetch } = mockFetch({ 'GET https://api.findip.net/': new TypeError(`fetch failed for ?token=${KEY}`) });
    const error = await failure(new FindIPClient(config(), fetch).lookupIp('10.0.0.1'));
    expect(error.code).toBe('network_error');
    expect(error.message).not.toContain(KEY);
  });
});

describe('verifySession', () => {
  it('posts the session ID with the site secret key', async () => {
    const reply = { verified: true, risk_status: 'available', risk_score: 87, recommendation: 'challenge' };
    const { fetch, calls } = mockFetch({ 'POST https://shield.findip.net/v1/shield/sessions/verify': { json: reply } });
    const result = await new FindIPClient(config(), fetch).verifySession('sess_abc', 'signup_attempt');
    expect(result).toEqual(reply);
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${SECRET}`);
    expect(calls[0]!.body).toEqual({ session_id: 'sess_abc', event: 'signup_attempt' });
    // The account API key never goes to the verification endpoint.
    expect(JSON.stringify(calls[0])).not.toContain(KEY);
  });

  it('passes an unknown session through as unverified', async () => {
    const reply = { verified: false, risk_score: null, recommendation: null };
    const { fetch } = mockFetch({ 'POST https://shield.findip.net/': { json: reply } });
    expect(await new FindIPClient(config(), fetch).verifySession('sess_x')).toEqual(reply);
  });

  it('needs a sec_ key and never sends anything else', async () => {
    for (const shieldSecretKey of ['', 'pub_abc', KEY]) {
      const { fetch, calls } = mockFetch({});
      const error = await failure(new FindIPClient(config({ shieldSecretKey }), fetch).verifySession('sess_abc'));
      expect(error.code).toBe('missing_secret_key');
      expect(calls).toHaveLength(0);
    }
  });

  it('maps a rejected secret key', async () => {
    const { fetch } = mockFetch({ 'POST https://shield.findip.net/': { status: 401, json: { error: 'invalid_secret_key' } } });
    const error = await failure(new FindIPClient(config(), fetch).verifySession('sess_abc'));
    expect(error.code).toBe('unauthorized');
    expect(error.message).not.toContain(SECRET);
  });
});

describe('Shield account API (proposed)', () => {
  it('is off by default: names the endpoint and sends nothing', async () => {
    const { fetch, calls } = mockFetch({});
    const client = new FindIPClient(config({ shieldAccountApiEnabled: false }), fetch);
    for (const work of [client.listShieldSites(), client.recentRiskyEvents({ site: 'shop.example' }), client.explainEvent('evt_1')]) {
      const error = await failure(work);
      expect(error.code).toBe('endpoint_not_available');
      expect(error.message).toContain('GET https://findip.net/api/shield/v1/sites');
    }
    expect(calls).toHaveLength(0);
  });

  it('treats a 404 on /sites as the endpoint not being deployed', async () => {
    const { fetch } = mockFetch({});
    const error = await failure(new FindIPClient(config(), fetch).listShieldSites());
    expect(error.code).toBe('endpoint_not_available');
  });

  it('lists sites with a bearer API key and trims them', async () => {
    const { fetch, calls } = mockFetch({ [`GET ${API}/sites`]: { json: [SITE_A, SITE_B] } });
    const sites = await new FindIPClient(config(), fetch).listShieldSites();
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${KEY}`);
    expect(calls[0]!.url).toBe(`${API}/sites`);
    expect(sites[0]).toEqual({
      id: SITE_A.id,
      name: 'Main shop',
      domain: 'shop.example',
      status: 'active',
      last_event_at: SITE_A.lastEventAt,
      events_today: 120,
      risky_events_today: 7,
    });
    expect(JSON.stringify(sites)).not.toContain('pub_abc');
  });

  it('fetches risky events for a site named by domain, without identity', async () => {
    const { fetch, calls } = mockFetch({
      [`GET ${API}/sites`]: { json: [SITE_A, SITE_B] },
      [`GET ${API}/sites/${SITE_A.id}/events`]: { json: { events: [EVENT], nextCursor: '25' } },
    });
    const result = await new FindIPClient(config(), fetch).recentRiskyEvents({
      site: 'Shop.Example',
      eventName: 'signup_attempt',
    });
    const url = new URL(calls[1]!.url);
    expect(url.pathname).toBe(`/api/shield/v1/sites/${SITE_A.id}/events`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      range: '7d',
      minRiskScore: '50',
      limit: '25',
      eventName: 'signup_attempt',
    });
    expect(result).toMatchObject({ range: '7d', min_risk_score: 50, returned: 1, has_more: true });
    const [event] = result.events as Array<Record<string, unknown>>;
    expect(event).toMatchObject({
      id: 'evt_1',
      event: 'signup_attempt',
      ip: '203.0.113.9',
      network_signals: ['VPN', 'hosting provider'],
      risk_score: 82,
      recommendation: 'block',
      identified: true,
    });
    const text = JSON.stringify(result);
    expect(text).not.toContain('person@example.com');
    expect(text).not.toContain('u_42');
    expect(text).not.toContain('email_hash');
  });

  it('reports the known sites when the name does not match', async () => {
    const { fetch } = mockFetch({ [`GET ${API}/sites`]: { json: [SITE_A, SITE_B] } });
    const error = await failure(new FindIPClient(config(), fetch).recentRiskyEvents({ site: 'nope.example' }));
    expect(error.code).toBe('not_found');
    expect(error.message).toContain('shop.example');
  });

  it('explains an event, searching each site when none is given', async () => {
    const { fetch, calls } = mockFetch({
      [`GET ${API}/sites`]: { json: [SITE_B, SITE_A] },
      [`GET ${API}/sites/${SITE_A.id}/events/evt_1`]: { json: EVENT },
    });
    const result = await new FindIPClient(config(), fetch).explainEvent('evt_1');
    expect(calls.map((c) => c.url)).toEqual([
      `${API}/sites`,
      `${API}/sites/${SITE_B.id}/events/evt_1`,
      `${API}/sites/${SITE_A.id}/events/evt_1`,
    ]);
    expect(result.site).toMatchObject({ id: SITE_A.id });
    const explanation = String(result.explanation);
    expect(explanation).toContain('signup_attempt on /signup');
    expect(explanation).toContain('Risk score 82 of 100 (critical); recommendation: block.');
    expect(explanation).toContain('Network signals: VPN, hosting provider.');
    expect(explanation).toContain('risk signals, not a verdict');
    expect(JSON.stringify(result)).not.toContain('person@example.com');
  });

  it('never calls an unscored event safe', async () => {
    const { fetch } = mockFetch({
      [`GET ${API}/sites`]: { json: [SITE_A] },
      [`GET ${API}/sites/${SITE_A.id}/events/evt_2`]: {
        json: { ...EVENT, id: 'evt_2', intelOk: false, riskScore: null, riskLevel: null, recommendation: null, isVpn: false, isHosting: false },
      },
    });
    const result = await new FindIPClient(config(), fetch).explainEvent('evt_2', SITE_A.id);
    expect((result.event as Record<string, unknown>).risk_status).toBe('unknown');
    expect(String(result.explanation)).toContain('Treat it as unknown, not as safe.');
  });

  it('says so when no site has the event, and surfaces a rejected key', async () => {
    const found = mockFetch({ [`GET ${API}/sites`]: { json: [SITE_A, SITE_B] } });
    expect((await failure(new FindIPClient(config(), found.fetch).explainEvent('evt_missing'))).code).toBe('not_found');

    const denied = mockFetch({ [`GET ${API}/sites`]: { status: 401, json: { error: 'invalid_api_key' } } });
    const error = await failure(new FindIPClient(config(), denied.fetch).listShieldSites());
    expect(error.code).toBe('unauthorized');
    expect(error.message).not.toContain(KEY);
  });
});

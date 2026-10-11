export const VERSION = '0.1.0';

export interface Config {
  /** FindIP API key (the token used with api.findip.net). */
  apiKey: string;
  /** Shield site secret key (`sec_...`) for server verification. */
  shieldSecretKey: string;
  /** Public IP lookup API. */
  lookupBaseUrl: string;
  /** Shield ingest and verification API. */
  shieldBaseUrl: string;
  /** FindIP portal, where the proposed account API would live. */
  portalBaseUrl: string;
  /**
   * The Shield account API (docs/BACKEND.md) is a proposal and is not live.
   * Off by default, so the API key is never sent to an endpoint that does not exist.
   */
  shieldAccountApiEnabled: boolean;
  timeoutMs: number;
}

function baseUrl(value: string | undefined, fallback: string, name: string): string {
  const raw = value?.trim() || fallback;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name} is not a valid URL.`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${name} must be an http(s) URL.`);
  }
  return raw.replace(/\/+$/, '');
}

function flag(value: string | undefined): boolean {
  return ['1', 'true', 'yes', 'on'].includes((value ?? '').trim().toLowerCase());
}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const timeout = Number.parseInt(env.FINDIP_TIMEOUT_MS ?? '', 10);
  return {
    apiKey: env.FINDIP_API_KEY?.trim() ?? '',
    shieldSecretKey: env.FINDIP_SHIELD_SECRET_KEY?.trim() ?? '',
    lookupBaseUrl: baseUrl(env.FINDIP_API_BASE_URL, 'https://api.findip.net', 'FINDIP_API_BASE_URL'),
    shieldBaseUrl: baseUrl(env.FINDIP_SHIELD_BASE_URL, 'https://shield.findip.net', 'FINDIP_SHIELD_BASE_URL'),
    portalBaseUrl: baseUrl(env.FINDIP_PORTAL_BASE_URL, 'https://findip.net', 'FINDIP_PORTAL_BASE_URL'),
    shieldAccountApiEnabled: flag(env.FINDIP_SHIELD_ACCOUNT_API),
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? Math.min(timeout, 60_000) : 15_000,
  };
}

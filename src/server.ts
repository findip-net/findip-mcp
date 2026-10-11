import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { FindIPClient, FindIPError, RANGES, type FetchLike } from './client.js';
import { VERSION, loadConfig, type Config } from './config.js';

export { FindIPClient, FindIPError, loadConfig };
export type { Config, FetchLike };

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

async function run(work: () => Promise<unknown>): Promise<CallToolResult> {
  try {
    return { content: [{ type: 'text', text: JSON.stringify(await work(), null, 2) }] };
  } catch (error) {
    const known = error instanceof FindIPError;
    const payload = {
      error: known ? error.code : 'internal_error',
      message: known ? error.message : 'Unexpected error in the FindIP MCP server.',
    };
    return { isError: true, content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
  }
}

export function createServer(config: Config = loadConfig(), fetchImpl?: FetchLike): McpServer {
  const client = new FindIPClient(config, fetchImpl);
  const server = new McpServer({ name: 'findip', version: VERSION });

  server.registerTool(
    'lookup_ip',
    {
      title: 'Look up an IP address',
      description:
        'IP intelligence for one IPv4 or IPv6 address from FindIP: country, city, ISP and ASN, connection type, ' +
        'and risk signals (VPN, proxy, Tor, relay, hosting, scanner, malicious listings, threat score). ' +
        'Signals describe the network an address belongs to, not the person using it.',
      inputSchema: { ip: z.string().min(2).max(45).describe('IPv4 or IPv6 address, for example 8.8.8.8') },
      annotations: READ_ONLY,
    },
    ({ ip }) => run(() => client.lookupIp(ip)),
  );

  server.registerTool(
    'verify_session',
    {
      title: 'Verify a Shield session',
      description:
        'Server-side risk check for one FindIP Shield session: risk score, recommendation (allow, monitor, challenge, block), ' +
        'whether a challenge was passed, and the session picture (IP, ASN and country rotation, network flags, risk reasons). ' +
        'This is the same check a backend runs before acting on a signup, login or checkout. ' +
        'An unknown session returns verified: false; a session without IP intelligence returns risk_status "unknown", which is not the same as safe. ' +
        'Uses the site secret key from FINDIP_SHIELD_SECRET_KEY.',
      inputSchema: {
        session_id: z.string().min(1).max(128).describe('Shield session ID sent by the browser SDK (FindIP.getSession().sessionId)'),
        event: z.string().max(64).optional().describe('Optional event the check is for, for example signup_attempt'),
      },
      annotations: READ_ONLY,
    },
    ({ session_id, event }) => run(() => client.verifySession(session_id, event)),
  );

  server.registerTool(
    'list_shield_sites',
    {
      title: 'List Shield sites',
      description:
        'Lists the FindIP Shield sites on your account: ID, name, domain, status, last event time and today\'s event and risky-event counts. ' +
        'Start here to find the site to ask about.',
      inputSchema: {},
      annotations: READ_ONLY,
    },
    () => run(() => client.listShieldSites()),
  );

  server.registerTool(
    'recent_risky_events',
    {
      title: 'Recent risky events',
      description:
        'Recent events on one Shield site at or above a risk score, newest first: event name, page, IP, country, network, ' +
        'network signals, score, recommendation and reasons. Good for questions like "what risky traffic hit my signup form this week". ' +
        'End-user identity is never returned.',
      inputSchema: {
        site: z.string().min(1).max(253).describe('Site ID, name or domain, as shown by list_shield_sites'),
        range: z.enum(RANGES).optional().describe('Time window. Default 7d'),
        min_risk_score: z.number().int().min(0).max(100).optional().describe('Lowest risk score to include. Default 50 (high and critical)'),
        event_name: z.string().max(64).optional().describe('Only this event, for example signup_attempt, login_attempt or payment_attempt'),
        limit: z.number().int().min(1).max(100).optional().describe('Maximum events to return. Default 25'),
      },
      annotations: READ_ONLY,
    },
    ({ site, range, min_risk_score, event_name, limit }) =>
      run(() => client.recentRiskyEvents({ site, range, minRiskScore: min_risk_score, eventName: event_name, limit })),
  );

  server.registerTool(
    'explain_event',
    {
      title: 'Explain a Shield event',
      description:
        'Explains one Shield event in plain language: where it came from, which risk signals fired, the score and recommendation, ' +
        'and what the in-page SDK did. The explanation describes risk signals, not a verdict about the visitor.',
      inputSchema: {
        event_id: z.string().min(1).max(128).describe('Event ID from recent_risky_events'),
        site: z.string().max(253).optional().describe('Site ID, name or domain. Optional; without it each of your sites is checked'),
      },
      annotations: READ_ONLY,
    },
    ({ event_id, site }) => run(() => client.explainEvent(event_id, site || undefined)),
  );

  return server;
}

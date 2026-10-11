import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { createServer, type Config, type FetchLike } from '../src/server.js';
import { KEY, SITE_A, config, mockFetch } from './helpers.js';

async function connect(cfg: Config, fetch: FetchLike): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createServer(cfg, fetch).connect(serverSide);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(clientSide);
  return client;
}

function text(result: Awaited<ReturnType<Client['callTool']>>): string {
  const content = result.content as Array<{ type: string; text: string }>;
  return content[0]!.text;
}

describe('MCP server', () => {
  it('registers the five read-only tools', async () => {
    const client = await connect(config(), mockFetch({}).fetch);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'explain_event',
      'list_shield_sites',
      'lookup_ip',
      'recent_risky_events',
      'verify_session',
    ]);
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.description).toBeTruthy();
      // Copy rules: risk signals, never proof.
      expect(tool.description).not.toMatch(/proof|fraudster|guarantee|not available yet/i);
    }
  });

  it('answers lookup_ip over the protocol', async () => {
    const { fetch } = mockFetch({ 'GET https://api.findip.net/1.1.1.1/': { json: { country: { names: { en: 'Australia' } } } } });
    const client = await connect(config(), fetch);
    const result = await client.callTool({ name: 'lookup_ip', arguments: { ip: '1.1.1.1' } });
    expect(result.isError).toBeFalsy();
    expect(JSON.parse(text(result))).toEqual({ country: { name: 'Australia' } });
  });

  it('answers verify_session over the protocol', async () => {
    const { fetch } = mockFetch({ 'POST https://shield.findip.net/v1/shield/sessions/verify': { json: { verified: true, risk_score: 12 } } });
    const client = await connect(config(), fetch);
    const result = await client.callTool({ name: 'verify_session', arguments: { session_id: 'sess_1' } });
    expect(JSON.parse(text(result))).toEqual({ verified: true, risk_score: 12 });
  });

  it('lists Shield sites by default, as a compact summary', async () => {
    const { fetch, calls } = mockFetch({ 'GET https://www.findip.net/api/shield/v1/sites': { json: [SITE_A] } });
    const client = await connect(config(), fetch);
    const result = await client.callTool({ name: 'list_shield_sites', arguments: {} });
    expect(result.isError).toBeFalsy();
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${KEY}`);
    const body = text(result);
    expect(JSON.parse(body)).toHaveLength(1);
    expect(body).not.toMatch(/identityKey|userId|enforcement|pub_abc/);
  });

  it('returns a clear tool error when the account tools are switched off', async () => {
    const { fetch, calls } = mockFetch({});
    const client = await connect(config({ shieldAccountApiEnabled: false }), fetch);
    const result = await client.callTool({ name: 'recent_risky_events', arguments: { site: 'shop.example' } });
    expect(result.isError).toBe(true);
    const payload = JSON.parse(text(result)) as { error: string; message: string };
    expect(payload.error).toBe('disabled');
    expect(payload.message).toContain('FINDIP_SHIELD_ACCOUNT_API');
    expect(calls).toHaveLength(0);
  });

  it('rejects invalid arguments and hides unexpected errors', async () => {
    const boom: FetchLike = async () => {
      throw new Error(`secret detail ${KEY}`);
    };
    const client = await connect(config(), boom);
    const bad = await client.callTool({ name: 'recent_risky_events', arguments: { site: 'x', range: '1y' } }).catch((e: unknown) => e);
    const badText = bad instanceof Error ? bad.message : text(bad as Awaited<ReturnType<Client['callTool']>>);
    expect(badText).toMatch(/range|invalid/i);

    const failed = await client.callTool({ name: 'lookup_ip', arguments: { ip: '1.1.1.1' } });
    expect(failed.isError).toBe(true);
    expect(text(failed)).not.toContain(KEY);
  });
});

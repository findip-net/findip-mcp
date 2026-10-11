#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer, loadConfig } from './server.js';

async function main(): Promise<void> {
  const config = loadConfig();
  // stdout carries the protocol; anything for a human goes to stderr.
  if (!config.apiKey) {
    console.error('findip-mcp: FINDIP_API_KEY is not set. Tools will ask for it. Get a free key at https://findip.net');
  }
  await createServer(config).connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  console.error(`findip-mcp: ${error instanceof Error ? error.message : 'failed to start'}`);
  process.exit(1);
});

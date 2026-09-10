import { createServer } from 'node:http';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { localhostHostValidation, toNodeHandler } from '@modelcontextprotocol/node';
import * as z from 'zod/v4';
import { createAuthenticator } from './auth.ts';
import type { Config } from './config.ts';
import { execute } from './exec.ts';

export function createWayfinder(config: Config) {
  const shutdown = new AbortController();
  const executions = new Set<Promise<unknown>>();
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'wayfinder', version: '0.1.0' });
    server.registerTool('exec', {
      description: 'Execute a shell command locally as the OS user running Wayfinder. No sandbox. Timeout is in milliseconds.',
      inputSchema: z.object({
        command: z.string().min(1).refine((s) => !s.includes('\0'), 'NUL is not allowed'),
        cwd: z.string().min(1).refine((s) => !s.includes('\0'), 'NUL is not allowed').optional(),
        timeout: z.number().int().min(1).max(config.maxTimeout).default(config.timeout),
        env: z.record(z.string().min(1).regex(/^[^=\0]+$/), z.string().refine((s) => !s.includes('\0'), 'NUL is not allowed')).optional(),
      }),
      outputSchema: z.object({
        stdout: z.string(), stderr: z.string(), exitCode: z.number().int().nullable(),
        signal: z.string().nullable(), timedOut: z.boolean(), error: z.string().optional(),
      }),
    }, async (input, context) => {
      const pending = execute(input, AbortSignal.any([shutdown.signal, context.mcpReq.signal]));
      executions.add(pending);
      try {
        const result = await pending;
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
          structuredContent: { ...result },
          isError: result.exitCode !== 0 || result.timedOut || !!result.error,
        };
      } finally { executions.delete(pending); }
    });
    return server;
  }, { responseMode: 'json' });
  const authenticate = createAuthenticator(config.token);
  const validateHost = localhostHostValidation();
  const loopback = ['localhost', '127.0.0.1', '::1'].includes(config.host);
  const nodeHandler = toNodeHandler(handler);
  const http = createServer((req, res) => {
    // Reject unknown paths before auth so OAuth/PRMD probes (and any other
    // non-MCP request) get a clean 404 instead of a 401 with a text body that
    // breaks JSON-expecting discovery clients. Only /mcp is auth-protected.
    if (req.url !== '/mcp') { res.writeHead(404).end('Not found'); return; }
    if (!authenticate(req, res)) return;
    if (loopback && !validateHost(req, res)) return;
    // This endpoint is for direct MCP clients, not browser pages.
    if (req.headers.origin) { res.writeHead(403).end('Browser origins are not supported'); return; }
    if (shutdown.signal.aborted) { res.writeHead(503).end('Shutting down'); return; }
    void nodeHandler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end('MCP request failed');
      else res.destroy();
    });
  });
  return {
    http,
    async close() {
      shutdown.abort();
      const closed = new Promise<void>((resolve) => http.close(() => resolve()));
      await Promise.allSettled(executions);
      await handler.close();
      http.closeAllConnections();
      await closed;
    },
  };
}

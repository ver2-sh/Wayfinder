import { loadConfig } from './config.ts';
import { createWayfinder } from './server.ts';

try {
  const config = loadConfig();
  const app = createWayfinder(config);
  app.http.on('error', (error: NodeJS.ErrnoException) => {
    console.error(`Wayfinder could not listen (${error.code ?? 'UNKNOWN'}). Check the configured host and port.`);
    process.exitCode = 1;
    void app.close().catch(() => { console.error('Wayfinder shutdown failed.'); process.exitCode = 1; });
  });
  app.http.listen(config.port, config.host, () => {
    const host = config.host.includes(':') ? `[${config.host}]` : config.host;
    console.log(`Wayfinder listening at http://${host}:${config.port}/mcp`);
  });
  let closing = false;
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
      if (closing) return;
      closing = true;
      void app.close().catch(() => { console.error('Wayfinder shutdown failed.'); process.exitCode = 1; });
    });
  }
} catch (error) {
  console.error((error as Error).message);
  process.exitCode = 1;
}

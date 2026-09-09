export interface Config {
  token: string;
  host: string;
  port: number;
  timeout: number;
  maxTimeout: number;
}

export function loadConfig(env = process.env): Config {
  const token = env.WAYFINDER_TOKEN;
  if (!token || token === 'replace-with-a-random-token' || !/^[A-Za-z0-9._~+/-]{32,}={0,2}$/.test(token)) {
    throw new Error('WAYFINDER_TOKEN must be a random bearer token of at least 32 characters.');
  }
  function integer(name: string, fallback: number, max: number): number {
    const raw = env[name] ?? String(fallback);
    const value = Number(raw);
    if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || value < 1 || value > max) {
      throw new Error(`${name} must be an integer between 1 and ${max}.`);
    }
    return value;
  }
  const maxTimeout = integer('WAYFINDER_MAX_TIMEOUT_MS', 300_000, 2_147_483_647);
  const timeout = integer('WAYFINDER_TIMEOUT_MS', 30_000, maxTimeout);
  const host = env.WAYFINDER_HOST ?? '127.0.0.1';
  if (!host.trim() || host !== host.trim() || /[\r\n]/.test(host)) throw new Error('Invalid WAYFINDER_HOST.');
  return { token, host, port: integer('WAYFINDER_PORT', 3000, 65535), timeout, maxTimeout };
}

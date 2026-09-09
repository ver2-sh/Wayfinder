import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

export function createAuthenticator(token: string) {
  const digest = (value: string) => createHash('sha256').update(value).digest();
  const expected = digest(token);
  return (req: IncomingMessage, res: ServerResponse): boolean => {
    const match = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/i.exec(req.headers.authorization ?? '');
    if (match && timingSafeEqual(expected, digest(match[1]))) return true;
    res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="wayfinder"', 'Cache-Control': 'no-store' });
    res.end('Unauthorized');
    return false;
  };
}

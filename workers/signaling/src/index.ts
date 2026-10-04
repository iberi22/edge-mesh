import { MeshRoom } from './room';
import { RID_RE, type Env } from './types';

export { MeshRoom };

/** "*.swal.network" matches subdomains (and apex); "http://localhost:*" matches any port. */
export function originAllowed(origin: string, allowed: string): boolean {
  let host: string;
  try {
    host = new URL(origin).hostname;
  } catch {
    return false;
  }
  for (const raw of allowed.split(',')) {
    const rule = raw.trim();
    if (!rule) continue;
    if (rule === '*') return true;
    if (rule.includes('://')) {
      const re = new RegExp('^' + rule.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[0-9]+') + '$');
      if (re.test(origin)) return true;
    } else if (rule.startsWith('*.')) {
      const base = rule.slice(2);
      if (host === base || host.endsWith('.' + base)) return true;
    } else if (host === rule) return true;
  }
  return false;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    if (origin && !originAllowed(origin, env.ALLOWED_ORIGINS ?? '')) {
      return new Response('forbidden origin', { status: 403 });
    }
    if (url.pathname === '/health') return new Response('ok');
    const m = /^\/r\/([^/]+)$/.exec(url.pathname);
    if (!m || !RID_RE.test(m[1])) return new Response('bad room id', { status: 400 });
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('expected websocket', { status: 426 });
    }
    const stub = env.MESH_ROOM.get(env.MESH_ROOM.idFromName(m[1]));
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;

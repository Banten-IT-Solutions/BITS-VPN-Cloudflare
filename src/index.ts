// Entry point: WS relay + Hono app
import { Hono } from 'hono';
import { websocketHandler } from './core/relay';
import { getKVPrxList } from './core/lists';
import { createApiRoutes } from './routes/api';
import { CORS_HEADER_OPTIONS, uuidFromToken, sha224Hex } from './core/constants';

interface Env {
  PRX_BANK_URL?: string;
  KV_PRX_URL?: string;
  SUB_TOKEN?: string;
  ASSETS: Fetcher;
}

const app = new Hono<{ Bindings: Env }>();

// Mount API routes (tanpa /v1, langsung /api/*)
app.route('/api', createApiRoutes());

// Serve static assets for frontend pages
const serveAsset = (filename: string) => async (c: any) => {
  const assetUrl = new URL(c.req.url);
  assetUrl.pathname = `/${filename}`;
  return c.env.ASSETS.fetch(new Request(assetUrl.toString()));
};

app.get('/', serveAsset('index.html'));
app.get('/build', serveAsset('build.html'));
app.get('/convert', serveAsset('convert.html'));
app.get('/country', serveAsset('country.html'));
app.get('/clash', serveAsset('clash.html'));

// Fallback 404
app.notFound(c => c.json({ error: 'Not found' }, 404, CORS_HEADER_OPTIONS));

// Export default fetch handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);

      // Redirect HTTP to HTTPS (except for local development)
      if (
        url.protocol === 'http:' &&
        !url.hostname.includes('localhost') &&
        !url.hostname.includes('127.0.0.1')
      ) {
        url.protocol = 'https:';
        return Response.redirect(url.toString(), 301);
      }

      const upgradeHeader = request.headers.get('Upgrade');

      // Handle WebSocket upgrade for relay
      if (upgradeHeader === 'websocket') {
        // Strict auth credentials derived from SUB_TOKEN:
        // - vmessUuid: UUID for VLESS/VMess (VLESS validated in header, VMess via AEAD)
        // - trojanPasswordHashes: accepted hex(SHA224(password)) values in the
        //   Trojan header. Accept BOTH forms:
        //     sha224Hex(SUB_TOKEN)            -> client configured with raw SUB_TOKEN
        //     sha224Hex(sha224Hex(SUB_TOKEN)) -> client used the hashed link password
        let vmessUuid: string | undefined;
        let trojanPasswordHashes: string[] | undefined;
        if (env.SUB_TOKEN) {
          vmessUuid = await uuidFromToken(env.SUB_TOKEN);
          const hashOnce = sha224Hex(env.SUB_TOKEN);
          trojanPasswordHashes = [hashOnce, sha224Hex(hashOnce)];
        }
        const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length == 3 || url.pathname.match(',')) {
          const prxKeys = url.pathname.replace('/', '').toUpperCase().split(',');
          const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
          const kvPrx = await getKVPrxList(env.KV_PRX_URL);

          // Validate KV key exists and has proxies
          if (!kvPrx[prxKey] || !Array.isArray(kvPrx[prxKey]) || kvPrx[prxKey].length === 0) {
            return new Response('Invalid proxy key or no proxies available', { status: 404 });
          }

          const prxIP = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];

          return await websocketHandler(request, prxIP, vmessUuid, trojanPasswordHashes);
        } else if (prxMatch) {
          const prxIP = prxMatch[1];
          return await websocketHandler(request, prxIP, vmessUuid, trojanPasswordHashes);
        }
      }

      // All non-WS requests go to Hono app
      return app.fetch(request, env, ctx);
    } catch (err: any) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: CORS_HEADER_OPTIONS,
      });
    }
  },
};

// API routes: /sub, /myip, /check, /proxies
import { Hono } from 'hono';
import { getPrxList, getKVPrxList } from '../core/lists';
import { checkPrxHealth } from '../core/relay';
import {
  PROTOCOLS,
  CORS_HEADER_OPTIONS,
  KV_PRX_URL,
  PRX_BANK_URL,
  horse,
  v2,
  getFlagEmoji,
  shuffleArray,
  uuidFromToken,
  sha224Hex,
} from '../core/constants';

interface Env {
  PRX_BANK_URL?: string;
  KV_PRX_URL?: string;
  SUB_TOKEN?: string;
}

// IP rate limiter: Map<clientIp, timestamp[]>
const rateLimitCache = new Map<string, number[]>();
const LIMIT_WINDOW_MS = 10 * 1000; // 10 seconds
const MAX_REQUESTS = 12; // Max 12 requests per window

// Constant-time string comparison to avoid timing attacks
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function createApiRoutes() {
  const app = new Hono<{ Bindings: Env }>();

  // GET /check - health check proxy
  app.get('/check', async c => {
    try {
      const clientIP = c.req.header('cf-connecting-ip') || 'unknown';
      const now = Date.now();
      let timestamps = rateLimitCache.get(clientIP) || [];

      // Remove stale timestamps
      timestamps = timestamps.filter(t => now - t < LIMIT_WINDOW_MS);

      if (timestamps.length >= MAX_REQUESTS) {
        return c.json({ error: 'Too many requests. Please slow down.' }, 429, CORS_HEADER_OPTIONS);
      }
      timestamps.push(now);
      rateLimitCache.set(clientIP, timestamps);

      const target = c.req.query('target');
      if (!target) {
        return c.json({ error: 'Missing target parameter' }, 400, CORS_HEADER_OPTIONS);
      }

      // Parse IP:PORT with validation
      const parts = target.split(':');
      if (parts.length !== 2) {
        return c.json(
          { error: 'Invalid target format. Expected IP:PORT' },
          400,
          CORS_HEADER_OPTIONS
        );
      }

      const [ip, portStr] = parts;
      const port = parseInt(portStr, 10);

      // Validate IP format (basic IPv4 check)
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipv4Regex.test(ip)) {
        return c.json({ error: 'Invalid IP address format' }, 400, CORS_HEADER_OPTIONS);
      }

      // Validate port range
      if (isNaN(port) || port < 1 || port > 65535) {
        return c.json({ error: 'Invalid port number' }, 400, CORS_HEADER_OPTIONS);
      }

      // Restrict to known proxy list only (prevent arbitrary probing)
      const prxBankUrl = c.env.PRX_BANK_URL || PRX_BANK_URL;
      const proxyList = await getPrxList(prxBankUrl);
      const isAllowed = proxyList.some(prx => prx.prxIP === ip && prx.prxPort === portStr);

      if (!isAllowed) {
        return c.json({ error: 'Target not in allowed proxy list' }, 403, CORS_HEADER_OPTIONS);
      }

      const result = await checkPrxHealth(ip, portStr);
      return c.json(result, 200, CORS_HEADER_OPTIONS);
    } catch (error: any) {
      console.error('Error in /check:', error);
      return c.json(
        { error: 'Internal server error', message: error.message },
        500,
        CORS_HEADER_OPTIONS
      );
    }
  });

  // GET /sub - subscription generator (v2ray, clash, singbox, mihomo)
  const subHandler = async (c: any) => {
    try {
      // Token-protected subscription: only valid with ?token=SUB_TOKEN
      // Token wajib dikonfigurasi via env/secret (tidak ada hardcoded fallback).
      const subToken = c.env.SUB_TOKEN;
      const requestToken = c.req.query('token') || '';
      if (!subToken || !safeEqual(requestToken, subToken)) {
        return c.text('Forbidden: invalid or missing token', 403, CORS_HEADER_OPTIONS);
      }

      const url = new URL(c.req.url);
      const hostname = url.hostname;

      // cc: default ID,SG. Gunakan "all" (atau kosong) untuk semua negara.
      const ccQuery = c.req.query('cc');
      const filterCC =
        ccQuery === undefined
          ? ['ID', 'SG']
          : ccQuery.trim().toLowerCase() === 'all' || ccQuery.trim() === ''
            ? [] // kosong = tanpa filter = semua negara
            : ccQuery
                .split(',')
                .map((s: string) => s.trim().toUpperCase())
                .filter(Boolean);
      const filterPort = c.req
        .query('port')
        ?.split(',')
        .map((p: string) => parseInt(p)) || [443];
      const protoParam = c.req.query('proto') || c.req.query('vpn') || 'vless';
      const protocols = protoParam.split(',').filter((p: string) => PROTOCOLS.includes(p));
      if (!protocols.length) protocols.push('vless'); // fallback jika nilai proto tidak dikenal
      const filterLimit = parseInt(c.req.query('limit') || '10') || 10;
      const filterFormat = c.req.query('format') || 'v2ray';

      // Build settings — sama dengan UI /build:
      //   mode     = sni | cdn          (default: cdn)
      //   domain   = custom domain "bug" (default: support.zoom.us)
      //   wildcard = yes | no           (default: yes)
      const mode = c.req.query('mode') || 'cdn';
      const hasCustomDomain = c.req.query('domain') !== undefined;
      const bugDomain = c.req.query('domain') || 'support.zoom.us';
      const wildcard = c.req.query('wildcard') || 'yes';

      // Hitung server (add), servername (SNI), dan host (WS Host header)
      // mengikuti logika yang sama dengan UI /build:
      let server: string, servername: string, host: string;
      if (mode === 'cdn') {
        if (wildcard === 'yes') {
          server = bugDomain;
          servername = `${bugDomain}.${hostname}`;
          host = `${bugDomain}.${hostname}`;
        } else {
          server = bugDomain;
          servername = hostname;
          host = hostname;
        }
      } else {
        // mode === "sni"
        if (wildcard === 'yes') {
          server = `${bugDomain}.${hostname}`;
          servername = bugDomain;
          host = bugDomain;
        } else {
          server = hostname;
          // Default SNI/Host pakai hostname sendiri, bukan "bug domain":
          // domain contoh seperti support.zoom.us tidak pernah diarahkan ke Worker
          // kita, sehingga handshake TLS gagal. Hostname sendiri sudah terbukti
          // bisa handshake (101 Switching Protocols) dan punya sertifikat valid.
          // Untuk mengembalikan perilaku lama, kirim &domain=support.zoom.us.
          servername = hasCustomDomain ? bugDomain : hostname;
          host = servername;
        }
      }

      const prxBankUrl = c.req.query('prx-list') || c.env.PRX_BANK_URL || PRX_BANK_URL;
      let prxList = await getPrxList(prxBankUrl);

      if (filterCC.length) {
        prxList = prxList.filter(prx => filterCC.includes(prx.country));
      }
      shuffleArray(prxList);

      // Static UUID derived deterministically from SUB_TOKEN:
      // - VLESS/VMess links always use the same UUID (matches relay's VMess AEAD key)
      // - Trojan links use hex(SHA224(SUB_TOKEN)) as password (hashed, not raw token)
      const uuid = await uuidFromToken(subToken);
      const trojanPassword = sha224Hex(subToken);

      // Struktur data lengkap untuk tiap link (dipakai semua format output)
      const links: Array<{
        protocol: string;
        server: string;
        port: number;
        username: string;
        security: string;
        sni: string;
        path: string;
        host: string;
        name: string;
        remark: string;
        uri: string;
      }> = [];

      for (const prx of prxList) {
        for (const port of filterPort) {
          for (const protocol of protocols) {
            if (links.length >= filterLimit) break;

            // Trojan uses hashed password (hex SHA224); VLESS/VMess use the static UUID
            const username = protocol === atob(horse) ? trojanPassword : uuid;
            const security = port == 443 ? 'tls' : 'none';
            const sni = port == 80 && protocol == atob('dm1lc3M=') ? '' : servername;
            const path = `/${prx.prxIP}-${prx.prxPort}`;
            const name = `${getFlagEmoji(prx.country)} ${prx.org}`;
            const remark = name;

            const uri = new URL(`${atob(horse)}://${server}`);
            uri.protocol = protocol;
            uri.port = port.toString();
            uri.username = username;
            // Urutan query params mengikuti contoh: encryption, security, sni, type, host, path
            uri.searchParams.set('encryption', 'none');
            uri.searchParams.set('security', security);
            uri.searchParams.set('sni', sni);
            uri.searchParams.set('type', 'ws');
            uri.searchParams.set('host', host);
            uri.searchParams.set('path', path);
            uri.hash = encodeURIComponent(remark);

            links.push({
              protocol,
              server,
              port,
              username,
              security,
              sni,
              path,
              host,
              name,
              remark,
              uri: uri.toString(),
            });
          }
        }
      }

      // Clash / mihomo mewajibkan proxy name unik secara global. Nama bawaan
      // ("bendera + nama organisasi") sangat sering tabrakan — terukur 100 node
      // hanya punya 27 nama berbeda. Clash menolak SELURUH konfigurasi kalau ada
      // nama ganda (duplicate name), sedangkan v2rayN tidak peduli. Tambahkan
      // nomor urut agar semua klien bisa menerima output ini.
      const nameCount = new Map<string, number>();
      for (const l of links) {
        const seen = nameCount.get(l.name) ?? 0;
        nameCount.set(l.name, seen + 1);
        if (seen > 0) {
          const suffix = ` ${String(seen + 1).padStart(2, '0')}`;
          const before = l.remark;
          l.name += suffix;
          l.remark += suffix;
          // Sinkronkan fragmen #remark di URI (dipakai format=v2ray) supaya nama
          // yang tampil di klien sama dengan nama di YAML/JSON.
          l.uri = l.uri.replace(`#${encodeURIComponent(before)}`, `#${encodeURIComponent(l.remark)}`);
        }
      }

      // Output: v2ray (default), clash, singbox, mihomo
      const resultLines = links.map(l => l.uri);

      // Escape + quote untuk nilai YAML (nama node berisi emoji bendera & spasi)
      const yq = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

      // Konversi link ke format Clash YAML (proxy list)
      const toClashYaml = (l: (typeof links)[number]) => {
        const name = l.name.replace(/"/g, '\\"');
        const tls = l.port == 443;
        const fields: string[] = [
          `  - name: "${name}"`,
          `    server: ${l.server}`,
          `    port: ${l.port}`,
        ];
        if (l.protocol === atob(horse)) {
          fields.push(`    type: trojan`, `    password: ${l.username}`);
        } else if (l.protocol === 'vmess') {
          fields.push(
            `    type: vmess`,
            `    uuid: ${l.username}`,
            `    alterId: 0`,
            `    cipher: auto`
          );
        } else {
          fields.push(`    type: vless`, `    uuid: ${l.username}`, `    cipher: auto`);
        }
        fields.push(
          `    tls: ${tls}`,
          `    skip-cert-verify: true`,
          `    servername: ${l.sni}`,
          `    network: ws`,
          `    ws-opts:`,
          `      path: ${l.path}`,
          `      headers:`,
          `        Host: ${l.host}`,
          `    udp: true`
        );
        return fields.join('\n');
      };

      // Konversi link ke entry proxy mihomo (dipakai format=mihomo)
      const toMihomoProxy = (l: (typeof links)[number]) => {
        const fields: string[] = [
          `  - name: ${yq(l.name)}`,
          `    server: ${l.server}`,
          `    port: ${l.port}`,
        ];
        if (l.protocol === atob(horse)) {
          fields.push(`    type: trojan`, `    password: ${yq(l.username)}`);
        } else if (l.protocol === 'vmess') {
          fields.push(
            `    type: vmess`,
            `    uuid: ${yq(l.username)}`,
            `    alterId: 0`,
            `    cipher: auto`
          );
        } else {
          fields.push(`    type: vless`, `    uuid: ${yq(l.username)}`, `    cipher: auto`);
        }
        fields.push(
          `    tls: ${l.port == 443}`,
          `    skip-cert-verify: true`,
          `    servername: ${yq(l.sni)}`,
          `    network: ws`,
          `    ws-opts:`,
          `      path: ${yq(l.path)}`,
          `      headers:`,
          `        Host: ${yq(l.host)}`,
          `    udp: true`
        );
        return fields.join('\n');
      };

      // Konversi link ke format Sing-box outbound (JSON)
      const toSingboxJson = (l: (typeof links)[number]) => {
        const tlsObj: Record<string, unknown> = {
          enabled: l.port == 443,
          server_name: l.sni || l.server,
          utls: { enabled: true, fingerprint: 'chrome' },
        };
        if (l.port != 443) delete tlsObj.utls;
        const transport = { type: 'ws', path: l.path, headers: { Host: l.host } };
        const base: Record<string, unknown> = {
          tag: l.name,
          server: l.server,
          server_port: l.port,
        };
        if (l.protocol === atob(horse)) {
          return {
            ...base,
            type: 'trojan',
            password: l.username,
            tls: tlsObj,
            transport,
          };
        }
        if (l.protocol === 'vmess') {
          return {
            ...base,
            type: 'vmess',
            uuid: l.username,
            security: 'auto',
            alter_id: 0,
            tls: tlsObj,
            transport,
          };
        }
        // vless
        return {
          ...base,
          type: 'vless',
          uuid: l.username,
          flow: '',
          packet_encoding: '',
          tls: tlsObj,
          transport,
        };
      };

      switch (filterFormat) {
        case atob(v2):
          return c.text(btoa(resultLines.join('\n')), 200, CORS_HEADER_OPTIONS);
        case 'clash':
          return c.text(`proxies:\n${links.map(toClashYaml).join('\n')}`, 200, CORS_HEADER_OPTIONS);
        case 'singbox':
          return c.json({ outbounds: links.map(toSingboxJson) }, 200, CORS_HEADER_OPTIONS);
        case 'mihomo': {
          // Konfigurasi utuh yang bisa dimuat langsung oleh Clash / mihomo:
          // port, dns, proxy-groups, dan rules ikut disertakan supaya klien Android
          // tidak menolak berkasnya ("bukan konfigurasi yang valid").
          const proxyList = links.map(toMihomoProxy).join('\n');
          const groupList = links.map(l => `      - ${yq(l.name)}`).join('\n');
          const body = `mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query

proxies:
${proxyList}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Auto
${groupList}
  - name: Auto
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
${groupList}

rules:
  - MATCH,PROXY
`;
          // Harus pakai c.body() agar Content-Type jadi text/yaml. c.text() akan
          // memaksanya jadi text/plain dan sebagian klien Android menolaknya.
          return c.body(body, 200, {
            ...CORS_HEADER_OPTIONS,
            'Content-Type': 'text/yaml; charset=utf-8',
          });
        }
        default:
          return c.text(
            `Unsupported format "${filterFormat}". Supported formats: ${atob(v2)}, clash, singbox, mihomo.`,
            400,
            CORS_HEADER_OPTIONS
          );
      }
    } catch (error: any) {
      console.error('Error in /sub:', error);
      return c.json(
        { error: 'Failed to generate subscription', message: error.message },
        500,
        CORS_HEADER_OPTIONS
      );
    }
  };

  app.get('/sub', subHandler);

  // GET /countries - country list + proxy count from KV list (for /country page)
  app.get('/countries', async c => {
    try {
      const kvPrx = await getKVPrxList(c.env.KV_PRX_URL || KV_PRX_URL);
      const countries = Object.entries(kvPrx)
        .filter(([, arr]) => Array.isArray(arr) && arr.length > 0)
        .map(([code, arr]) => ({ code: code.toUpperCase(), count: arr.length }))
        .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
      return c.json({ count: countries.length, countries }, 200, CORS_HEADER_OPTIONS);
    } catch (error: any) {
      console.error('Error in /countries:', error);
      return c.json(
        { error: 'Failed to fetch countries', message: error.message },
        500,
        CORS_HEADER_OPTIONS
      );
    }
  });

  // GET /myip - client IP info
  app.get('/myip', async c => {
    const req = c.req.raw;
    return c.json(
      {
        ip:
          req.headers.get('cf-connecting-ipv6') ||
          req.headers.get('cf-connecting-ip') ||
          req.headers.get('x-real-ip'),
        colo: req.headers.get('cf-ray')?.split('-')[1],
        ...(req as any).cf,
      },
      200,
      CORS_HEADER_OPTIONS
    );
  });

  // GET /proxies - proxy list with filter & pagination (for /build page)
  app.get('/proxies', async c => {
    try {
      const q = c.req.query('q') || '';
      const ccParam = c.req.query('cc') || '';
      const cc = ccParam ? ccParam.split(',').filter(Boolean) : [];
      const port = c.req.query('port');
      const pageRaw = parseInt(c.req.query('page') || '1') || 1;
      const page = Math.max(1, pageRaw); // Clamp to >= 1
      const limitRaw = parseInt(c.req.query('limit') || '20') || 20;
      const limit = Math.min(Math.max(1, limitRaw), 100); // Clamp 1-100

      const prxBankUrl = c.env.PRX_BANK_URL || PRX_BANK_URL;
      let items = await getPrxList(prxBankUrl);

      // Filter by country only when cc is not empty
      if (cc.length > 0 && cc[0] !== '') {
        items = items.filter(prx => cc.includes(prx.country));
      }

      // Filter by port
      if (port) {
        items = items.filter(prx => prx.prxPort === port);
      }

      // Filter by search query (ip, country, or org)
      if (q) {
        const query = q.toLowerCase();
        items = items.filter(
          prx =>
            prx.prxIP.toLowerCase().includes(query) ||
            prx.country.toLowerCase().includes(query) ||
            prx.org.toLowerCase().includes(query)
        );
      }

      const count = items.length;
      const pages = Math.ceil(count / limit);
      const offset = (page - 1) * limit;
      const paginatedItems = items.slice(offset, offset + limit);

      // Unique country list from pre-filter data for filter chips
      const countryCounts = new Map<string, number>();
      for (const prx of items) {
        countryCounts.set(prx.country, (countryCounts.get(prx.country) || 0) + 1);
      }
      const countries = Array.from(countryCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([code, count]) => ({ code, count }));

      return c.json(
        {
          count,
          page,
          pages,
          items: paginatedItems,
          countries,
        },
        200,
        CORS_HEADER_OPTIONS
      );
    } catch (error: any) {
      console.error('Error in /proxies:', error);
      return c.json(
        { error: 'Failed to fetch proxy list', message: error.message },
        500,
        CORS_HEADER_OPTIONS
      );
    }
  });

  return app;
}

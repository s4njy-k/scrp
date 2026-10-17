/**
 * Local controlled fixtures (blueprint §16, §18 Phase B): static HTML, JS
 * hydration, fragment routes, lazy/long pages, QR/element capture, challenge
 * responses, API-returning-HTML, frames/popups/service workers/WebSocket,
 * slow (never-finishing) documents and redirects to internal addresses.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';

const QR_PNG = readFileSync(new URL('./upi-qr.png', import.meta.url));

const html = (body: string, title = 'Fixture', head = '') =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>${head}</head><body>${body}</body></html>`;

const routes: Record<string, (req: IncomingMessage, res: ServerResponse, url: URL) => void> = {
  '/static': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html(`<header><img src="/logo.png" alt="Acme logo" width="120" height="40"></header>
      <h1>Acme Refund Desk</h1>
      <p>Call our customer care helpline at +91 98765 43210 or email help@acme-refund.example.</p>
      <p>Pay processing fee to UPI ID refunds.desk@ybl. Bank A/C No: 123456789012 IFSC SBIN0001234.</p>
      <a href="/contact">Contact us</a> <a href="/about">About</a> <a href="https://wa.me/919876543210">WhatsApp</a>
      <a href="https://t.me/acme_refund_support">Telegram</a>
      <form action="/collect" method="post"><input name="q"></form>
      ${'<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. </p>'.repeat(12)}`, 'Acme Refund Desk'));
  },
  '/contact': (_q, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(html('<h1>Contact</h1><p>Email: contact@acme-refund.example</p>', 'Contact')); },
  '/about': (_q, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(html('<h1>About</h1><p>We are totally legitimate.</p>', 'About')); },
  '/logo.png': (_q, res) => { res.writeHead(200, { 'content-type': 'image/png' }); res.end(QR_PNG); },
  '/qr.png': (_q, res) => { res.writeHead(200, { 'content-type': 'image/png' }); res.end(QR_PNG); },
  '/qr': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html(`<h1>Scan to pay refund fee</h1><div class="pay"><img id="upi-qr" alt="UPI QR scan to pay" src="/qr.png" width="246" height="246"></div>
      <p>Amount: Rs 499</p>`, 'Pay'));
  },
  // Client-rendered SPA: content depends on the URL fragment (never sent to the server).
  '/spa': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html(`<div id="root"></div><script>
      function render(){ var r = location.hash.replace('#',''); document.getElementById('root').innerHTML =
        r === '/victim/42' ? '<h2>Victim portal for case 42</h2><p>Transfer to scam.wallet@paytm now.</p>' : '<h2>Home</h2>'; }
      setTimeout(render, 300); window.addEventListener('hashchange', render);</script>`, 'SPA'));
  },
  // HTML that hydrates after a delay; JS shell to an HTTP client.
  '/hydrate': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html(`<div id="app"></div><noscript>Please enable JavaScript</noscript><script src="/a.js"></script><script src="/b.js"></script><script>
      setTimeout(function(){ document.getElementById('app').innerHTML = '<h1>Hydrated offer</h1><p>Guaranteed returns 30% monthly. Telegram t.me/hydrated_offer</p>'; }, 800);</script>`, 'Loading'));
  },
  '/a.js': (_q, res) => { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end('window.a=1;'); },
  '/b.js': (_q, res) => { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end('window.b=1;'); },
  // Long page with lazy-loaded content appended on scroll.
  '/long': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html(`<div id="list">${Array.from({ length: 40 }, (_, i) => `<p style="height:120px">Row ${i}</p>`).join('')}</div>
      <div id="lazy"></div><script>
      var added=false; window.addEventListener('scroll', function(){ if(!added && scrollY > 2000){ added=true;
        document.getElementById('lazy').innerHTML='<p id="lazy-content">Lazy loaded contact: lazy@acme-refund.example</p>'; } });</script>`, 'Long'));
  },
  // Cloudflare-style challenge interstitial (HTTP 403 + cf-mitigated header).
  '/challenge': (_q, res) => {
    res.writeHead(403, { 'content-type': 'text/html', 'cf-mitigated': 'challenge', server: 'cloudflare' });
    res.end(html('<div id="challenge-form">Checking your browser before accessing the site.</div>', 'Just a moment...'));
  },
  // Plain 403 that is NOT a challenge (ACL denial).
  '/denied': (_q, res) => { res.writeHead(403, { 'content-type': 'text/html', server: 'cloudflare' }); res.end(html('<h1>Forbidden</h1><p>You do not have permission.</p>', 'Forbidden')); },
  '/gone': (_q, res) => { res.writeHead(404, { 'content-type': 'text/html' }); res.end(html('<h1>Not found</h1>', 'Not found')); },
  '/ratelimited': (_q, res) => { res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '120' }); res.end('slow down'); },
  '/error500': (_q, res) => { res.writeHead(500, { 'content-type': 'text/plain' }); res.end('boom'); },
  // API endpoint that returns HTML (e.g. a challenge) instead of JSON.
  '/api/data': (_q, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(html('<p>Please verify</p>', 'Verify')); },
  // Document that renders useful content but never finishes loading.
  '/slow': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.write(`<!doctype html><html><head><title>Slow</title></head><body><h1>Partial content visible</h1><p>Contact slow@acme-refund.example</p>${' '.repeat(2048)}`);
    // Never call res.end(): navigation/readiness time out while content is renderable.
  },
  '/login': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html('<h1>Sign in</h1><form action="/do-login"><input name="u"><input type="password" name="p"><button>Login</button></form>', 'Login'));
  },
  // Frames, popup, service worker and WebSocket in one page.
  '/rich': (_q, res, url) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html(`<h1>Rich page</h1><iframe src="/frame" width="300" height="100"></iframe>
      <script>
        if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
        try { var ws = new WebSocket('ws://' + location.host + '/ws'); ws.onopen = function(){ ws.send('hello-from-page'); }; } catch(e) {}
        setTimeout(function(){ window.open('/popup', '_blank'); }, 200);
        fetch('/api/items?x=1').then(function(r){ return r.json(); });
      </script>`, 'Rich'));
    void url;
  },
  '/frame': (_q, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(html('<p>Frame content: frame@acme-refund.example</p>', 'Frame')); },
  '/popup': (_q, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(html('<p>Popup window</p>', 'Popup')); },
  '/sw.js': (_q, res) => { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end("self.addEventListener('fetch', function(){});"); },
  '/api/items': (_q, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ items: [{ vpa: 'api.payee@okicici' }] })); },
  // Redirect into cloud metadata / internal address (must be refused by the gateway).
  '/redirect-internal': (_q, res) => { res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }); res.end(); },
  // Page that tries to load internal resources (refused by the gateway; page still renders).
  '/internal-probe': (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html(`<h1>Probe</h1><img src="http://10.0.0.1/x.png"><img src="http://[::ffff:127.0.0.1]:1/x.png"><script>fetch('http://169.254.169.254/latest/meta-data/').catch(function(){});</script>`, 'Probe'));
  },
};

function handleUpgrade(req: IncomingMessage, socket: Socket): void {
  const key = req.headers['sec-websocket-key'];
  if (req.url !== '/ws' || typeof key !== 'string') {
    socket.destroy();
    return;
  }
  const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  const payload = Buffer.from('hello-from-server');
  socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
  socket.on('data', () => undefined);
  socket.on('error', () => undefined);
}

export interface FixtureServer {
  server: Server;
  port: number;
  url: (path: string) => string;
  close: () => Promise<void>;
}

export async function startFixtureServer(): Promise<FixtureServer> {
  const sockets = new Set<Socket>();
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://fixture.local');
    const route = routes[url.pathname];
    if (route) route(req, res, url);
    else {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('no route');
    }
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.on('upgrade', (req, socket) => handleUpgrade(req, socket as Socket));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    server,
    port,
    url: (path: string) => `http://127.0.0.1:${port}${path}`,
    close: () => new Promise((r) => { sockets.forEach((s) => s.destroy()); server.close(() => r()); }),
  };
}

'use strict';

// A minimal HTTP app with a deliberate access control bug.
// User A owns orders 1001 and 1002.
// User B owns order 2001.
// The /api/orders/:id endpoint does NOT check ownership — IDOR bug.
// The /api/profile endpoint DOES check — correct behaviour.

const http = require('http');

const TOKENS = {
  'token-user-a': { id: 'user-a', name: 'Alice' },
  'token-user-b': { id: 'user-b', name: 'Bob'   },
};

const ORDERS = {
  '1001': { id: '1001', owner: 'user-a', item: 'Laptop',  total: 1299.00 },
  '1002': { id: '1002', owner: 'user-a', item: 'Mouse',   total:   29.99 },
  '2001': { id: '2001', owner: 'user-b', item: 'Monitor', total:  499.00 },
};

function getUser(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^bearer\s+/i, '').trim();
  return TOKENS[token] || null;
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const user = getUser(req);
  const url  = new URL(req.url, 'http://localhost');
  const path = url.pathname;

  // Public health check
  if (path === '/api/health') return json(res, 200, { ok: true });

  // Auth required from here
  if (!user) return json(res, 401, { error: 'unauthorized' });

  // GET /api/profile — correct: returns only your own profile
  if (path === '/api/profile') {
    return json(res, 200, { id: user.id, name: user.name });
  }

  // GET /api/orders — returns only your own orders (correct)
  if (path === '/api/orders') {
    const mine = Object.values(ORDERS).filter(o => o.owner === user.id);
    return json(res, 200, mine);
  }

  // GET /api/orders/:id — BUG: no ownership check (IDOR)
  const orderMatch = path.match(/^\/api\/orders\/(\d+)$/);
  if (orderMatch) {
    const order = ORDERS[orderMatch[1]];
    if (!order) return json(res, 404, { error: 'not found' });
    // ← Missing: if (order.owner !== user.id) return json(res, 403, ...)
    return json(res, 200, order);
  }

  return json(res, 404, { error: 'not found' });
});

const PORT = parseInt(process.env.PORT || '3000', 10);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[test-app] Listening on 127.0.0.1:${PORT}`);
  console.log('[test-app] User A token: token-user-a');
  console.log('[test-app] User B token: token-user-b');
  console.log('[test-app] IDOR bug on: GET /api/orders/:id');
});

module.exports = server; // exported so the test harness can close it

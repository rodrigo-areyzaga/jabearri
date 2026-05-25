'use strict';

const http = require('http');
const path = require('path');

// ─── Minimal test harness (no dependencies) ───────────────────────────────────
let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓  ${label}`);
    passed++;
  } else {
    console.error(`  ✗  ${label}`);
    failed++;
  }
}

function section(name) {
  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 50 - name.length))}`);
}

// ─── Unit: safety module ──────────────────────────────────────────────────────
section('safety.js');
const { isPrivateHost, verifyScope } = require('../src/safety');

assert(isPrivateHost('127.0.0.1'),    'loopback 127.0.0.1 is private');
assert(isPrivateHost('localhost'),    'localhost is private');
assert(isPrivateHost('10.0.0.1'),     '10.x is private');
assert(isPrivateHost('192.168.1.50'), '192.168.x is private');
assert(!isPrivateHost('8.8.8.8'),     '8.8.8.8 is NOT private');
assert(!isPrivateHost('93.184.216.34'), 'example.com IP is NOT private');

try { verifyScope(null);   assert(false, 'null scope should throw'); }
catch { assert(true, 'null scope throws'); }

try { verifyScope([]);     assert(false, 'empty scope should throw'); }
catch { assert(true, 'empty scope throws'); }

try { verifyScope(['/api/']); assert(true, 'valid scope passes'); }
catch { assert(false, 'valid scope should not throw'); }

// ─── Unit: session store ──────────────────────────────────────────────────────
section('session-store.js');
const { SessionStore, extractToken, extractResourceIds, fingerprintToken } = require('../src/session-store');

// Token extraction
assert(extractToken({ authorization: 'Bearer abc123' }) === 'abc123', 'extracts Bearer token');
assert(extractToken({ cookie: 'session=xyz789; other=foo' }) === 'xyz789', 'extracts session cookie');
assert(extractToken({}) === null, 'returns null when no token');

// Resource ID extraction
const ids1 = extractResourceIds('/api/orders/1042');
assert(ids1.some(i => i.value === '1042'), 'extracts integer ID from path');

const ids2 = extractResourceIds('/api/users/a3f2c1d0-e5b6-4f78-9012-abcdef012345');
assert(ids2.some(i => i.type === 'uuid'), 'extracts UUID from path');

const ids3 = extractResourceIds('/api/health');
assert(ids3.length === 0, 'no IDs on clean path');

// Fingerprint is deterministic and non-reversible
const fp1 = fingerprintToken('secret-token');
const fp2 = fingerprintToken('secret-token');
const fp3 = fingerprintToken('different-token');
assert(fp1 === fp2, 'fingerprint is deterministic');
assert(fp1 !== fp3, 'different tokens have different fingerprints');
assert(!fp1.includes('secret'), 'fingerprint does not contain original token');

// Store recording
const store = new SessionStore();
store.record({ method: 'GET', url: '/api/orders/1042', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 120 });
store.record({ method: 'GET', url: '/api/orders/1043', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 130 });
store.record({ method: 'GET', url: '/api/health',      headers: {}, statusCode: 200, contentLength: 20 }); // no token
assert(store.size() === 2, 'records authenticated requests only');
assert(store.replayable().length === 2, 'both entries are replayable');
assert(store.knownTokens().length === 1, 'one distinct token seen');

// ─── Unit: replay heuristic ───────────────────────────────────────────────────
section('replay.js — looksLikeRealData');
const { looksLikeRealData } = require('../src/replay');

assert(
  looksLikeRealData({ statusCode: 200, contentLength: 200 }, { statusCode: 200, bodyLength: 190 }),
  'similar body size = real data'
);
assert(
  !looksLikeRealData({ statusCode: 200, contentLength: 200 }, { statusCode: 403, bodyLength: 30 }),
  '403 replay = not a finding'
);
assert(
  !looksLikeRealData({ statusCode: 200, contentLength: 200 }, { statusCode: 200, bodyLength: 5 }),
  'tiny replay body = not a finding'
);
assert(
  !looksLikeRealData({ statusCode: 404, contentLength: 0  }, { statusCode: 200, bodyLength: 200 }),
  'original was 404 — skip'
);

// ─── Integration: proxy + fake app ───────────────────────────────────────────
section('integration — proxy against fake app');

async function runIntegration() {
  // Start the fake app
  process.env.PORT = '3099';
  const appServer = require('./fake-app');
  await new Promise(r => appServer.once('listening', r));

  const { ProxyCore } = require('../src/proxy');
  const iStore = new SessionStore();
  const proxy = new ProxyCore({
    target:  'http://localhost:3099',
    scope:   ['/api/'],
    exclude: ['/api/health'],
    store:   iStore,
    logger:  { log: () => {}, error: console.error },
  });
  await proxy.listen(8899);

  // Helper: make a request through the proxy
  function req(path, token) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: '127.0.0.1',
        port: 8899,
        path,
        method: 'GET',
        headers: token ? { authorization: `Bearer ${token}` } : {},
      };
      const r = http.request(options, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
      });
      r.on('error', reject);
      r.end();
    });
  }

  // Proxy should forward correctly
  const health = await req('/api/health');
  assert(health.status === 200, 'health check passes through');

  const unauth = await req('/api/orders', null);
  assert(unauth.status === 401, 'unauthenticated request returns 401');

  const orders = await req('/api/orders', 'token-user-a');
  assert(orders.status === 200, 'user A can list their orders');
  assert(Array.isArray(orders.body), 'orders response is an array');

  // Access user A's specific order (this gets recorded)
  const order = await req('/api/orders/1001', 'token-user-a');
  assert(order.status === 200, 'user A fetches their own order');
  assert(order.body.item === 'Laptop', 'correct order returned');

  // Session store should have captured the scoped authenticated requests
  assert(iStore.size() >= 2, 'store recorded scoped requests');
  const healthEntry = iStore.entries.find(e => e.path === '/api/health');
  assert(!healthEntry, 'excluded path /api/health not recorded');

  const orderEntry = iStore.entries.find(e => e.path === '/api/orders/1001');
  assert(!!orderEntry, 'order request was recorded');
  assert(orderEntry.resourceIds.some(r => r.value === '1001'), 'resource ID 1001 extracted');
  assert(!JSON.stringify(orderEntry).includes('token-user-a'), 'raw token not stored');

  // Now run replay as user B — should detect the IDOR
  const { runReplay } = require('../src/replay');
  const findings = await runReplay({
    store:       iStore,
    targetUrl:   'http://localhost:3099',
    secondToken: 'token-user-b',
    logger:      { log: () => {} },
  });

  const idorFinding = findings.find(f => f.path.includes('/api/orders/1001'));
  assert(!!idorFinding, 'IDOR on /api/orders/1001 detected');
  assert(idorFinding.severity === 'high', 'finding is high severity');
  assert(!!idorFinding.curl, 'finding includes curl reproduction command');

  // Profile endpoint should NOT trigger a finding (it's not parameterised by ID)
  const profileFinding = findings.find(f => f.path === '/api/profile');
  assert(!profileFinding, 'no false positive on /api/profile');

  await proxy.close();
  appServer.close();
}

runIntegration()
  .then(() => {
    section('results');
    console.log(`\n  Passed: ${passed}`);
    console.log(`  Failed: ${failed}`);
    if (failed > 0) {
      console.error('\n  Some tests failed.\n');
      process.exit(1);
    } else {
      console.log('\n  All tests passed.\n');
      process.exit(0);
    }
  })
  .catch(err => {
    console.error('\n  Integration test threw:', err.message);
    console.error(err.stack);
    process.exit(1);
  });

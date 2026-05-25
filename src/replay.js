'use strict';

const http  = require('http');
const https = require('https');
const { URL } = require('url');

// Heuristics to decide if a replay response is a genuine access control failure.
// Returns true if the replay looks like it returned real data it shouldn't have.
function looksLikeRealData(original, replay) {
  // Must have gotten 200-level on replay
  if (replay.statusCode < 200 || replay.statusCode >= 300) return false;

  // Original was already non-200 — skip (nothing to compare against)
  if (original.statusCode < 200 || original.statusCode >= 300) return false;

  // If the replay body is empty or tiny, it's probably an empty 200 — not real data
  if (replay.bodyLength < 10) return false;

  // If the replay body is within 20% of the original size, it probably
  // returned the same data. This is the key signal.
  if (original.contentLength > 0) {
    const ratio = replay.bodyLength / original.contentLength;
    if (ratio > 0.8) return true;
  }

  // Fallback: any non-trivial body returned for a resource-ID endpoint
  return replay.bodyLength > 50;
}

async function replayRequest({ targetUrl, entry, secondToken }) {
  return new Promise((resolve, reject) => {
    const target  = new URL(targetUrl);
    const options = {
      hostname: target.hostname,
      port:     target.port || (target.protocol === 'https:' ? 443 : 80),
      path:     entry.path + entry.query,
      method:   entry.method,
      headers: {
        'authorization': `Bearer ${secondToken}`,
        'accept':        'application/json',
        'user-agent':    'accguard-replay/0.1',
      },
    };

    const transport = target.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        statusCode:  res.statusCode,
        bodyLength:  Buffer.concat(chunks).length,
        headers:     res.headers,
      }));
    });

    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// Run the full replay pass. Returns array of confirmed findings.
async function runReplay({ store, targetUrl, secondToken, logger }) {
  const log      = logger || console;
  const entries  = store.replayable();
  const tokens   = store.knownTokens();
  const findings = [];

  if (tokens.length < 2 && !secondToken) {
    log.log('[accguard] Only one session token observed — provide ACCGUARD_TOKEN_B to enable replay.');
    return findings;
  }

  log.log(`[accguard] Replaying ${entries.length} requests as user B...`);

  for (const entry of entries) {
    let result;
    try {
      result = await replayRequest({ targetUrl, entry, secondToken });
    } catch (err) {
      log.log(`[accguard] Replay error on ${entry.path}: ${err.message}`);
      continue;
    }

    if (looksLikeRealData(entry, result)) {
      findings.push({
        severity:   'high',
        type:       'broken-access-control',
        method:     entry.method,
        path:       entry.path + entry.query,
        resourceIds: entry.resourceIds,
        originalStatus: entry.statusCode,
        replayStatus:   result.statusCode,
        originalSize:   entry.contentLength,
        replaySize:     result.bodyLength,
        // Reproducible curl command — the main output developers care about
        curl: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN_B" "${targetUrl}${entry.path}${entry.query}"`,
      });
    }
  }

  return findings;
}

module.exports = { runReplay, looksLikeRealData };

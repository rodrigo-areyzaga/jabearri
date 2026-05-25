'use strict';

const crypto = require('crypto');
const fs = require('fs');

// Patterns used to extract resource IDs from URL paths.
// Order matters — UUID before integer so /items/uuid isn't
// partially matched as an integer.
const ID_PATTERNS = [
  { type: 'uuid',    re: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi },
  { type: 'integer', re: /(?<![.\d])(\d{1,20})(?![.\d])/g },
];

// One-way fingerprint — the real token is never stored anywhere
function fingerprintToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

// Extract the token value from common locations in a request
function extractToken(headers) {
  const auth = headers['authorization'] || '';
  if (auth.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }
  const cookie = headers['cookie'] || '';
  // Common session cookie names — configurable later
  const sessionMatch = cookie.match(/(?:session|token|auth|jwt)=([^;]+)/i);
  if (sessionMatch) return sessionMatch[1].trim();

  return null;
}

// Pull resource IDs out of a URL path + query string
function extractResourceIds(urlPath) {
  const ids = [];
  for (const { type, re } of ID_PATTERNS) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(urlPath)) !== null) {
      ids.push({ type, value: m[0] });
    }
  }
  // Deduplicate by value
  return ids.filter((id, i, arr) => arr.findIndex(x => x.value === id.value) === i);
}

class SessionStore {
  constructor() {
    this.entries = [];
  }

  // Called once per proxied request + response
  record({ method, url, headers, statusCode, contentLength }) {
    const rawToken = extractToken(headers);
    if (!rawToken) return; // unauthenticated — skip

    const parsed = new URL(url, 'http://localhost');
    const resourceIds = extractResourceIds(parsed.pathname + parsed.search);

    this.entries.push({
      method:        method.toUpperCase(),
      path:          parsed.pathname,
      query:         parsed.search,
      tokenHash:     fingerprintToken(rawToken),
      resourceIds,
      statusCode,
      contentLength: contentLength || 0,
      recordedAt:    Date.now(),
    });
  }

  // Returns only entries with resource IDs (candidates for IDOR replay)
  replayable() {
    return this.entries.filter(e =>
      e.resourceIds.length > 0 &&
      ['GET', 'HEAD'].includes(e.method) // read-only only in v1
    );
  }

  // Unique token hashes seen — tells us how many distinct users were active
  knownTokens() {
    return [...new Set(this.entries.map(e => e.tokenHash))];
  }

  saveTo(filePath) {
    const payload = {
      version:     1,
      generatedAt: new Date().toISOString(),
      totalCount:  this.entries.length,
      entries:     this.entries,
    };
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
  }

  static loadFrom(filePath) {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const store = new SessionStore();
    store.entries = raw.entries;
    return store;
  }

  size() { return this.entries.length; }
}

module.exports = { SessionStore, extractToken, extractResourceIds, fingerprintToken };

'use strict';

const crypto = require('crypto');
const fs     = require('fs');

// Maximum entries before the store warns and stops recording.
// Prevents unbounded memory growth in large test suites.
const MAX_ENTRIES = parseInt(process.env.ACCGUARD_MAX_ENTRIES || "10000", 10);

const ID_PATTERNS = [
  { type: 'uuid',    re: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi },
  { type: 'integer', re: /(?<![.\d])(\d{1,20})(?![.\d])/g },
];

function fingerprintToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

// Returns { raw, type, cookieName } or null.
// type is 'bearer' or 'cookie' — used by replay to send the
// second token in the correct format.
function extractToken(headers) {
  const auth = headers['authorization'] || '';
  if (auth.toLowerCase().startsWith('bearer ')) {
    return { raw: auth.slice(7).trim(), type: 'bearer', cookieName: null };
  }

  const cookie = headers['cookie'] || '';

  // Split on ';' first, then match each pair exactly.
  // Prevents junk from malformed or multi-value segments bleeding into the token.
  const SESSION_NAMES = new Set(['session', 'token', 'auth', 'jwt', 'sid']);
  for (const part of cookie.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const name  = part.slice(0, eqIdx).trim().toLowerCase();
    const value = part.slice(eqIdx + 1).trim();
    if (SESSION_NAMES.has(name) && value) {
      // Note: value is taken as everything after the first '=' in this segment.
      // Cookie attributes like expires= or path= are separated by ';' and handled
      // by the outer split, so they do not bleed into the token value.
      // However, malformed cookies without proper ';' separators (e.g.
      // "session=abc expires=Friday") will include the trailing text in the raw
      // value. This is a known boundary behavior — the token is still fingerprinted
      // correctly, but the raw value is not perfectly clean. Documented, not fixed.
      return { raw: value, type: 'cookie', cookieName: name };
    }
  }

  return null;
}

// Extracts resource IDs from a URL path.
// Handles integers, UUIDs, and slug-style IDs (ord-1001, user-alice, pay-1).
function extractResourceIds(urlPath) {
  const ids = [];

  for (const { type, re } of ID_PATTERNS) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(urlPath)) !== null) {
      ids.push({ type, value: m[0] });
    }
  }

  // Slug IDs: letters+digits separated by hyphens
  const segments = urlPath.split('/').filter(Boolean);
  for (const seg of segments) {
    if (/^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(seg)) {
      ids.push({ type: 'slug', value: seg });
    }
  }

  return ids.filter((id, i, arr) => arr.findIndex(x => x.value === id.value) === i);
}

class SessionStore {
  constructor() {
    this.entries    = [];
    this._capped    = false;
  }

  record({ method, url, headers, statusCode, contentLength, contentHash }) {
    // Memory guard — warn once and stop recording if limit reached
    if (this.entries.length >= MAX_ENTRIES) {
      if (!this._capped) {
        console.warn(
          `[accguard] Session store reached ${MAX_ENTRIES} entries — ` +
          `stopping recording. Increase MAX_ENTRIES if needed.`
        );
        this._capped = true;
      }
      return;
    }

    const tokenInfo = extractToken(headers);
    if (!tokenInfo) return;

    const parsed      = new URL(url, 'http://localhost');
    const resourceIds = extractResourceIds(parsed.pathname + parsed.search);

    this.entries.push({
      method:        method.toUpperCase(),
      path:          parsed.pathname,
      query:         parsed.search,
      tokenHash:     fingerprintToken(tokenInfo.raw),
      tokenType:     tokenInfo.type,
      cookieName:    tokenInfo.cookieName,
      resourceIds,
      statusCode,
      contentLength: contentLength || 0,
      contentHash:   contentHash   || null,
      recordedAt:    Date.now(),
    });
  }

  // Returns deduplicated replayable entries.
  // Deduplication key: method + path + query + tokenHash.
  // Prevents 15 identical findings when a test suite hits the same
  // endpoint repeatedly in beforeEach hooks — preserves signal clarity.
  replayable() {
    const seen = new Set();
    return this.entries.filter(e => {
      if (!e.resourceIds.length) return false;
      if (!['GET', 'HEAD'].includes(e.method)) return false;
      const key = `${e.method}:${e.path}:${e.query}:${e.tokenHash}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  knownTokens() {
    return [...new Set(this.entries.map(e => e.tokenHash))];
  }

  // FIX: wrapped in try/catch — file write failure is surfaced clearly,
  // not silently crashed. Findings already printed to terminal are safe.
  saveTo(filePath) {
    try {
      fs.writeFileSync(filePath, JSON.stringify({
        version:     '0.9.2',
        generatedAt: new Date().toISOString(),
        totalCount:  this.entries.length,
        entries:     this.entries,
      }, null, 2), 'utf8');
    } catch (err) {
      console.error(`[accguard] Could not save session store to ${filePath}: ${err.message}`);
    }
  }

  // FIX: separate guards for file read and JSON parse — each gives a precise
  // error message so developers know exactly what went wrong.
  static loadFrom(filePath) {
    let raw;
    try {
      raw = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
      throw new Error(`Could not read session store at ${filePath}: ${err.message}`);
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`Session store at ${filePath} is not valid JSON: ${err.message}`);
    }

    if (!parsed.entries || !Array.isArray(parsed.entries)) {
      throw new Error(`Session store at ${filePath} has unexpected format — missing entries array.`);
    }

    const store = new SessionStore();
    store.entries = parsed.entries;
    return store;
  }

  size() { return this.entries.length; }
}

module.exports = { SessionStore, extractToken, extractResourceIds, fingerprintToken };

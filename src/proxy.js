'use strict';

const http   = require('http');
const https  = require('https');
const { URL } = require('url');
const { contentHash } = require('./replay');

// Headers to strip before forwarding.
// accept-encoding  — forces uncompressed JSON for reliable hashing
// transfer-encoding — stale framing from chunked requests; we buffer fully
// connection        — hop-by-hop, must not be forwarded per HTTP spec
const STRIP_HEADERS = new Set(['accept-encoding', 'transfer-encoding', 'connection']);

class ProxyCore {
  constructor({ target, scope, exclude = [], store, logger, onFlush }) {
    this.target   = new URL(target);
    this.scope    = scope;
    this.exclude  = exclude;
    this.store    = store;
    this.logger   = logger || console;
    this.onFlush  = onFlush || null; // callback for CI /--flush endpoint
    this.server   = null;
  }

  _inScope(pathname) {
    if (this.exclude.some(p => pathname.startsWith(p))) return false;
    return this.scope.some(p => pathname.startsWith(p));
  }

  _forward(incomingReq, bodyBuffer, inScope) {
    return new Promise((resolve, reject) => {
      // Normalize absolute URLs — HTTP_PROXY clients send full URLs as path:
      // "GET http://127.0.0.1:3100/api/orders/1" instead of "GET /api/orders/1"
      // Many frameworks reject absolute-form request targets.
      let targetPath;
      try {
        const parsed = new URL(incomingReq.url, this.target.href);
        targetPath = parsed.pathname + parsed.search;
      } catch {
        targetPath = incomingReq.url;
      }

      // For in-scope requests, strip accept-encoding so upstream returns
      // uncompressed JSON that can be reliably hashed.
      const headers = { ...incomingReq.headers, host: this.target.host };
      // Always strip hop-by-hop and encoding headers.
      // transfer-encoding and connection must not be forwarded per HTTP/1.1 spec.
      // accept-encoding stripped for in-scope requests to ensure uncompressed JSON.
      for (const h of STRIP_HEADERS) {
        if (h === 'accept-encoding' && !inScope) continue; // only strip for in-scope
        delete headers[h];
      }
      // Recalculate content-length from the actual buffer — original header
      // may not match after chunked reassembly or proxy middleware manipulation.
      if (bodyBuffer && bodyBuffer.length) {
        headers['content-length'] = bodyBuffer.length;
      } else {
        delete headers['content-length'];
      }

      const options = {
        hostname: this.target.hostname,
        port:     this.target.port || (this.target.protocol === 'https:' ? 443 : 80),
        path:     targetPath,
        method:   incomingReq.method,
        headers,
      };

      const transport = this.target.protocol === 'https:' ? https : http;
      const req = transport.request(options, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({
          statusCode:  res.statusCode,
          headers:     res.headers,
          body:        Buffer.concat(chunks),
        }));
      });

      req.on('error', reject);
      req.setTimeout(30000, () => { req.destroy(); reject(new Error('upstream timeout after 30s')); });
      if (bodyBuffer && bodyBuffer.length) req.write(bodyBuffer);
      req.end();
    });
  }

  _readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end',  () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  async _handleRequest(req, res) {
    // CI flush endpoint — handled entirely here, not forwarded.
    // onFlush callback is set by cli.js so the proxy doesn't need to
    // know about replay logic.
    if (req.url === '/--flush' && req.method === 'POST') {
      res.writeHead(200);
      res.end('flushing');
      if (this.onFlush) setImmediate(this.onFlush); // respond first, then flush
      return;
    }

    const parsed  = new URL(req.url, 'http://localhost');
    const inScope = this._inScope(parsed.pathname);
    const bodyBuffer = await this._readBody(req);

    let upstream;
    try {
      upstream = await this._forward(req, bodyBuffer, inScope);
    } catch (err) {
      this.logger.error(`[accguard] Forward error: ${err.message}`);
      res.writeHead(502);
      res.end('accguard: upstream connection failed');
      return;
    }

    if (inScope) {
      this.store.record({
        method:        req.method,
        url:           req.url,
        headers:       req.headers,
        statusCode:    upstream.statusCode,
        contentLength: upstream.body.length,
        contentHash:   contentHash(upstream.body, upstream.headers['content-type'] || ''),
      });
    }

    res.writeHead(upstream.statusCode, upstream.headers);
    res.end(upstream.body);
  }

  listen(port) {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch(err => {
          this.logger.error(`[accguard] Unhandled error: ${err.message}`);
          if (!res.headersSent) { res.writeHead(500); res.end('accguard: internal error'); }
        });
      });

      // Catch HTTPS CONNECT attempts — explain clearly instead of failing silently
      this.server.on('connect', (req, socket) => {
        this.logger.log(
          `[accguard] HTTPS request for "${req.url}" — accguard records HTTP only.\n` +
          `           Update your target to http:// or configure your app to use HTTP in tests.`
        );
        socket.write('HTTP/1.1 501 HTTPS Not Supported\r\n\r\n');
        socket.end();
      });

      // Reject on startup errors — e.g. port already in use
      this.server.once('error', reject);

      // SAFETY: bind only to loopback — cannot be reached from outside this machine
      this.server.listen(port, '127.0.0.1', () => {
        this.server.removeListener('error', reject);
        this.logger.log(`[accguard] Proxy listening on 127.0.0.1:${port} → ${this.target.href}`);
        resolve();
      });
    });
  }

  close() {
    return new Promise(resolve => {
      if (this.server) this.server.close(resolve);
      else resolve();
    });
  }
}

module.exports = { ProxyCore };

'use strict';

const http  = require('http');
const https = require('https');
const { URL } = require('url');

class ProxyCore {
  constructor({ target, scope, exclude = [], store, logger }) {
    this.target  = new URL(target);
    this.scope   = scope;   // string[] of path prefixes to record
    this.exclude = exclude; // string[] of path prefixes to always skip
    this.store   = store;
    this.logger  = logger || console;
    this.server  = null;
  }

  // Is this path inside the declared scope and not excluded?
  _inScope(pathname) {
    const excluded = this.exclude.some(p => pathname.startsWith(p));
    if (excluded) return false;
    return this.scope.some(p => pathname.startsWith(p));
  }

  // Forward one request to the real app and return { statusCode, headers, body }
  _forward(incomingReq, bodyBuffer) {
    return new Promise((resolve, reject) => {
      const targetPath = incomingReq.url; // preserve path + query
      const options = {
        hostname: this.target.hostname,
        port:     this.target.port || (this.target.protocol === 'https:' ? 443 : 80),
        path:     targetPath,
        method:   incomingReq.method,
        headers:  { ...incomingReq.headers, host: this.target.host },
      };

      const transport = this.target.protocol === 'https:' ? https : http;
      const proxyReq  = transport.request(options, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => resolve({
          statusCode:    proxyRes.statusCode,
          headers:       proxyRes.headers,
          body:          Buffer.concat(chunks),
          contentLength: parseInt(proxyRes.headers['content-length'] || '0', 10),
        }));
      });

      proxyReq.on('error', reject);
      if (bodyBuffer && bodyBuffer.length) proxyReq.write(bodyBuffer);
      proxyReq.end();
    });
  }

  // Read the full body of an incoming request into a buffer
  _readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end',  () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  async _handleRequest(req, res) {
    const parsed   = new URL(req.url, 'http://localhost');
    const pathname = parsed.pathname;
    const inScope  = this._inScope(pathname);

    // Read the body regardless — we need to forward it even if not recording
    const bodyBuffer = await this._readBody(req);

    // Forward to the real app
    let upstream;
    try {
      upstream = await this._forward(req, bodyBuffer);
    } catch (err) {
      this.logger.error(`[accguard] Forward error: ${err.message}`);
      res.writeHead(502);
      res.end('accguard: upstream connection failed');
      return;
    }

    // Record metadata (never body content) if in scope
    if (inScope) {
      this.store.record({
        method:        req.method,
        url:           req.url,
        headers:       req.headers,
        statusCode:    upstream.statusCode,
        contentLength: upstream.contentLength,
      });
    }

    // Return the upstream response unmodified
    res.writeHead(upstream.statusCode, upstream.headers);
    res.end(upstream.body);
  }

  // Start listening. Always binds to 127.0.0.1 only — never 0.0.0.0
  listen(port) {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch(err => {
          this.logger.error(`[accguard] Unhandled error: ${err.message}`);
          if (!res.headersSent) {
            res.writeHead(500);
            res.end('accguard: internal error');
          }
        });
      });

      // SAFETY: bind only to loopback — cannot be reached from outside this machine
      this.server.listen(port, '127.0.0.1', () => {
        this.logger.log(`[accguard] Proxy listening on 127.0.0.1:${port} → ${this.target.href}`);
        resolve();
      });
    });
  }

  close() {
    return new Promise((resolve) => {
      if (this.server) this.server.close(resolve);
      else resolve();
    });
  }
}

module.exports = { ProxyCore };

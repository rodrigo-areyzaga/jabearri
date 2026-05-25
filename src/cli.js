#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');
const readline = require('readline');

const { verifyTarget, verifyScope } = require('./safety');
const { SessionStore }              = require('./session-store');
const { ProxyCore }                 = require('./proxy');
const { runReplay }                 = require('./replay');
const { printFindings, saveReport } = require('./reporter');

// ─── Authorization gate ───────────────────────────────────────────────────────
// Must be completed once before the tool will run. Creates a local marker file.
const CONSENT_FILE = path.join(
  process.env.HOME || process.env.USERPROFILE || '.', '.accguard_consent'
);
const REQUIRED_PHRASE = 'I own or have written authorization to test the target system';

async function requireConsent() {
  if (fs.existsSync(CONSENT_FILE)) return;

  console.log('\n' + '═'.repeat(66));
  console.log('  accguard — authorization required');
  console.log('═'.repeat(66));
  console.log('\n  This tool probes your application for access control');
  console.log('  vulnerabilities. You must only use it against systems');
  console.log('  you own or have explicit written permission to test.');
  console.log('\n  Unauthorized use may violate:');
  console.log('    · Computer Fraud and Abuse Act (US)');
  console.log('    · Computer Misuse Act (UK)');
  console.log('    · Equivalent laws in your jurisdiction');
  console.log('\n  Type the following sentence exactly to continue:\n');
  console.log(`  "${REQUIRED_PHRASE}"\n`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise(resolve => rl.question('  > ', resolve));
  rl.close();

  if (answer.trim() !== REQUIRED_PHRASE) {
    console.log('\n  Phrase did not match. Exiting.\n');
    process.exit(1);
  }

  fs.writeFileSync(CONSENT_FILE, JSON.stringify({
    agreedAt: new Date().toISOString(),
    phrase:   REQUIRED_PHRASE,
  }), 'utf8');

  console.log('\n  Consent recorded. accguard is ready to use.\n');
}

// ─── Config loading ───────────────────────────────────────────────────────────
function loadConfig() {
  const configPath = path.resolve(process.env.ACCGUARD_CONFIG || 'accguard.config.json');
  if (!fs.existsSync(configPath)) {
    console.error(`[accguard] No config found at ${configPath}`);
    console.error('[accguard] Create accguard.config.json — see README for format.');
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  await requireConsent();

  const config = loadConfig();
  const {
    target,
    scope,
    exclude    = [],
    port       = 8877,
    outputFile = 'accguard-report.json',
  } = config;

  // Safety checks — these throw and exit if they fail
  try {
    await verifyTarget(target);
    verifyScope(scope);
  } catch (err) {
    console.error(`\n[accguard] ${err.message}\n`);
    process.exit(1);
  }

  const store = new SessionStore();
  const proxy = new ProxyCore({ target, scope, exclude, store });

  await proxy.listen(port);
  console.log(`[accguard] Set HTTP_PROXY=http://127.0.0.1:${port} and run your tests.`);
  console.log('[accguard] Send SIGINT (Ctrl+C) or POST /--flush when done.\n');

  // Flush endpoint — useful in CI where you can't send signals easily
  proxy.server.on('request', (req, res) => {
    if (req.url === '/--flush' && req.method === 'POST') {
      res.writeHead(200);
      res.end('flushing');
      triggerFlush();
    }
  });

  // Handle shutdown
  const triggerFlush = async () => {
    console.log('\n[accguard] Stopping proxy and running replay...');
    await proxy.close();

    const secondToken = process.env.ACCGUARD_TOKEN_B;
    if (!secondToken) {
      console.log('[accguard] ACCGUARD_TOKEN_B not set — skipping replay.');
      console.log('[accguard] Set it to a second user\'s session token to enable access control checks.');
      process.exit(0);
    }

    const findings = await runReplay({ store, targetUrl: target, secondToken });

    printFindings(findings, store);

    if (outputFile) saveReport(findings, store, outputFile);

    // Exit 1 if findings — integrates cleanly with CI pass/fail
    process.exit(findings.length > 0 ? 1 : 0);
  };

  process.on('SIGINT',  triggerFlush);
  process.on('SIGTERM', triggerFlush);
}

main().catch(err => {
  console.error('[accguard] Fatal:', err.message);
  process.exit(1);
});

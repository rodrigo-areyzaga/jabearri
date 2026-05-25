'use strict';

const fs = require('fs');

function printFindings(findings, store) {
  const divider = '─'.repeat(60);

  console.log('\n' + divider);
  console.log('  accguard — access control scan results');
  console.log(divider);
  console.log(`  Requests observed : ${store.size()}`);
  console.log(`  Replayed          : ${store.replayable().length}`);
  console.log(`  Findings          : ${findings.length}`);
  console.log(divider);

  if (findings.length === 0) {
    console.log('\n  No access control failures detected.\n');
    return;
  }

  findings.forEach((f, i) => {
    console.log(`\n  [${i + 1}] ${f.severity.toUpperCase()} — ${f.type}`);
    console.log(`      ${f.method} ${f.path}`);
    console.log(`      Resource IDs : ${f.resourceIds.map(r => r.value).join(', ')}`);
    console.log(`      User A got   : ${f.originalStatus} (${f.originalSize} bytes)`);
    console.log(`      User B got   : ${f.replayStatus} (${f.replaySize} bytes)`);
    console.log(`\n      Reproduce:`);
    console.log(`      ${f.curl}`);
  });

  console.log('\n' + divider + '\n');
}

function saveReport(findings, store, outputPath) {
  const report = {
    version:     1,
    generatedAt: new Date().toISOString(),
    summary: {
      observed:  store.size(),
      replayed:  store.replayable().length,
      findings:  findings.length,
    },
    findings,
  };
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
  console.log(`[accguard] Report saved to ${outputPath}`);
}

module.exports = { printFindings, saveReport };

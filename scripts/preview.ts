/**
 * 调试用：把编译产物写到 runtime/preview/
 * 用法：node scripts/preview.ts
 */
import fs from 'node:fs';
import path from 'node:path';
import { compileDesiredState } from '../src/compiler/compile.ts';
import { CREDENTIALS, buildFixtureState } from '../test/fixtures.ts';

const result = compileDesiredState({
  state: buildFixtureState(),
  credentials: CREDENTIALS,
  controlEndpoints: ['54.199.10.8'],
  now: Date.parse('2026-11-14T02:00:00.000Z'),
});

const dir = path.resolve('runtime/preview');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'singbox.json'), JSON.stringify(result.artifacts.singbox, null, 2));
fs.writeFileSync(path.join(dir, 'nftables.nft'), result.artifacts.nftables);
fs.writeFileSync(path.join(dir, 'apply.uci.sh'), result.artifacts.uci);
fs.writeFileSync(path.join(dir, 'leases.json'), JSON.stringify(result.artifacts.leases, null, 2));
fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(result.artifacts.manifest, null, 2));

console.log(`digest   ${result.digest}`);
console.log(`clients  ${result.stats.clients}  pending ${result.stats.pending}  lines ${result.stats.lines}`);
console.log(`rules    route ${result.stats.routeRules}  dns ${result.stats.dnsRules}`);
console.log(`size     singbox ${result.stats.singboxBytes}B  nftables ${result.stats.nftablesBytes}B`);
console.log(`warnings ${result.warnings.length}`);
for (const w of result.warnings) console.log(`  - ${w}`);
console.log(`output   ${dir}`);

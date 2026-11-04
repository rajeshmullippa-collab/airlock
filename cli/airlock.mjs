#!/usr/bin/env node
// Airlock CLI: put the checkpoint in front of any agent, script, or CI job.
//
//   CLOCKED_API_KEY=... node cli/airlock.mjs email.txt --policy "Support assistant..." --safe-out safe.txt --report audit.json
//   cat issue.md | node cli/airlock.mjs - --json
//
// Exit codes: 0 forward · 1 forward the masked copy · 2 hold for human review · 3 block · 4 usage/config error.
import { readFileSync, writeFileSync } from 'node:fs';
import { ClockedClient } from '../js/clocked.js';
import { runAirlock, auditReport, ROUTE_LABEL, ROUTES } from '../js/airlock.js';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); if (i < 0) return null; const v = args[i + 1]; args.splice(i, 2); return v; };
const flag = (name) => { const i = args.indexOf(name); if (i < 0) return false; args.splice(i, 1); return true; };

if (flag('--help') || flag('-h')) {
  console.log(`Usage: airlock <file|-> [--policy TEXT | --policy-file FILE] [--safe-out FILE] [--report FILE] [--json]
Reads untrusted text, runs Clocked Guard, Inspect, Protect and Decide, and prints the route.
Needs CLOCKED_API_KEY in the environment. Exit code: 0 forward, 1 forward masked, 2 review, 3 block.`);
  process.exit(0);
}
let policy = opt('--policy');
const policyFile = opt('--policy-file');
const safeOut = opt('--safe-out');
const reportOut = opt('--report');
const asJson = flag('--json');
const src = args[0];
if (!src) { console.error('airlock: give a file path, or - for stdin (see --help)'); process.exit(4); }
if (!process.env.CLOCKED_API_KEY) { console.error('airlock: set CLOCKED_API_KEY (create one at https://clocked.rezolve.ai/account)'); process.exit(4); }
if (policyFile) policy = readFileSync(policyFile, 'utf8');
const text = readFileSync(src === '-' ? 0 : src, 'utf8');

const client = new ClockedClient({ apiKey: process.env.CLOCKED_API_KEY });
const run = await runAirlock(client, { text, policy }, ev => {
  if (!asJson && ev.status === 'error') console.error(`  ! ${ev.step}: ${ev.error}`);
});
const report = auditReport(run, { mode: 'cli', source: src });
if (safeOut && run.safeCopy != null) writeFileSync(safeOut, run.safeCopy);
if (reportOut) writeFileSync(reportOut, JSON.stringify(report, null, 2));
if (asJson) console.log(JSON.stringify(report, null, 2));
else {
  console.log(`\nAirlock: ${ROUTE_LABEL[run.route].toUpperCase()}`);
  for (const r of run.reasons) console.log(`  - ${r}`);
  console.log(`  ${Object.keys(run.steps).length} Clocked calls${run.credits ? `, ${run.credits} credits` : ''}, ${run.ms} ms`);
  if (safeOut) console.log(`  safe copy → ${safeOut}`);
}
process.exit(ROUTES.indexOf(run.route));

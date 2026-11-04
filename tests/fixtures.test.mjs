// The demo replays must be honest: replaying each recorded run through the current pipeline
// must produce exactly the requests that were sent to Clocked when it was recorded.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { runAirlock } from '../js/airlock.js';
import { SAMPLES } from '../js/samples.js';

const dir = new URL('../demo/', import.meta.url);
for (const f of readdirSync(dir).filter(f => f.endsWith('.json'))) {
  test(`recorded run ${f} matches the current pipeline and sample`, async () => {
    const fx = JSON.parse(readFileSync(new URL(f, dir), 'utf8'));
    const sample = SAMPLES.find(s => s.id === fx.sample_id);
    assert.ok(sample, 'sample exists');
    assert.equal(fx.text, sample.text);
    assert.equal(fx.policy, sample.policy);
    const client = { async call(endpoint, body, step) {
      const s = fx.steps[step];
      assert.ok(s, `step ${step} recorded`);
      assert.equal(s.endpoint, endpoint);
      assert.deepEqual(body, s.request);
      return { data: s.response, credits: s.credits };
    } };
    const run = await runAirlock(client, { text: fx.text, policy: fx.policy });
    assert.equal(run.route, fx.route);
  });
}

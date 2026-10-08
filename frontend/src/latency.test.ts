import { test } from "node:test";
import assert from "node:assert/strict";
import { latencyTone } from "./latency.ts";
test("latency indicators distinguish measurement state and boundary values", () => {
  assert.equal(latencyTone(), "unknown");
  assert.equal(latencyTone({ success: true, latency_ms: NaN }), "unknown");
  assert.equal(latencyTone({ success: true, latency_ms: -1 }), "unknown");
  assert.equal(latencyTone({ success: true, latency_ms: 149 }), "fast");
  assert.equal(latencyTone({ success: true, latency_ms: 150 }), "moderate");
  assert.equal(latencyTone({ success: true, latency_ms: 399 }), "moderate");
  assert.equal(latencyTone({ success: true, latency_ms: 400 }), "slow");
  assert.equal(latencyTone({ success: false, latency_ms: 0 }), "failed");
  assert.equal(latencyTone({ error: "unavailable" }), "failed");
  assert.equal(latencyTone({ checking: true, success: false }), "checking");
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { overlap } from "./network.ts";
test("network conflict preview uses whole CIDR not hostonly", () => {
  assert.equal(overlap("198.19.128.0/24", "198.18.0.0/15"), true);
  assert.equal(overlap("192.168.88.1/24", "198.18.0.0/15"), false);
  assert.equal(overlap("198.20.0.0/16", "198.18.0.0/15"), false);
  assert.equal(overlap("::1", "198.18.0.0/15"), false);
});

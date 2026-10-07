import { test } from "node:test";
import assert from "node:assert/strict";
import type { Rule } from "./types.ts";
import { analyseRuleConflicts } from "./rule-conflicts.ts";
const base = {
  id: "a",
  outbound: "proxy",
  domains: ["video.example"],
  priority: 20,
};
test("exact and suffix collision with different routes exposes real stable priority", () => {
  const result = analyseRuleConflicts([
    base,
    { id: "b", outbound: "direct", suffixes: ["example"], priority: 10 },
  ]);
  assert.equal(result.conflicts.length, 1);
  assert.equal(result.conflicts[0].first.id, "b");
  const tied = analyseRuleConflicts([
    base,
    { id: "b", outbound: "direct", domains: ["video.example"], priority: 20 },
  ]);
  assert.equal(tied.conflicts[0].first.id, "a");
});
test("disjoint source, network, ports or destination never produce collision", () => {
  for (const [a, b] of [
    [
      { ...base, source_cidrs: ["192.168.1.0/24"] },
      {
        ...base,
        id: "b",
        outbound: "direct",
        source_cidrs: ["192.168.2.0/24"],
      },
    ],
    [
      { ...base, network: "tcp" },
      { ...base, id: "b", outbound: "direct", network: "udp" },
    ],
    [
      { ...base, ports: [443] },
      { ...base, id: "b", outbound: "direct", ports: [80] },
    ],
    [
      { ...base, domains: ["one.example"] },
      { ...base, id: "b", outbound: "direct", domains: ["two.example"] },
    ],
  ] as Rule[][])
    assert.equal(analyseRuleConflicts([a, b]).conflicts.length, 0);
});
test("IPv4 destination overlap and source intersection detected", () => {
  assert.equal(
    analyseRuleConflicts([
      {
        id: "one",
        outbound: "proxy",
        destination_cidrs: ["203.0.113.0/24"],
        source_cidrs: ["192.168.88.0/24"],
      },
      {
        id: "two",
        outbound: "direct",
        destination_cidrs: ["203.0.113.10/32"],
        source_cidrs: ["192.168.88.10/32"],
      },
    ]).conflicts.length,
    1,
  );
});
test("disabled and same route omitted; remote or excessive input explicitly incomplete", () => {
  assert.equal(
    analyseRuleConflicts([
      base,
      { ...base, id: "b", enabled: false, outbound: "direct" },
    ]).conflicts.length,
    0,
  );
  assert.equal(
    analyseRuleConflicts([base, { ...base, id: "b" }]).conflicts.length,
    0,
  );
  assert.equal(
    analyseRuleConflicts([{ ...base, rule_sets: ["external"] }]).incomplete,
    true,
  );
  assert.equal(
    analyseRuleConflicts(
      Array.from({ length: 257 }, (_, i) => ({ ...base, id: "rule" + i })),
    ).incomplete,
    true,
  );
});

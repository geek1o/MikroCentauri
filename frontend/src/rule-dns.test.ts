import { test } from "node:test";
import assert from "node:assert/strict";
import { selectedDNSForRule } from "./rule-dns.ts";
test("proxy rule appends finite names once and preserves prior DNS", () => {
  const existing = ["retained.example", "new.example"];
  assert.deepEqual(
    selectedDNSForRule(existing, {
      id: "one",
      outbound: "proxy",
      domains: ["new.example", "another.example"],
      suffixes: ["wild.example"],
    }),
    ["retained.example", "new.example", "another.example"],
  );
  assert.deepEqual(existing, ["retained.example", "new.example"]);
});
test("direct and disabled rules never add names or remove retained names", () => {
  for (const rule of [
    { id: "one", outbound: "direct", domains: ["new.example"] },
    { id: "two", outbound: "proxy", enabled: false, domains: ["new.example"] },
    { id: "three", outbound: "proxy", domains: [] },
  ])
    assert.deepEqual(selectedDNSForRule(["retained.example"], rule), [
      "retained.example",
    ]);
});

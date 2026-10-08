import { test } from "node:test";
import assert from "node:assert/strict";
import { sectionConflicts } from "./section-conflicts.ts";
import type { Section } from "./types.ts";
const section = (id: string, extra: Partial<Section> = {}): Section => ({
  id,
  name: id,
  enabled: true,
  outbound: "direct",
  ...extra,
});
test("section overlap accounts for nested suffixes, networks, scope and disabled sections", () => {
  const values = [
    section("root", { domains: ["example.org"] }),
    section("child", { domains: ["video.example.org"] }),
    section("separate", { domains: ["other.org"] }),
    section("net", { destination_cidrs: ["203.0.113.0/24"] }),
    section("host", { destination_cidrs: ["203.0.113.2/32"] }),
    section("scoped-a", {
      domains: ["scoped.org"],
      source_cidrs: ["192.168.1.0/24"],
    }),
    section("scoped-b", {
      domains: ["scoped.org"],
      source_cidrs: ["192.168.2.0/24"],
    }),
    section("disabled", { domains: ["example.org"], enabled: false }),
  ];
  const result = sectionConflicts(values);
  assert.deepEqual(
    result.child.map((x) => x.id),
    ["root"],
  );
  assert.deepEqual(
    result.host.map((x) => x.id),
    ["net"],
  );
  assert.deepEqual(result.separate, []);
  assert.deepEqual(result["scoped-b"], []);
  assert.deepEqual(result.disabled, []);
});
test("shared list snapshots and explicit whole-device scope participate in warnings", () => {
  const a = section("list", {
    lists: [
      {
        id: "shared",
        name: "Shared",
        sha256: "a".repeat(64),
        domains: ["list.example"],
      },
    ],
  });
  const b = section("manual", { domains: ["child.list.example"] });
  const c = section("device", {
    all_traffic: true,
    source_cidrs: ["192.168.1.1/32"],
  });
  assert.deepEqual(
    sectionConflicts([a, b, c]).manual.map((x) => x.id),
    ["list"],
  );
  assert.deepEqual(
    sectionConflicts([a, b, c]).device.map((x) => x.id),
    ["list", "manual"],
  );
});

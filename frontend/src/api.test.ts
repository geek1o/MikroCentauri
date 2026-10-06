import { test } from "node:test";
import assert from "node:assert/strict";
import {
  api,
  setToken,
  clearToken,
  split,
  importURIList,
  copy,
  APIError,
} from "./api.ts";
test("same-origin request omits cookies and bearer is memory-only", async () => {
  let seen: any;
  globalThis.fetch = async (url, options) => {
    seen = { url, options };
    return new Response('{"ok":true}', { status: 200 });
  };
  setToken("secret");
  await api("config");
  assert.equal(seen.url, "/api/v1/config");
  assert.equal(seen.options.credentials, "omit");
  assert.equal(seen.options.headers.Authorization, "Bearer secret");
  clearToken();
  await api("health/live");
  assert.equal(seen.options.headers.Authorization, undefined);
});
test("401 destroys bearer; stale draft remains explicit error", async () => {
  globalThis.fetch = async () =>
    new Response('{"error":"unauthorized"}', { status: 401 });
  setToken("secret");
  await assert.rejects(api("config"), APIError);
  let header: any;
  globalThis.fetch = async (_, options) => {
    header = options?.headers;
    return new Response("{}");
  };
  await api("config");
  assert.equal(header.Authorization, undefined);
  assert.deepEqual(split("a,b\n c "), ["a", "b", "c"]);
});

test("URI import preserves literal commas in query and fragment", () => {
  assert.deepEqual(
    importURIList(
      " vless://uuid@host:443?path=a,b#Node,One\r\n\n trojan://pass@other:443#Two ",
    ),
    ["vless://uuid@host:443?path=a,b#Node,One", "trojan://pass@other:443#Two"],
  );
});

test("JSON model snapshots accept nested reactive proxies", () => {
  const nested = new Proxy(
    { groups: [{ id: "manual", members: ["node"] }], policy: { rules: null } },
    {},
  );
  const reactive = new Proxy({ model: nested }, {});
  const snapshot = copy(reactive);
  assert.deepEqual(snapshot, {
    model: {
      groups: [{ id: "manual", members: ["node"] }],
      policy: { rules: null },
    },
  });
  snapshot.model.groups[0].members.push("other");
  assert.deepEqual(reactive.model.groups[0].members, ["node"]);
});

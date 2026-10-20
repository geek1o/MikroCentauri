import assert from "node:assert/strict";
import test from "node:test";
import { subscriptionFailure } from "./subscription-failure.ts";

test("download failures distinguish network path from endpoint import", () => {
  assert.match(subscriptionFailure("timeout"), /прямой доступ/);
  assert.match(
    subscriptionFailure("timeout", "selected-node"),
    /через выбранный прокси/,
  );
  assert.match(subscriptionFailure("dns_failed"), /DNS/);
  assert.match(subscriptionFailure("tls_failed"), /сертификат/);
  assert.match(subscriptionFailure("destination_refused"), /запрещена/);
  assert.doesNotMatch(
    subscriptionFailure("private-secret-url"),
    /private-secret/,
  );
  assert.equal(subscriptionFailure(undefined), subscriptionFailure("unknown"));
  assert.equal(
    subscriptionFailure("constructor"),
    subscriptionFailure("unknown"),
  );
});

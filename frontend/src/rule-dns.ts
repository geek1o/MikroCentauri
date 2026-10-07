import type { Rule } from "./types";
// Only finite explicit names can be admitted. Removing or disabling a rule never
// retires published names; retirement remains an explicit DNS policy operation.
export function selectedDNSForRule(
  existing: string[] | null | undefined,
  rule: Rule,
): string[] {
  const retained = [...(existing || [])];
  if (rule.enabled === false || rule.outbound === "direct") return retained;
  return [...new Set([...retained, ...(rule.domains || [])])];
}

import type { Section } from "./types";
import { range } from "./network.ts";

type Span = [number, number];
const spans = (items: string[]) =>
  items
    .map(range)
    .filter((r): r is Span => !!r)
    .sort((a, b) => a[0] - b[0]);
function intersects(a: Span[], b: Span[]) {
  let i = 0,
    j = 0;
  while (i < a.length && j < b.length) {
    if (a[i][0] <= b[j][1] && b[j][0] <= a[i][1]) return true;
    if (a[i][1] < b[j][0]) i++;
    else j++;
  }
  return false;
}
function suffixIntersection(a: Set<string>, b: Set<string>) {
  const matches = (roots: Set<string>, other: Set<string>) => {
    for (const root of roots) {
      let candidate = root;
      for (;;) {
        if (other.has(candidate)) return true;
        const dot = candidate.indexOf(".");
        if (dot < 0) break;
        candidate = candidate.slice(dot + 1);
      }
    }
    return false;
  };
  return matches(a, b) || matches(b, a);
}
// Precompute ranges and domain sets once per draft update. Large community lists
// must not trigger quadratic per-record comparisons during each engine poll.
export function sectionConflicts(
  sections: Section[],
): Record<string, Section[]> {
  const prepared = sections.map((s) => ({
    section: s,
    domains: new Set([
      ...(s.domains || []),
      ...(s.lists || []).flatMap((l) => l.domains || []),
    ]),
    networks: spans([
      ...(s.destination_cidrs || []),
      ...(s.lists || []).flatMap((l) => l.prefixes || []),
    ]),
    sources: spans(s.source_cidrs || []),
  }));
  const result: Record<string, Section[]> = {};
  for (let i = 0; i < prepared.length; i++) {
    const b = prepared[i];
    result[b.section.id] = [];
    if (!b.section.enabled) continue;
    for (let j = 0; j < i; j++) {
      const a = prepared[j];
      if (!a.section.enabled) continue;
      if (
        a.sources.length &&
        b.sources.length &&
        !intersects(a.sources, b.sources)
      )
        continue;
      if (
        a.section.all_traffic ||
        b.section.all_traffic ||
        suffixIntersection(a.domains, b.domains) ||
        intersects(a.networks, b.networks)
      )
        result[b.section.id].push(a.section);
    }
  }
  return result;
}

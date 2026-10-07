import type { Rule } from "./types";
import { overlap } from "./network.ts";
export interface RuleConflict {
  first: Rule;
  second: Rule;
  reason: string;
}
export interface ConflictAnalysis {
  conflicts: RuleConflict[];
  incomplete: boolean;
  notes: string[];
  analysed: number;
}
function intersects<T>(left: T[], right: T[]) {
  const set = new Set(right);
  return left.some((x) => set.has(x));
}
function suffixMatch(name: string, suffix: string) {
  return name === suffix || name.endsWith("." + suffix);
}
function domainOverlap(a: Rule, b: Rule) {
  const ad = a.domains || [],
    bd = b.domains || [],
    as = a.suffixes || [],
    bs = b.suffixes || [];
  return (
    intersects(ad, bd) ||
    ad.some((x) => bs.some((y) => suffixMatch(x, y))) ||
    bd.some((x) => as.some((y) => suffixMatch(x, y))) ||
    as.some((x) => bs.some((y) => suffixMatch(x, y) || suffixMatch(y, x)))
  );
}
export function analyseRuleConflicts(
  rules: Rule[] | null | undefined,
): ConflictAnalysis {
  const enabled = (rules || [])
    .map((rule, index) => ({ rule, index }))
    .filter((x) => x.rule.enabled !== false);
  const notes: string[] = [];
  if (enabled.length > 256)
    notes.push("Проверены только первые 256 включённых правил.");
  let skipped = 0;
  const limited = enabled.slice(0, 256).filter(({ rule: r }) => {
    const lists = [
      r.domains,
      r.suffixes,
      r.destination_cidrs,
      r.source_cidrs,
      r.ports,
    ];
    const unsupported =
      !!r.rule_sets?.length ||
      !!r.services?.length ||
      lists.some((x) => (x?.length || 0) > 32) ||
      [...(r.source_cidrs || []), ...(r.destination_cidrs || [])].some((x) =>
        x.includes(":"),
      );
    if (unsupported) skipped++;
    return !unsupported;
  });
  if (skipped)
    notes.push(
      `${skipped} правил пропущено: удалённые наборы, сервисы, IPv6 или более 32 значений одного условия требуют серверного анализа.`,
    );
  const ordered = limited.sort(
    (a, b) =>
      (a.rule.priority || 0) - (b.rule.priority || 0) || a.index - b.index,
  );
  const conflicts: RuleConflict[] = [];
  let unresolved = 0,
    capped = false;
  outer: for (let i = 0; i < ordered.length; i++)
    for (let j = i + 1; j < ordered.length; j++) {
      const a = ordered[i].rule,
        b = ordered[j].rule;
      if (a.outbound === b.outbound) continue;
      if (a.network && b.network && a.network !== b.network) continue;
      if (a.ports?.length && b.ports?.length && !intersects(a.ports, b.ports))
        continue;
      if (
        a.source_cidrs?.length &&
        b.source_cidrs?.length &&
        !a.source_cidrs.some((x) => b.source_cidrs!.some((y) => overlap(x, y)))
      )
        continue;
      const ah = !!a.domains?.length || !!a.suffixes?.length,
        bh = !!b.domains?.length || !!b.suffixes?.length;
      const ai = !!a.destination_cidrs?.length,
        bi = !!b.destination_cidrs?.length;
      if (ah && bh && !domainOverlap(a, b)) continue;
      if (
        ai &&
        bi &&
        !a.destination_cidrs!.some((x) =>
          b.destination_cidrs!.some((y) => overlap(x, y)),
        )
      )
        continue;
      if ((ah && bi && !bh) || (bh && ai && !ah)) {
        unresolved++;
        continue;
      }
      conflicts.push({
        first: a,
        second: b,
        reason:
          ah && bh
            ? "Совпадающие домены или суффиксы"
            : ai && bi
              ? "Пересекающиеся IPv4-назначения"
              : "Общая область назначения",
      });
      if (conflicts.length === 64) {
        capped = true;
        break outer;
      }
    }
  if (unresolved)
    notes.push(
      `${unresolved} пар домен/IP не сопоставлены: для них нужно разрешение DNS.`,
    );
  if (capped)
    notes.push("Показаны первые 64 пересечения; оставшиеся пары не проверены.");
  return {
    conflicts,
    incomplete: notes.length > 0,
    notes,
    analysed: limited.length,
  };
}

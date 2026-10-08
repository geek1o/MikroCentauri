export function latencyTone(status?: {
  checking?: boolean;
  pending?: boolean;
  success?: boolean;
  latency_ms?: number;
  error?: string;
}) {
  if (status?.checking || status?.pending) return "checking";
  if (status?.success === false || status?.error) return "failed";
  if (
    status?.success !== true ||
    !Number.isFinite(status.latency_ms) ||
    status.latency_ms! < 0
  )
    return "unknown";
  return status.latency_ms! < 150
    ? "fast"
    : status.latency_ms! < 400
      ? "moderate"
      : "slow";
}

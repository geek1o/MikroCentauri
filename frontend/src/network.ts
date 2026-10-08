export function range(value: string): [number, number] | undefined {
  const [address, bitsText] = value.split("/");
  const parts = address.split(".");
  const bits = bitsText === undefined ? 32 : Number(bitsText);
  if (
    parts.length !== 4 ||
    !Number.isInteger(bits) ||
    bits < 0 ||
    bits > 32 ||
    parts.some((x) => !/^\d+$/.test(x) || Number(x) > 255)
  )
    return;
  const ip = parts.reduce((sum, x) => sum * 256 + Number(x), 0);
  const size = 2 ** (32 - bits);
  const start = Math.floor(ip / size) * size;
  return [start, start + size - 1];
}
export function overlap(left: string, right: string) {
  const a = range(left),
    b = range(right);
  return !!a && !!b && a[0] <= b[1] && b[0] <= a[1];
}

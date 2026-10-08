export const testTargets = [
  { id: "google", name: "Google", url: "https://www.gstatic.com/generate_204" },
  {
    id: "cloudflare",
    name: "Cloudflare",
    url: "https://cp.cloudflare.com/generate_204",
  },
  {
    id: "apple",
    name: "Apple",
    url: "https://www.apple.com/library/test/success.html",
  },
  {
    id: "mozilla",
    name: "Mozilla",
    url: "https://detectportal.firefox.com/success.txt",
  },
];
export const testTargetLabel = (id?: string) =>
  testTargets.find((t) => t.id === id)?.url || "Сохранённая цель оператора";

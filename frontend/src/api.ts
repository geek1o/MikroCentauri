export class APIError extends Error {
  code: string;
  status: number;
  constructor(code: string, status: number) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
let token = "";
export function setToken(value: string) {
  token = value;
}
export function clearToken() {
  token = "";
}
export async function api<T = any>(path: string, body?: unknown): Promise<T> {
  const response = await fetch("/api/v1/" + path, {
    method: body === undefined ? "GET" : "POST",
    credentials: "omit",
    cache: "no-store",
    headers: {
      ...(token ? { Authorization: "Bearer " + token } : {}),
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) clearToken();
    throw new APIError(data.error || "request_failed", response.status);
  }
  return data as T;
}
export async function download(path: string, name: string) {
  const r = await fetch("/api/v1/" + path, {
    credentials: "omit",
    cache: "no-store",
    headers: { Authorization: "Bearer " + token },
  });
  if (!r.ok) throw new APIError("download_failed", r.status);
  saveBlob(await r.blob(), name);
}
export function saveBlob(value: Blob, name: string) {
  const url = URL.createObjectURL(value);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function importURIList(value: string) {
  return value
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean);
}
export function split(value: string) {
  return value
    .split(/[\n,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}
export function copy<T>(value: T): T {
  // API models are JSON projections. JSON cloning also accepts Svelte reactive
  // proxies, which structuredClone rejects with DataCloneError.
  return JSON.parse(JSON.stringify(value)) as T;
}
export const errors: Record<string, string> = {
  engine_not_connected:
    "API sing-box не подключён. Можно подготовить выбор сервера в черновике.",
  engine_unavailable: "Нет связи с sing-box. Текущий сервер не подтверждён.",
  engine_switch_failed:
    "Движок не подтвердил переключение. Обновите состояние и повторите.",
  stale_engine_revision:
    "Конфигурация движка изменилась. Обновите панель и повторите выбор.",
  invalid_selector_member: "Сервер отсутствует в действующем ручном селекторе.",
  invalid_network_list:
    "Нужен список канонических публичных IPv4-подсетей. IPv6 и локальные сети не поддерживаются.",
  empty_network_list: "В источнике нет IPv4-подсетей.",
  list_network_limit:
    "Список превышает лимит 4096 подсетей. Данные не обрезаются.",
  invalid_model:
    "Правка нарушает связи модели. Проверьте участников групп, правила и наличие включённого узла.",
  empty_group: "Выберите хотя бы одного участника группы.",
  invalid_backup: "Файл не является допустимой резервной копией.",
  list_download_failed:
    "Не удалось скачать список. Проверьте HTTPS URL и доступность источника. Рабочая конфигурация сохранена.",
  list_source_limit: "Достигнут лимит 64 сохранённых источников списков.",
  list_domain_limit:
    "Список или итоговый DNS-допуск превышает лимит 4096 доменов. Выберите более узкий список; данные не обрезаются.",
  invalid_domain_list:
    "Файл должен содержать домены по одному на строку. JSON, IP-подсети и конфигурации DNS-сервера здесь не поддерживаются.",
  empty_domain_list: "В скачанном файле нет доменов.",
  invalid_list_source:
    "Проверьте источник списка и выбранные элементы каталога.",
  list_state_invalid:
    "Снимок списка недоступен или повреждён. Повторите загрузку.",
  subscription_refresh_failed:
    "Подписку не удалось загрузить или разобрать. Проверьте её формат и доступность. Предыдущие данные сохранены.",
  invalid_policy:
    "Проверьте выбранную группу, её участников и соответствие правил конфигурации.",
  subscription_absent: "Сначала добавьте подписку.",
  unauthorized: "Сессия завершена. Войдите снова.",
  login_denied: "Вход отклонён. Проверьте пароль и попробуйте позже.",
  stale_draft: "Черновик изменился. Обновите данные и повторите правку.",
  stale_plan: "План устарел. Сформируйте новый план.",
  validation_failed:
    "Конфигурация не прошла проверку. Проверьте группы, правила и DNS.",
  runtime_not_connected:
    "Обработчик трафика не подключён. Доступно редактирование черновиков.",
  adapter_not_connected: "Источник данных не подключён.",
  busy: "Сервис занят. Повторите запрос.",
  origin_denied: "Адрес браузера не разрешён.",
  client_denied: "Адрес клиента не разрешён.",
};
export function errorMessage(error: unknown) {
  return error instanceof APIError
    ? errors[error.code] || `Запрос отклонён: ${error.code}`
    : "Не удалось связаться с сервисом.";
}

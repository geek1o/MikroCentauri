<script lang="ts">
  import { onMount } from "svelte";
  import IPv6Notice from "./IPv6Notice.svelte";
  import {
    api,
    APIError,
    setToken,
    clearToken,
    download,
    saveBlob,
    split,
    importURIList,
    copy,
    errorMessage,
  } from "./api";
  import type { Config, Group, Rule } from "./types";
  import { overlap } from "./network";
  import { selectedDNSForRule } from "./rule-dns";
  import { analyseRuleConflicts } from "./rule-conflicts";
  const pages = [
    ["dashboard", "Обзор", "◈"],
    ["setup", "Начальная настройка", "◇"],
    ["proxies", "Прокси", "↗"],
    ["subscriptions", "Подписки", "↻"],
    ["lists", "Списки сайтов", "▤"],
    ["groups", "Селекторы", "◎"],
    ["rules", "Правила", "≡"],
    ["devices", "Устройства", "▣"],
    ["dns", "DNS", "⌁"],
    ["diagnostics", "Диагностика", "✓"],
    ["system", "Система", "⚙"],
  ];
  let page = $state("dashboard"),
    logged = $state(false),
    password = $state(""),
    busy = $state(false),
    error = $state(""),
    notice = $state("");
  let config = $state<Config>(),
    current = $state<Config>(),
    system = $state<any>(),
    info = $state<any>(),
    router = $state<any>(),
    network = $state<any>(),
    subscriptions = $state<any[]>([]),
    logs = $state<any[]>([]),
    plan = $state<any>();
  let catalog = $state<any[]>([]),
    listSnapshots = $state<any[]>([]);
  let selectedLists = $state<string[]>([]),
    listSearch = $state(""),
    listOutbound = $state("");
  let customList = $state({ name: "", url: "" });
  let importSelector = $state("proxy");
  let nodeSearch = $state(""),
    diagnosticDetails = $state<Record<string, any>>({});
  const diagnosticCards = [
    {
      id: "routeros",
      title: "Связь с MikroTik",
      description: "Доступность API и сведения о роутере.",
      hint: "Проверьте адрес RouterOS, сертификат и учётную запись.",
      page: "setup",
    },
    {
      id: "core",
      title: "Конфигурация движка",
      description: "Проверка конфигурации настоящим sing-box.",
      hint: "Проверьте серверы, участников селекторов и правила.",
      page: "groups",
    },
    {
      id: "subscription",
      title: "Подписки",
      description: "Загрузка всех настроенных подписок и подсчёт серверов.",
      hint: "Проверьте URL, формат ответа и фильтры серверов.",
      page: "subscriptions",
    },
    {
      id: "direct",
      title: "Интернет напрямую",
      description: "Доступность контрольного адреса без прокси.",
      hint: "Проверьте основной маршрут и подключение к интернету.",
      page: "setup",
    },
    {
      id: "proxy",
      title: "Соединение через прокси",
      description: "Контрольный запрос через настроенный прокси.",
      hint: "Выберите работающий сервер и проверьте параметры подключения.",
      page: "groups",
    },
    {
      id: "dns",
      title: "Разрешение доменов",
      description: "Ответ настроенного DNS-шлюза для выбранного домена.",
      hint: "Проверьте DNS и список допущенных доменов.",
      page: "dns",
    },
    {
      id: "routing",
      title: "Применённые маршруты",
      description: "Соответствие маршрутов утверждённому сетевому профилю.",
      hint: "Проверьте профиль RouterOS и права контейнера.",
      page: "rules",
    },
    {
      id: "watchdog",
      title: "Защита при сбое",
      description: "Соответствие защитных правил и наблюдателя профилю.",
      hint: "Проверьте защитные правила RouterOS. Эта проверка не имитирует отказ.",
      page: "setup",
    },
  ];
  let visibleCatalog = $derived(
    catalog.filter((x) =>
      (x.name + " " + x.description)
        .toLowerCase()
        .includes(listSearch.toLowerCase()),
    ),
  );
  let pref = $state({ language: "ru", theme: "system", time_zone: "UTC" }),
    uris = $state("");
  let schedule = $state<any>(),
    scheduleEnabled = $state(false),
    scheduleMinutes = $state(60),
    resourceErrors = $state<Record<string, string>>({});
  let sub = $state({ id: "main", url: "", include: "", exclude: "" }),
    selectedNodes = $state<string[]>([]),
    provider = $state<any>(),
    offset = $state(0);
  let visibleNodes = $derived(
    (provider?.nodes || []).filter((x: any) =>
      (x.Name + " " + x.Server + " " + x.Protocol)
        .toLowerCase()
        .includes(nodeSearch.toLowerCase()),
    ),
  );

  let group = $state({
      id: "",
      type: "selector",
      members: "",
      selected: "",
      interval: "5m",
      tolerance: 50,
    }),
    editingGroup = $state(""),
    groupMembers = $state<string[]>([]),
    ruleSets = $state<string[]>([]);
  let rule = $state({
      id: "",
      name: "",
      domains: "",
      suffixes: "",
      sources: "",
      destinations: "",
      rule_sets: "",
      outbound: "direct",
      network: "",
      priority: 0,
      enabled: true,
    }),
    editingRule = $state("");
  let device = $state({ cidrs: "", outbound: "direct" }),
    dnsDomains = $state(""),
    dnsSuffixes = $state("");
  let proxyEdit = $state({ id: "", name: "", enabled: true, uri: "" }),
    restoreFile = $state<File>(),
    restore = $state<any>(),
    restorePreview = $state<any>(),
    wizard = $state(0),
    checks = $state<Record<string, string>>({}),
    nodeChecks = $state<Record<string, any>>({});
  const titles: Record<string, string> = {
    mode: "Режим",
    endpoints: "Прокси",
    wireguard: "WireGuard",
    groups: "Группы",
    rules: "Правила",
    services: "Сервисы",
    source_direct: "Устройства DIRECT",
    source_proxy: "Политики устройств",
    dns: "DNS",
    rule_sets: "Наборы правил",
    default_outbound: "Маршрут по умолчанию",
    preferences: "Настройки интерфейса",
    subscription_metadata: "Подписки",
  };
  let revision = $derived(config?.draft_revision || 0);
  let outbounds = $derived([
    "direct",
    ...(config?.model.groups || []).map((x) => x.id),
    ...(config?.model.endpoints || [])
      .filter((x) => x.Enabled !== false)
      .map((x) => x.ID),
    ...(config?.model.wireguard || [])
      .filter((x) => x.enabled !== false)
      .map((x) => x.id),
  ]);
  let draftChanged = $derived(
    !!config?.draft_revision && config?.base_revision === current?.revision,
  );
  function bytes(value: number) {
    return Number.isFinite(value)
      ? (value / 1024 / 1024).toFixed(0) + " MiB"
      : "нет данных";
  }
  let ruleConflicts = $derived(analyseRuleConflicts(config?.policy.rules));
  let ready = $derived(system?.status?.ready === true);
  function date(value: string) {
    try {
      return new Date(value).toLocaleString("ru-RU", {
        timeZone: pref.time_zone,
      });
    } catch {
      return new Date(value).toLocaleString("ru-RU");
    }
  }
  function navigate(value: string) {
    page = pages.some((p) => p[0] === value) ? value : "dashboard";
    location.hash = page;
    error = "";
  }
  async function run(work: () => Promise<void>) {
    if (busy) return;
    busy = true;
    error = "";
    notice = "";
    try {
      await work();
    } catch (e) {
      error = errorMessage(e);
      if (e instanceof APIError && e.status === 401) {
        logged = false;
        password = "";
        clearToken();
        config = undefined;
        current = undefined;
        plan = undefined;
        uris = "";
        sub.url = "";
        proxyEdit.uri = "";
        restore = undefined;
        restoreFile = undefined;
      }
    } finally {
      busy = false;
    }
  }
  async function optional(path: string) {
    try {
      const value = await api(path);
      resourceErrors[path] = "";
      return value;
    } catch (e) {
      if (
        e instanceof APIError &&
        (e.status === 501 || e.status === 404 || e.status === 503)
      ) {
        resourceErrors[path] = errorMessage(e);
        return undefined;
      }
      throw e;
    }
  }
  async function load() {
    current = await api<Config>("config");
    config = (await optional("config/draft")) || copy(current);
    if (config) {
      config.model.groups ||= [];
      config.model.endpoints ||= [];
      config.policy.rules ||= [];
      config.policy.dns.selected_domains ||= [];
    }
    system = await api("system");
    catalog = (await optional("traffic-lists/catalog")) || [];
    listSnapshots = (await optional("traffic-lists")) || [];
    if (!outbounds.includes(listOutbound))
      listOutbound = config?.model.groups[0]?.id || "direct";
    info = await optional("system/info");
    router = await optional("routeros");
    network = await optional("routeros/network");
    subscriptions = (await optional("subscriptions")) || [];
    schedule = await optional("subscriptions/schedule");
    scheduleEnabled = !!schedule?.interval_seconds;
    scheduleMinutes = schedule?.interval_seconds
      ? schedule.interval_seconds / 60
      : 60;
    logs = await api("logs");
    pref = await api("preferences");
    document.documentElement.dataset.theme = pref.theme;
    syncDNS();
  }
  function syncDNS() {
    dnsDomains = (config?.policy.dns.selected_domains || []).join("\n");
    dnsSuffixes = (config?.policy.dns.selected_suffixes || []).join("\n");
  }
  async function login() {
    const secret = password;
    password = "";
    await run(async () => {
      const result = await api("auth/login", { password: secret });
      setToken(result.access_token);
      await load();
      logged = true;
    });
  }
  async function logout() {
    await run(async () => {
      await api("auth/logout", {});
      clearToken();
      logged = false;
      config = undefined;
      current = undefined;
      plan = undefined;
      restore = undefined;
      restorePreview = undefined;
      restoreFile = undefined;
      provider = undefined;
      uris = "";
      proxyEdit.uri = "";
      sub.url = "";
      notice = "";
    });
  }
  async function savePolicy(change: (candidate: Config) => void) {
    if (!config) return;
    const candidate = copy(config);
    change(candidate);
    await api("config/draft/policy", {
      draft_revision: revision,
      mode: candidate.model.mode,
      groups: candidate.model.groups,
      policy: candidate.policy,
    });
    plan = undefined;
    await load();
    notice = "Черновик сохранён. Проверьте план перед применением.";
  }
  async function prepare() {
    await api("config/validate", { draft_revision: revision });
    plan = await api("config/plan", { draft_revision: revision });
    notice = "Проверка пройдена. План готов к просмотру.";
  }
  async function apply() {
    const value = plan;
    plan = undefined;
    await api("config/apply", { plan_id: value.plan_id });
    await load();
    notice = ready
      ? "Конфигурация применена; готовность подтверждена."
      : "Операция завершена. Проверьте состояние обработки трафика.";
    wizard = 5;
  }
  function labelFor(id: string) {
    const endpoint = config?.model.endpoints.find((x) => x.ID === id);
    const wg = config?.model.wireguard.find((x) => x.id === id);
    if (wg) return wg.name || wg.id;
    return id === "direct"
      ? "DIRECT"
      : endpoint
        ? endpoint.Name || endpoint.Server
        : id;
  }
  function editGroup(g: Group) {
    groupMembers = [...g.members];
    editingGroup = g.id;
    group = {
      id: g.id,
      type: g.type,
      members: g.members.join("\n"),
      selected: g.selected || "",
      interval: g.interval || "5m",
      tolerance: g.tolerance || 50,
    };
  }
  async function switchNode(id: string, selected: string) {
    await savePolicy((c) => {
      const g = c.model.groups.find((x) => x.id === id);
      if (g) g.selected = selected;
    });
    notice =
      "Сервер выбран в черновике. Проверьте и примените изменения в верхней панели.";
  }
  async function importLists(
    ids = selectedLists,
    custom = false,
    outbound = listOutbound,
  ) {
    const source = custom
      ? {
          id: "custom-" + Date.now(),
          name: customList.name,
          url: customList.url,
        }
      : undefined;
    const result = await api("traffic-lists/import", {
      draft_revision: revision,
      ids: custom ? [] : ids,
      outbound,
      ...(source ? { custom: source } : {}),
    });
    selectedLists = [];
    customList = { name: "", url: "" };
    plan = undefined;
    await load();
    notice = `Добавлено списков: ${result.imported}. Маршрут — ${labelFor(outbound)}. Проверьте и примените черновик.`;
  }
  async function saveGroup() {
    if (!groupMembers.length) throw new APIError("empty_group", 400);
    const g: Group = {
      id: group.id,
      type: group.type,
      members: [...groupMembers],
    };
    if (g.type === "selector")
      g.selected = groupMembers.includes(group.selected)
        ? group.selected
        : groupMembers[0];
    if (g.type !== "selector") {
      g.interval = group.interval;
      g.tolerance = Number(group.tolerance);
    }
    await savePolicy((c) => {
      c.model.groups = c.model.groups.filter((x) => x.id !== editingGroup);
      c.model.groups.push(g);
    });
    editingGroup = "";
    groupMembers = [];
    group = {
      id: "",
      type: "selector",
      members: "",
      selected: "",
      interval: "5m",
      tolerance: 50,
    };
  }
  function editRule(r: Rule) {
    ruleSets = [...(r.rule_sets || [])];
    editingRule = r.id;
    rule = {
      id: r.id,
      name: r.name || "",
      domains: (r.domains || []).join("\n"),
      suffixes: (r.suffixes || []).join("\n"),
      sources: (r.source_cidrs || []).join("\n"),
      destinations: (r.destination_cidrs || []).join("\n"),
      rule_sets: (r.rule_sets || []).join("\n"),
      outbound: r.outbound,
      network: r.network || "",
      priority: r.priority || 0,
      enabled: r.enabled !== false,
    };
  }
  async function saveRule() {
    const old = config?.policy.rules?.find((x) => x.id === editingRule);
    const value: Rule = {
      ...old,
      id: rule.id,
      name: rule.name,
      enabled: rule.enabled,
      priority: Number(rule.priority),
      domains: split(rule.domains),
      suffixes: split(rule.suffixes),
      source_cidrs: split(rule.sources),
      destination_cidrs: split(rule.destinations),
      rule_sets: [...ruleSets],
      outbound: rule.outbound,
    };
    if (rule.network) value.network = rule.network;
    else delete value.network;
    await savePolicy((c) => {
      c.policy.rules = (c.policy.rules || []).filter(
        (x) => x.id !== editingRule,
      );
      c.policy.rules.push(value);
      c.policy.dns.selected_domains = selectedDNSForRule(
        c.policy.dns.selected_domains,
        value,
      );
    });
    if (
      value.enabled !== false &&
      value.outbound !== "direct" &&
      (value.domains || []).length
    )
      notice =
        "Правило и его явные домены DNS сохранены в одном черновике. Просмотрите изменения перед применением.";
    if (
      value.enabled !== false &&
      value.outbound !== "direct" &&
      (value.suffixes || []).length
    )
      notice +=
        " Суффиксы поддерживаются правилами маршрутизации, но автоматическая FakeIP-публикация для них недоступна: задайте конечный список явных доменов.";
    editingRule = "";
    ruleSets = [];
    rule = {
      id: "",
      name: "",
      domains: "",
      suffixes: "",
      sources: "",
      destinations: "",
      rule_sets: "",
      outbound: "direct",
      network: "",
      priority: 0,
      enabled: true,
    };
  }
  async function importURIs() {
    const values = importURIList(uris);
    uris = "";
    await api("proxies/import", { draft_revision: revision, uris: values });
    plan = undefined;
    await load();
    notice = "Прокси добавлены в черновик.";
  }
  function activeNode(id: string) {
    return (
      !!current?.model.endpoints.some(
        (x) => x.ID === id && x.Enabled !== false,
      ) ||
      !!current?.model.wireguard.some((x) => x.id === id && x.enabled !== false)
    );
  }
  async function probeNode(id: string) {
    nodeChecks[id] = { pending: true };
    try {
      nodeChecks[id] = await api("proxies/probe", { id });
    } catch (e) {
      nodeChecks[id] = { error: errorMessage(e) };
      throw e;
    }
  }
  async function saveProxy() {
    const values = {
      draft_revision: revision,
      id: proxyEdit.id,
      name: proxyEdit.name,
      enabled: proxyEdit.enabled,
      ...(proxyEdit.uri ? { uri: proxyEdit.uri } : {}),
    };
    proxyEdit.uri = "";
    await api("proxies/update", values);
    proxyEdit.id = "";
    plan = undefined;
    await load();
    notice = "Прокси изменён в черновике.";
  }
  async function removeProxy(id: string) {
    await api("proxies/delete", { draft_revision: revision, id });
    plan = undefined;
    await load();
    notice = "Прокси удалён из черновика.";
  }
  async function inspect(id: string, start = 0) {
    nodeSearch = "";
    provider = await api("subscriptions/inspect", {
      id,
      offset: start,
      limit: 128,
    });
    offset = start;
    selectedNodes = [];
  }
  async function diagnose(kind: string) {
    checks[kind] = "Проверка…";
    diagnosticDetails[kind] = { state: "running" };
    try {
      if (kind === "routeros") {
        router = await api("routeros");
        network = await api("routeros/network");
        checks[kind] = system?.runtime_simulated
          ? "Данные RouterOS симулируются на этом стенде"
          : "MikroTik отвечает; данные получены";
        diagnosticDetails[kind] = {
          state: system?.runtime_simulated ? "unavailable" : "passed",
        };
      } else if (kind === "subscription") {
        if (!subscriptions.length)
          throw new APIError("subscription_absent", 400);
        let total = 0,
          failed = 0;
        for (const source of subscriptions) {
          const result = await api("subscriptions/refresh", { id: source.id });
          total += result.node_count || 0;
          if (result.failed) failed++;
        }
        await load();
        checks[kind] = failed
          ? `Не обновлено подписок: ${failed}. Последние удачные данные сохранены.`
          : `Подписки обновлены. Найдено серверов: ${total}.`;
        diagnosticDetails[kind] = { state: failed ? "failed" : "passed" };
      } else {
        const result = await api("diagnostics/run", { kind });
        diagnosticDetails[kind] = {
          state: result.success ? "passed" : "failed",
          ...result,
        };
        checks[kind] =
          (result.success ? "Проверка пройдена" : "Проверка не пройдена") +
          " · " +
          result.latency_ms +
          " мс";
      }
    } catch (e) {
      checks[kind] = errorMessage(e);
      diagnosticDetails[kind] = {
        state:
          e instanceof APIError && e.code === "adapter_not_connected"
            ? "unavailable"
            : "failed",
      };
      if (!(e instanceof APIError && e.code === "adapter_not_connected"))
        throw e;
    }
  }
  async function readRestore() {
    if (!restoreFile) return;
    if (restoreFile.size > 4 * 1024 * 1024) throw new Error();
    try {
      restore = JSON.parse(await restoreFile.text());
    } catch {
      throw new APIError("invalid_backup", 400);
    }
    restorePreview = await api("backup/restore-preview", restore);
  }
  onMount(() => {
    page = pages.some((p) => p[0] === location.hash.slice(1))
      ? location.hash.slice(1)
      : "dashboard";
    const change = () => {
      page = pages.some((p) => p[0] === location.hash.slice(1))
        ? location.hash.slice(1)
        : "dashboard";
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  });
</script>

<svelte:head
  ><title
    >{logged
      ? pages.find((x) => x[0] === page)?.[1] + " · "
      : ""}MikroCentauri</title
  ></svelte:head
>
{#if !logged}
  <main class="login">
    <section class="login-card">
      <div class="brand-mark">✦</div>
      <p class="eyebrow">MIKROCENTAURI</p>
      <h1>Ваш маршрут.<br />Ваши правила.</h1>
      <p class="muted">Управление выборочной маршрутизацией RouterOS.</p>
      <form
        onsubmit={(e) => {
          e.preventDefault();
          login();
        }}
      >
        <label
          >Пароль администратора<input
            type="password"
            bind:value={password}
            required
            minlength="16"
            maxlength="1024"
            autocomplete="current-password"
          /></label
        ><button class="primary" disabled={busy}
          >{busy ? "Вход…" : "Войти"}</button
        >
      </form>
      <p class="muted small">Защищённое соединение · Сессия на 30 минут</p>
      {#if error}<p role="alert" class="error">{error}</p>{/if}
    </section>
    <aside class="login-art" aria-hidden="true">
      <div class="orbit"><span>✦</span></div>
      <p>SELECTIVE ROUTING<br />ROUTEROS NATIVE</p>
    </aside>
  </main>
{:else}
  <div class="shell">
    <aside class="sidebar">
      <a href="#dashboard" class="brand"><span>✦</span> MikroCentauri</a>
      <p class="eyebrow">УПРАВЛЕНИЕ СЕТЬЮ</p>
      <nav aria-label="Основная навигация">
        {#each pages as p}<a
            href={"#" + p[0]}
            class:active={page === p[0]}
            aria-current={page === p[0] ? "page" : undefined}
            ><span aria-hidden="true">{p[2]}</span>{p[1]}</a
          >{/each}
      </nav>
      <div class="side-bottom">
        <span class:good={ready && !system?.runtime_simulated} class="dot"
        ></span>{system?.runtime_simulated
          ? "Режим стенда"
          : ready
            ? "Обработка активна"
            : "Требует внимания"}<button
          class="text"
          onclick={logout}
          disabled={busy}>Выйти</button
        >
      </div>
    </aside>
    <main class="content">
      <header>
        <div>
          <p class="eyebrow">
            MIKROCENTAURI / {config?.model.instance || "LOCAL"}
          </p>
          <h1>{pages.find((x) => x[0] === page)?.[1] || "Обзор"}</h1>
        </div>
        <button onclick={() => run(load)} disabled={busy}>↻ Обновить</button>
      </header>
      {#if system?.runtime_simulated}<div class="preview-banner" role="note">
          <strong>Тестовый стенд</strong>
          <span
            >RouterOS и применение маршрутов симулируются. {system.subscriptions_simulated
              ? "Подписки возвращают тестовые данные."
              : "Подписки скачиваются настоящим загрузчиком."}</span
          >
        </div>{/if}
      {#if error}<div class="error" role="alert">
          {error}
        </div>{/if}{#if notice}<div class="success" role="status">
          {notice}
        </div>{/if}
      {#if !config}<section class="card">
          <p>
            Не удалось загрузить конфигурацию. Обновите данные или войдите
            снова.
          </p>
        </section>{/if}
      {#if config}
        <section class="draftbar" aria-label="Управление черновиком">
          <div>
            <strong
              >{draftChanged
                ? "Есть неприменённые изменения"
                : "Рабочая конфигурация"}</strong
            >
            <p>
              {draftChanged
                ? "Изменения ещё не влияют на трафик. Проверьте план, затем примените его."
                : "Изменений для применения нет."}
              <span class="revision-note">Ревизия {current?.revision || 0}</span
              >
            </p>
          </div>
          <button onclick={() => run(prepare)} disabled={busy || !draftChanged}
            >Проверить и показать план</button
          >
        </section>
        {#if plan}<section class="card plan" aria-label="План изменений">
            <h2>План изменений</h2>
            <p>
              Ревизия {plan.base_revision} → {plan.base_revision + 1}. План
              действует до {date(plan.expires_at)}.
            </p>
            <div class="chips">
              {#each plan.changed_sections as name}<span
                  >{titles[name] || name}</span
                >{/each}
            </div>
            <p>
              {plan.model.endpoints.length} прокси · {plan.model.groups.length} групп
              · {plan.model.rule_count} правил
            </p>
            <details>
              <summary>Посмотреть конфигурацию кандидата</summary
              >{#each plan.policy.rules || [] as r}<p>
                  {r.name || r.id}: {[
                    ...(r.domains || []),
                    ...(r.suffixes || []),
                    ...(r.destination_cidrs || []),
                  ].join(", ")} → {r.outbound}
                </p>{/each}
              <h3>Прокси</h3>
              {#each plan.model.endpoints as ep}<p>
                  {ep.Name || ep.Server}: {ep.Protocol} · {ep.Server}:{ep.Port} ·
                  {ep.Enabled === false ? "отключён" : "включён"}
                </p>{/each}
              <h3>Группы</h3>
              {#each plan.model.groups as g}<p>
                  {g.id} ({g.type}): {g.members
                    .map((id: string) => labelFor(id))
                    .join(", ")}; выбран {labelFor(
                    g.selected || g.members[0] || "",
                  )}
                </p>{/each}
              <h3>Устройства</h3>
              <p>
                DIRECT: {(plan.policy.source_direct || []).join(", ") ||
                  "нет явных политик"}
              </p>
              {#each plan.policy.source_proxy || [] as policy}<p>
                  {policy.cidrs.join(", ")} → {labelFor(policy.outbound)}
                </p>{/each}
              <p>
                Маршрут по умолчанию: {labelFor(plan.policy.default_outbound)}
              </p>
              <h3>DNS</h3>
              <p>
                Домены: {(plan.policy.dns.selected_domains || []).join(", ") ||
                  "нет"}. Суффиксы: {(
                  plan.policy.dns.selected_suffixes || []
                ).join(", ") || "нет"}.
              </p>
              <p>
                DNS: {plan.policy.dns.bootstrap}; FakeIP: {plan.policy.dns
                  .fakeip_range}
              </p>
            </details>
            <p class="muted">
              Применение временно приостанавливает приём трафика и включает его
              после проверки готовности. Топология RouterOS сохраняется.
            </p>
            <button
              class="primary"
              disabled={busy ||
                !plan.apply_available ||
                Date.parse(plan.expires_at) < Date.now()}
              onclick={() => run(apply)}>Применить подтверждённый план</button
            >{#if !plan.apply_available}<p>
                Обработчик трафика не подключён; применение недоступно.
              </p>{/if}<button onclick={() => (plan = undefined)}
              >Закрыть план</button
            >
          </section>{/if}
        {#if page === "dashboard"}
          <div class="hero">
            <div>
              <p class="eyebrow">СОСТОЯНИЕ ПРИЛОЖЕНИЯ</p>
              <h2>
                {system?.runtime_simulated
                  ? "Настройте свой маршрут"
                  : ready
                    ? "Маршруты под контролем"
                    : "Начните с настройки подключения"}
              </h2>
              <p>
                {system?.runtime_simulated
                  ? "Добавьте серверы, выберите списки сайтов и назначьте им селектор."
                  : ready
                    ? "DNS, процесс и текущий маршрут подтвердили готовность."
                    : "Панель доступна. Сетевой runtime пока не подтвердил готовность."}
              </p>
            </div>
            <span class="hero-star" aria-hidden="true">✦</span>
          </div>
          <div class="workflow-steps" aria-label="Настройка маршрутизации">
            {#each [["subscriptions", "1", "Добавить серверы", "Загрузите подписку или вставьте ссылки."], ["lists", "2", "Выбрать сайты", "Готовые списки и собственный URL."], ["groups", "3", "Выбрать маршрут", "Ручной селектор или автоматический выбор."]] as step}
              <a href={"#" + step[0]}
                ><span class="step-number">{step[1]}</span><strong
                  >{step[2]}</strong
                >
                <p>{step[3]}</p></a
              >
            {/each}
          </div>
          <section class="card selector-section">
            <div class="section-heading">
              <div>
                <h2>Селекторы серверов</h2>
                <p class="muted">
                  Выберите сервер для каждой группы. Списки сайтов используют
                  выбранную группу.
                </p>
              </div>
              <a class="button-link" href="#groups">Управлять селекторами</a>
            </div>
            {#if !config.model.groups.length}<p>
                Сначала добавьте серверы и создайте селектор.
              </p>{/if}
            {#each config.model.groups as g}<div class="selector-row">
                <div>
                  <strong>{g.id}</strong>
                  <p class="muted">
                    {g.members.length} серверов · {g.type === "selector"
                      ? "Ручной выбор"
                      : g.type === "urltest"
                        ? "Автоматический выбор"
                        : "Резервирование"}
                  </p>
                </div>
                {#if g.type === "selector"}<label
                    >Сервер для {g.id}<select
                      aria-label={"Сервер для " + g.id}
                      value={g.selected || g.members[0]}
                      disabled={busy}
                      onchange={(e) =>
                        run(() => switchNode(g.id, e.currentTarget.value))}
                      >{#each g.members as id}<option value={id}
                          >{labelFor(id)}</option
                        >{/each}</select
                    ></label
                  >{:else}<span>Выбор выполняет движок</span>{/if}
              </div>{/each}
          </section>
          <div class="grid stats">
            <section class="card">
              <p class="muted">sing-box / runtime</p>
              <h2>
                {system?.runtime_simulated
                  ? "Симуляция"
                  : ready
                    ? "Готов"
                    : system?.runtime_connected
                      ? "Не готов"
                      : "Не подключён"}
              </h2>
              <p>Ревизия {system?.status?.revision || 0}</p>
            </section>
            <section class="card">
              <p class="muted">RouterOS</p>
              <h2>
                {system?.runtime_simulated
                  ? "Симуляция"
                  : router
                    ? "Подключён"
                    : "Нет данных"}
              </h2>
              <p>
                {router?.capabilities?.version ||
                  resourceErrors["routeros"] ||
                  "REST API недоступен"}
              </p>
            </section>
            <section class="card">
              <p class="muted">Подписки</p>
              <h2>{subscriptions.length}</h2>
              <p>
                {subscriptions.filter((x) => x.failed).length} с ошибками обновления
              </p>
            </section>
            <section class="card">
              <p class="muted">DNS / fail-open</p>
              <h2>{config.model.mode}</h2>
              <p>
                {system?.status?.pending
                  ? "Идёт восстановление"
                  : ready
                    ? "Приём трафика разрешён"
                    : "Готовность снята; состояние DIRECT проверяйте в диагностике"}
              </p>
            </section>
          </div>
          <section class="card">
            <h2>Маршрутизация</h2>
            <div class="route-visual">
              <span>Устройства</span><b>→</b><span>Правила + DNS</span><b>→</b
              ><span
                >{config.policy.default_outbound === "direct"
                  ? "DIRECT"
                  : config.policy.default_outbound}</span
              >
            </div>
            <p>
              {config.model.endpoints.length} прокси · {config.model.groups
                .length} групп · {config.policy.rules?.length || 0} правил
            </p>
          </section>
          <section class="card">
            <h2>Последние события</h2>
            {#if !logs.length}<p class="muted">
                Событий пока нет.
              </p>{/if}{#each logs.slice(-6).reverse() as item}<div
                class="event"
              >
                <time>{date(item.timestamp)}</time><span>{item.component}</span
                ><strong>{item.event}</strong>
              </div>{/each}
          </section>
        {:else if page === "setup"}
          <section class="card">
            <h2>Мастер проверки окружения</h2>
            <p>
              Мастер работает с заранее подготовленным профилем RouterOS.
              Установка контейнера и изменение сетевой топологии относятся к
              этапу установки.
            </p>
            <ol class="steps">
              {#each ["Окружение", "Доступ к RouterOS", "Сеть", "Конфликты", "План и применение", "Готовность"] as name, i}<li
                  class:current={wizard === i}
                >
                  {i + 1}. {name}
                </li>{/each}
            </ol>
            {#if wizard === 0}<h3>Окружение приложения</h3>
              <p>
                API: {system?.api_version}; runtime: {system?.runtime_connected
                  ? "подключён"
                  : "не подключён"}.
              </p>
              <p>
                RouterOS: {router?.capabilities?.version || "не определён"} · {router
                  ?.capabilities?.architecture || "архитектура неизвестна"}
              </p>
              <p>
                RAM: {bytes(network?.memory_free)} свободно / {bytes(
                  network?.memory_total,
                )} всего. Storage: {bytes(network?.disk_free)} свободно / {bytes(
                  network?.disk_total,
                )} всего.
              </p>
            {:else if wizard === 1}<h3>Проверка доступа</h3>
              <p>
                {router
                  ? "Авторизованный REST API отвечает."
                  : "Доступ к RouterOS не настроен. Завершите настройку подключения при установке приложения."}
              </p>
              <button
                onclick={() =>
                  run(async () => {
                    await diagnose("routeros");
                  })}
                disabled={busy}>Проверить RouterOS API</button
              >
            {:else if wizard === 2}<h3>Обнаруженная сеть</h3>
              <p>
                LAN: {(network?.addresses || [])
                  .map((x: any) => x.address + " (" + x.interface + ")")
                  .join(", ") || "нет данных"}. WAN gateway: {(
                  network?.default_routes || []
                )
                  .map((x: any) => x.gateway)
                  .join(", ") || "нет данных"}. FastTrack: {network?.fasttrack_enabled ??
                  "не определён"} подтверждённых включённых правил; статус {network?.fasttrack_unknown ??
                  "не определён"} правил не определён.
              </p>
              <p>
                {network
                  ? "Данные сети получены."
                  : "Источник данных сети не подключён."}
              </p>
              <p>
                Пул FakeIP: {config.policy.dns.fakeip_range}; upstream: {config
                  .policy.dns.bootstrap}
              </p>
              <IPv6Notice {network} />
            {:else if wizard === 3}<h3>Проверка конфликтов</h3>
              {#if !network}<p class="error">
                  Данные сети не получены: проверка пересечений недоступна.
                </p>{:else if network.addresses.some((x: any) => !x.disabled && overlap(x.address, config!.policy.dns.fakeip_range))}<p
                  class="error"
                >
                  Пул FakeIP пересекается с адресом интерфейса RouterOS.
                  Устраните конфликт в операторском профиле.
                </p>{:else}<p class="success">
                  По полученным IPv4-адресам интерфейсов пересечения с пулом
                  FakeIP не найдены.
                </p>{/if}
              <p class="muted">
                Это предварительная проверка адресов; доступность VETH, портов,
                управляемых объектов и публикации проверяет runtime перед
                активацией.
              </p>
              <p>
                Сервер проверяет модель, sing-box и профиль runtime. Сеть, VETH
                и порты задаёт операторский профиль.
              </p>
              <button
                disabled={busy || !revision}
                onclick={() =>
                  run(async () => {
                    await api("config/validate", { draft_revision: revision });
                    notice = "Черновик прошёл проверку.";
                  })}>Проверить конфигурацию</button
              >
              <p class="muted">
                Если черновика ещё нет, сохраните правило, группу или DNS.
              </p>
            {:else if wizard === 4}<h3>Просмотр изменений</h3>
              <p>
                Перед активацией получите одноразовый план. Мастер не создаёт
                VETH, таблицы маршрутов или правила firewall.
              </p>
              <button
                disabled={busy || !draftChanged}
                onclick={() => run(prepare)}>Проверить и показать план</button
              >
            {:else}<h3>
                {ready
                  ? "Готовность подтверждена"
                  : "Готовность не подтверждена"}
              </h3>
              <p>
                {ready
                  ? "Профиль работает. Основные сценарии доступны в панели."
                  : "Завершите применение плана и устраните ошибки runtime."}
              </p>{/if}
            <div class="actions">
              <button disabled={wizard === 0} onclick={() => wizard--}
                >Назад</button
              ><button disabled={wizard === 5} onclick={() => wizard++}
                >Далее</button
              >
            </div>
          </section>
        {:else if page === "proxies"}
          <section class="card">
            <h2>Импорт по ссылке</h2>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(importURIs);
              }}
            >
              <label
                >URI прокси, по одному на строку<textarea
                  bind:value={uris}
                  required
                  placeholder="vless://… · trojan://… · ss://… · hysteria2://…"
                  autocomplete="off"></textarea></label
              >
              <p class="muted">
                Ссылки передаются серверу и очищаются из формы. Импорт создаёт
                черновик.
              </p>
              <button class="primary" disabled={busy}
                >Импортировать прокси</button
              >
            </form>
          </section>
          <section class="card">
            <h2>Узлы черновика</h2>
            {#each [...config.model.endpoints, ...config.model.wireguard.map( (x) => ({ ID: x.id, Name: x.name, Protocol: x.protocol, Enabled: x.enabled, Server: (x.address || []).join(", "), Port: x.listen_port }) )] as ep}<div
                class="row"
              >
                <div>
                  <strong>{ep.Name || ep.ID.slice(0, 12)}</strong>
                  <p>{ep.Protocol || "wireguard"} · {ep.Server}:{ep.Port}</p>
                  <span class="muted small"
                    >{ep.Enabled === false ? "Отключён" : "Включён"}</span
                  >
                  {#if nodeChecks[ep.ID]}<p class="small" role="status">
                      {nodeChecks[ep.ID].pending
                        ? "Проверяем узел…"
                        : nodeChecks[ep.ID].error ||
                          (nodeChecks[ep.ID].success
                            ? "Доступен"
                            : "Проверка не пройдена") +
                            " · " +
                            nodeChecks[ep.ID].latency_ms +
                            " мс · " +
                            nodeChecks[ep.ID].code}
                    </p>
                    {#if nodeChecks[ep.ID].checked_at}<p class="muted small">
                        {date(nodeChecks[ep.ID].checked_at)} · Разовая задержка HTTP,
                        без времени запуска проверки. {nodeChecks[ep.ID].scope}
                      </p>{/if}{:else}<p class="small muted">
                      Индивидуальная задержка не измерена
                    </p>{/if}
                </div>
                <div class="actions">
                  <button
                    disabled={busy ||
                      !system?.runtime_connected ||
                      !activeNode(ep.ID)}
                    onclick={() => run(() => probeNode(ep.ID))}
                    >Проверить узел</button
                  >
                  <button
                    onclick={() =>
                      (proxyEdit = {
                        id: ep.ID,
                        name: ep.Name || "",
                        enabled: ep.Enabled !== false,
                        uri: "",
                      })}>Изменить</button
                  ><button
                    class="danger"
                    disabled={busy}
                    onclick={() => run(() => removeProxy(ep.ID))}
                    >Удалить</button
                  >
                </div>
              </div>{/each}
            <p class="muted small">
              Проверка доступна для включённых узлов активной конфигурации. Она
              измеряет отдельный путь до заданной оператором цели; общая
              готовность приложения от неё не меняется. Новый узел черновика
              сначала нужно применить. Используемый группой или правилом узел
              перед удалением нужно убрать из этих ссылок.
            </p>
          </section>
          {#if proxyEdit.id}<section class="card">
              <h2>Изменить прокси</h2>
              <form
                onsubmit={(e) => {
                  e.preventDefault();
                  run(saveProxy);
                }}
              >
                <label
                  >Название<input
                    bind:value={proxyEdit.name}
                    maxlength="128"
                  /></label
                ><label class="check"
                  ><input
                    type="checkbox"
                    bind:checked={proxyEdit.enabled}
                  />Включён</label
                ><label
                  >Новая URI для замены подключения (необязательно)<input
                    type="password"
                    bind:value={proxyEdit.uri}
                    autocomplete="new-password"
                  /></label
                ><button disabled={busy}>Сохранить прокси в черновик</button
                ><button
                  type="button"
                  onclick={() =>
                    (proxyEdit = { id: "", name: "", enabled: true, uri: "" })}
                  >Отмена</button
                >
              </form>
            </section>{/if}
        {:else if page === "subscriptions"}
          <section class="card">
            <h2>Загрузить серверы из подписки</h2>
            <p class="muted">
              Подписка — источник серверов. Списки сайтов выбираются отдельно на
              странице «Списки сайтов». Поддерживается текст или Base64 со
              ссылками SS, Trojan, VLESS, VMess, Hysteria2 и TUIC. YAML Clash и
              JSON-конфигурации движков не являются списками ссылок.
            </p>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(async () => {
                  const value = copy(sub);
                  await api("subscriptions", value);
                  sub.url = "";
                  let result;
                  let refreshError;
                  try {
                    result = await api("subscriptions/refresh", {
                      id: value.id,
                    });
                  } catch (e) {
                    refreshError = e;
                  }
                  await load();
                  await inspect(value.id);
                  if (refreshError) throw refreshError;
                  notice = result.failed
                    ? "Подписка сохранена, но загрузка не удалась. Проверьте формат ответа и фильтры."
                    : `Подписка загружена. Найдено серверов: ${result.node_count}. Выберите нужные или импортируйте все.`;
                });
              }}
            >
              <div class="grid">
                <label
                  >ID подписки<input
                    bind:value={sub.id}
                    required
                    pattern={"[a-z][a-z0-9-]{0,63}"}
                    placeholder="provider-one"
                  /></label
                ><label
                  >HTTPS URL<input
                    type="password"
                    bind:value={sub.url}
                    required
                    autocomplete="new-password"
                  /></label
                ><label
                  >Включить: регулярное выражение<input
                    bind:value={sub.include}
                  /></label
                ><label
                  >Исключить: регулярное выражение<input
                    bind:value={sub.exclude}
                  /></label
                >
              </div>
              <button disabled={busy}>Сохранить подписку</button>
            </form>
            <p class="muted">
              Автообновление обходит все источники последовательно. Обновление
              не импортирует и не применяет узлы.
            </p>
          </section>
          <section class="card">
            <h2>Автообновление подписок</h2>
            {#if schedule}<form
                onsubmit={(e) => {
                  e.preventDefault();
                  run(async () => {
                    schedule = await api("subscriptions/schedule", {
                      interval_seconds: scheduleEnabled
                        ? Math.round(scheduleMinutes * 60)
                        : 0,
                    });
                    notice =
                      "Расписание сохранено. Первый запуск произойдёт после интервала.";
                  });
                }}
              >
                <label class="check"
                  ><input
                    type="checkbox"
                    bind:checked={scheduleEnabled}
                  />Включить автообновление</label
                ><label
                  >Интервал, минуты<input
                    type="number"
                    min="1"
                    max="1440"
                    step="1"
                    bind:value={scheduleMinutes}
                    disabled={!scheduleEnabled}
                  /></label
                ><button disabled={busy}>Сохранить расписание</button>
              </form>
              <p class="muted">
                {schedule.interval_seconds === 0
                  ? "Автообновление выключено"
                  : schedule.running
                    ? "Автообновление работает"
                    : "Автообновление остановлено"}
              </p>{:else}<p>
                {resourceErrors["subscriptions/schedule"] ||
                  "Расписание недоступно."}
              </p>{/if}
          </section>
          <section class="card">
            <h2>Источники</h2>
            {#if !subscriptions.length}<p>
                Подписок пока нет или источник не подключён.
              </p>{/if}{#each subscriptions as s}<div class="row">
                <div>
                  <strong>{s.id}</strong>
                  <p>
                    {s.node_count} узлов · {s.failed
                      ? "Обновление не удалось"
                      : "Ошибок обновления нет"}
                  </p>
                  <p class="muted small">
                    Последний успех: {s.last_success &&
                    !s.last_success.startsWith("0001")
                      ? date(s.last_success)
                      : "ещё не обновлялась"}
                  </p>
                </div>
                <div class="actions">
                  <button
                    disabled={busy}
                    onclick={() =>
                      run(async () => {
                        await api("subscriptions/refresh", { id: s.id });
                        await load();
                        notice = "Подписка обновлена.";
                      })}>Обновить подписку</button
                  ><button
                    disabled={busy}
                    onclick={() => run(() => inspect(s.id))}
                    >Выбрать узлы</button
                  ><button
                    class="danger"
                    disabled={busy}
                    onclick={() =>
                      run(async () => {
                        await api("subscriptions/delete", { id: s.id });
                        provider = undefined;
                        await load();
                      })}>Удалить подписку</button
                  >
                </div>
              </div>{/each}
          </section>
          {#if provider}<section class="card">
              <div class="section-heading">
                <div>
                  <h2>Серверы подписки {provider.id}</h2>
                  <p>
                    Доступно: {provider.node_count}{provider.source_count
                      ? " из " + provider.source_count
                      : ""}. Выбрано на этой странице: {selectedNodes.length}.
                  </p>
                </div>
                <button
                  disabled={busy}
                  onclick={() =>
                    (selectedNodes = visibleNodes.map((n: any) => n.ID))}
                  >Выбрать все показанные</button
                >
              </div>
              <label
                >Поиск серверов<input
                  type="search"
                  bind:value={nodeSearch}
                  placeholder="Название, страна, протокол или адрес"
                /></label
              >
              {#if provider.issues?.length}<div class="preview-banner">
                  <div>
                    <strong
                      >Не импортировано записей: {provider.issues
                        .length}</strong
                    >
                    <p>
                      Поддерживаемые серверы показаны ниже. Отключение проверки
                      TLS и несовместимые параметры не заменяются другими
                      настройками.
                    </p>
                    <details>
                      <summary>Причины пропуска</summary
                      >{#each provider.issues as issue}<p>
                          Строка {issue.line} · {issue.protocol}: {(
                            {
                              unsupported_transport:
                                "транспорт не поддерживается движком",
                              unsupported_grpc_authority:
                                "нестандартный gRPC authority не поддерживается",
                              insecure_tls_refused:
                                "запрошено отключение проверки сертификата",
                              invalid_or_unsupported_endpoint:
                                "неподдерживаемые параметры или некорректная ссылка",
                            } as Record<string, string>
                          )[issue.code] || "запись не поддерживается"}
                        </p>{/each}
                    </details>
                  </div>
                </div>{/if}
              {#if provider.failed}<div class="error">
                  Последнее обновление не удалось. Показан последний успешно
                  загруженный список.
                </div>{/if}
              {#if !provider.nodes.length}<p>
                  Серверов нет. Загрузите подписку или проверьте её формат и
                  фильтры.
                </p>{/if}
              {#each visibleNodes as n}<label class="check"
                  ><input
                    type="checkbox"
                    bind:group={selectedNodes}
                    value={n.ID}
                  />{n.Name || n.Server} · {n.Protocol}</label
                >{/each}
              <label
                >Селектор для импортируемых серверов<input
                  bind:value={importSelector}
                  pattern={"[a-z][a-z0-9-]{0,63}"}
                  placeholder="proxy"
                  maxlength="64"
                /></label
              >
              <p class="muted">
                Серверы добавятся в выбранный селектор. Если его ещё нет, он
                будет создан с ручным выбором.
              </p>
              <div class="actions">
                <button
                  disabled={busy || offset === 0}
                  onclick={() =>
                    run(() => inspect(provider.id, Math.max(0, offset - 128)))}
                  >Предыдущие</button
                ><button
                  disabled={busy || !provider.has_more}
                  onclick={() => run(() => inspect(provider.id, offset + 128))}
                  >Следующие</button
                ><button
                  class="primary"
                  disabled={busy || !selectedNodes.length}
                  onclick={() =>
                    run(async () => {
                      await api("subscriptions/import", {
                        id: provider.id,
                        node_ids: selectedNodes,
                        selector_id: importSelector,
                        draft_revision: revision,
                      });
                      plan = undefined;
                      await load();
                      notice = `Серверы добавлены в селектор ${importSelector}. Выберите активный сервер на странице «Селекторы», затем примените черновик.`;
                    })}>Импортировать выбранные</button
                >
              </div>
            </section>{/if}
        {:else if page === "lists"}
          <section class="card">
            <div class="section-heading">
              <div>
                <h2>Что отправлять через прокси</h2>
                <p class="muted">
                  Выберите готовые списки, назначьте маршрут и добавьте их в
                  черновик.
                </p>
              </div>
              <a class="button-link" href="#groups">Настроить селекторы</a>
            </div>
            <div class="grid">
              <label
                >Маршрут для выбранных списков<select bind:value={listOutbound}
                  >{#each outbounds as id}<option value={id}
                      >{labelFor(id)}</option
                    >{/each}</select
                ></label
              ><label
                >Найти список<input
                  type="search"
                  bind:value={listSearch}
                  placeholder="YouTube, Discord, Google AI…"
                /></label
              >
            </div>
            {#if resourceErrors["traffic-lists/catalog"]}<p class="error">
                {resourceErrors["traffic-lists/catalog"]}
              </p>{/if}
            <div class="list-catalog">
              {#each visibleCatalog as item}<label
                  class="list-card"
                  class:selected={selectedLists.includes(item.id)}
                >
                  <input
                    type="checkbox"
                    bind:group={selectedLists}
                    value={item.id}
                    disabled={busy}
                  />
                  <span
                    ><strong>{item.name}</strong><span class="list-description"
                      >{item.description}</span
                    ><span class="list-state"
                      >{config.policy.rules.some(
                        (r) => r.id === "list-" + item.id,
                      )
                        ? "Добавлен в конфигурацию"
                        : "Готовый список"}</span
                    ></span
                  >
                </label>{/each}
            </div>
            <div class="actions">
              <button
                class="primary"
                disabled={busy || !selectedLists.length}
                onclick={() => run(() => importLists())}
                >Добавить выбранные списки ({selectedLists.length})</button
              >
            </div>
            <p class="muted small">
              Источник: <a
                href="https://github.com/itdoginfo/allow-domains"
                target="_blank"
                rel="noreferrer">itdoginfo/allow-domains</a
              >. Скачивается текстовый список доменов; содержимое проверяется и
              сохраняется перед применением.
            </p>
          </section>
          <section class="card">
            <h2>Подключённые списки</h2>
            {#if !listSnapshots.length}<p class="muted">
                Списки пока не загружены. Выберите сервисы выше или добавьте
                свой URL.
              </p>{/if}
            {#each listSnapshots as list}{@const savedRule =
                config.policy.rules.find((r) => r.id === "list-" + list.id)}
              <div class="row">
                <div>
                  <strong>{list.name}</strong>
                  <p>
                    {list.domain_count} доменов · Обновлён {date(
                      list.updated_at,
                    )}
                  </p>
                  <p class="muted">
                    {savedRule
                      ? "Маршрут: " + labelFor(savedRule.outbound)
                      : "Снимок сохранён; правило не включено"}
                  </p>
                  <details>
                    <summary>Примеры доменов и контрольная сумма</summary>
                    <p>{list.sample.join(", ")}</p>
                    <code class="hash">{list.sha256}</code>
                  </details>
                </div>
                <div class="actions">
                  {#if savedRule}<label
                      >Маршрут для {list.name}<select
                        value={savedRule.outbound}
                        disabled={busy}
                        onchange={(e) => {
                          const outbound = e.currentTarget.value;
                          run(() =>
                            savePolicy((c) => {
                              const rule = c.policy.rules.find(
                                (r) => r.id === savedRule.id,
                              );
                              if (rule) rule.outbound = outbound;
                            }),
                          );
                        }}
                        >{#each outbounds as id}<option value={id}
                            >{labelFor(id)}</option
                          >{/each}</select
                      ></label
                    >{/if}
                  <button
                    disabled={busy}
                    onclick={() =>
                      run(() =>
                        importLists(
                          [list.id],
                          false,
                          savedRule?.outbound || listOutbound,
                        ),
                      )}>Обновить список в черновике</button
                  >{#if savedRule}<button
                      disabled={busy}
                      onclick={() =>
                        run(() =>
                          savePolicy((c) => {
                            c.policy.rules = c.policy.rules.filter(
                              (r) => r.id !== "list-" + list.id,
                            );
                          }),
                        )}>Удалить правило списка</button
                    >{/if}
                </div>
              </div>{/each}
          </section>
          <section class="card">
            <h2>Свой список по URL</h2>
            <p class="muted">
              HTTPS-файл: по одному домену на строку, комментарии начинаются с #
              или //. URL хранится приватно.
            </p>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(() => importLists([], true));
              }}
            >
              <div class="grid">
                <label
                  >Название списка<input
                    bind:value={customList.name}
                    required
                    maxlength="128"
                    placeholder="Мои сервисы"
                  /></label
                ><label
                  >URL списка<input
                    type="password"
                    bind:value={customList.url}
                    required
                    autocomplete="new-password"
                    placeholder="https://…/domains.txt"
                  /></label
                >
              </div>
              <button disabled={busy}>Скачать и добавить свой список</button>
            </form>
          </section>
          <section class="card scope-note">
            <h2>Покрытие доменов</h2>
            <p>
              Правила списков учитывают домены и поддомены. В режиме SOCKS они
              применяются к переданным именам. В нативном режиме DNS допускает
              только конечный набор имён: при импорте добавляются сами домены
              списка. Произвольные поддомены автоматически не допускаются; их
              нужно добавить в DNS отдельно. IP-подсети, альтернативный DNS и
              IPv6 не входят в покрытие этого каталога.
            </p>
            <a href="#dns">Проверить DNS-допуск</a>
          </section>
        {:else if page === "groups"}
          <section class="card">
            <h2>Селекторы и автоматический выбор</h2>
            <p class="muted">
              Одна группа может обслуживать несколько списков сайтов. Выбирайте
              сервер здесь, а списки привязывайте к группе.
            </p>
            {#each config.model.groups as g}<div class="row">
                <div>
                  <strong>{g.id}</strong>
                  <p>
                    {g.type === "selector"
                      ? "Ручной выбор"
                      : g.type === "urltest"
                        ? "Автоматический выбор"
                        : "Резервирование"} · {g.members.length} серверов
                  </p>
                </div>
                <div class="actions">
                  {#if g.type === "selector"}<label class="inline-selector"
                      >Сервер для {g.id}<select
                        aria-label={"Сервер для " + g.id}
                        value={g.selected || g.members[0]}
                        disabled={busy}
                        onchange={(e) =>
                          run(() => switchNode(g.id, e.currentTarget.value))}
                        >{#each g.members as id}<option value={id}
                            >{labelFor(id)}</option
                          >{/each}</select
                      ></label
                    >{/if}
                  <button onclick={() => editGroup(g)}>Изменить группу</button
                  ><button
                    class="danger"
                    disabled={busy}
                    onclick={() =>
                      run(() =>
                        savePolicy((c) => {
                          c.model.groups = c.model.groups.filter(
                            (x) => x.id !== g.id,
                          );
                        }),
                      )}>Удалить группу</button
                  >
                </div>
              </div>{/each}
          </section>
          <section class="card">
            <h2>{editingGroup ? "Изменить группу" : "Новая группа"}</h2>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(saveGroup);
              }}
            >
              <div class="grid">
                <label
                  >ID группы<input
                    bind:value={group.id}
                    required
                    pattern={"[a-z][a-z0-9-]{0,63}"}
                  /></label
                ><label
                  >Тип<select bind:value={group.type}
                    ><option value="selector">Ручной выбор</option><option
                      value="urltest">Автоматический (urltest)</option
                    ><option value="fallback">Резервирование (fallback)</option
                    ></select
                  ></label
                >
                <fieldset>
                  <legend>Участники группы</legend
                  >{#each outbounds.filter((x) => x !== group.id) as id}<label
                      class="check"
                      ><input
                        type="checkbox"
                        bind:group={groupMembers}
                        value={id}
                      />{labelFor(id)}</label
                    >{/each}
                </fieldset>
                {#if group.type === "selector"}<label
                    >Выбранный узел<select bind:value={group.selected}
                      ><option value="">Первый участник</option
                      >{#each groupMembers as x}<option value={x}
                          >{labelFor(x)}</option
                        >{/each}</select
                    ></label
                  >{:else}<label
                    >Интервал проверки<input
                      bind:value={group.interval}
                    /></label
                  ><label
                    >Допуск, мс<input
                      type="number"
                      min="0"
                      bind:value={group.tolerance}
                    /></label
                  >{/if}
              </div>
              <button disabled={busy}>Сохранить группу</button>
            </form>
          </section>
        {:else if page === "rules"}
          <section class="card">
            <h2>Политики маршрутизации</h2>
            <section class="conflicts" aria-label="Пересечения правил">
              <h3>Проверка пересечений</h3>
              <p class="muted small">
                Проверено {ruleConflicts.analysed} правил. Это предварительный анализ
                видимых условий; он не заменяет проверку sing-box и фактического маршрута.
              </p>
              {#each ruleConflicts.conflicts as item}<p class="error">
                  {item.reason}: «{item.first.name || item.first.id}» → {labelFor(
                    item.first.outbound,
                  )} исполняется раньше «{item.second.name || item.second.id}» → {labelFor(
                    item.second.outbound,
                  )} (меньший приоритет первым; при равном приоритете — порядок списка).
                </p>{/each}{#if !ruleConflicts.conflicts.length}<p>
                  В проверенной области пересечения разных маршрутов не найдены.
                </p>{/if}{#each ruleConflicts.notes as note}<p class="muted">
                  Анализ неполный: {note}
                </p>{/each}
            </section>
            <p class="muted">
              Явные домены включённого прокси-правила автоматически добавляются
              в выборочный DNS в том же черновике. Удаление правила сохраняет
              ранее выбранные DNS-имена; их вывод из публикации выполняется
              отдельно на странице <a href="#dns">DNS</a>. Суффиксы FakeIP пока
              не поддерживаются: для hybrid задавайте конечный список доменов.
              Пересекающиеся правила исполняются по приоритету.
            </p>
            <label
              >Маршрут по умолчанию<select
                value={config.policy.default_outbound}
                disabled={busy}
                onchange={(e) =>
                  run(() =>
                    savePolicy((c) => {
                      c.policy.default_outbound = e.currentTarget.value;
                    }),
                  )}
                >{#each outbounds as x}<option value={x}>{labelFor(x)}</option
                  >{/each}</select
              ></label
            >{#each config.policy.rules || [] as r}<div class="row">
                <div>
                  <strong>{r.name || r.id}</strong>
                  <p>
                    {[
                      ...(r.domains || []),
                      ...(r.suffixes || []),
                      ...(r.destination_cidrs || []),
                      ...(r.rule_sets || []),
                    ].join(", ") || "Все назначения"} → {r.outbound}
                  </p>
                  <p class="muted small">
                    {r.enabled === false ? "Отключено" : "Включено"} · Источники:
                    {(r.source_cidrs || []).join(", ") || "все устройства"} · Приоритет
                    {r.priority || 0}
                  </p>
                </div>
                <div class="actions">
                  <button onclick={() => editRule(r)}>Изменить правило</button
                  ><button
                    class="danger"
                    disabled={busy}
                    onclick={() =>
                      run(() =>
                        savePolicy((c) => {
                          c.policy.rules = c.policy.rules.filter(
                            (x) => x.id !== r.id,
                          );
                        }),
                      )}>Удалить правило</button
                  >
                </div>
              </div>{/each}
          </section>
          <section class="card">
            <h2>{editingRule ? "Изменить правило" : "Новое правило"}</h2>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(saveRule);
              }}
            >
              <div class="grid">
                <label
                  >ID правила<input
                    bind:value={rule.id}
                    required
                    pattern={"[a-z][a-z0-9-]{0,63}"}
                  /></label
                ><label
                  >Название<input
                    bind:value={rule.name}
                    maxlength="128"
                  /></label
                ><label
                  >Домены<textarea
                    bind:value={rule.domains}
                    placeholder="example.com"></textarea></label
                ><label
                  >Суффиксы доменов<textarea
                    bind:value={rule.suffixes}
                    placeholder="example.org"></textarea></label
                ><label
                  >Источники CIDR (пусто — все устройства)<textarea
                    bind:value={rule.sources}
                    placeholder="192.168.88.10/32"></textarea></label
                ><label
                  >Назначения CIDR<textarea bind:value={rule.destinations}
                  ></textarea></label
                >
                <fieldset>
                  <legend>Удалённые наборы правил</legend
                  >{#each config.policy.rule_sets || [] as item}<label
                      class="check"
                      ><input
                        type="checkbox"
                        bind:group={ruleSets}
                        value={item.id}
                      />{item.id}</label
                    >{:else}<p class="muted">
                      Источники наборов правил задаются оператором.
                    </p>{/each}
                </fieldset>
                <label
                  >Маршрут<select bind:value={rule.outbound}
                    >{#each outbounds as x}<option value={x}
                        >{labelFor(x)}</option
                      >{/each}</select
                  ></label
                ><label
                  >Транспорт<select bind:value={rule.network}
                    ><option value="">TCP и UDP</option><option value="tcp"
                      >TCP</option
                    ><option value="udp">UDP</option></select
                  ></label
                ><label
                  >Приоритет<input
                    type="number"
                    min="0"
                    bind:value={rule.priority}
                  /></label
                >
              </div>
              <label class="check"
                ><input type="checkbox" bind:checked={rule.enabled} />Правило
                включено</label
              >
              <p class="muted small">
                Наборы правил: {config.policy.rule_sets
                  ?.map((x) => x.id)
                  .join(", ") || "не зарегистрированы"}.
              </p>
              <button disabled={busy}>Сохранить правило</button>
            </form>
          </section>
        {:else if page === "devices"}
          <section class="card">
            <h2>Устройства LAN</h2>
            {#if network?.devices?.length}{#each network.devices as d}<div
                  class="row"
                >
                  <div>
                    <strong>{d.hostname || d.host_name || "Без имени"}</strong>
                    <p>{d.address || d.ip} · {d.mac}</p>
                  </div>
                  <button
                    onclick={() => (device.cidrs = (d.address || d.ip) + "/32")}
                    >Назначить политику</button
                  >
                </div>{/each}{:else}<p>
                {resourceErrors["routeros/network"] ||
                  "DHCP-устройства не обнаружены."}
              </p>{/if}
          </section>
          <section class="card">
            <h2>Политики источников</h2>
            <p class="muted">
              Политики действуют на трафик, который подготовленный профиль
              направляет в sing-box. В hybrid это выборочные назначения DNS;
              политика устройства сама по себе не включает перехват всего
              интернета устройства.
            </p>
            {#each config.policy.source_direct || [] as cidr}<div class="row">
                <span>{cidr} → DIRECT</span><button
                  disabled={busy}
                  onclick={() =>
                    run(() =>
                      savePolicy((c) => {
                        c.policy.source_direct = c.policy.source_direct.filter(
                          (x) => x !== cidr,
                        );
                      }),
                    )}>Удалить политику</button
                >
              </div>{/each}{#each config.policy.source_proxy || [] as value}<div
                class="row"
              >
                <span>{value.cidrs.join(", ")} → {value.outbound}</span><button
                  disabled={busy}
                  onclick={() =>
                    run(() =>
                      savePolicy((c) => {
                        c.policy.source_proxy = c.policy.source_proxy.filter(
                          (x) => JSON.stringify(x) !== JSON.stringify(value),
                        );
                      }),
                    )}>Удалить политику</button
                >
              </div>{/each}
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(() =>
                  savePolicy((c) => {
                    const cidrs = split(device.cidrs);
                    if (device.outbound === "direct")
                      c.policy.source_direct = [
                        ...(c.policy.source_direct || []),
                        ...cidrs,
                      ];
                    else
                      c.policy.source_proxy = [
                        ...(c.policy.source_proxy || []),
                        { cidrs, outbound: device.outbound },
                      ];
                  }),
                );
              }}
            >
              <label
                >IP/CIDR устройств<textarea
                  bind:value={device.cidrs}
                  required
                  placeholder="192.168.88.10/32"></textarea></label
              ><label
                >Политика<select bind:value={device.outbound}
                  >{#each outbounds as x}<option value={x}>{labelFor(x)}</option
                    >{/each}</select
                ></label
              ><button disabled={busy}>Сохранить политику устройства</button>
            </form>
          </section>
        {:else if page === "dns"}
          <section class="card">
            <h2>DNS и FakeIP</h2>
            <dl>
              <dt>Активный режим</dt>
              <dd>{current?.model.mode}</dd>
              <dt>Upstream / bootstrap</dt>
              <dd>{config.policy.dns.bootstrap}</dd>
              <dt>Пул FakeIP IPv4</dt>
              <dd>{config.policy.dns.fakeip_range}</dd>
              <dt>Публикация</dt>
              <dd>{ready ? "Runtime готов" : "Готовность не подтверждена"}</dd>
              <dt>IPv6 FakeIP</dt>
              <dd>Не поддерживается</dd>
            </dl>
            <p class="muted">
              Upstream, пул и сетевой перехват закреплены операторским профилем.
              DNS публикует адрес после доказательства маршрута.
            </p>
            <IPv6Notice {network} />
          </section>
          <section class="card">
            <h2>Выборочные назначения</h2>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(() =>
                  savePolicy((c) => {
                    c.policy.dns.selected_domains = split(dnsDomains);
                    c.policy.dns.selected_suffixes = split(dnsSuffixes);
                  }),
                );
              }}
            >
              <div class="grid">
                <label
                  >Домены для FakeIP<textarea
                    bind:value={dnsDomains}
                    placeholder="selected.example"></textarea></label
                ><label
                  >Суффиксы для FakeIP<textarea
                    disabled
                    aria-describedby="dns-suffix-note"
                    bind:value={dnsSuffixes}></textarea></label
                >
              </div>
              <p id="dns-suffix-note" class="muted">
                Выборочный FakeIP принимает только конечный список явных
                доменов. Публикация суффиксов недоступна, пока admission не
                охватывает динамические имена.
              </p>
              <button disabled={busy}>Сохранить DNS в черновик</button>
            </form>
            <button disabled={busy} onclick={() => run(() => diagnose("dns"))}
              >Проверить состояние DNS</button
            >{#if checks.dns}<p role="status">{checks.dns}</p>{/if}
          </section>
        {:else if page === "diagnostics"}
          <section class="card">
            <div class="section-heading">
              <div>
                <h2>Что сейчас работает</h2>
                <p class="muted">
                  Проверяйте по шагам: конфигурация, подписки, соединение,
                  маршруты.
                </p>
              </div>
              <button
                disabled={busy}
                onclick={() =>
                  run(async () => {
                    for (const check of diagnosticCards) {
                      try {
                        await diagnose(check.id);
                      } catch {
                        /* Individual results remain visible. */
                      }
                    }
                  })}>Проверить всё</button
              >
            </div>
            <div class="diagnostic-grid">
              {#each diagnosticCards as check}<article
                  class="diagnostic-card"
                  class:passed={diagnosticDetails[check.id]?.state === "passed"}
                  class:failed={diagnosticDetails[check.id]?.state === "failed"}
                >
                  <div class="section-heading">
                    <h3>{check.title}</h3>
                    <span class="status-pill"
                      >{(
                        {
                          passed: "Работает",
                          failed: "Ошибка",
                          running: "Проверка…",
                          unavailable: "Нет данных",
                        } as Record<string, string>
                      )[diagnosticDetails[check.id]?.state] ||
                        "Не проверено"}</span
                    >
                  </div>
                  <p class="muted">{check.description}</p>
                  <p class="check-result" role="status">
                    {checks[check.id] ||
                      "Запустите проверку, чтобы получить результат."}
                  </p>
                  {#if ["failed", "unavailable"].includes(diagnosticDetails[check.id]?.state)}<p
                      class="check-hint"
                    >
                      {check.hint}
                    </p>
                    <a href={"#" + check.page}>Открыть настройки →</a>{/if}
                  <button
                    disabled={busy}
                    onclick={() => run(() => diagnose(check.id))}
                    >Проверить</button
                  >
                  {#if diagnosticDetails[check.id]?.scope}<details>
                      <summary>Технические сведения</summary>
                      <p>{diagnosticDetails[check.id].scope}</p>
                      <code>{diagnosticDetails[check.id].code}</code>
                    </details>{/if}
                </article>{/each}
            </div>
            <button
              onclick={() =>
                run(() =>
                  download(
                    "diagnostics/bundle",
                    "mikrocentauri-diagnostics.tar.gz",
                  ),
                )}
              disabled={busy}>Скачать диагностику</button
            >
          </section>
        {:else if page === "system"}
          <section class="card">
            <h2>Система</h2>
            <dl>
              <dt>Версия приложения</dt>
              <dd>{info?.app_version || "Не определена"}</dd>
              <dt>Сборка</dt>
              <dd>{info?.build_revision || "Не определена"}</dd>
              <dt>sing-box</dt>
              <dd>
                {info?.sing_box_verified
                  ? info.sing_box_observed
                  : "Проверка не подтверждена"} · ожидаемая {info?.sing_box_expected ||
                  "не определена"}
              </dd>
              <dt>Свободное хранилище приложения</dt>
              <dd>{bytes(info?.storage?.available_bytes)}</dd>
              <dt>Версия API</dt>
              <dd>{system?.api_version}</dd>
              <dt>Модель конфигурации</dt>
              <dd>v{system?.core_schema}</dd>
              <dt>RouterOS</dt>
              <dd>{router?.capabilities?.version || "Недоступен"}</dd>
              <dt>Обработчик трафика</dt>
              <dd>
                {system?.runtime_connected ? "Подключён" : "Не подключён"}
              </dd>
            </dl>
            <p class="muted">
              Обновление приложения и установка RouterOS App появятся на этапе
              установки.
            </p>
            <button
              disabled={busy || !system?.runtime_connected}
              onclick={() =>
                run(async () => {
                  await api("system/recover", {});
                  await load();
                  notice = "Восстановление завершено; проверьте готовность.";
                })}>Повторить восстановление</button
            >
          </section>
          <section class="card">
            <h2>Настройки интерфейса</h2>
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(async () => {
                  await api("preferences", pref);
                  document.documentElement.dataset.theme = pref.theme;
                  notice = "Настройки сохранены.";
                });
              }}
            >
              <div class="grid">
                <label
                  >Тема<select bind:value={pref.theme}
                    ><option value="system">Системная</option><option
                      value="light">Светлая</option
                    ><option value="dark">Тёмная</option></select
                  ></label
                ><label
                  >Часовой пояс<input
                    bind:value={pref.time_zone}
                    required
                    placeholder="Europe/Moscow"
                  /></label
                >
              </div>
              <button disabled={busy}>Сохранить настройки</button>
            </form>
          </section>
          <section class="card">
            <h2>Резервная копия</h2>
            <p>
              Безопасная копия сохраняет политики и метаданные. Для
              восстановления нужны соответствующие локальные учётные данные;
              ключи и подписочные URL не экспортируются.
            </p>
            <button
              disabled={busy}
              onclick={() =>
                run(async () => {
                  const value = await api("backup");
                  saveBlob(
                    new Blob([JSON.stringify(value, null, 2)], {
                      type: "application/json",
                    }),
                    "mikrocentauri-safe.json",
                  );
                })}>Скачать резервную копию</button
            >
            <form
              onsubmit={(e) => {
                e.preventDefault();
                run(readRestore);
              }}
            >
              <label
                >Файл безопасной копии<input
                  type="file"
                  accept="application/json,.json"
                  onchange={(e) => {
                    restoreFile = e.currentTarget.files?.[0];
                    restore = undefined;
                    restorePreview = undefined;
                  }}
                  required
                /></label
              ><button disabled={busy || !restoreFile}
                >Проверить восстановление</button
              >
            </form>
            {#if restorePreview}<p class="success">
                Копия совместима. {restorePreview.model.rule_count} правил · {restorePreview
                  .model.groups.length} групп. Применение ещё не выполнено.
              </p>
              <button
                disabled={busy}
                onclick={() =>
                  run(async () => {
                    await api("backup/restore-draft", restore);
                    restore = undefined;
                    restorePreview = undefined;
                    plan = undefined;
                    await load();
                    notice =
                      "Восстановление сохранено в черновик. Проверьте и примените план.";
                  })}>Создать черновик восстановления</button
              >{/if}
          </section>
          <section class="card">
            <h2>Журнал событий</h2>
            {#each [...logs].reverse() as item}<div class="event">
                <time>{date(item.timestamp)}</time><span
                  >{item.level} · {item.component}</span
                ><strong>{item.event}</strong>
              </div>{/each}
          </section>
        {/if}
      {/if}
      <footer>
        MikroCentauri · RouterOS native · Изменения активируются после просмотра
        плана · <a href="/licenses.txt" target="_blank" rel="noopener"
          >Лицензии</a
        >
      </footer>
    </main>
  </div>
{/if}

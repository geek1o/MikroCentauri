<script lang="ts">
  import { testTargetLabel } from "./test-targets";
  import { latencyTone } from "./latency";
  import type { Group, Endpoint } from "./types";
  let {
    group,
    nodes,
    live,
    health = {},
    busy = false,
    onDraft,
    onLive,
    onProbe,
    onEdit,
    title,
  }: {
    group: Group;
    title?: string;
    nodes: Endpoint[];
    live?: any;
    health?: Record<string, any>;
    busy?: boolean;
    onDraft: (g: string, n: string) => void;
    onLive: (g: string, n: string) => void;
    onProbe: (n: string) => Promise<void>;
    onEdit?: () => void;
  } = $props();
  let search = $state("");
  let order = $state("list");
  const label = (id: string) =>
    id === "direct"
      ? "DIRECT"
      : nodes.find((x) => x.ID === id)?.Name ||
        nodes.find((x) => x.ID === id)?.Server ||
        id;
  let members = $derived(
    group.members
      .filter((id) => label(id).toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) =>
        order === "name"
          ? label(a).localeCompare(label(b), "ru")
          : order === "latency"
            ? (health[a]?.success ? health[a].latency_ms : Infinity) -
              (health[b]?.success ? health[b].latency_ms : Infinity)
            : 0,
      ),
  );
  let checking = $derived(members.some((id) => health[id]?.checking));
  async function probeAll() {
    const ids = members.filter(
      (id) => live?.members.includes(id) && nodes.some((n) => n.ID === id),
    );
    let next = 0;
    await Promise.all(
      Array.from({ length: Math.min(3, ids.length) }, async () => {
        while (next < ids.length) {
          const id = ids[next++];
          await onProbe(id);
        }
      }),
    );
  }
</script>

<section class="selector-panel" aria-label={"Селектор " + group.id}>
  <div class="selector-title">
    <div>
      <span class="eyebrow"
        >{group.type === "selector"
          ? "Ручной выбор"
          : "Автоматический выбор"}</span
      >
      <h3>{title || group.id}</h3>
      <p class="muted">
        Серверов: {group.members.length}
        {#if live?.selected}· Сейчас: <strong>{label(live.selected)}</strong
          >{/if}
      </p>
    </div>
    <span class="connection-pill" class:connected={!!live}
      >{live ? "В движке" : "В черновике"}</span
    >
  </div>
  {#if group.type === "urltest"}<p class="auto-policy" role="status">
      Автоматически · проверка каждые {group.interval || "3m"} · допуск {group.tolerance ||
        50} мс. Во время использования недоступные серверы исключаются при проверке.
      Режим работает в sing-box даже при закрытой панели.
      <span class="test-target"
        >Цель URLTest: {testTargetLabel(group.test_target)}</span
      >
      {#if live?.type !== "urltest"}Изменение режима ещё не применено.{/if}
    </p>{/if}
  <div class="selector-toolbar">
    <label class="server-search"
      >Поиск серверов<input
        aria-label={"Найти сервер в " + group.id}
        bind:value={search}
        placeholder="Название сервера…"
      /></label
    ><label class="server-order"
      >Порядок<select
        aria-label={"Порядок серверов в " + group.id}
        bind:value={order}
        ><option value="list">Из подписки</option><option value="latency"
          >По задержке</option
        ><option value="name">По названию</option></select
      ></label
    ><button disabled={busy || !live || checking} onclick={probeAll}
      >Проверить серверы</button
    >{#if onEdit}<button class="text" onclick={onEdit}>Настроить выбор</button
      >{/if}
  </div>
  <p class="latency-legend">
    Задержка HTTPS: зелёный &lt; 150 мс · жёлтый 150–399 мс · красный ≥ 400 мс
    или нет ответа.
  </p>
  <div class="server-grid">
    {#each members as id}{@const node = nodes.find(
        (n) => n.ID === id,
      )}{@const active = live?.selected === id}{@const canLive =
        group.type === "selector" && live?.members.includes(id)}{@const status =
        health[id]}
      <article
        class="server-card"
        class:active
        class:failed={status?.success === false}
      >
        <div class="server-card-top">
          <span
            title={status?.checked_at
              ? "Измерено " +
                new Date(status.checked_at).toLocaleTimeString("ru-RU")
              : "Задержка HTTPS-запроса"}
            class="latency"
            data-tone={latencyTone(status)}
            class:healthy={status?.success === true}
            class:unhealthy={status?.success === false}
            >{status?.checking
              ? "Проверка…"
              : status?.success === false
                ? "Нет ответа"
                : status?.success === true
                  ? status.latency_ms + " мс"
                  : "Не проверен"}</span
          >
        </div>
        <h4>{label(id)}</h4>
        <p class="server-meta">
          {node?.Protocol?.toUpperCase() || "МАРШРУТ"}{#if node}
            · {node.Server}:{node.Port}{/if}
        </p>
        <div class="server-card-actions">
          <button
            class="choose-server"
            aria-pressed={active}
            disabled={busy || group.type !== "selector"}
            onclick={() =>
              canLive ? onLive(group.id, id) : onDraft(group.id, id)}
            >{group.type === "urltest"
              ? active
                ? "✓ Автовыбор"
                : "Резерв"
              : active
                ? "✓ Сейчас выбран"
                : canLive
                  ? "Подключить"
                  : (group.selected || group.members[0]) === id
                    ? "✓ Выбран в черновике"
                    : "В черновик"}</button
          ><button
            class="probe-server"
            aria-label={"Проверить сервер " + label(id)}
            title="HTTPS-запрос через сервер; это не ICMP ping"
            disabled={busy ||
              !live?.members.includes(id) ||
              !node ||
              status?.checking}
            onclick={() => onProbe(id)}>↻</button
          >
        </div>
      </article>{/each}
  </div>
  {#if !members.length}<p class="empty-state">
      Серверы не найдены. Измените поиск.
    </p>{/if}
  {#if !live}<p class="muted small">
      Примените группу и подключите API движка, чтобы переключать серверы сразу.
      Выбор в черновике требует применения плана.
    </p>{:else}<p class="muted small">
      {group.type === "urltest"
        ? "Движок автоматически выбирает сервер для новых соединений."
        : "Переключение действует сразу для новых соединений."} Задержка — время HTTPS-проверки
      через сервер, а не ICMP ping.
    </p>{/if}
  {#if group.type === "selector"}<details class="advanced-selector">
      <summary>Выбор сервера в черновике</summary><label
        >Сервер для {group.id}<select
          aria-label={"Сервер для " + group.id}
          value={group.selected || group.members[0]}
          disabled={busy}
          onchange={(e) => onDraft(group.id, e.currentTarget.value)}
          >{#each group.members as id}<option value={id}>{label(id)}</option
            >{/each}</select
        ></label
      >
    </details>{/if}
</section>

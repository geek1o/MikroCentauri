<script lang="ts">
  import { testTargets } from "./test-targets";
  import SelectorPanel from "./SelectorPanel.svelte";
  import type { Config, Section, Group } from "./types";
  import { copy, split } from "./api";
  import { sectionConflicts } from "./section-conflicts";
  let {
    config,
    catalog,
    snapshots,
    engine,
    health,
    busy,
    onSave,
    onDraft,
    onLive,
    onProbe,
    onLists,
  }: {
    config: Config;
    catalog: any[];
    snapshots: any[];
    engine: any;
    health: Record<string, any>;
    busy: boolean;
    onSave: (
      sections: Section[],
      refreshID?: string,
      groups?: Group[],
    ) => Promise<boolean>;
    onDraft: (group: string, node: string) => Promise<void>;
    onLive: (group: string, node: string) => Promise<void>;
    onProbe: (node: string) => Promise<void>;
    onLists: () => void;
  } = $props();
  let sections = $derived(config.policy.sections || []);
  let conflicts = $derived(sectionConflicts(sections));
  let editing = $state<Section>();
  let domainText = $state(""),
    networkText = $state(""),
    sourceText = $state(""),
    search = $state(""),
    kind = $state("all"),
    validation = $state("");
  let selected = $state<string[]>([]);
  let ownSelector = $state(false),
    selectorType = $state("selector"),
    selectorTarget = $state("google"),
    selectorInterval = $state("1m"),
    selectorTolerance = $state(50),
    selectorMembers = $state<string[]>([]);
  let targets = $derived([
    { id: "direct", name: "Напрямую · исключение" },
    ...config.model.groups.map((g) => ({
      id: g.id,
      name: `${config.policy.sections?.find((s) => s.outbound === g.id)?.name || g.id} · ${g.type === "selector" ? "ручной выбор" : "автоматический выбор"}`,
    })),
    ...config.model.endpoints
      .filter((e) => e.Enabled !== false)
      .map((e) => ({ id: e.ID, name: e.Name || e.ID })),
    ...config.model.wireguard
      .filter((e) => e.enabled !== false)
      .map((e) => ({ id: e.id, name: `${e.id} · WireGuard` })),
  ]);
  let sources = $derived([
    ...catalog,
    ...snapshots.filter((s) => !catalog.some((c) => c.id === s.id)),
  ]);
  let filtered = $derived(
    sources.filter(
      (s) =>
        (kind === "all" || s.kind === kind) &&
        `${s.name} ${s.description || ""}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    ),
  );
  function begin(section?: Section, template?: string) {
    editing = section
      ? copy(section)
      : {
          id: `s-${crypto.randomUUID().slice(0, 8)}`,
          name:
            template === "youtube"
              ? "Видео"
              : template === "google-ai"
                ? "AI-сервисы"
                : "",
          enabled: true,
          outbound: config.model.groups[0]?.id || "direct",
        };
    editing.all_traffic = !!editing.all_traffic;
    domainText = (editing.domains || []).join("\n");
    networkText = (editing.destination_cidrs || []).join("\n");
    sourceText = (editing.source_cidrs || []).join("\n");
    selected = template ? [template] : (editing.lists || []).map((l) => l.id);
    search = "";
    kind = "all";
    validation = "";
    const managed = config.model.groups.find(
      (g) => g.id === "sel-" + editing?.id && g.id === editing?.outbound,
    );
    ownSelector = !!managed;
    selectorType = managed?.type || "selector";
    selectorTarget = managed ? managed.test_target || "" : "google";
    selectorInterval = managed?.interval || "1m";
    selectorTolerance = managed?.tolerance || 50;
    selectorMembers = managed
      ? copy(managed.members)
      : config.model.endpoints
          .filter((e) => e.Enabled !== false)
          .map((e) => e.ID);
  }
  async function save() {
    if (!editing) return;
    const value = copy(editing);
    value.name = value.name.trim();
    value.domains = [
      ...new Set(
        split(domainText).map((d) => d.toLowerCase().replace(/^\*\./, "")),
      ),
    ];
    value.destination_cidrs = [...new Set(split(networkText))];
    value.source_cidrs = [
      ...new Set(
        split(sourceText).map((ip) => (ip.includes("/") ? ip : `${ip}/32`)),
      ),
    ];
    value.lists = selected.map((id) => ({ id, name: "", sha256: "" }));
    if (!value.name) {
      validation = "Дайте секции название.";
      return;
    }
    if (value.all_traffic) {
      value.domains = [];
      value.destination_cidrs = [];
      value.lists = [];
      if (!value.source_cidrs.length) {
        validation = "Укажите устройства для всего их трафика.";
        return;
      }
    } else if (
      !value.domains.length &&
      !value.destination_cidrs.length &&
      !value.lists.length
    ) {
      validation = "Выберите список или добавьте домены / подсети.";
      return;
    }
    const next = copy(sections),
      index = next.findIndex((s) => s.id === value.id);
    if (index < 0) next.push(value);
    else next[index] = value;
    let groups: Group[] | undefined;
    if (ownSelector) {
      if (!selectorMembers.length) {
        validation = "Выберите хотя бы один сервер для селектора.";
        return;
      }
      const id = "sel-" + value.id;
      const existing = config.model.groups.find((g) => g.id === id);
      if (existing && editing.outbound !== id) {
        validation =
          "Этот селектор уже существует. Выберите его в поле маршрута.";
        return;
      }
      value.outbound = id;
      const preferred =
        existing?.selected ||
        engine?.groups?.find((g: any) => g.id === id)?.selected;
      const replacement: Group = {
        id,
        type: selectorType,
        members: copy(selectorMembers),
        ...(selectorType === "selector"
          ? {
              selected: selectorMembers.includes(preferred || "")
                ? preferred
                : selectorMembers[0],
            }
          : {
              test_target: selectorTarget,
              interval: selectorInterval,
              tolerance: selectorTolerance,
            }),
      };
      groups = existing
        ? config.model.groups.map((g) => (g.id === id ? replacement : copy(g)))
        : [...copy(config.model.groups), replacement];
    }
    if (await onSave(next, undefined, groups)) editing = undefined;
  }
  async function move(index: number, offset: number) {
    const next = copy(sections);
    [next[index], next[index + offset]] = [next[index + offset], next[index]];
    await onSave(next);
  }
  function domains(s: Section) {
    return [
      ...(s.domains || []),
      ...(s.lists || []).flatMap((l) => l.domains || []),
    ];
  }
  function networks(s: Section) {
    return [
      ...(s.destination_cidrs || []),
      ...(s.lists || []).flatMap((l) => l.prefixes || []),
    ];
  }
</script>

<section class="card">
  <div class="section-heading">
    <div>
      <p class="eyebrow">ПОЛИТИКА МАРШРУТИЗАЦИИ</p>
      <h2>Секции</h2>
      <p class="muted">
        Выберите сайты, назначьте маршрут. Для разных задач можно использовать
        разные серверы.
      </p>
    </div>
    <button class="primary" disabled={busy || !!editing} onclick={() => begin()}
      >Добавить секцию</button
    >
  </div>
  <p class="muted">
    Секции проверяются сверху вниз: первое совпадение определяет маршрут.
    Изменения сохраняются в черновик.
  </p>
  {#if config.policy.source_direct?.length || config.policy.source_proxy?.length}<p
      class="warning"
    >
      Общие маршруты устройств имеют приоритет над секциями. Проверьте раздел
      «Устройства».
    </p>{/if}
  {#if config.policy.rules.some((r) => r.enabled !== false && (r.priority || 0) <= -1000 + sections.length - 1)}<p
      class="warning"
    >
      Расширенные правила с отрицательным приоритетом могут обработать трафик
      раньше секций.
    </p>{/if}
  {#if !sections.length && !editing}<div class="section-empty">
      <h3>Создайте первую секцию</h3>
      <p>Начните с готового сценария и выберите свой сервер.</p>
      <div class="actions">
        <button disabled={busy} onclick={() => begin(undefined, "youtube")}
          >Видео · YouTube</button
        ><button disabled={busy} onclick={() => begin(undefined, "google-ai")}
          >AI · Google</button
        ><button disabled={busy} onclick={() => begin()}>Своя секция</button>
      </div>
    </div>{/if}
</section>
{#if editing}
  <section class="card section-editor" aria-label="Редактор секции">
    <h2>
      {sections.some((s) => s.id === editing?.id)
        ? "Изменить секцию"
        : "Новая секция"}
    </h2>
    <div class="section-grid">
      <label
        >Название<input
          bind:value={editing.name}
          maxlength="120"
          placeholder="Например, Видео"
        /></label
      ><label
        >Маршрут секции<select
          aria-label="Маршрут секции"
          disabled={ownSelector}
          bind:value={editing.outbound}
          >{#each targets as t}<option value={t.id}>{t.name}</option
            >{/each}</select
        ></label
      >
    </div>
    <label class="own-selector"
      ><input type="checkbox" bind:checked={ownSelector} />Собственный селектор
      серверов для секции</label
    >
    {#if ownSelector}<label
        >Режим выбора сервера<select
          aria-label="Режим выбора сервера"
          bind:value={selectorType}
          ><option value="selector"
            >Вручную · переключение в реальном времени</option
          ><option value="urltest">Автоматически · по задержке</option></select
        ></label
      >
      {#if selectorType === "urltest"}
        <label
          >Цель URLTest<select
            aria-label="Цель URLTest"
            bind:value={selectorTarget}
          >
            {#if selectorTarget === ""}<option value=""
                >Сохранить текущую цель оператора</option
              >{/if}
            {#each testTargets as target}<option value={target.id}
                >{target.name} · {target.url}</option
              >{/each}
          </select></label
        >
        <div class="section-grid">
          <label
            >Период проверки<select
              aria-label="Период проверки"
              bind:value={selectorInterval}
            >
              <option value="30s">30 секунд</option><option value="1m"
                >1 минута</option
              ><option value="3m">3 минуты</option><option value="5m"
                >5 минут</option
              ><option value="10m">10 минут</option>
            </select></label
          >
          <label
            >Переключать при выигрыше<select
              aria-label="Переключать при выигрыше"
              bind:value={selectorTolerance}
            >
              <option value={1}>1 мс · минимальная задержка</option><option
                value={50}>50 мс · меньше переключений</option
              ><option value={100}>100 мс · стабильный выбор</option>
            </select></label
          >
        </div>
        <p class="muted small">
          sing-box периодически проверяет HTTPS через серверы и выбирает
          доступный с меньшей задержкой. После отказа переключение происходит
          при следующей проверке. Режим включится после применения плана.
        </p>{/if}
      <fieldset>
        <legend>Серверы секции</legend>
        <div class="section-catalog">
          {#each config.model.endpoints.filter((e) => e.Enabled !== false) as node}<label
              class="section-source"
              ><input
                type="checkbox"
                value={node.ID}
                bind:group={selectorMembers}
              /><span>{node.Name || node.Server}</span></label
            >{/each}
        </div>
      </fieldset>{/if}
    <p class="muted">
      Селектор позволяет переключать серверы после применения секции. Напрямую —
      исключение из проксирования.
    </p>
    <label
      >Что маршрутизировать<select
        aria-label="Что маршрутизировать"
        bind:value={editing.all_traffic}
        ><option value={false}>Выбранные сайты и IP-подсети</option><option
          value={true}>Весь трафик указанных устройств</option
        ></select
      ></label
    >
    {#if !editing.all_traffic}
      <h3>Готовые списки · выбрано {selected.length}</h3>
      <div class="section-grid">
        <label
          >Поиск списков<input
            type="search"
            bind:value={search}
            placeholder="YouTube, Cloudflare, Telegram…"
          /></label
        ><label
          >Тип списка<select aria-label="Тип списка" bind:value={kind}
            ><option value="all">Все списки</option><option value="domains"
              >Сайты и сервисы</option
            ><option value="networks">CDN и IP-сети</option></select
          ></label
        >
      </div>
      <div class="section-catalog">
        {#each filtered as source}<label class="section-source"
            ><input
              type="checkbox"
              value={source.id}
              bind:group={selected}
            /><span
              ><strong>{source.name}</strong><small
                >{source.kind === "networks"
                  ? "IP-сети"
                  : source.description || "Домены и поддомены"}</small
              ></span
            ></label
          >{/each}
      </div>
      {#if !filtered.length}<p class="muted">
          Списки не найдены. Измените запрос.
        </p>{/if}
      <p class="muted">
        Списки загружаются при сохранении. Каждая секция хранит свой снимок. CDN
        может включать сайты других сервисов.
      </p>
      <details>
        <summary>Свои домены и IP-подсети</summary>
        <div class="section-grid">
          <label
            >Домены и поддомены<textarea
              rows="5"
              bind:value={domainText}
              placeholder="example.com&#10;video.example.org"></textarea></label
          ><label
            >IP-подсети назначения<textarea
              rows="5"
              bind:value={networkText}
              placeholder="203.0.113.0/24"></textarea></label
          >
        </div>
        <p class="muted">
          По одной записи на строку. Достаточно совпадения домена или подсети.
        </p>
      </details>
      <details>
        <summary>Свой список по URL</summary>
        <p>
          Добавьте источник в разделе списков и выберите его здесь. URL хранится
          только на сервере.
        </p>
        <button disabled={busy} onclick={onLists}>Открыть списки</button>
      </details>
    {/if}
    <details open={editing.all_traffic}>
      <summary>Для каких устройств</summary><label
        >IP-адреса или подсети устройств<textarea
          rows="3"
          bind:value={sourceText}
          placeholder="192.168.88.10&#10;192.168.88.0/24"></textarea></label
      >
      <p class="muted">
        Пустое поле — все устройства. При заполнении секция действует только для
        них. Для всего трафика поле обязательно.
      </p>
    </details>
    {#if validation}<p class="error" role="alert">{validation}</p>{/if}
    <div class="actions">
      <button class="primary" disabled={busy} onclick={save}
        >{busy ? "Сохранение и загрузка списков…" : "Сохранить секцию"}</button
      ><button disabled={busy} onclick={() => (editing = undefined)}
        >Отмена</button
      >
    </div>
  </section>
{/if}
{#each sections as section, index (section.id)}
  {@const group = config.model.groups.find((g) => g.id === section.outbound)}
  <section
    class="card section-card"
    class:section-disabled={!section.enabled}
    aria-label={`Секция ${section.name}`}
  >
    <div class="section-heading">
      <div>
        <p class="eyebrow">
          {index + 1} · {section.enabled ? "Включена" : "Отключена"}
        </p>
        <h2>{section.name}</h2>
        <p>
          → {targets.find((t) => t.id === section.outbound)?.name ||
            section.outbound}
        </p>
      </div>
      <div class="actions">
        <button
          aria-label={`Поднять ${section.name}`}
          disabled={busy || !!editing || index === 0}
          onclick={() => move(index, -1)}>↑</button
        ><button
          aria-label={`Опустить ${section.name}`}
          disabled={busy || !!editing || index === sections.length - 1}
          onclick={() => move(index, 1)}>↓</button
        ><button disabled={busy || !!editing} onclick={() => begin(section)}
          >Изменить</button
        >
      </div>
    </div>
    <div class="section-facts">
      <span
        >{section.all_traffic
          ? "Весь трафик устройств"
          : `Домены: ${new Set(domains(section)).size} · Подсети: ${new Set(networks(section)).size}`}</span
      ><span
        >{section.source_cidrs?.length
          ? section.source_cidrs.join(", ")
          : "Все устройства"}</span
      >
    </div>
    <div class="section-tags">
      {#each section.lists || [] as list}<span>{list.name || list.id}</span
        >{/each}{#each section.domains?.slice(0, 5) || [] as domain}<span
          >{domain}</span
        >{/each}
    </div>
    {#each conflicts[section.id] || [] as prior}<p class="warning">
        Пересечение с «{prior.name}»: при совпадении условий сработает более
        ранняя секция.
      </p>{/each}

    {#if group && section.enabled}<p class="muted">
        Переключение действует на все секции с этим селектором.
      </p>
      <SelectorPanel
        {group}
        title={section.name + " · серверы"}
        nodes={config.model.endpoints}
        live={engine?.groups?.find((g: any) => g.id === group.id)}
        {health}
        {busy}
        {onDraft}
        {onLive}
        {onProbe}
        onEdit={() => begin(section)}
      />{/if}
    <details class="section-maintenance">
      <summary>Действия с секцией</summary>
      <div class="actions">
        <button
          disabled={busy || !!editing}
          onclick={() =>
            onSave(
              sections.map((s) =>
                s.id === section.id
                  ? { ...copy(s), enabled: !s.enabled }
                  : copy(s),
              ),
            )}>{section.enabled ? "Отключить" : "Включить"}</button
        ><button
          disabled={busy || !!editing}
          onclick={() => {
            const duplicate = copy(section);
            duplicate.id = `s-${crypto.randomUUID().slice(0, 8)}`;
            duplicate.name += " · копия";
            begin(duplicate);
          }}>Копировать</button
        ><button
          disabled={busy || !!editing || !section.lists?.length}
          onclick={() => onSave(copy(sections), section.id)}
          >Обновить списки секции</button
        ><button
          class="danger"
          disabled={busy || !!editing}
          onclick={() =>
            onSave(copy(sections).filter((s) => s.id !== section.id))}
          >Удалить из черновика</button
        >
      </div>
    </details>
  </section>
{/each}

<style>
  .warning {
    border-left: 3px solid #c99b43;
    background: var(--tint);
    color: var(--ink);
    padding: 0.8rem 1rem;
    border-radius: 3px;
    font-size: 0.875rem;
  }
  .own-selector {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }
  .own-selector input {
    width: auto;
  }
  .section-heading {
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: 1rem;
  }
  .section-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .section-empty {
    text-align: left;
    padding: 1rem 0;
    background: none;
    border-radius: 3px;
  }

  .section-empty .actions {
    justify-content: flex-start;
  }
  .section-catalog {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.5rem;
    max-height: 360px;
    overflow: auto;
    margin: 1rem 0;
  }
  .section-source {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 0.8rem;
    margin: 0;
    cursor: pointer;
  }
  .section-source:has(input:checked) {
    border-color: var(--accent);
    background: var(--tint);
  }
  .section-source input {
    width: auto;
    flex-shrink: 0;
  }
  .section-source span {
    display: grid;
    gap: 0.2rem;
  }
  .section-source small {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .section-facts,
  .section-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.75rem 0;
  }
  .section-facts > span,
  .section-tags > span {
    padding: 0;
    background: none;
    border: 0;
    border-radius: 3px;
    font-size: 0.85rem;
    overflow-wrap: anywhere;
  }
  .section-tags > span {
    border-bottom: 1px dotted var(--line);
    margin-right: 0.5rem;
  }
  .section-facts > span {
    color: var(--muted);
    margin-right: 1rem;
  }
  .section-maintenance {
    margin-top: 1rem;
  }
  .section-disabled {
    border-style: dashed;
  }
  .section-editor details {
    margin: 1rem 0;
  }
  .section-editor summary {
    cursor: pointer;
    margin-bottom: 0.8rem;
  }
  .section-heading > div {
    min-width: 0;
  }
  @media (max-width: 700px) {
    .section-grid,
    .section-catalog {
      grid-template-columns: 1fr;
    }
    .section-heading {
      flex-direction: column;
    }
    .section-heading .actions {
      width: 100%;
    }
  }
</style>

<script lang="ts">
  let { network }: { network: any } = $props();
  const labels: Record<string, string> = {
    configured_enabled: "включён в настройках RouterOS",
    configured_disabled: "выключен в настройках RouterOS",
    unknown: "настройки не получены",
  };
</script>

<aside aria-label="Граница IPv6" class="ipv6-notice">
  <p><strong>IPv6:</strong> {labels[network?.ipv6?.state] ?? labels.unknown}.</p>
  {#if network?.ipv6?.forwarding !== null && network?.ipv6?.forwarding !== undefined}
    <p>Forwarding: {network.ipv6.forwarding ? "включён" : "выключен"}.</p>
  {/if}
  {#if network?.available?.["ipv6/address"]}
    <p>Адресов без disabled/invalid: {network.ipv6.enabled_addresses}.</p>
  {/if}
  {#if network?.available?.["ipv6/route"]}
    <p>Default routes обнаружено: {network.ipv6.default_routes}.</p>
  {/if}
  <p>Selective routing работает с IPv4. Управляемый DNS не возвращает AAAA;
    сохранённый IPv6-адрес или сторонний DNS может обойти выбранный маршрут.</p>
  <p>Настройки не подтверждают отсутствие обхода по IPv6. Изменения IPv6 settings
    могут требовать перезагрузки. Политику IPv6 нужно проверить отдельно.</p>
</aside>

<style>
  .ipv6-notice { border-left: 3px solid #c68a36; padding: 0.1rem 1rem; margin: 1rem 0; }
  p { margin: 0.5rem 0; }
</style>

<script lang="ts">
  import { onMount } from "svelte";
  import { api, APIError } from "./api";
  let { onConnected }: { onConnected: () => Promise<void> } = $props();
  let address = $state(""),
    username = $state("mikrocentauri"),
    password = $state(""),
    certificate = $state("");
  let status = $state<any>(),
    result = $state<any>(),
    preflight = $state<any>();
  let working = $state(false),
    error = $state(""),
    message = $state("");
  let reuseSaved = $derived(
    !!status?.has_password &&
      status.base_url === address.trim() &&
      status.username === username.trim(),
  );
  const errors: Record<string, string> = {
    router_setup_https_required:
      "Укажите HTTPS-адрес с путём /rest, например https://10.99.0.1/rest.",
    router_setup_private_ip_required:
      "Нужен локальный IPv4-адрес роутера. Публичные адреса и DNS-имена здесь не используются.",
    router_setup_credentials_required:
      "Введите имя служебного пользователя и пароль.",
    router_setup_invalid_certificate:
      "Не удалось прочитать сертификат. Загрузите открытый сертификат PEM (.crt), без закрытого ключа.",
    router_setup_tls_untrusted:
      "Сертификат RouterOS не прошёл проверку. Загрузите сертификат его центра сертификации и проверьте, что он выдан для указанного IP.",
    router_setup_auth_failed: "RouterOS отклонил имя пользователя или пароль.",
    router_setup_permissions_denied:
      "Подключение установлено, но у пользователя недостаточно прав чтения RouterOS.",
    router_setup_unreachable:
      "RouterOS не отвечает по HTTPS. Проверьте www-ssl, порт и разрешение в firewall для IP контейнера.",
    router_setup_native_managed:
      "Подключение закреплено работающим профилем маршрутизации. Его изменение требует отдельного плана.",
    router_setup_save_failed:
      "Не удалось сохранить защищённый файл подключения. Проверьте состояние подключения перед повторной попыткой.",
    router_setup_network_unavailable:
      "Не удалось прочитать сеть роутера. Проверьте права служебной учётной записи.",
  };
  onMount(async () => {
    try {
      status = await api("setup/router");
      address = status.base_url || "";
      username = status.username || "mikrocentauri";
      if (status.configured) preflight = await api("setup/preflight");
    } catch {
      error = "Не удалось загрузить настройки подключения.";
    }
  });
  function changed() {
    result = undefined;
    message = "";
    preflight = undefined;
  }
  async function checkManaged() {
    working = true;
    error = "";
    try {
      await onConnected();
      preflight = await api("setup/preflight");
      message = "Проверка подключения завершена.";
    } catch {
      error =
        "Не удалось проверить сохранённое подключение. Подробности доступны в диагностике.";
    } finally {
      working = false;
    }
  }
  async function submit(save: boolean) {
    working = true;
    error = "";
    message = "";
    try {
      result = await api("setup/router/" + (save ? "save" : "test"), {
        base_url: address.trim(),
        username: username.trim(),
        password,
        certificate_pem: certificate,
      });
      if (save) {
        status = result.status;
        password = "";
        certificate = "";
        message =
          "Подключение сохранено. Пароль хранится в защищённом файле приложения.";
        await onConnected();
        preflight = await api("setup/preflight");
      } else
        message =
          "HTTPS, авторизация и чтение сети работают. Можно сохранить подключение.";
    } catch (e) {
      error =
        errors[e instanceof APIError ? e.code : ""] ||
        (result?.saved
          ? "Подключение сохранено. Обновите страницу для повторной проверки состояния."
          : "Проверка не завершилась. Настройки подключения не изменены.");
    } finally {
      working = false;
    }
  }
</script>

<div class="router-setup">
  <p class="muted">
    Подключите роутер, чтобы обнаружить сеть и проверить возможности установки.
    Это не включает перенаправление трафика.
  </p>
  {#if status?.configured}<p class="success" role="status">
      Подключение настроено{status.base_url
        ? `: ${status.base_url}`
        : " через установочный профиль"}.
    </p>{/if}
  {#if status?.editable === false}<p class="muted">
      Подключение используется работающим профилем маршрутизации. Проверить его
      можно в диагностике.
    </p>
    <button disabled={working} onclick={checkManaged}
      >Проверить RouterOS API</button
    >{:else}
    <form
      onsubmit={(e) => {
        e.preventDefault();
        submit(false);
      }}
    >
      <div class="grid">
        <label
          >Адрес RouterOS REST API<input
            aria-label="Адрес RouterOS REST API"
            type="url"
            bind:value={address}
            oninput={changed}
            placeholder="https://10.99.0.1/rest"
            required
          /></label
        >
        <label
          >Пользователь RouterOS<input
            aria-label="Пользователь RouterOS"
            bind:value={username}
            oninput={changed}
            autocomplete="username"
            required
          /></label
        >
        <label
          >Пароль RouterOS<input
            aria-label="Пароль RouterOS"
            type="password"
            bind:value={password}
            oninput={changed}
            autocomplete="new-password"
            placeholder={reuseSaved
              ? "Сохранён · оставьте пустым, чтобы не менять"
              : "Пароль служебного пользователя"}
            required={!reuseSaved}
          /></label
        >
      </div>
      <details class="certificate-settings">
        <summary>Доверие к сертификату RouterOS</summary>
        <p class="muted small">
          Для собственного центра сертификации загрузите его открытый сертификат
          .crt. Сверьте сертификат через WinBox или другой доверенный канал.
          Закрытый ключ не нужен.
        </p>
        {#if status?.certificate_sha256}<p
            class="small certificate-fingerprint"
          >
            SHA-256 сохранённого сертификата: {status.certificate_sha256}
          </p>{/if}
        <label
          >Сертификат RouterOS<input
            type="file"
            accept=".crt,.pem,application/x-pem-file"
            onchange={async (e) => {
              const f = e.currentTarget.files?.[0];
              if (!f) return;
              changed();
              if (f.size > 16384) {
                error = "Сертификат должен занимать не более 16 КБ.";
                return;
              }
              certificate = await f.text();
              changed();
            }}
          /></label
        >
        <label
          >Открытый сертификат PEM<textarea
            aria-label="Открытый сертификат PEM"
            bind:value={certificate}
            oninput={changed}
            placeholder="-----BEGIN CERTIFICATE-----"
            rows="5"></textarea></label
        >
        <p class="muted small">
          Пустое поле сохраняет прежний сертификат для того же адреса и
          пользователя. Для публичного центра используется системное доверие.
        </p>
      </details>
      <div class="actions">
        <button disabled={working || !address || !username}
          >{working ? "Проверяем…" : "Проверить подключение"}</button
        ><button
          type="button"
          class="primary"
          disabled={working || !result}
          onclick={() => submit(true)}>Сохранить подключение</button
        >
      </div>
    </form>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if message}<p class="success" role="status">{message}</p>{/if}
  {#if result}<div class="setup-router-result" role="status">
      <strong
        >RouterOS {result.router.capabilities.version} · {result.router
          .capabilities.board}</strong
      >
      <p>
        HTTPS и авторизация проверены. Адресов интерфейсов: {result.network
          .addresses.length}.
      </p>
    </div>{/if}
  <details class="router-preparation">
    <summary>Если HTTPS REST ещё не настроен</summary>
    <ol>
      <li>
        В WinBox откройте <strong>System → Certificates</strong>. Подготовьте
        сертификат сервера для локального IP роутера и экспортируйте открытый
        сертификат его центра сертификации.
      </li>
      <li>
        В <strong>IP → Services → www-ssl</strong> выберите сертификат и включите
        HTTPS. В firewall разрешите IP контейнера обращаться к этому сервису.
      </li>
      <li>
        Создайте отдельного пользователя с правами <strong
          >read, api, rest-api</strong
        >. Эти права нужны для обнаружения сети; права записи на этом шаге не
        проверяются.
      </li>
      <li>
        Вернитесь к форме, укажите адрес с <strong>/rest</strong>, имя, пароль и
        сертификат. Нажмите «Проверить подключение», затем «Сохранить
        подключение».
      </li>
    </ol>
  </details>
  {#if preflight}<div class="setup-installation-status">
      <h4>Подготовка маршрутизации</h4>
      <p>
        Подключение к роутеру и готовность маршрутизации проверяются отдельно.
      </p>
      <ul>
        {#each preflight.checks as check}<li>
            <strong
              >{check.passed ? "✓" : "○"}
              {(
                {
                  router_connection: "Доступ к RouterOS",
                  qualified_platform: "Проверенная платформа",
                  tun_device: "TUN-устройство",
                  network_permissions: "Права контейнера",
                  native_profile: "Профиль маршрутизации",
                  routing_ready: "Готовность трафика",
                } as Record<string, string>
              )[check.id] || check.id}</strong
            >
            <p class="muted small">{check.message}</p>
          </li>{/each}
      </ul>
      {#if !preflight.runtime_connected}<p class="note">
          Маршрутизация пока не включена. Нужен проверенный установочный профиль
          для этой платформы; мастер не будет выдавать сохранение доступа за
          готовность проксирования.
        </p>{/if}
    </div>{/if}
</div>

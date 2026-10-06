# RouterOS `/app` schema and packaging constraints

Research date: 2026-10-04. **CONFIRMED** from [Apps manual](https://manual.mikrotik.com/docs/containers/apps/) and [full manual](https://manual.mikrotik.com/llms-full.txt). **TODO:** no manifest import, generated network inspection, healthcheck or secrets lifecycle was executed on RouterOS.

Custom apps are available since **7.22** and require the `container` package plus device-mode enablement. The YAML resembles Compose but is a RouterOS-specific schema; Docker Compose validation is not RouterOS validation. Do not ship an invented generic `routeros:` section or assume arbitrary Compose properties are supported.

This is the original research snapshot. Native 7.24.5 import and generated-container
observations supersede its untested statements: [Phase 6 investigation](product-phase-6-app-import.md).
Current manual version 7.26 is not identical to the pinned target; admitting unknown
fields does not establish privilege support.

## Documented fields

| Level | Fields |
| --- | --- |
| App metadata | `name`, `descr`, `page`, `category`, `default-credentials`, `icon`, `url-path`, `auto-update`, `supported-archs`, `compatible-boards` |
| App structures | `services` (required map), `volumes`, `secrets`, `configs`, `networks` |
| Service | `image` (required), `container_name`, `command`, `entrypoint`, `environment`, `volumes`, `ports`, `expose`, `restart`, `depends_on`, `healthcheck`, `shm_size`, `stop_grace_period`, `devices`, `user`, `hostname`, `security_opt`, `build`, `secrets`, `configs` |

`supported-archs` uses RouterOS names (`arm`, `arm64`, `arm_v5`, `x86`), not OCI `linux/amd64`. MikroCentauri initially advertises `arm64` and `x86`; build images for linux/arm64 and linux/amd64. The Apps requirements section narrows current support to arm64/x86 even though the field reference lists more architectures. Avoid advertising unsupported ARM variants.

`privileged` and `cap_add` are **not listed** in the service field reference. `/container privileged` was added in 7.24, according to the [vendor announcement](https://forum.mikrotik.com/t/7-24-stable-is-released/272381). That does not prove equivalent app YAML accepts it. `working_dir` appears in that release's changelog but is absent from the current field reference. Limit baseline packaging to fields established by docs and lab import tests. A full TUN path may require separate capabilities/setup outside the baseline manifest; do not silently broaden privileges during installation.

## Ports and readiness

Syntax is `host:container` or `host:container:name`; `:web` integrates reverse proxy and app URL, while UDP uses the unusual `host:container/udp:name` form. TCP is the default. Port 80 is inferred as web unless explicitly named; if port 80 is absent the first port is used for probing. A non-listening inferred web port can leave an app stuck starting. Explicitly name every published port.

Keep the future UI/API web endpoint separate from RouterOS watchdog readiness. App web reachability is not proof of sing-box health. A dedicated internal port can return 200 at `/` only while the applied generation and sing-box are ready. Do not expose SOCKS, DNS, debugging, or watchdog ports on WAN through a broad mapping.

The field reference describes container healthcheck commands, but the [Container manual](https://manual.mikrotik.com/docs/containers/#healthcheck) dates underlying support to **7.23**. Keep Netwatch authoritative for fail-open at the required 7.22 floor. A manifest containing healthcheck must have a 7.22 import/runtime test before it is advertised as compatible.

## Networking and lifecycle

Default apps use an internal network behind NAT; external `networks.default.name: lan` with `external: true` places them on the LAN. Apps create VETH, bridge and NAT state automatically. The app object's `network=lan|internal|default` can affect this. `network-outgoing-access=no` creates a mangle drop rule and is a later addition in 7.24.

**ASSUMED packaging decision:** start with internal isolation for control-plane exposure. Full-gateway dataplane needs a controlled stable next hop and existing firewall review; external LAN placement exposes all container listeners unless firewalled. Do not treat automatic app setup as authoritative desired-state routing.

7.24 changed app VETH address retention on stop/start, per official release notes. On 7.22, discover assigned IP/interface after lifecycle changes; a persisted Netwatch target or route cannot rely on an untested stable IP. Runtime placeholders help configure the container, but they do not automatically update independently created RouterOS objects.

`/app cleanup` permanently deletes data and app-specific network configuration. It is not a substitute for MikroCentauri's dry-run/owned-object cleanup and export-before-uninstall workflow. Store state in app volumes, not the mutable image root. Preserve data through image updates; test this rather than inferring it from restart policy.

## Persistence, secrets, configs

Named volume mounting is documented as `data:/data`, plus app-storage subdirectories and relative mounts. Config declarations use a `content` string and service `source`, `target`, optional `mode`. Secrets may be declared as names, replaced into environment through `[secret:name]`, or mounted under `/run/secrets/<name>` using a service secrets list. RouterOS generates secret values when the app runs; persistence/rotation behavior needs a lab test. Do not use a generated secret placeholder as if it supplied the user's existing RouterOS password.

7.24 added sensitive handling to app secrets and randomized new-app secrets. Thus current docs are insufficient evidence that secret exposure protections are identical on 7.22. Prefer a credentials file mounted separately for the controller, protect its permissions, and redact environment/diagnostic exports. Avoid publishing default credentials or baking user secrets into YAML.

## Runtime placeholders

Documented: `[accessIP]`, `[accessPort]`, `[accessProto]`, `[containerIP]`, `[containerInterface]`, `[routerIP]`, `[env:variable]`, `[env:service:variable]`, `[secret:name]`. Placeholders are supported in environment values and default credentials. The docs do not establish replacement in arbitrary nested config JSON, scripts, route fields or volume content. The controller must read supplied runtime values and perform explicit discovery.

## Import and catalog

Documented installation methods:

```routeros
/app/add network=lan
/app/edit app yaml
```

or uploaded manifest contents:

```routeros
/app/add yaml=[/file/get mikrocentauri.yml contents]
```

A custom catalog is an HTTPS-hosted **YAML array** of app definitions, configured with `/app/settings set app-store-urls=<url>`. No public repository, catalog URL, registry location or icon URL has been assigned; do not invent one. Local build/import artifacts are sufficient for the research milestone.

## Conservative manifest skeleton

This is a **draft**, not an installation-tested release manifest. Supply an actual built image and immutable digest before use; the placeholder is intentionally invalid so it cannot accidentally install an unrelated image.

```yaml
name: mikrocentauri
descr: Selective routing controller and proxy engine
category: networking
auto-update: false
supported-archs:
  - arm64
  - x86
services:
  core:
    image: REQUIRED_ACTUAL_IMAGE_AT_IMMUTABLE_DIGEST
    container_name: mikrocentauri
    environment:
      MC_ROUTER_IP: "[routerIP]"
      MC_CONTAINER_IP: "[containerIP]"
      MC_CONTAINER_INTERFACE: "[containerInterface]"
    ports:
      - "8080:8080:web"
    volumes:
      - state:/var/lib/mikrocentauri
    restart: unless-stopped
volumes:
  state:
```

The documentation lists `unless-stopped` for app restart while the container property table separately lists `no/on-failure/always`. Test the translation on each target release. Digest image syntax, persistence on upgrade, generated firewall ordering, UI HTTPS trust, healthcheck and secrets all remain packaging acceptance tests.

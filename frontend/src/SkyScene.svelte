<script lang="ts">
  import type { SkyPreferences } from "./sky";
  let {
    settings,
    preview = false,
    enabled = true,
  }: {
    settings: SkyPreferences;
    preview?: boolean;
    enabled?: boolean;
  } = $props();
  const id = $props.id();
  // Deterministic vector field: stable between frames, no timers or canvas loop.
  const stars = Array.from({ length: 200 }, (_, i) => ({
    x: (i * 137.508 + 29) % 1000,
    y: (i * i * 17.31 + i * 81.7 + 43) % 700,
    r: i % 11 === 0 ? 1.7 : i % 3 === 0 ? 1 : 0.6,
    opacity: 0.35 + (i % 7) / 10,
  }));
  let visible = $derived(enabled && settings.mode !== "none");
</script>

<div
  class="sky-scene"
  class:sky-preview={preview}
  class:sky-motion={settings.motion && visible}
  aria-hidden="true"
>
  {#if visible}
    <svg viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid slice">
      <defs>
        <radialGradient id={id + "-cloud"}>
          <stop stop-color="#568bc8" stop-opacity=".22" />
          <stop offset="1" stop-color="#568bc8" stop-opacity="0" />
        </radialGradient>
      </defs>
      <g opacity={settings.brightness / 100}>
        <ellipse
          cx="760"
          cy="280"
          rx="460"
          ry="360"
          fill={"url(#" + id + "-cloud)"}
        />
        <g class="sky-drift" fill="currentColor">
          {#each stars.slice(0, settings.density * 2) as star}
            <circle
              cx={star.x}
              cy={star.y}
              r={(star.r * settings.scale) / 100}
              opacity={star.opacity}
            />
          {/each}
        </g>
        {#if settings.mode === "constellations"}
          <g
            class="sky-constellation"
            fill="none"
            stroke="currentColor"
            stroke-width=".65"
          >
            <path
              d="M580 190 L660 240 L748 200 L822 305 L760 394 L670 350 L660 240 M748 200 L850 160 L913 220"
              opacity=".3"
            />
            <path
              d="M96 440 L161 402 L214 475 L285 420 L320 510"
              opacity=".18"
            />
            {#each [[580, 190], [660, 240], [748, 200], [822, 305], [760, 394], [670, 350], [850, 160], [913, 220], [96, 440], [161, 402], [214, 475], [285, 420], [320, 510]] as point}
              <circle
                cx={point[0]}
                cy={point[1]}
                r="3"
                fill="currentColor"
                stroke="none"
              />
              <path
                d={`M${point[0] - 7} ${point[1]}h14 M${point[0]} ${point[1] - 7}v14`}
                opacity=".55"
              />
            {/each}
          </g>
        {/if}
      </g>
    </svg>
  {/if}
</div>

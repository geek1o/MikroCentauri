# Stellar interface acceptance — 2026-10-08

The interface adds an original vector sky, constellations and cool blue surfaces.
The login form contains one product name, a description, password field and login
action. Decorative orbital artwork sits beside it on wider screens.

System preferences expose sky mode, density, brightness, scale, motion and a
separate login-background switch. Changes preview immediately and persist only
on Save. Theme and sky are available as a public read-only appearance projection;
other preferences, routing state and credentials require authentication.
Old preference files remain valid; old clients preserve saved sky settings.

Validation:

- Production UI build: no Svelte errors/warnings; 13 unit tests pass.
- Frontend asset budget: 182,019 bytes, 56,962 gzip bytes; within enforced limits.
- Full Go race suite and vet pass; dedicated appearance race tests also pass.
- Browser acceptance covers saved appearance across fresh login, an empty browser
  storage, reduced motion, density changes, reset, mobile width and CSP.
- Existing browser workflows exercise list downloads, sections, reviewed apply,
  theme contrast and live switching against local sing-box over real HTTPS.
- Public appearance transport/client guards and authenticated writes are tested.

Screenshots use synthetic fixture data only. The persistent local preview retains
15 imported subscription endpoints, one running selector and 27 catalog entries.
RouterOS activation in this preview remains simulated; this visual acceptance
adds no native packet-path evidence.

Each browser specification uses fresh fixture state to prevent unrelated login
scenarios from exhausting the production authentication rate limiter. WebKit's
screenshot-only injected inline stylesheet is explicitly rejected by application
CSP and accounted for by the screenshot helper; application actions must produce
zero CSP violations.

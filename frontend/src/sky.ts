export interface SkyPreferences {
  mode: "none" | "stars" | "constellations";
  density: number;
  brightness: number;
  scale: number;
  motion: boolean;
  login: boolean;
}
export const defaultSky = (): SkyPreferences => ({
  mode: "constellations",
  density: 65,
  brightness: 65,
  scale: 100,
  motion: false,
  login: true,
});

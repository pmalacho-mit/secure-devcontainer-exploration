import {
  themeDark as dark,
  themeAbyss as abyss,
  themeDracula as dracula,
  themeVisualStudio as vs,
  themeLight as light,
  themeReplit as replit,
  themeAbyssSpaced as abyssSpaced,
  themeLightSpaced as lightSpaced,
} from "dockview-core";

const themes = {
  dark,
  abyss,
  dracula,
  vs,
  light,
  replit,
  abyssSpaced,
  lightSpaced,
};

export default themes;

export type Theme = keyof typeof themes;

export const themeOptions = Object.keys(themes) as Theme[];

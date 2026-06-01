import { ViewAPI } from ".";
import { AddedPanelByView } from "./utils";

export const defaultDuration = 500;

export function animateSize(
  { api }: AddedPanelByView<"grid" | "dock">,
  dimension: "width" | "height",
  {
    from,
    to,
    onComplete,
    duration = defaultDuration,
  }: {
    from: number;
    to: number;
    onComplete?: () => void;
    duration?: number;
  }
) {
  const start = performance.now();
  function frame(now: number) {
    const t = Math.min((now - start) / duration, 1);
    const easeInOut = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
    const eased = easeInOut * easeInOut * (3 - 2 * easeInOut);
    api.setSize({ [dimension]: from + (to - from) * eased });
    if (t < 1) requestAnimationFrame(frame);
    else onComplete?.();
  }
  requestAnimationFrame(frame);
}

export const animateEntry = (
  { panels, width }: ViewAPI<"grid", any>,
  { id }: AddedPanelByView<"grid">
) => {
  const entryWidth = width / panels.length;
  for (const panel of panels) {
    const isEntering = panel.id === id;
    const from = isEntering ? 0 : panel.width;
    const to = isEntering
      ? entryWidth
      : (panel.width / width) * (width - entryWidth);
    animateSize(panel, "width", { from, to });
  }
};

export const animateExit = (
  api: ViewAPI<"grid", any>,
  { id, width: exitingWidth }: AddedPanelByView<"grid">,
  onComplete: () => void,
  removePanelOnComplete = true
) => {
  const { panels, width: fullWidth } = api;
  const difference = fullWidth - exitingWidth;
  for (const panel of panels) {
    const isExiting = panel.id === id;
    const from = panel.width;
    const to = isExiting ? 0 : (panel.width / difference) * fullWidth;
    animateSize(panel, "width", {
      from,
      to,
      onComplete:
        isExiting && removePanelOnComplete
          ? () => (api.removePanel(panel), onComplete())
          : onComplete,
    });
  }
};

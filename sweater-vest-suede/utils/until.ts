export const untilNextFrame = () => new Promise(requestAnimationFrame);
export const untilMilliseconds = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

export default {
  nextFrame: untilNextFrame,
  milliseconds: untilMilliseconds,
};

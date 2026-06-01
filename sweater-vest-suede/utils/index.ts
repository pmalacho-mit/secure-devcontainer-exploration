/** Can be replaced in the future with `Promise.withResolvers` */
export const defer = <T>() => {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: any) => void;

  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
};

export type Deferred<T> = ReturnType<typeof defer<T>>;

export type KeyLike = string | number | symbol;

export const accumulate = <Key extends KeyLike, T>(keys: Key[], values: T[]) =>
  keys.reduce(
    (acc, curr, index) => {
      (acc as any)[curr] = values[index];
      return acc;
    },
    {} as Record<Key, T>,
  );

export const readableTimestamp = (date: Date = new Date()) => {
  const pad = (value: number) => value.toString().padStart(2, "0");
  return (
    [date.getFullYear(), pad(date.getMonth() + 1), pad(date.getDate())].join(
      "-",
    ) +
    `_at_${[pad(date.getHours()), pad(date.getMinutes()), pad(date.getSeconds())].join("-")}`
  );
};

export type Expand<T> = T extends infer O ? { [K in keyof O]: O[K] } : never;

export const sort = {
  byIndex: <T extends { index: number }>(a: T, b: T) => a.index - b.index,
};

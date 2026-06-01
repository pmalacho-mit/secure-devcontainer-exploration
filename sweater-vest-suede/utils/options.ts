import type { Expand } from ".";

/** Utility: remove only `undefined` while preserving `null` if present. */
type Defined<T> = Exclude<T, undefined>;

/**
 * A key is considered "defined-defaulted" when:
 * 1) the key exists in `Defaults`, and
 * 2) the default value type does not include `undefined`.
 *
 * This is the switch used by `ValuesOrDefaults` to decide whether a key
 * should be required in the final object shape.
 */
type HasDefinedDefault<D, K extends PropertyKey> = K extends keyof D
  ? undefined extends D[K]
    ? false
    : true
  : false;

/**
 * Computes the value type for one option key after defaulting.
 *
 * Behavior:
 * - Key has a defined default: remove `undefined` from option type.
 * - Key has no default (or an `undefined` default): keep `| undefined`.
 * - String-valued keys are widened to `(string & {})` so callers get flexible
 *   string assignment while still preserving literal default completions.
 */
export type ValueOrDefault<
  Options extends Record<string, any>,
  Defaults extends Partial<Options>,
  K extends keyof Options,
> = K extends keyof Defaults
  ? undefined extends Defaults[K]
    ? Options[K] | undefined
    : NonNullable<Options[K]> extends string
      ? (string & {}) | Defined<Defaults[K]> // widen but keep literal autocomplete
      : NonNullable<Options[K]> | Defined<Defaults[K]>
  : Options[K] | undefined;

/**
 * Computes an object shape for a selected key set `K`.
 *
 * - Keys with defined defaults become required (`-?`).
 * - Remaining keys stay optional (`?`) and therefore retain `| undefined`.
 *
 * This gives ergonomic destructuring for guaranteed defaults while keeping
 * non-defaulted option keys correctly nullable/optional.
 */
export type ValuesOrDefaults<
  Options extends Record<string, any>,
  Defaults extends Partial<Options>,
  K extends keyof Options,
> = Expand<
  {
    [P in K as HasDefinedDefault<Defaults, P> extends true
      ? P
      : never]-?: ValueOrDefault<Options, Defaults, P>;
  } & {
    [P in K as HasDefinedDefault<Defaults, P> extends true
      ? never
      : P]?: ValueOrDefault<Options, Defaults, P>;
  }
>;

/**
 * Returns one option value, falling back to defaults at runtime.
 */
export const getOrDefault = <
  Options extends Record<string, any>,
  Defaults extends Partial<Options>,
  K extends keyof Options,
>(
  options: Options,
  defaults: Defaults,
  key: K,
) => (options[key] ?? defaults[key]) as ValueOrDefault<Options, Defaults, K>;

/**
 * Returns a partial options object for the selected keys with per-key
 * defaulting semantics preserved in the resulting type.
 */
export const getOrDefaults = <
  Options extends Record<string, any>,
  Defaults extends Partial<Options>,
  K extends keyof Options,
>(
  options: Options,
  defaults: Defaults,
  ...keys: K[]
) => {
  const result = {} as ValuesOrDefaults<Options, Defaults, K>;
  for (const key of keys)
    (result as any)[key] = getOrDefault(options, defaults, key);
  return result;
};

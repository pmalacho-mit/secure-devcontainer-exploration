// Helper: distributes over `M` so that when M = boolean (the generic-Flag
// default), the resulting type is the union T | readonly T[], keeping
// specific Flag instances assignable to the generic Flag.
type _DefaultValue<T, M extends boolean> = M extends true
  ? T | readonly T[]
  : T;

export type Flag<
  T extends string | number | boolean = string | number | boolean,
  Long extends string = string,
  Config extends { default: boolean; multiple: boolean } = {
    default: boolean;
    multiple: boolean;
  },
> = {
  longform: Long;
  description: string;
  shorthand?: string;
  multiple: Config["multiple"];
} & (Config["default"] extends true
  ? { default: _DefaultValue<T, Config["multiple"]> }
  : { default?: _DefaultValue<T, Config["multiple"]> | undefined }) &
  (T extends string | number ? { options?: T[] } : {}) &
  (T extends boolean
    ? { negation?: { longform: string; shorthand?: string } }
    : {});

namespace Arguments {
  type SingleDefault = string | number | boolean;
  type PluralDefault = string | number;
  type Options = {
    [T in string | number]: T[] | ReadonlyArray<T>;
  }[string | number];
  type Description = string;
  type Name = string | readonly [longform: string, shorthand: string];
  type Negation = Name;

  export type Single = readonly [
    Name,
    Description,
    ...(
      | []
      | [SingleDefault]
      | [Options]
      | [Extract<SingleDefault, boolean>, Negation]
      | [Options, SingleDefault]
    ),
  ];

  export type Plural = readonly [
    Name,
    Description,
    ...([] | [PluralDefault] | [Options] | [Options, PluralDefault]),
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// flag() — boolean overloads
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Boolean flag. Presence of `--<name>` sets the value to `true`; presence of the
 * negation form sets it to `false`, which since it is not specified defaults to `no-<longform>` (e.g. `--no-verbose`).
 * The default value determines what is returned when neither form appears.
 * @example cli.flag("verbose", "Enable verbose output", false)
 *   → --verbose / --no-verbose
 */
export function flag<const L extends string>(
  name: L,
  description: string,
  _default: boolean,
): Flag<boolean, L, { multiple: false; default: true }>;

/**
 * Boolean flag with an explicit negation longform (e.g. `--concise`).
 * @example cli.flag("verbose", "Enable verbose output", false, "concise")
 *   → --verbose / --concise
 */
export function flag<const L extends string>(
  name: L,
  description: string,
  _default: boolean,
  negation: string,
): Flag<boolean, L, { multiple: false; default: true }>;

/**
 * Boolean flag with a shorthand for the positive form.
 * @example cli.flag(["verbose", "v"], "Enable verbose output", false)
 *   → -v/--verbose / --no-verbose
 */
export function flag<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: boolean,
): Flag<boolean, L, { multiple: false; default: true }>;

/**
 * Boolean flag with a shorthand and an explicit negation longform.
 * @example cli.flag(["verbose", "v"], "Enable verbose output", false, "concise")
 *   → -v/--verbose / --concise
 */
export function flag<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: boolean,
  negation: string,
): Flag<boolean, L, { multiple: false; default: true }>;

/**
 * Boolean flag with shorthands for both the positive and negative forms.
 * @example cli.flag(["verbose", "v"], "Enable verbose output", false, ["no-verbose", "V"])
 *   → -v/--verbose / -V/--no-verbose
 */
export function flag<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: boolean,
  negation: readonly [longform: string, shorthand: string],
): Flag<boolean, L, { multiple: false; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flag() — numeric overloads (plain number, not enum)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Numeric flag. The raw string argument is parsed with `Number()` and the
 * result is guaranteed non-`undefined` (the default is always applied).
 * @example cli.flag("timeout", "Request timeout ms", 5000)  → --timeout <number>
 */
export function flag<const L extends string>(
  name: L,
  description: string,
  _default: number,
): Flag<number, L, { multiple: false; default: true }>;

/**
 * Numeric flag with a shorthand alias.
 * @example cli.flag(["timeout", "t"], "Request timeout ms", 5000)  → -t/--timeout <number>
 */
export function flag<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: number,
): Flag<number, L, { multiple: false; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flag() — string-enum overloads
// ─────────────────────────────────────────────────────────────────────────────

/**
 * String-enum flag. Values are validated against `options` at parse time;
 * an `InvalidOptionError` is thrown for unlisted values. Result is
 * `Options | undefined` because no default is provided.
 * @example cli.flag("env", "Deploy target", ["production", "staging", "development"])
 */
export function flag<const L extends string, const Options extends string>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: false; default: false }>;

/**
 * String-enum flag with a default value (result is `Options`, never `undefined`).
 * @example cli.flag("env", "Deploy target", ["production", "staging"], "staging")
 */
export function flag<const L extends string, const Options extends string>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default: NoInfer<Options>,
): Flag<Options, L, { multiple: false; default: true }>;

/**
 * String-enum flag with a shorthand alias.
 * @example cli.flag(["env", "e"], "Deploy target", ["production", "staging"])
 */
export function flag<const L extends string, const Options extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: false; default: false }>;

/**
 * String-enum flag with a shorthand alias and a default value.
 * @example cli.flag(["env", "e"], "Deploy target", ["production", "staging"], "staging")
 */
export function flag<const L extends string, const Options extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default: NoInfer<Options>,
): Flag<Options, L, { multiple: false; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flag() — numeric-enum overloads
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Numeric-enum flag. Values are parsed as numbers and validated against
 * `options`; result is `Options | undefined`.
 * @example cli.flag("workers", "Thread count", [1, 2, 4, 8])
 */
export function flag<const L extends string, const Options extends number>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: false; default: false }>;

/**
 * Numeric-enum flag with a default value (result is `Options`, never `undefined`).
 * @example cli.flag("workers", "Thread count", [1, 2, 4, 8], 4)
 */
export function flag<const L extends string, const Options extends number>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default: NoInfer<Options>,
): Flag<Options, L, { multiple: false; default: true }>;

/**
 * Numeric-enum flag with a shorthand alias.
 */
export function flag<const L extends string, const Options extends number>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: false; default: false }>;

/**
 * Numeric-enum flag with a shorthand alias and default value.
 */
export function flag<const L extends string, const Options extends number>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default: NoInfer<Options>,
): Flag<Options, L, { multiple: false; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flag() — plain string overloads (least specific; must come last)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Optional plain-string flag (result is `string | undefined`).
 * @example cli.flag("output", "Output file path")  → --output <value>
 */
export function flag<const L extends string>(
  name: L,
  description: string,
): Flag<string, L, { multiple: false; default: false }>;

/**
 * Plain-string flag with a default (result is `string`, never `undefined`).
 * @example cli.flag("output", "Output file path", "./dist")
 */
export function flag<const L extends string>(
  name: L,
  description: string,
  _default: string,
): Flag<string, L, { multiple: false; default: true }>;

/**
 * Plain-string flag with a shorthand alias (result is `string | undefined`).
 * @example cli.flag(["output", "o"], "Output file path")  → -o/--output <value>
 */
export function flag<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
): Flag<string, L, { multiple: false; default: false }>;

/**
 * Plain-string flag with a shorthand alias and default.
 * @example cli.flag(["output", "o"], "Output file path", "./dist")
 */
export function flag<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: string,
): Flag<string, L, { multiple: false; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flag() — implementation
// ─────────────────────────────────────────────────────────────────────────────

export function flag(...args: Arguments.Single): any {
  return build(args, false);
}

// ─────────────────────────────────────────────────────────────────────────────
// flags() — numeric (plain) overloads
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Multi-value numeric flag. Each `--<name> <n>` adds a parsed number to the
 * result array. The default seeds the array when the flag is absent.
 * @example cli.flags("port", "Bind port", 8080)  → --port <number> (repeatable)
 */
export function flags<const L extends string>(
  name: L,
  description: string,
  _default: number,
): Flag<number, L, { multiple: true; default: true }>;

/**
 * Multi-value numeric flag with a shorthand alias.
 * @example cli.flags(["port", "p"], "Bind port", 8080)
 */
export function flags<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: number,
): Flag<number, L, { multiple: true; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flags() — string-enum overloads
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Multi-value string-enum flag. Repeated `--<name> <value>` invocations build
 * an array; each value is validated against `options`.
 * @example cli.flags("tag", "Filter tag", ["alpha", "beta", "stable"])
 */
export function flags<const L extends string, const Options extends string>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: true; default: false }>;

/**
 * Multi-value string-enum flag with a default seed. The seed may be one
 * option or an array of options.
 * @example cli.flags("tag", "Filter tag", ["alpha", "beta"], "stable")
 * @example cli.flags("tag", "Filter tag", ["alpha", "beta", "stable"], ["alpha", "beta"])
 */
export function flags<const L extends string, const Options extends string>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default:
    | NoInfer<Options>
    | NoInfer<Options>[]
    | ReadonlyArray<NoInfer<Options>>,
): Flag<Options, L, { multiple: true; default: true }>;

/**
 * Multi-value string-enum flag with a shorthand alias.
 * @example cli.flags(["tag", "t"], "Filter tag", ["alpha", "beta", "stable"])
 */
export function flags<const L extends string, const Options extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: true; default: false }>;

/**
 * Multi-value string-enum flag with a shorthand alias and default seed. The
 * seed may be one option or an array of options.
 * @example cli.flags(["tag", "t"], "Filter tag", ["alpha", "beta"], "stable")
 * @example cli.flags(["tag", "t"], "Filter tag", ["alpha", "beta", "stable"], ["alpha", "beta"])
 */
export function flags<const L extends string, const Options extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default:
    | NoInfer<Options>
    | NoInfer<Options>[]
    | ReadonlyArray<NoInfer<Options>>,
): Flag<Options, L, { multiple: true; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flags() — numeric-enum overloads
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Multi-value numeric-enum flag.
 * @example cli.flags("worker", "Worker count", [1, 2, 4, 8])
 */
export function flags<const L extends string, const Options extends number>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: true; default: false }>;

/**
 * Multi-value numeric-enum flag with a default seed. The seed may be one
 * option or an array of options.
 */
export function flags<const L extends string, const Options extends number>(
  name: L,
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default:
    | NoInfer<Options>
    | NoInfer<Options>[]
    | ReadonlyArray<NoInfer<Options>>,
): Flag<Options, L, { multiple: true; default: true }>;

/**
 * Multi-value numeric-enum flag with a shorthand alias.
 */
export function flags<const L extends string, const Options extends number>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
): Flag<Options, L, { multiple: true; default: false }>;

/**
 * Multi-value numeric-enum flag with a shorthand alias and default seed. The
 * seed may be one option or an array of options.
 */
export function flags<const L extends string, const Options extends number>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  options: Options[] | ReadonlyArray<Options>,
  _default:
    | NoInfer<Options>
    | NoInfer<Options>[]
    | ReadonlyArray<NoInfer<Options>>,
): Flag<Options, L, { multiple: true; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flags() — plain string overloads (least specific; must come last)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Multi-value plain-string flag (result is `string[]`, possibly empty).
 * @example cli.flags("include", "Paths to include")  → --include <value> (repeatable)
 */
export function flags<const L extends string>(
  name: L,
  description: string,
): Flag<string, L, { multiple: true; default: false }>;

/**
 * Multi-value plain-string flag with a default seed value.
 * @example cli.flags("include", "Paths to include", "src")
 */
export function flags<const L extends string>(
  name: L,
  description: string,
  _default: string,
): Flag<string, L, { multiple: true; default: true }>;

/**
 * Multi-value plain-string flag with a shorthand alias.
 * @example cli.flags(["include", "i"], "Paths to include")
 */
export function flags<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
): Flag<string, L, { multiple: true; default: false }>;

/**
 * Multi-value plain-string flag with a shorthand alias and default seed.
 * @example cli.flags(["include", "i"], "Paths to include", "src")
 */
export function flags<const L extends string>(
  names: readonly [longform: L, shorthand: string],
  description: string,
  _default: string,
): Flag<string, L, { multiple: true; default: true }>;

// ─────────────────────────────────────────────────────────────────────────────
// flags() — implementation
// ─────────────────────────────────────────────────────────────────────────────

export function flags(...args: Arguments.Plural): any {
  return build(args, true);
}

// ─────────────────────────────────────────────────────────────────────────────
// shared builder
// ─────────────────────────────────────────────────────────────────────────────

const build = (
  args: Arguments.Single | Arguments.Plural,
  multiple: boolean,
): Flag => {
  const [names, description, third, fourth] = args;
  const base = {
    longform: Array.isArray(names) ? names[0] : names,
    description,
    multiple,
    ...(Array.isArray(names) &&
      names[1] !== undefined && { shorthand: names[1] }),
  };

  if (typeof third === "boolean") {
    if (multiple)
      throw new Error(
        "flags(): boolean is not a valid multi-value type; use flag() for booleans",
      );
    const negation = Array.isArray(fourth)
      ? { longform: fourth[0], shorthand: fourth[1] }
      : fourth !== undefined
        ? { longform: fourth }
        : undefined;
    return { ...base, default: third, negation } as Flag;
  }

  if (typeof third === "number") return { ...base, default: third } as Flag;

  if (Array.isArray(third))
    return {
      ...base,
      options: third,
      ...(fourth !== undefined && { default: fourth }),
    } as Flag;

  return { ...base, ...(third !== undefined && { default: third }) } as Flag;
};

export const is = <const T extends "string" | "number" | "boolean">(
  flag: Flag,
  type: T,
): flag is Flag<
  T extends "string" ? string : T extends "number" ? number : boolean
> => {
  if (flag.default !== undefined) {
    // multi flags may carry an array of seed values — sample the first element.
    const sample = Array.isArray(flag.default) ? flag.default[0] : flag.default;
    if (sample !== undefined)
      switch (type) {
        case "boolean":
          return typeof sample === "boolean";
        case "number":
          return typeof sample === "number";
        case "string":
          return typeof sample === "string";
      }
  }

  if (type === "boolean") return false;

  if (!("options" in flag)) return type === "string";

  return (
    Array.isArray(flag.options) &&
    flag.options.length > 0 &&
    typeof flag.options[0] === type
  );
};

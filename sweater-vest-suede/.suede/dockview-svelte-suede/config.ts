import type { Renderables, ViewAPI, ViewKey } from ".";
import type { Chainable, TryGet } from "./utils/types";

export const panel = <T extends ViewKey>(type?: T) => {
  type API = ViewAPI<T, Renderables<T>>;
  type ExtractConfigParameter<Key extends string> = TryGet<Key, API> extends (
    ...args: infer Args
  ) => any
    ? Args[2]
    : never;

  type ConfigParameter = Exclude<
    ExtractConfigParameter<"addSnippetPanel"> &
      ExtractConfigParameter<"addComponentPanel">,
    undefined
  >;
  type Position = TryGet<"position", ConfigParameter>;
  type Reference = string;

  type WithReference<T = any> = { reference: T };

  interface Customized {
    direction: (
      direction: TryGet<"direction", Position>
    ) => Customized & Chainable<ConfigParameter, Customized>;
    reference: (
      reference: Reference | WithReference<Reference>
    ) => Customized & Chainable<ConfigParameter, Customized>;
    (): Exclude<ConfigParameter, undefined>;
  }

  let options = {} as Record<string, any>;

  const proxy = new Proxy(() => options, {
    get(_, prop) {
      switch (prop as keyof Customized) {
        case "direction":
          return ((direction) => {
            options["position"] ??= {};
            options["position"]["direction"] = direction;
            return proxy;
          }) satisfies Customized["direction"];
        case "reference":
          return ((reference) => {
            options["position"] ??= {};
            options["position"]["referencePanel"] =
              typeof reference === "string"
                ? reference
                : (reference as WithReference).reference;
            return proxy;
          }) satisfies Customized["reference"];
        default:
          return (setting: any) => {
            options[prop as string] = setting;
            return proxy;
          };
      }
    },
  }) as Chainable<ConfigParameter, Customized> & Customized;

  return proxy;
};

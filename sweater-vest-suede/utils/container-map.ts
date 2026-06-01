import type Container from "../Container.svelte";
import { getContext, setContext } from "svelte";

type ContainerMapSupplement = {
  total: number;
  find(index: number): Container | undefined;
  set current(container: Container);
  get context(): Container | undefined;
  each(callback: (container: Container) => void): void;
  reset(): void;
};

type ContainerMap = Record<number, Container> &
  Map<number, Container> &
  ContainerMapSupplement;

export const createContainerMap = () => {
  const contextKey = "container";
  const contexts: Container[] = [];
  return new Proxy(new Map<number, Container>() as ContainerMap, {
    get(target, prop) {
      const key = prop as keyof ContainerMapSupplement;

      switch (key) {
        case "context":
          return getContext(contextKey) satisfies ContainerMap[typeof key];
        case "find":
          return ((index: number) => {
            while (!target.has(index) && index >= 0) index--;
            const container = target.get(index);
            return container;
          }) satisfies ContainerMap[typeof key];
        case "total":
          return (target.size +
            contexts.length) satisfies ContainerMap[typeof key];
        case "each":
          return ((callback: (container: Container) => void) => {
            for (const container of target.values()) callback(container);
            for (const context of contexts) callback(context);
          }) satisfies ContainerMap[typeof key];
        case "reset":
          return (() => {
            target.clear();
            contexts.length = 0;
          }) satisfies ContainerMap[typeof key];
      }

      const numeric = parseInt(String(prop));
      if (isNaN(numeric)) return target[prop as keyof typeof target];
      return target.get(numeric);
    },
    set(target, prop, value) {
      const key = prop as keyof ContainerMapSupplement;

      switch (key) {
        case "current":
          const current = value as ContainerMap[typeof key];
          setContext(contextKey, current);
          contexts.push(value);
          return true;
      }

      const numeric = parseInt(String(prop));
      if (isNaN(numeric)) return true;
      target.set(numeric, value);
      return true;
    },
  });
};

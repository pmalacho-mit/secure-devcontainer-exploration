export type Fn = (...args: any[]) => any;

export type ExcludeOptional<T extends object> = {
  [K in keyof T as undefined extends T[K] ? never : K]: T[K];
};

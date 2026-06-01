import DockView from "./DockView.svelte";
import PaneView from "./PaneView.svelte";
import SplitView from "./SplitView.svelte";
import GridView from "./GridView.svelte";
import DefaultDockTab, {
  type Props as DefaultDockTabProps,
} from "./dock/DefaultDockTab.svelte";
import type {
  IDockviewHeaderActionsProps,
  IDockviewPanelHeaderProps,
  IDockviewPanelProps,
  IWatermarkPanelProps,
} from "dockview-core";
import type {
  IPaneviewPanelProps,
  ISplitviewPanelProps,
  IGridviewPanelProps,
} from "dockview";
import type {
  ViewKey,
  ComponentsConstraint,
  SnippetsConstraint,
  ModifiedProps,
  AdditionalAddPanelOptions,
  PanePanelHeaderConstraint,
  ExtractComponentsFromRenderables,
  ExtractSnippetsFromRenderables,
  AddedPanelByView,
  Renderables,
} from "./utils/index.js";
import { reactive } from "./utils/index.js";
import themes, { type Theme, themeOptions } from "./utils/themes.js";
import { Orientation } from "dockview-core";

export {
  DockView,
  PaneView,
  SplitView,
  GridView,
  Orientation,
  reactive,
  themes,
  themeOptions,
  DefaultDockTab,
};

export type {
  AddedPanelByView,
  ViewKey,
  Theme,
  DefaultDockTabProps,
  Renderables,
};

export type PanelProps<
  T extends ViewKey,
  Options extends Record<string, any>
> = {
  grid: IGridviewPanelProps<Options>;
  dock: IDockviewPanelProps<Options>;
  pane: IPaneviewPanelProps<Options>;
  split: ISplitviewPanelProps<Options>;
}[T];

export type AuxiliaryDockPanelProps = {
  watermark: IWatermarkPanelProps;
  tab: IDockviewPanelHeaderProps;
  headerAction: IDockviewHeaderActionsProps;
};

export type ViewProps<
  ViewType extends ViewKey,
  Renderables extends Record<
    string,
    | ComponentsConstraint<ViewType>[string]
    | SnippetsConstraint<ViewType>[string]
  >,
  Additional extends AdditionalAddPanelOptions<ViewType> = never
> = ModifiedProps<
  ViewType,
  keyof ExtractComponentsFromRenderables<ViewType, Renderables> extends never
    ? ComponentsConstraint<ViewType> & Record<never, never>
    : ExtractComponentsFromRenderables<ViewType, Renderables>,
  keyof ExtractSnippetsFromRenderables<ViewType, Renderables> extends never
    ? SnippetsConstraint<ViewType> & Record<never, never>
    : ExtractSnippetsFromRenderables<ViewType, Renderables>,
  Additional
>;

export type WithViewOnReady<
  ViewType extends ViewKey,
  Renderables extends Record<
    string,
    | ComponentsConstraint<ViewType>[string]
    | SnippetsConstraint<ViewType>[string]
  >,
  Additional extends AdditionalAddPanelOptions<ViewType> = ViewType extends "pane"
    ? { headers: PanePanelHeaderConstraint }
    : never
> = Pick<ViewProps<ViewType, Renderables, Additional>, "onReady">;

export type ViewAPI<
  ViewType extends ViewKey,
  Renderables extends Record<
    string,
    | ComponentsConstraint<ViewType>[string]
    | SnippetsConstraint<ViewType>[string]
  >,
  Additional extends AdditionalAddPanelOptions<ViewType> = ViewType extends "pane"
    ? { headers: PanePanelHeaderConstraint }
    : never
> = "api" extends keyof Parameters<
  Required<ViewProps<ViewType, Renderables, Additional>>["onReady"]
>[0]
  ? Parameters<
      Required<ViewProps<ViewType, Renderables, Additional>>["onReady"]
    >[0]["api"]
  : never;

export type ViewHelper<
  Type extends ViewKey,
  Views extends Renderables<Type>
> = {
  api: ViewAPI<Type, Views>;
} & WithViewOnReady<Type, Views>;

export type ViewsHelper<
  T extends Record<string, { type: ViewKey } | Renderables<ViewKey>>
> = {
  [K in keyof T]: T[K]["type"] extends ViewKey
    ? Omit<T[K], "type"> extends Renderables<T[K]["type"]>
      ? ViewHelper<T[K]["type"], Omit<T[K], "type">>
      : never
    : never;
};

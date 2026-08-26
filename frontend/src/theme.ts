// theme.ts —— 昼夜主题偏好：跟随系统 / 亮 / 暗，持久化到 localStorage。

export type ThemePref = "system" | "light" | "dark";

const KEY = "pocwb-theme";

export function getPref(): ThemePref {
  const v = localStorage.getItem(KEY);
  return v === "light" || v === "dark" ? v : "system";
}

export function resolvedTheme(): "light" | "dark" {
  if (getPref() === "dark") return "dark";
  if (getPref() === "light") return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

const listeners = new Set<() => void>();

export function applyTheme(pref: ThemePref) {
  localStorage.setItem(KEY, pref);
  const resolved = resolvedTheme();
  document.documentElement.dataset.theme = resolved;
  listeners.forEach((fn) => fn());
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const onSystem = () => { if (getPref() === "system") fn(); };
  mq.addEventListener("change", onSystem);
  return () => {
    listeners.delete(fn);
    mq.removeEventListener("change", onSystem);
  };
}

import { useSyncExternalStore } from "react";

export function useResolvedTheme(): "light" | "dark" {
  return useSyncExternalStore(subscribe, resolvedTheme, () => "light" as const);
}

/** 应用启动时调用一次。 */
export function initTheme() {
  applyTheme(getPref());
}

import { useEffect, useState } from "react";
import { Minus, X, Copy } from "lucide-react";
import {
  LayoutDashboard, Database, FilePlus2, BookMarked,
  PlayCircle, Settings2,
} from "lucide-react";
import { api, win } from "./api";
import Dashboard from "./pages/Dashboard";
import PocList from "./pages/PocList";
import PocDetail from "./pages/PocDetail";
import PocForm from "./pages/PocForm";
import Dict from "./pages/Dict";
import TestPage from "./pages/TestPage";
import Settings from "./pages/Settings";

export type Route =
  | { page: "dashboard" }
  | { page: "list"; status?: string; severity?: string }
  | { page: "detail"; uid: string }
  | { page: "create" }
  | { page: "edit"; uid: string }
  | { page: "dict" }
  | { page: "test"; uid?: string }
  | { page: "settings" };

const NAV = [
  { key: "dashboard", label: "总览", icon: LayoutDashboard, route: { page: "dashboard" } as Route },
  { key: "list", label: "PoC 库", icon: Database, route: { page: "list" } as Route },
  { key: "create", label: "新增 PoC", icon: FilePlus2, route: { page: "create" } as Route },
  { key: "dict", label: "字典", icon: BookMarked, route: { page: "dict" } as Route },
  { key: "test", label: "验证测试", icon: PlayCircle, route: { page: "test" } as Route },
  { key: "settings", label: "设置", icon: Settings2, route: { page: "settings" } as Route },
];

export default function App() {
  const [route, setRoute] = useState<Route>({ page: "list" });
  const nav = (r: Route) => setRoute(r);
  // 后端启动失败：持久横幅展示，不阻塞其余 UI
  const [startupErr, setStartupErr] = useState("");

  useEffect(() => {
    // OnStartup 阶段的事件先于本监听器注册，须挂载后主动拉取兜底
    api.onStartupError((msg) => setStartupErr(msg));
    api.startupError().then((msg) => {
      if (msg) setStartupErr(msg);
    }).catch(() => {});
    return () => api.offStartupError();
  }, []);

  const activeKey =
    route.page === "detail" ? "list"
    : route.page === "edit" ? "create"
    : route.page;

  return (
    <div className="flex h-screen overflow-hidden">
      {/* ── 侧边栏：整列通顶（含自己的标题拖拽区）── */}
      <aside
        className="flex w-56 shrink-0 flex-col border-r bg-[var(--bg-side)]"
        style={{ borderColor: "var(--line)" }}
      >
        <div
          className="flex h-10 shrink-0 items-center px-4 select-none"
          style={{ ["--wails-draggable" as string]: "drag" }}
        >
          <span className="text-[15px] font-semibold text-slate-100 dark:text-slate-100" style={{ color: "var(--txt)" }}>破壳 PoCShell</span>
        </div>

        <nav className="flex flex-col gap-px px-2">
          {NAV.map((n) => {
            const Icon = n.icon;
            const active = activeKey === n.key;
            return (
              <button
                key={n.key}
                onClick={() => nav(n.route)}
                className={`flex h-10 items-center gap-2.5 rounded-lg px-3 text-sm transition-colors duration-150 ${
                  active
                    ? "bg-[var(--accent)] font-medium text-white"
                    : "text-[var(--txt-dim)] hover:bg-[var(--hover)] hover:text-[var(--txt)]"
                }`}
              >
                <Icon size={17} strokeWidth={active ? 2 : 1.7} />
                {n.label}
              </button>
            );
          })}
        </nav>

        <div className="mt-auto px-5 pb-4">
          <div className="font-mono-data text-[11px] leading-relaxed text-[var(--txt-faint)]">
            PWF v1 · SQLite<br />
            engine: internal
          </div>
        </div>
      </aside>

      {/* ── 主区：自己的顶部条（拖拽 + 窗控悬浮右上）── */}
      <main className="relative flex min-w-0 flex-1 flex-col">
        <div
          className="flex h-10 shrink-0 items-center justify-end"
          style={{ ["--wails-draggable" as string]: "drag" }}
        >
          <div
            className="flex h-full"
            style={{ ["--wails-draggable" as string]: "noDrag" }}
          >
            <WinBtn onClick={() => win.minimize()}><Minus size={14} strokeWidth={1.8} /></WinBtn>
            <WinBtn onClick={() => win.toggleMaximize()}><Copy size={11} strokeWidth={2} /></WinBtn>
            <WinBtn onClick={() => win.close()} danger><X size={15} strokeWidth={1.8} /></WinBtn>
          </div>
        </div>

        {startupErr && (
          <div
            className="shrink-0 border-b px-5 py-2 text-[13px] text-[var(--danger)]"
            style={{ borderColor: "var(--line)", background: "var(--bg-panel)" }}
          >
            后端启动失败：{startupErr}
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-auto p-5 pt-1">
          {route.page === "dashboard" && <Dashboard onNav={nav} />}
          {route.page === "list" && <PocList onNav={nav} initialStatus={route.status ?? ""} initialSeverity={route.severity ?? ""} />}
          {route.page === "detail" && <PocDetail uid={route.uid} onNav={nav} />}
          {route.page === "create" && <PocForm mode="create" onNav={nav} />}
          {route.page === "edit" && <PocForm mode="edit" uid={route.uid} onNav={nav} />}
          {route.page === "dict" && <Dict />}
          {route.page === "test" && <TestPage presetUid={route.uid} />}
          {route.page === "settings" && <Settings />}
        </div>
      </main>
    </div>
  );
}

function WinBtn({ children, onClick, danger }: {
  children: React.ReactNode; onClick: () => void; danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex h-full w-11 items-center justify-center text-[var(--txt-dim)] transition-colors duration-150 ${
        danger ? "hover:bg-[var(--danger)] hover:text-white" : "hover:bg-[var(--hover)]"
      }`}
    >
      {children}
    </button>
  );
}

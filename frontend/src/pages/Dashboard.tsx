import { useEffect, useState } from "react";
import { FilePlus2, ClipboardPaste, ShieldCheck } from "lucide-react";
import { api, sevColor, type DashboardData } from "../api";
import type { Route } from "../App";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Dashboard({ onNav }: { onNav: (r: Route) => void }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.dashboard().then(setData).catch((e: unknown) =>
      setErr(e instanceof Error ? e.message : String(e)),
    );
  }, []);

  if (err) return <div className="text-[var(--danger)]">{err}</div>;
  if (!data) return <div className="text-sm text-[var(--txt-dim)]">加载中…</div>;

  // ── 空状态：第一屏应该是引导，不是一堆零 ──
  if ((data.totalPocs ?? 0) === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="w-[460px] space-y-7 text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--chip)]">
            <ShieldCheck size={30} strokeWidth={1.5} className="text-[var(--accent)]" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-[var(--txt)]">PoC 库还是空的</h1>
            <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--txt-dim)]">
              从现有 Xray 模板一键转换导入，或手动逐项创建。
              <br />
              所有数据存储在本地 SQLite，格式统一为 PWF。
            </p>
          </div>
          <div className="flex justify-center gap-2.5">
            <button
              onClick={() => onNav({ page: "create" })}
              className="flex h-9 items-center gap-1.5 rounded-lg bg-[var(--accent)] px-4 text-[13px] font-medium text-white transition-colors duration-150 hover:brightness-110"
            >
              <ClipboardPaste size={14} strokeWidth={2} /> 粘贴 Xray 导入
            </button>
            <button
              onClick={() => onNav({ page: "create" })}
              className="flex h-9 items-center gap-1.5 rounded-lg border px-4 text-[13px] text-[var(--txt)] transition-colors duration-150 hover:bg-[var(--hover)]"
              style={{ borderColor: "var(--line-strong)" }}
            >
              <FilePlus2 size={14} strokeWidth={2} /> 手动创建
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── 有数据：紧凑统计条 + 双栏结构 ──
  const maxSev = Math.max(1, ...SEV_ORDER.map((s) => data.bySeverity[s] ?? 0));

  return (
    <div className="space-y-6">
      <div className="flex items-baseline gap-4 border-b pb-3" style={{ borderColor: "var(--line)" }}>
        <h1 className="text-base font-semibold text-[var(--txt)]">总览</h1>
        <span className="tabular font-mono-data text-xs text-[var(--txt-dim)]">{data.totalPocs} 个 PoC</span>
      </div>

      <div className="grid grid-cols-5 gap-px overflow-hidden rounded-lg border" style={{ borderColor: "var(--line)", background: "var(--line)" }}>
        {[
          { label: "已测试", value: data.byStatus["tested"] ?? 0 },
          { label: "未测试", value: data.byStatus["untested"] ?? 0 },
          { label: "失败", value: data.byStatus["failed"] ?? 0 },
          { label: "假 PoC", value: data.byStatus["faked"] ?? 0 },
          { label: "测试次数", value: data.totalTestRuns },
        ].map((c) => (
          <div key={c.label} className="bg-[var(--bg-panel)] px-4 py-3">
            <div className="text-[11px] text-[var(--txt-dim)]">{c.label}</div>
            <div className="tabular mt-1 font-mono-data text-base font-semibold text-[var(--txt)]">{c.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        <section className="rounded-lg border p-4" style={{ borderColor: "var(--line)" }}>
          <div className="mb-3 text-[11px] text-[var(--txt-dim)]">按严重度</div>
          <div className="space-y-2.5">
            {SEV_ORDER.map((s) => {
              const n = data.bySeverity[s] ?? 0;
              return (
                <button
                  key={s}
                  onClick={() => onNav({ page: "list" })}
                  className="flex w-full items-center gap-2.5 rounded text-left"
                >
                  <span className={`h-2 w-2 shrink-0 rounded-full ${sevColor(s)}`} />
                  <span className="w-14 shrink-0 font-mono-data text-xs text-[var(--txt)]">{s}</span>
                  <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--track)]">
                    <span
                      className={`block h-full rounded-full ${sevColor(s)} opacity-60`}
                      style={{ width: `${(n / maxSev) * 100}%` }}
                    />
                  </span>
                  <span className="tabular w-8 shrink-0 text-right font-mono-data text-xs text-[var(--txt-dim)]">{n}</span>
                </button>
              );
            })}
          </div>
        </section>

        <section className="rounded-lg border p-4" style={{ borderColor: "var(--line)" }}>
          <div className="mb-3 text-[11px] text-[var(--txt-dim)]">厂商 Top10</div>
          {(data.topVendors?.length ?? 0) === 0 && (
            <div className="py-8 text-center text-xs text-[var(--txt-faint)]">暂无厂商数据</div>
          )}
          <div className="space-y-0.5">
            {(data.topVendors ?? []).map((vc, i) => (
              <button
                key={vc.vendor}
                onClick={() => onNav({ page: "list" })}
                className="flex w-full items-center gap-2.5 rounded px-1.5 py-1 text-left transition-colors duration-150 hover:bg-[var(--hover)]"
              >
                <span className="tabular w-4 text-right font-mono-data text-[10px] text-[var(--txt-faint)]">{i + 1}</span>
                <span className="truncate text-[13px] text-[var(--txt)]">{vc.vendor}</span>
                <span className="tabular ml-auto font-mono-data text-xs text-[var(--txt-dim)]">{vc.count}</span>
              </button>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

import { useCallback, useEffect, useRef, useState } from "react";
import { Search, ChevronLeft, ChevronRight } from "lucide-react";
import {
  api, sevColor, sevText, statusColor, SEVERITIES, STATUSES, CATEGORIES,
  type Summary,
} from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import type { Route } from "../App";

export default function PocList({ onNav, initialStatus = "", initialSeverity = "" }: { onNav: (r: Route) => void; initialStatus?: string; initialSeverity?: string }) {
  const [items, setItems] = useState<Summary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  // 搜索输入防抖：每敲一键不再触发一次后端全量查询
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState(initialSeverity);
  const [status, setStatus] = useState(initialStatus);
  const [category, setCategory] = useState("");
  const [err, setErr] = useState("");
  // 待彻底删除的 PoC（弹窗确认前仅暂存 uid）
  const [delUid, setDelUid] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  // 请求序号：筛选快速连续变化时丢弃过期响应
  const loadSeq = useRef(0);
  const size = 50;

  useEffect(() => {
    const t = setTimeout(() => { setQuery(queryInput); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [queryInput]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const load = useCallback(() => {
    const seq = ++loadSeq.current;
    api
      .listPocs(
        { query, severity, status, category },
        { number: page, size, sort: "updated_desc" },
      )
      .then((r) => {
        if (seq !== loadSeq.current) return;
        setItems(r.items ?? []);
        setTotal(r.total);
      })
      .catch((e: unknown) => {
        if (seq !== loadSeq.current) return;
        setErr(e instanceof Error ? e.message : String(e));
      });
  }, [query, severity, status, category, page]);

  useEffect(() => { load(); }, [load]);

  const pages = Math.max(1, Math.ceil(total / size));
  const hasFilter = query !== "" || severity !== "" || status !== "" || category !== "";
  const clearFilters = () => {
    setQueryInput(""); setQuery(""); setSeverity(""); setStatus(""); setCategory(""); setPage(1);
  };
  const selectCls =
    "h-[30px] rounded-md border bg-transparent px-2 text-xs text-[var(--txt)] outline-none transition-colors duration-150 hover:border-[var(--line-strong)] focus:border-[var(--accent-dim)]";
  const borderStyle = { borderColor: "var(--line)" };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-[340px]">
          <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--txt-faint)]" />
          <input
            ref={searchRef}
            value={queryInput}
            onChange={(e) => setQueryInput(e.target.value)}
            placeholder="搜索名称 / CVE / 标签 / 描述…"
            className="h-[30px] w-full rounded-md border bg-transparent pl-8 pr-12 text-[13px] outline-none transition-colors duration-150 placeholder:text-[var(--txt-faint)] focus:border-[var(--accent-dim)]"
            style={borderStyle}
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 font-mono-data text-[10px] text-[var(--txt-faint)]">Ctrl K</kbd>
        </div>

        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} className={selectCls} style={borderStyle}>
          <option value="">严重度</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={category} onChange={(e) => { setCategory(e.target.value); setPage(1); }} className={selectCls} style={borderStyle}>
          <option value="">类别</option>
          {CATEGORIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} className={selectCls} style={borderStyle}>
          <option value="">状态</option>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
          <option value="archived">已归档</option>
        </select>

        <span className="tabular ml-auto mr-1 text-xs text-[var(--txt-dim)]">{total} 条</span>
      </div>

      {err && (
        <div className="rounded-md border border-red-500/25 bg-red-500/[0.06] p-3 text-[13px] text-red-300">
          {err}
        </div>
      )}

      <div className="overflow-hidden rounded-lg border" style={{ borderColor: "var(--line)" }}>
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b bg-[var(--stripe)] text-left text-[11px] text-[var(--txt-dim)]" style={{ borderColor: "var(--line)" }}>
              <th className="px-4 py-2 font-medium">名称</th>
              <th className="px-3 py-2 font-medium">CVE</th>
              <th className="px-3 py-2 font-medium">严重度</th>
              <th className="px-3 py-2 font-medium">厂商 / 产品</th>
              <th className="px-3 py-2 font-medium">状态</th>
              <th className="px-3 py-2 text-right font-medium">更新时间</th><th className="px-4 py-2 text-center font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && !err && !hasFilter && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center">
                  <div className="text-[13px] text-[var(--txt-dim)]">库是空的</div>
                  <button
                    onClick={() => onNav({ page: "create" })}
                    className="mt-3 inline-flex h-8 items-center gap-1.5 rounded-lg bg-[var(--accent)] px-4 text-[13px] font-medium text-white transition-colors duration-150 hover:brightness-110"
                  >
                    去导入第一个 PoC
                  </button>
                </td>
              </tr>
            )}
            {items.length === 0 && !err && hasFilter && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center">
                  <div className="text-[13px] text-[var(--txt-dim)]">没有符合条件的结果</div>
                  <button
                    onClick={clearFilters}
                    className="mt-3 inline-flex h-8 items-center rounded-lg border px-4 text-[13px] text-[var(--txt-dim)] transition-colors duration-150 hover:bg-[var(--hover)]"
                    style={{ borderColor: "var(--line-strong)" }}
                  >
                    清除筛选
                  </button>
                </td>
              </tr>
            )}
            {items.map((it) => (
              <tr
                key={it.uid}
                onClick={() => onNav({ page: "detail", uid: it.uid })}
                className="cursor-pointer border-b transition-colors duration-150 last:border-b-0 hover:bg-[var(--hover)]"
                style={{ borderColor: "var(--line)" }}
              >
                <td className="max-w-[260px] truncate px-4 py-[7px] text-[var(--txt)]">{it.name}</td>
                <td className="px-3 py-[7px]">
                  {it.cve
                    ? <span className="font-mono-data text-xs text-[var(--info)]">{it.cve}</span>
                    : <span className="text-[var(--txt-faint)]">—</span>}
                </td>
                <td className="px-3 py-[7px]">
                  <span className={`inline-flex items-center gap-1.5 font-mono-data text-xs ${sevText(it.severity)}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${sevColor(it.severity)}`} />
                    {it.severity}
                  </span>
                </td>
                <td className="px-3 py-[7px] text-xs text-[var(--txt-dim)]">
                  {it.vendor}<span className="mx-1 text-[var(--txt-faint)]">/</span>{it.product}
                </td>
                <td className={`px-3 py-[7px] text-xs ${statusColor(it.status)}`}>{it.status}</td>
                <td className="tabular px-4 py-[7px] text-right font-mono-data text-[11px] text-[var(--txt-faint)]">
                  {(it.updatedAt ?? "").replace("T", " ").slice(0, 16)}
                </td>
                <td className="px-4 py-[7px] text-center">
                  {it.status === "archived" ? (
                    <span className="flex justify-center gap-1.5">
                      <button
                        onClick={(e) => { e.stopPropagation(); api.restorePoc(it.uid).then(load); }}
                        className="rounded border px-2 py-0.5 text-[11px] text-emerald-600 transition-colors duration-150 hover:bg-emerald-500/10"
                        style={{ borderColor: "var(--line-strong)" }}
                      >恢复</button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setDelUid(it.uid);
                        }}
                        className="rounded border border-red-500/40 px-2 py-0.5 text-[11px] text-red-500 transition-colors duration-150 hover:bg-red-500/10"
                      >删除</button>
                    </span>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        open={delUid !== null}
        title="彻底删除该 PoC？"
        danger
        confirmText="删除"
        onCancel={() => setDelUid(null)}
        onConfirm={async () => {
          if (delUid === null) return;
          try {
            await api.deletePoc(delUid);
            setDelUid(null);
            load();
          } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
            setDelUid(null);
          }
        }}
      >
        「{items.find((i) => i.uid === delUid)?.name ?? delUid}」将被永久移除，此操作不可恢复。
      </ConfirmDialog>

      <div className="flex items-center justify-end gap-2 text-xs">
        <span className="tabular mr-1 font-mono-data text-[var(--txt-dim)]">{page} / {pages}</span>
        <button
          disabled={page <= 1}
          onClick={() => setPage(page - 1)}
          className="flex h-7 w-7 items-center justify-center rounded-md border transition-colors duration-150 hover:bg-[var(--hover)] disabled:opacity-30"
          style={borderStyle}
        >
          <ChevronLeft size={14} />
        </button>
        <button
          disabled={page >= pages}
          onClick={() => setPage(page + 1)}
          className="flex h-7 w-7 items-center justify-center rounded-md border transition-colors duration-150 hover:bg-[var(--hover)] disabled:opacity-30"
          style={borderStyle}
        >
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}

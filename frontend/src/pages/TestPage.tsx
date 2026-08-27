import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Play, Square, ShieldCheck, Zap } from "lucide-react";
import { api, type BatchResultRow } from "../api";

const resultBadge = (r: string): { cls: string; label: string } => {
  switch (r) {
    case "hit": return { cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400", label: "命中" };
    case "miss": return { cls: "bg-[var(--chip)] text-[var(--txt-dim)]", label: "未命中" };
    case "timeout": return { cls: "bg-orange-500/15 text-orange-600 dark:text-orange-400", label: "超时" };
    case "cancelled": return { cls: "bg-[var(--chip)] text-[var(--txt-faint)]", label: "已取消" };
    default: return { cls: "bg-red-500/15 text-red-500", label: r || "error" };
  }
};

// 结果表每页渲染行数：尾部窗口分页，避免上千目标时整表重渲
const RESULT_PAGE = 200;

export default function TestPage({ presetUid }: { presetUid?: string }) {
  const [uid, setUid] = useState(presetUid ?? "");
  const [targetsText, setTargetsText] = useState("");
  const [proxy, setProxy] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [batchId, setBatchId] = useState<string | null>(null);
  // 事件回调经 ref 读取当前批次 id，避免监听器闭包持有过期 batchId
  const batchIdRef = useRef<string | null>(null);
  const [invalidCount, setInvalidCount] = useState(0);
  const [rows, setRows] = useState<BatchResultRow[]>([]);
  const [total, setTotal] = useState(0);
  const [done, setDone] = useState(0);
  const [summary, setSummary] = useState("");
  const [lines, setLines] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const logRef = useRef<HTMLPreElement>(null);

  // 结果行先落 ref 缓冲、定时批量刷入 state：结果风暴下不再逐事件整表重渲
  const pendingRows = useRef<BatchResultRow[]>([]);
  const flushTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // 仅当日志本就贴近底部时才自动滚动，翻看旧日志不被拽回
  const stickBottom = useRef(true);

  useEffect(() => {
    const scheduleFlush = () => {
      if (flushTimer.current !== undefined) return;
      flushTimer.current = setTimeout(() => {
        flushTimer.current = undefined;
        const add = pendingRows.current;
        pendingRows.current = [];
        if (add.length > 0) setRows((rs) => [...rs, ...add]);
      }, 200);
    };
    // 仅挂载时注册一次；回调内读 ref 而非 state，规避重挂间隙丢事件
    api.onBatchLog((id, line) => {
      const bid = batchIdRef.current;
      if (bid === null || id === bid) setLines((ls) => [...ls.slice(-3000), line]);
    });
    api.onBatchResult((id, row) => {
      const bid = batchIdRef.current;
      if (bid === null || id === bid) { pendingRows.current.push(row); scheduleFlush(); }
    });
    api.onBatchProgress((id, d, t) => {
      const bid = batchIdRef.current;
      if (bid === null || id === bid) { setDone(d); setTotal(t); }
    });
    api.onBatchDone((id, t, hits, status) => {
      const bid = batchIdRef.current;
      if (bid === null || id !== bid) return;
      // 收尾前把缓冲中的剩余结果一次性入库到视图
      if (flushTimer.current !== undefined) { clearTimeout(flushTimer.current); flushTimer.current = undefined; }
      const add = pendingRows.current;
      pendingRows.current = [];
      setRows((rs) => [...rs, ...add]);
      setRunning(false);
      setDone(t);
      setTotal(t);
      setSummary(
        status === "cancelled"
          ? `已取消 · 完成 ${t} 个中的 ${hits} 命中`
          : `完成 ${t} 个 · 命中 ${hits} · 未命中 ${t - hits}`,
      );
    });
    return () => {
      api.offBatchEvents();
      if (flushTimer.current !== undefined) clearTimeout(flushTimer.current);
    };
  }, []);

  useEffect(() => {
    if (stickBottom.current) logRef.current?.scrollTo(0, logRef.current.scrollHeight);
  }, [lines]);

  const targetList = targetsText.split("\n").map((s) => s.trim()).filter(Boolean);

  // 统计一次遍历得出；此前每次 render 对全量 rows 做 3 遍 filter
  const stats = useMemo(() => {
    let hit = 0, miss = 0;
    for (const r of rows) {
      if (r.result === "hit") hit++;
      else if (r.result === "miss") miss++;
    }
    return { hit, miss, other: rows.length - hit - miss };
  }, [rows]);

  const [pageBack, setPageBack] = useState(0); // 0=最新一页，N=往前 N 页
  const totalPages = Math.max(1, Math.ceil(rows.length / RESULT_PAGE));
  const viewStart = Math.max(0, rows.length - (pageBack + 1) * RESULT_PAGE);
  const viewRows = useMemo(
    () => rows.slice(viewStart, viewStart + RESULT_PAGE),
    [rows, viewStart],
  );

  const start = async () => {
    setErr(""); setLines([]); setRows([]); setDone(0); setTotal(targetList.length); setSummary(""); setInvalidCount(0);
    pendingRows.current = []; setPageBack(0); stickBottom.current = true;
    try {
      const res = await api.runTestBatch(uid, targetList, proxy.trim(), authorized);
      setBatchId(res.id);
      batchIdRef.current = res.id;
      setInvalidCount(res.invalid?.length ?? 0);
      setRunning(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const cancel = async () => {
    if (batchId !== null) await api.cancelBatch(batchId).catch(() => {});
  };

  const inputCls =
    "mt-1.5 w-full rounded-lg border bg-[var(--bg-input)] px-3 py-2 font-mono-data text-sm text-[var(--txt)] outline-none transition-colors duration-150 placeholder:font-[var(--sans)] placeholder:text-[var(--txt-faint)] focus:border-[var(--accent)]";
  const borderStyle = { borderColor: "var(--line)" };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-base font-semibold">批量验证</h1>
        <p className="mt-1 text-[13px] text-[var(--txt-dim)]">
          单个 PoC 对多目标顺序执行 —— 每行一个目标，结果实时播报
        </p>
      </div>

      <section className="panel space-y-4 p-5">
        <label className="block text-xs">
          <span className="font-medium text-[var(--txt-dim)]">PoC UID</span>
          <input value={uid} onChange={(e) => setUid(e.target.value)}
            placeholder="从 PoC 详情页跳转自动填入"
            className={inputCls} style={borderStyle} />
        </label>

        <label className="block text-xs">
          <span className="flex items-center justify-between font-medium text-[var(--txt-dim)]">
            <span>目标列表（每行一个）</span>
            <span className="tabular font-mono-data text-[11px]">{targetList.length} 个目标</span>
          </span>
          <textarea value={targetsText} onChange={(e) => setTargetsText(e.target.value)} rows={6}
            placeholder={"http://target1.com\nhttp://target2.com:8080\n10.0.0.5:873  ← tcp 型 PoC 用 host:port"}
            className={`${inputCls} leading-6`} style={borderStyle} />
        </label>

        <label className="block text-xs">
          <span className="font-medium text-[var(--txt-dim)]">代理（可选，挂 Burp 等调试请求）</span>
          <input value={proxy} onChange={(e) => setProxy(e.target.value)}
            placeholder="http://127.0.0.1:8080　留空=直连"
            className={inputCls} style={borderStyle} />
        </label>

        <label className="flex w-fit cursor-pointer items-center gap-2.5 rounded-lg border px-3.5 py-2.5"
          style={{ borderColor: "rgba(255,149,0,0.35)", background: "rgba(255,149,0,0.07)" }}>
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)}
            className="h-4 w-4 accent-[var(--warn)]" />
          <ShieldCheck size={15} className="text-[var(--warn)]" strokeWidth={2} />
          <span className="text-[13px]" style={{ color: "var(--warn)" }}>
            我确认对以上所有目标拥有测试授权（未勾选后端将拒绝执行）
          </span>
        </label>

        <div className="flex items-center gap-3">
          <button onClick={start}
            disabled={running || !uid || targetList.length === 0 || !authorized}
            className="flex h-9 items-center gap-2 rounded-lg bg-sky-500 px-5 text-[13px] font-medium text-white transition-colors duration-150 hover:brightness-110 disabled:opacity-40">
            <Zap size={14} strokeWidth={2.2} /> 开始批量验证
          </button>
          {running && (
            <button onClick={cancel}
              className="flex h-8 items-center gap-2 rounded-lg border border-red-500/40 px-3 text-[13px] text-red-400 transition-colors duration-150 hover:bg-red-500/10">
              <Square size={12} strokeWidth={2.2} /> 取消剩余
            </button>
          )}
          {running && (
            <span className="text-[13px] text-[var(--info)]">执行中 {done}/{total}</span>
          )}
        </div>

        {/* 进度条 */}
        {running && total > 0 && (
          <div className="h-1.5 overflow-hidden rounded-full bg-[var(--track)]">
            <div className="h-full rounded-full bg-sky-500 transition-all duration-300"
              style={{ width: `${total ? Math.round((done / total) * 100) : 0}%` }} />
          </div>
        )}

        {err && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-[13px] text-red-400">{err}</div>}
      </section>

      {(rows.length > 0 || summary) && (
        <section className="panel overflow-hidden">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b px-4 py-2.5"
            style={{ borderColor: "var(--line)", background: "var(--bg-raise)" }}>
            <span className="text-[11px] font-medium text-[var(--txt-dim)]">结果播报</span>
            <span className="tabular font-mono-data text-xs text-[var(--txt-dim)]">
              共 <b className="text-[var(--txt)]">{rows.length}</b> ·
              <b className="ml-1 text-emerald-600 dark:text-emerald-400">命中 {stats.hit}</b> ·
              未命中 {stats.miss}{stats.other > 0 ? <> · 异常 {stats.other}</> : null}
              {invalidCount > 0 && <> · 非法目标 {invalidCount}</>}
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              {summary && <span className="mr-2 text-xs text-[var(--accent)]">{summary}</span>}
              {totalPages > 1 && (
                <>
                  <button disabled={pageBack >= totalPages - 1} onClick={() => setPageBack((p) => p + 1)}
                    className="flex h-6 w-6 items-center justify-center rounded border transition-colors duration-150 hover:bg-[var(--hover)] disabled:opacity-30"
                    style={{ borderColor: "var(--line)" }} title="较早的结果">
                    <ChevronLeft size={12} />
                  </button>
                  <span className="tabular font-mono-data text-[11px] text-[var(--txt-dim)]">
                    {pageBack === 0 ? `最新 ${rows.length - viewStart}/${totalPages} 页` : `-第 ${pageBack + 1}/${totalPages} 页`}
                  </span>
                  <button disabled={pageBack === 0} onClick={() => setPageBack((p) => Math.max(0, p - 1))}
                    className="flex h-6 w-6 items-center justify-center rounded border transition-colors duration-150 hover:bg-[var(--hover)] disabled:opacity-30"
                    style={{ borderColor: "var(--line)" }} title="较新的结果">
                    <ChevronRight size={12} />
                  </button>
                </>
              )}
            </div>
          </div>
          <table className="w-full text-[13px]">
            <tbody>
              {viewRows.map((r, i) => {
                const b = resultBadge(r.result);
                return (
                  <tr key={`${r.target}-${viewStart + i}`} className="border-b last:border-b-0 hover:bg-[var(--hover)] transition-colors duration-150"
                    style={{ borderColor: "var(--line)" }}>
                    <td className="px-4 py-2 font-mono-data text-xs">{r.target}</td>
                    <td className="w-24 px-3 py-2">
                      <span className={`inline-flex h-5 items-center rounded px-2 font-mono-data text-[10px] font-bold ${b.cls}`}>
                        {b.label}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {totalPages > 1 && pageBack === 0 && (
            <div className="border-t px-4 py-1.5 text-right text-[11px] text-[var(--txt-faint)]" style={{ borderColor: "var(--line)" }}>
              仅渲染最近 {RESULT_PAGE} 条，左侧箭头回看更早结果（完整记录均已落库）
            </div>
          )}
        </section>
      )}

      {lines.length > 0 && (
        <section>
          <div className="mb-2 text-[11px] font-medium text-[var(--txt-dim)]">详细日志</div>
          <pre ref={logRef} onScroll={(e) => {
            const el = e.currentTarget;
            stickBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
          }}
            className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-xl border bg-[var(--bg-input)] p-4 font-mono-data text-xs leading-6"
            style={{ borderColor: "var(--line)" }}>
            {lines.join("\n")}
          </pre>
        </section>
      )}

      {/* 保留单次运行的历史记录查询入口语义：最近一次 run 的详情仍在 PoC 详情页测试历史中 */}
      {finalRunHint()}
    </div>
  );
}

function finalRunHint() {
  return (
    <p className="text-[11px] text-[var(--txt-faint)]">
      每个目标的执行记录都会写入对应 PoC 的「测试历史」，可在详情页回查完整日志。
    </p>
  );
}

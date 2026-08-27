import { useEffect, useState } from "react";
import { ArrowLeft, Pencil, Play, Archive, RotateCcw, Check, Download, Tag, Building2, Package, FileCode2, History } from "lucide-react";
import CodeMirror from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import { api, sevColor, statusColor, type Pwf, type TestRun } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import { useResolvedTheme } from "../theme";
import type { Route } from "../App";

export default function PocDetail({ uid, onNav }: { uid: string; onNav: (r: Route) => void }) {
  const [poc, setPoc] = useState<Pwf | null>(null);
  const [runs, setRuns] = useState<TestRun[]>([]);
  const [err, setErr] = useState("");
  const theme = useResolvedTheme();
  // 列表接口只带日志预览；展开时按需拉取全文
  const [fullLogs, setFullLogs] = useState<Record<number, string>>({});
  // 归档确认弹窗（替代原生 confirm）
  const [confirmArchive, setConfirmArchive] = useState(false);

  useEffect(() => {
    api.getPoc(uid).then(setPoc).catch((e: unknown) =>
      setErr(e instanceof Error ? e.message : String(e)),
    );
    api.listTestRuns(uid).then((rs) => setRuns(rs ?? [])).catch(() => {});
  }, [uid]);

  const loadFullLog = async (id: number) => {
    try {
      const t = await api.getTestRun(id);
      if (t) setFullLogs((m) => ({ ...m, [id]: t.log }));
    } catch { /* 拉取失败保留预览 */ }
  };

  if (err) return <div className="text-[var(--danger)]">{err}</div>;
  if (!poc) return <div className="animate-pulse text-sm text-[var(--txt-dim)]">加载中…</div>;

  const m = poc.metadata;

  const metaItems = [
    { icon: Tag, label: "CVE", value: m.cve || "—", mono: true },
    { icon: Building2, label: "厂商", value: m.vendor || "—" },
    { icon: Package, label: "产品", value: m.product || "—" },
    { icon: FileCode2, label: "来源", value: m.source, mono: true },
  ];

  return (
    <div className="w-full space-y-4">
      <button
        onClick={() => onNav({ page: "list" })}
        className="flex h-8 items-center gap-1.5 rounded-lg px-2 text-xs text-[var(--txt-dim)] transition-colors duration-150 hover:bg-[var(--hover)] hover:text-[var(--txt)]"
      >
        <ArrowLeft size={14} /> 返回列表
      </button>

      <div className="flex flex-wrap items-center gap-3">
        <h1 className="heading-balance text-base font-semibold text-[var(--txt)]">{m.name}</h1>
        <span className={`inline-flex h-6 items-center rounded-md px-2 font-mono-data text-[11px] font-bold text-white ${sevColor(m.severity)}`}>
          {m.severity}
        </span>
        <span className={`font-mono-data text-sm ${statusColor(m.status)}`}>{m.status}</span>

        <span className="ml-auto flex gap-2">
          <ActionBtn icon={Pencil} label="编辑" onClick={() => onNav({ page: "edit", uid })} tone="accent" />
          <ActionBtn icon={Play} label="验证测试" onClick={() => onNav({ page: "test", uid })} tone="info" />
          <ExportBtn uid={uid} />
          {m.status === "archived" ? (
            <ActionBtn icon={RotateCcw} label="恢复" onClick={async () => {
              try {
                await api.restorePoc(uid);
                setPoc({ ...poc, metadata: { ...m, status: "untested" } });
              } catch (e) {
                setErr(e instanceof Error ? e.message : String(e));
              }
            }} />
          ) : (
            <ActionBtn
              icon={Archive} label="归档"
              onClick={() => setConfirmArchive(true)}
            />
          )}
        </span>
      </div>

      <ConfirmDialog
        open={confirmArchive}
        title="归档该 PoC？"
        confirmText="归档"
        onCancel={() => setConfirmArchive(false)}
        onConfirm={async () => {
          try {
            await api.archivePoc(uid);
            if (poc) setPoc({ ...poc, metadata: { ...m, status: "archived" } });
            setConfirmArchive(false);
          } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
            setConfirmArchive(false);
          }
        }}
      >
        归档后从默认列表隐藏，在列表筛选「已归档」可查看并恢复。
      </ConfirmDialog>

      <div className="panel grid grid-cols-4 gap-x-5 gap-y-3 p-5">
        {metaItems.map((it) => {
          const Icon = it.icon;
          return (
            <div key={it.label}>
              <div className="panel-title mb-1.5 flex items-center gap-1.5">
                <Icon size={12} strokeWidth={1.8} /> {it.label}
              </div>
              <div className={`truncate text-sm text-[var(--txt)] ${it.mono ? "font-mono-data" : ""}`}>{it.value}</div>
            </div>
          );
        })}
        <div className="col-span-4">
          <div className="panel-title mb-1.5">别名</div>
          <div className="flex flex-wrap gap-1.5">
            {(m.aliases ?? []).map((a) => (
              <span key={a} className="font-mono-data rounded-md border border-[var(--line-strong)] px-2 py-0.5 text-[11px] text-[var(--txt-dim)]">{a}</span>
            ))}
            {(m.aliases ?? []).length === 0 && <span className="text-sm text-[var(--txt-faint)]">—</span>}
          </div>
        </div>
        {(m.tags ?? []).length > 0 && (
          <div className="col-span-4">
            <div className="panel-title mb-1.5">标签</div>
            <div className="flex flex-wrap gap-1.5">
              {m.tags.map((t) => (
                <span key={t} className="rounded-md bg-[var(--chip)] px-2 py-0.5 text-[11px] text-[var(--txt-dim)]">#{t}</span>
              ))}
            </div>
          </div>
        )}
        {m.description && (
          <div className="col-span-4">
            <div className="panel-title mb-1.5">描述</div>
            <p className="text-sm leading-relaxed text-[var(--txt)]" style={{ textWrap: "pretty" }}>{m.description}</p>
          </div>
        )}
      </div>

      <section>
        <SectionTitle>{m.kind === "script" ? "脚本内容" : "PWF 模板"}</SectionTitle>
        <CodeMirror
          value={m.kind === "script"
            ? (poc.specRaw ?? "")
            : JSON.stringify(poc.spec, null, 2)}
          extensions={[yaml()]}
          editable={false}
          theme={theme}
          height="260px"
        />
      </section>

      <section>
        <SectionTitle icon={<History size={13} strokeWidth={1.8} />}>测试历史（{runs.length}）</SectionTitle>
        {runs.length === 0 && (
          <div className="panel px-4 py-8 text-center text-sm text-[var(--txt-faint)]">
            还没测过 —— 到「验证测试」页跑一发
          </div>
        )}
        <div className="space-y-2">
          {runs.map((r) => (
            <details key={r.id} className="panel group overflow-hidden">
              <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3 transition-colors duration-150 hover:bg-[var(--hover)]">
                <span className={`font-mono-data rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                  r.result === "hit" ? "bg-emerald-500/15 text-emerald-400"
                  : r.result === "miss" ? "bg-[var(--track)] text-[var(--txt-dim)]"
                  : "bg-red-500/15 text-red-400"
                }`}>{r.result}</span>
                <span className="font-mono-data truncate text-xs text-[var(--txt)]">{r.target}</span>
                <span className="tabular ml-auto shrink-0 font-mono-data text-[10px] text-[var(--txt-faint)]">
                  {(r.startedAt ?? "").replace("T", " ").slice(0, 19)}
                </span>
              </summary>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all border-t bg-[var(--bg-input)] p-4 text-xs leading-5 text-[var(--txt)]" style={{ borderColor: "var(--line)" }}>
                {fullLogs[r.id] ?? r.log}
              </pre>
              {r.logTruncated && fullLogs[r.id] === undefined && (
                <div className="border-t px-4 py-2" style={{ borderColor: "var(--line)" }}>
                  <button
                    onClick={(e) => { e.preventDefault(); loadFullLog(r.id); }}
                    className="text-[11px] text-[var(--accent)] hover:underline"
                  >
                    日志已截断，点击加载完整内容
                  </button>
                </div>
              )}
            </details>
          ))}
        </div>
      </section>
    </div>
  );
}

function SectionTitle({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="mb-2.5 mt-1 flex items-center gap-1.5 text-xs font-medium text-[var(--txt-dim)]">
      {icon}{children}
    </div>
  );
}

function ActionBtn({ icon: Icon, label, onClick, tone }: {
  icon: React.ComponentType<{ size?: number; strokeWidth?: number }>;
  label: string; onClick: () => void; tone?: "accent" | "info";
}) {
  const color =
    tone === "accent" ? "border-[var(--accent-dim)] text-[var(--accent)] hover:bg-[var(--accent-dim)]/40"
    : tone === "info" ? "border-sky-500/30 text-sky-400 hover:bg-sky-500/10"
    : "border-[var(--line-strong)] text-[var(--txt-dim)] hover:bg-[var(--hover)]";
  return (
    <button
      onClick={onClick}
      className={`flex h-9 items-center gap-1.5 rounded-lg border px-3.5 text-sm transition-colors duration-150 active:scale-[0.97] ${color}`}
    >
      <Icon size={14} strokeWidth={2} />
      {label}
    </button>
  );
}

function ExportBtn({ uid }: { uid: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          const ymlText = await api.exportPoc(uid);
          await navigator.clipboard.writeText(ymlText);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch { /* 剪贴板失败静默 */ }
      }}
      className={`flex h-8 items-center gap-1.5 rounded-lg border px-3.5 text-sm transition-colors duration-150 ${
        copied
          ? "border-emerald-500/40 text-emerald-600"
          : "text-[var(--txt-dim)] hover:bg-[var(--hover)]"
      }`}
      style={copied ? undefined : { borderColor: "var(--line-strong)" }}
    >
      {copied ? <Check size={14} strokeWidth={2.2} /> : <Download size={14} strokeWidth={1.8} />}
      {copied ? "已复制" : "导出"}
    </button>
  );
}

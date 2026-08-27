import { useEffect, useState } from "react";
import { Save, AlertTriangle, DatabaseBackup, Gauge, Check, SunMoon, Undo2 } from "lucide-react";
import { api } from "../api";
import { getPref, applyTheme, type ThemePref } from "../theme";
import ConfirmDialog from "../components/ConfirmDialog";

export default function Settings() {
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [pref, setPref] = useState<ThemePref>(getPref());
  const [version, setVersion] = useState("…");
  // 待恢复的备份路径（弹窗确认前暂存）
  const [restorePath, setRestorePath] = useState<string | null>(null);

  useEffect(() => {
    api.appVersion().then(setVersion).catch(() => setVersion("unknown"));
  }, []);

  const doBackup = async () => {
    setMsg(""); setErr(""); setBusy(true);
    try {
      const p = await api.backupDB();
      setMsg(p);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doRestore = async () => {
    setMsg(""); setErr("");
    try {
      const p = await api.pickRestoreFile();
      if (!p) return; // 用户取消选择
      setRestorePath(p); // 进入确认弹窗，确认后才执行
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const doRestoreConfirmed = async () => {
    if (restorePath === null) return;
    setBusy(true);
    try {
      await api.restoreBackup(restorePath);
      window.location.reload(); // 全量加载恢复后的数据
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setRestorePath(null);
      setBusy(false);
    }
  };

  return (
    <div className="max-w-[560px] space-y-4">
      <h1 className="text-base font-semibold">设置</h1>

      <section className="panel space-y-3 p-4">
        <div className="flex items-center gap-2">
          <SunMoon size={15} className="text-[var(--accent)]" strokeWidth={1.9} />
          <span className="text-[11px] font-medium text-[var(--txt-dim)]">外观</span>
        </div>
        <div className="inline-flex rounded-lg border p-0.5" style={{ borderColor: "var(--line)" }}>
          {(["system", "light", "dark"] as const).map((p) => (
            <button
              key={p}
              onClick={() => { setPref(p); applyTheme(p); }}
              className={`h-7 rounded-md px-3 text-xs transition-colors duration-150 ${
                pref === p
                  ? "bg-[var(--accent)] font-medium text-white"
                  : "text-[var(--txt-dim)] hover:bg-[var(--hover)]"
              }`}
            >
              {p === "system" ? "跟随系统" : p === "light" ? "浅色" : "深色"}
            </button>
          ))}
        </div>
      </section>

      <section className="panel space-y-3 p-4">
        <div className="flex items-center gap-2">
          <DatabaseBackup size={15} className="text-[var(--accent)]" strokeWidth={1.9} />
          <span className="text-[11px] font-medium text-[var(--txt-dim)]">数据备份</span>
        </div>
        <p className="text-[13px] leading-relaxed text-[var(--txt-dim)]">
          使用 SQLite VACUUM INTO 生成带时间戳的备份文件，WAL 模式下保证一致性；自动保留最近 10 份。
        </p>
        <div className="flex items-center gap-2.5">
          <button onClick={doBackup} disabled={busy}
            className="flex h-8 items-center gap-2 rounded-lg bg-[var(--accent)] px-4 text-[13px] font-medium text-white transition-colors duration-150 hover:brightness-110 disabled:opacity-40">
            <Save size={14} strokeWidth={2} /> 一键备份
          </button>
          <button onClick={doRestore} disabled={busy}
            className="flex h-8 items-center gap-2 rounded-lg border border-[var(--warn)]/40 px-4 text-[13px] text-[var(--warn)] transition-colors duration-150 hover:bg-[var(--warn)]/10 disabled:opacity-40"
            style={{ background: "rgba(255,149,0,0.05)" }}>
            <Undo2 size={14} strokeWidth={2} /> 从备份恢复…
          </button>
        </div>
        {msg && (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.07] p-2.5 text-[13px] text-emerald-600 dark:text-emerald-400">
            <Check size={14} /> 已备份到：<span className="font-mono-data text-xs">{msg}</span>
          </div>
        )}
        {err && <div className="text-[13px] text-[var(--danger)]">{err}</div>}
      </section>

      <ConfirmDialog
        open={restorePath !== null}
        title="用备份覆盖当前数据库？"
        danger
        confirmText="恢复"
        busy={busy}
        onCancel={() => setRestorePath(null)}
        onConfirm={doRestoreConfirmed}
      >
        {`将使用以下备份覆盖现有数据，进行中的测试会被取消，恢复成功后页面自动刷新。\n\n${restorePath ?? ""}`}
      </ConfirmDialog>

      <section className="rounded-xl border border-[var(--warn)]/30 bg-[var(--warn)]/[0.06] p-4">
        <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-[var(--warn)]">
          <AlertTriangle size={14} strokeWidth={2} /> 数据安全提示
        </div>
        <ul className="list-disc space-y-1 pl-5 text-xs leading-relaxed text-[var(--txt-dim)]">
          <li>数据库明文存储全部 PoC 载荷与测试日志（含目标响应内容）。</li>
          <li>请勿将数据库文件同步到网盘或提交 git。</li>
          <li>默认位置：<code className="font-mono-data">%APPDATA%\PoCWorkbench\pocwb.db</code></li>
        </ul>
      </section>

      <section className="panel space-y-2 p-4">
        <div className="flex items-center gap-2">
          <Gauge size={15} className="text-[var(--info)]" strokeWidth={1.9} />
          <span className="text-[11px] font-medium text-[var(--txt-dim)]">引擎参数（当前固定值）</span>
        </div>
        <div className="grid grid-cols-2 gap-x-8 gap-y-1.5 pt-1 text-[13px]">
          <ParamRow k="版本" v={version} />
          <ParamRow k="单次运行硬超时" v="60s" />
          <ParamRow k="全局并发" v="1" />
          <ParamRow k="响应读上限" v="10 MB" />
          <ParamRow k="重定向跟随" v="关闭" />
          <ParamRow k="TCP 默认读超时" v="rule 内 read_timeout" />
          <ParamRow k="正则引擎" v="RE2（线性时间）" />
        </div>
      </section>
    </div>
  );
}

function ParamRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between border-b border-dashed pb-1.5" style={{ borderColor: "var(--line)" }}>
      <span className="text-[var(--txt-dim)]">{k}</span>
      <span className="font-mono-data text-xs">{v}</span>
    </div>
  );
}

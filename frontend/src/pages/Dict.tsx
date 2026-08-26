import { useEffect, useState } from "react";
import { Merge, Plus } from "lucide-react";
import { api, type Vendor } from "../api";

export default function Dict() {
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [canonical, setCanonical] = useState("");
  const [alias, setAlias] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = () => api.listVendors().then(setVendors).catch(() => {});
  useEffect(() => { load(); }, []);

  const merge = async () => {
    setMsg(""); setErr("");
    try {
      await api.mergeVendorAlias(canonical.trim(), alias.trim());
      setMsg(`已把 ${alias} 归并到 ${canonical}`);
      setAlias("");
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const inputCls =
    "h-10 flex-1 rounded-lg border bg-[var(--bg-input)] px-3 text-sm text-[var(--txt)] font-mono-data outline-none transition-colors duration-150 placeholder:font-[var(--sans)] placeholder:text-[var(--txt-faint)] focus:border-[var(--accent-dim)]";
  const borderStyle = { borderColor: "var(--line)" };

  return (
    <div className="w-full space-y-4">
      <div>
        <h1 className="heading-balance text-base font-semibold text-[var(--txt)]">字典管理</h1>
        <p className="mt-1 text-sm text-[var(--txt-dim)]">厂商规范名与别名治理 —— 归并后全文检索立即生效</p>
      </div>

      <section className="panel space-y-4 p-5">
        <div className="panel-title">别名归并</div>
        <p className="-mt-2 text-[13px] leading-relaxed text-[var(--txt-dim)]">
          把别名（如 <code className="font-mono-data text-[var(--accent)]">xwiki</code>、
          <code className="font-mono-data text-[var(--accent)]">XWiki SAS</code>）合并到规范厂商名；
          若别名已是独立厂商，其下 PoC 引用会一并迁移。
        </p>
        <div className="flex gap-2.5">
          <input value={canonical} onChange={(e) => setCanonical(e.target.value)} placeholder="规范厂商名"
            className={inputCls} style={borderStyle} />
          <Plus size={15} className="self-center text-[var(--txt-faint)]" />
          <input value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="要归并的别名"
            className={inputCls} style={borderStyle} />
          <button onClick={merge} disabled={!canonical.trim() || !alias.trim()}
            className="flex h-10 shrink-0 items-center gap-1.5 rounded-lg bg-[var(--accent)] px-4 text-sm font-medium text-white transition-all duration-150 hover:brightness-110 active:scale-[0.97] disabled:opacity-40">
            <Merge size={14} strokeWidth={2.2} /> 归并
          </button>
        </div>
        {msg && <div className="text-sm text-emerald-400">{msg}</div>}
        {err && <div className="text-sm text-[var(--danger)]">{err}</div>}
      </section>

      <section className="panel overflow-hidden">
        <div className="flex items-center justify-between border-b px-5 py-3" style={{ borderColor: "var(--line)", background: "var(--bg-raise)" }}>
          <span className="panel-title">厂商列表</span>
          <span className="tabular font-mono-data text-xs text-[var(--txt-dim)]">{vendors.length}</span>
        </div>
        {vendors.length === 0 ? (
          <div className="px-5 py-12 text-center text-sm text-[var(--txt-faint)]">
            字典还是空的 —— 导入 PoC 时会自动按 fingerprint 建厂商标记，或手动归并
          </div>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {vendors.map((v) => (
                <tr key={v.id} className="border-b transition-colors duration-150 last:border-b-0 hover:bg-[var(--hover)]" style={{ borderColor: "var(--line)" }}>
                  <td className="px-5 py-2.5 font-medium text-[var(--txt)]">{v.canonicalName}</td>
                  <td className="px-5 py-2.5">
                    <span className="flex flex-wrap gap-1.5">
                      {(v.aliases ?? []).map((a) => (
                        <span key={a} className="font-mono-data rounded border border-[var(--line-strong)] px-1.5 py-0.5 text-[10px] text-[var(--txt-faint)]">{a}</span>
                      ))}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

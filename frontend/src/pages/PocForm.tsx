import { useEffect, useMemo, useRef, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import {
  ClipboardPaste, PenLine, AlertTriangle, Save, Check,
  Plus, Trash2, BookOpen, Copy, CheckCheck,
} from "lucide-react";
import { dump as yamlDump, load as yamlLoad } from "js-yaml";
import { api, SEVERITIES, CATEGORIES, STATUSES, type Draft } from "../api";
import { useResolvedTheme } from "../theme";
import type { Route } from "../App";

// ── 结构化规则草稿 ────────────────────────────────────

interface KV { k: string; v: string }

interface RuleUI {
  method: string;
  path: string;
  headers: KV[];
  body: string;
  inputs: string[];
  readTimeout: number;
  expression: string;
}

const blankRule = (transport: "http" | "tcp"): RuleUI => ({
  method: "GET", path: "", headers: [], body: "",
  inputs: transport === "tcp" ? [""] : [],
  readTimeout: 3,
  expression: transport === "tcp"
    ? "response.raw.bcontains(b'')"
    : "response.status == 200",
});

const emptyDraft = (): Draft => ({
  name: "", aliases: [], severity: "info", category: "other",
  vendor: "", product: "", tags: [], description: "", cve: "",
  status: "untested", source: "manual", kind: "template",
  specYaml: "",
});

// ── 安全取值（外部 YAML 输入，逐字段防御读取） ──────────
const asStr = (v: unknown): string => (typeof v === "string" ? v : "");
const asNum = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

function loadSpecToUI(txt: string): {
  transport: "http" | "tcp"; rules: RuleUI[]; finalExpr: string;
} | null {
  // 外部输入：js-yaml 解析后按已知 schema 逐字段收敛
  let obj: Record<string, unknown> | null;
  try {
    obj = yamlLoad(txt) as Record<string, unknown> | null;
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  const transport: "http" | "tcp" = obj.transport === "tcp" ? "tcp" : "http";
  const rulesObj = (obj.rules ?? {}) as Record<string, unknown>;
  const rules: RuleUI[] = [];
  for (const key of Object.keys(rulesObj).sort()) {
    const r = (rulesObj[key] ?? {}) as Record<string, unknown>;
    const req = (r.request ?? {}) as Record<string, unknown>;
    const hobj = (req.headers ?? {}) as Record<string, unknown>;
    const inputsArr = Array.isArray(req.inputs) ? req.inputs : [];
    rules.push({
      method: asStr(req.method) || "GET",
      path: asStr(req.path),
      headers: Object.keys(hobj).map((k) => ({ k, v: asStr(hobj[k]) })),
      body: asStr(req.body),
      inputs: inputsArr.map((x) => asStr((x as Record<string, unknown>).data)),
      readTimeout: asNum(req.read_timeout) || asNum(req.readTimeout) || 3,
      expression: asStr(r.expression),
    });
  }
  if (rules.length === 0) return null;
  return { transport, rules, finalExpr: asStr(obj.expression) };
}

export default function PocForm({ mode, uid, onNav }: {
  mode: "create" | "edit"; uid?: string; onNav: (r: Route) => void;
}) {
  const cmTheme = useResolvedTheme();
  const [tab, setTab] = useState<"paste" | "manual">("paste");
  const [xrayText, setXrayText] = useState("");
  const [draft, setDraft] = useState<Draft>(emptyDraft());
  const [warnings, setWarnings] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  // 结构化规则状态
  const [transport, setTransport] = useState<"http" | "tcp">("http");
  const [rules, setRules] = useState<RuleUI[]>([blankRule("http")]);
  const [finalExpr, setFinalExpr] = useState("r0()");
  const ruleNames = useMemo(() => rules.map((_, i) => `r${i}`), [rules.length]);

  useEffect(() => {
    if (mode === "edit" && uid) {
      api.getPoc(uid).then((p) => {
        setDraft({
          uid: p.metadata.uid, name: p.metadata.name, aliases: p.metadata.aliases ?? [],
          severity: p.metadata.severity, category: p.metadata.category,
          vendor: p.metadata.vendor, product: p.metadata.product,
          tags: p.metadata.tags ?? [], description: p.metadata.description,
          cve: p.metadata.cve, status: p.metadata.status, source: p.metadata.source,
          kind: p.metadata.kind,
          // script 类内容不是 PWF spec，后端经 specRaw 透传原文；template 走解析后的结构体
          specYaml: p.metadata.kind === "script"
            ? (p.specRaw ?? "")
            : JSON.stringify(p.spec, null, 2),
        });
        if (p.metadata.kind === "template") {
          const y = yamlDump(p.spec, { lineWidth: -1 });
          const ui = loadSpecToUI(y);
          if (ui) {
            setTransport(ui.transport);
            setRules(ui.rules);
            setFinalExpr(ui.finalExpr);
          }
        }
        setTab("manual");
      }).catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
    }
  }, [mode, uid]);

  const buildSpecYaml = (): string => {
    const rulesObj: Record<string, unknown> = {};
    rules.forEach((r, i) => {
      if (transport === "http") {
        const req: Record<string, unknown> = { method: r.method || "GET", path: r.path };
        const hs = r.headers.filter((h) => h.k.trim() !== "");
        if (hs.length > 0) {
          const hmap: Record<string, string> = {};
          hs.forEach((h) => { hmap[h.k.trim()] = h.v; });
          req.headers = hmap;
        }
        if (r.body !== "") req.body = r.body;
        rulesObj[`r${i}`] = { request: req, expression: r.expression };
      } else {
        rulesObj[`r${i}`] = {
          request: {
            inputs: (r.inputs.length ? r.inputs : [""]).map((d) => ({ data: d })),
            read_timeout: r.readTimeout > 0 ? r.readTimeout : 3,
          },
          expression: r.expression,
        };
      }
    });
    return yamlDump(
      { transport, rules: rulesObj, expression: finalExpr },
      { lineWidth: -1 },
    );
  };

  const doConvert = async () => {
    setErr(""); setBusy(true);
    try {
      const d = await api.convertTemplate(xrayText);
      setDraft(d);
      setWarnings(d.warnings ?? []);
      const ui = loadSpecToUI(d.specYaml);
      if (ui) {
        setTransport(ui.transport);
        setRules(ui.rules);
        setFinalExpr(ui.finalExpr);
      }
      setTab("manual");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doSave = async () => {
    setErr(""); setBusy(true); setSaved(false);
    try {
      // 入库前清洗：输入态允许尾随逗号产生空段，这里统一剔除
      const clean = { ...draft, tags: draft.tags.map((s) => s.trim()).filter(Boolean), aliases: draft.aliases.map((s) => s.trim()).filter(Boolean) };
      const d: Draft =
        clean.kind === "script"
          ? clean
          : { ...clean, specYaml: buildSpecYaml(), source: mode === "create" ? clean.source : clean.source };
      if (mode === "create") {
        await api.createPoc(d);
        onNav({ page: "list" });
      } else if (uid) {
        await api.updatePocMeta(uid, d);
        // template 与 script 都要落内容：后端按 kind 分流校验（此前 script 改动被静默丢弃）
        await api.updatePocSpec(uid, d.specYaml);
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));

  const switchTransport = (t: "http" | "tcp") => {
    setTransport(t);
    setRules([blankRule(t)]);
    setFinalExpr("r0()");
  };

  const patchRule = (i: number, patch: Partial<RuleUI>) =>
    setRules((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));

  const inputCls =
    "mt-1.5 w-full rounded-lg border bg-[var(--bg-input)] px-3 py-2 text-sm text-[var(--txt)] outline-none transition-colors duration-150 placeholder:text-[var(--txt-faint)] focus:border-[var(--accent)]";
  const borderStyle = { borderColor: "var(--line)" };

  const previewYaml = useMemo(
    () => (draft.kind === "template" ? buildSpecYaml() : ""),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [transport, rules, finalExpr, draft.kind],
  );

  return (
    <div className="space-y-5">
      <h1 className="text-base font-semibold">
        {mode === "create" ? "新增 PoC" : "编辑 PoC"}
      </h1>

      {mode === "create" && (
        <div className="inline-flex rounded-xl border p-1" style={{ borderColor: "var(--line)", background: "var(--bg-panel)" }}>
          <SegTab active={tab === "paste"} onClick={() => setTab("paste")} icon={<ClipboardPaste size={14} strokeWidth={1.9} />}>
            粘贴模板转换
          </SegTab>
          <SegTab active={tab === "manual"} onClick={() => setTab("manual")} icon={<PenLine size={14} strokeWidth={1.9} />}>
            手动创建
          </SegTab>
        </div>
      )}

      {tab === "paste" && mode === "create" && (
        <div className="max-w-4xl space-y-3">
          <p className="text-[13px] text-[var(--txt-dim)]">
            粘贴完整 Xray 或 Nuclei 模板 YAML（自动识别格式，上限 256KB），解析后进入下方表单确认入库。
          </p>
          <CodeMirror value={xrayText} onChange={setXrayText} extensions={[yaml()]} theme={cmTheme} height="320px" />
          <button onClick={doConvert} disabled={busy || !xrayText.trim()}
            className="h-8 rounded-lg bg-[var(--accent)] px-4 text-[13px] font-medium text-white transition-colors duration-150 hover:brightness-110 disabled:opacity-40">
            解析预览
          </button>
          {err && <ErrorBar text={err} />}
        </div>
      )}

      {(tab === "manual" || mode === "edit") && (
        <div className="max-w-4xl space-y-5">
          {warnings.length > 0 && (
            <div className="rounded-xl border border-[var(--warn)]/30 bg-[var(--warn)]/[0.06] p-4 text-sm">
              <div className="mb-1.5 flex items-center gap-1.5 font-semibold text-[var(--warn)]">
                <AlertTriangle size={14} strokeWidth={2} /> 转换警告
              </div>
              <ul className="list-disc space-y-0.5 pl-5 text-[13px] opacity-80">
                {warnings.map((w, i) => <li key={i}>{w}</li>)}
              </ul>
            </div>
          )}

          {/* ── 元数据 ── */}
          <div className="panel grid grid-cols-3 gap-x-5 gap-y-4 p-5">
            <Field label="名称" required>
              <input value={draft.name} onChange={(e) => set({ name: e.target.value })} className={inputCls} style={borderStyle} />
            </Field>
            <Field label="CVE">
              <input value={draft.cve} onChange={(e) => set({ cve: e.target.value })} placeholder="CVE-2025-XXXXX"
                className={`${inputCls} font-mono-data`} style={borderStyle} />
            </Field>
            <Field label="严重度">
              <select value={draft.severity} onChange={(e) => set({ severity: e.target.value })} className={inputCls} style={borderStyle}>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="类别">
              <select value={draft.category} onChange={(e) => set({ category: e.target.value })} className={inputCls} style={borderStyle}>
                {CATEGORIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </Field>
            <VendorInput draft={draft} set={set} inputCls={inputCls} borderStyle={borderStyle} />
            <Field label="产品">
              <input value={draft.product} onChange={(e) => set({ product: e.target.value })} className={inputCls} style={borderStyle} />
            </Field>
            <Field label="状态">
              <select value={draft.status} onChange={(e) => set({ status: e.target.value })} className={inputCls} style={borderStyle}>
                {STATUSES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </Field>
            <div className="col-span-2">
              <Field label="标签（逗号分隔）">
                <input value={draft.tags.join(",")}
                  onChange={(e) => set({ tags: e.target.value.split(",").map((s) => s.trim()) })}
                  placeholder="cve, xwiki, rce"
                  className={`${inputCls}`} style={borderStyle} />
              </Field>
            </div>
            <div className="col-span-2">
              <Field label="别名（逗号分隔）">
                <input value={draft.aliases.join(",")}
                  onChange={(e) => set({ aliases: e.target.value.split(",").map((s) => s.trim()) })}
                  className={`${inputCls}`} style={borderStyle} />
              </Field>
            </div>
            <Field label="描述">
              <textarea value={draft.description} onChange={(e) => set({ description: e.target.value })} rows={2}
                className={inputCls} style={borderStyle} />
            </Field>
          </div>

          {draft.kind === "script" ? (
            <section>
              <SectionTitleIcon title="脚本内容（不可执行，仅存储管理）" />
              <CodeMirror value={draft.specYaml} onChange={(v) => set({ specYaml: v })} theme={cmTheme} height="300px" />
            </section>
          ) : (
            <>
              {/* ── 传输类型 ── */}
              <div className="flex items-center gap-3">
                <span className="text-[11px] font-medium text-[var(--txt-dim)]">传输类型</span>
                <div className="inline-flex rounded-lg border p-0.5" style={{ borderColor: "var(--line)", background: "var(--bg-panel)" }}>
                  {(["http", "tcp"] as const).map((t) => (
                    <button key={t} onClick={() => switchTransport(t)}
                      className={`h-7 rounded-md px-3.5 text-xs transition-colors duration-150 ${
                        transport === t ? "bg-[var(--accent)] font-medium text-white" : "text-[var(--txt-dim)] hover:bg-[var(--hover)]"
                      }`}>
                      {t.toUpperCase()}
                    </button>
                  ))}
                </div>
                <span className="text-[11px] text-[var(--txt-faint)]">切换会清空已填规则</span>
              </div>

              {/* ── 规则卡片 ── */}
              <div className="space-y-3">
                {rules.map((r, i) => (
                  <div key={i} className="panel space-y-3 p-4">
                    <div className="flex items-center gap-2">
                      <span className="font-mono-data rounded bg-[var(--chip)] px-2 py-0.5 text-xs font-semibold text-[var(--txt)]">
                        r{i}
                      </span>
                      <span className="text-xs text-[var(--txt-faint)]">请求规则</span>
                      <button
                        onClick={() => setRules((rs) => (rs.length > 1 ? rs.filter((_, x) => x !== i) : rs))}
                        disabled={rules.length <= 1}
                        className="ml-auto flex h-7 w-7 items-center justify-center rounded-md text-[var(--txt-faint)] transition-colors duration-150 hover:bg-red-500/10 hover:text-[var(--danger)] disabled:opacity-30"
                        title="删除此规则"
                      >
                        <Trash2 size={14} strokeWidth={1.8} />
                      </button>
                    </div>

                    {transport === "http" ? (
                      <>
                        <div className="grid grid-cols-[110px_1fr] gap-3">
                          <Field label="Method">
                            <select value={r.method} onChange={(e) => patchRule(i, { method: e.target.value })}
                              className={inputCls} style={borderStyle}>
                              {["GET", "POST", "PUT", "DELETE", "HEAD"].map((m) => <option key={m}>{m}</option>)}
                            </select>
                          </Field>
                          <Field label="Path" hint="以 / 开头，可带 query；运行时拼接在目标后">
                            <input value={r.path} onChange={(e) => patchRule(i, { path: e.target.value })}
                              placeholder="/admin/login?action=login"
                              className={`${inputCls} font-mono-data`} style={borderStyle} />
                          </Field>
                        </div>

                        <div>
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-medium text-[var(--txt-dim)]">Headers</span>
                            <button onClick={() => patchRule(i, { headers: [...r.headers, { k: "", v: "" }] })}
                              className="flex h-6 items-center gap-1 rounded px-1.5 text-[11px] text-[var(--accent)] hover:bg-[var(--hover)]">
                              <Plus size={12} /> 添加
                            </button>
                          </div>
                          {r.headers.map((h, hi) => (
                            <div key={hi} className="mt-1.5 grid grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)_28px] gap-2">
                              <input value={h.k} onChange={(e) => patchRule(i, {
                                headers: r.headers.map((x, xi) => xi === hi ? { ...x, k: e.target.value } : x) })}
                                placeholder="Content-Type" className={`${inputCls} !mt-0 font-mono-data`} style={borderStyle} />
                              <input value={h.v} onChange={(e) => patchRule(i, {
                                headers: r.headers.map((x, xi) => xi === hi ? { ...x, v: e.target.value } : x) })}
                                placeholder="application/x-www-form-urlencoded"
                                className={`${inputCls} !mt-0`} style={borderStyle} />
                              <button onClick={() => patchRule(i, { headers: r.headers.filter((_, xi) => xi !== hi) })}
                                className="flex items-center justify-center rounded-md text-[var(--txt-faint)] hover:bg-[var(--hover)] hover:text-[var(--danger)]">
                                <Trash2 size={13} />
                              </button>
                            </div>
                          ))}
                        </div>

                        <Field label="Body（POST 等非 GET 时填写）">
                          <textarea value={r.body} onChange={(e) => patchRule(i, { body: e.target.value })} rows={2}
                            placeholder="action=login&user=admin"
                            className={`${inputCls} font-mono-data`} style={borderStyle} />
                        </Field>
                      </>
                    ) : (
                      <>
                        <div>
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-medium text-[var(--txt-dim)]">
                              Inputs —— 按序发送的原始报文（\n 表示换行）
                            </span>
                            <button onClick={() => patchRule(i, { inputs: [...r.inputs, ""] })}
                              className="flex h-6 items-center gap-1 rounded px-1.5 text-[11px] text-[var(--accent)] hover:bg-[var(--hover)]">
                              <Plus size={12} /> 添加
                            </button>
                          </div>
                          {r.inputs.map((inp, ii) => (
                            <div key={ii} className="mt-1.5 flex gap-2">
                              <input value={inp} onChange={(e) => patchRule(i, {
                                inputs: r.inputs.map((x, xi) => xi === ii ? e.target.value : x) })}
                                className={`${inputCls} !mt-0 font-mono-data`} style={borderStyle} />
                              <button onClick={() => patchRule(i, { inputs: r.inputs.filter((_, xi) => xi !== ii) })}
                                className="flex w-7 items-center justify-center rounded-md text-[var(--txt-faint)] hover:bg-[var(--hover)] hover:text-[var(--danger)]">
                                <Trash2 size={13} />
                              </button>
                            </div>
                          ))}
                        </div>
                        <Field label="Read Timeout（秒）">
                          <input type="number" min={1} max={30} value={r.readTimeout}
                            onChange={(e) => patchRule(i, { readTimeout: Number(e.target.value) || 3 })}
                            className={`${inputCls} !w-32 font-mono-data`} style={borderStyle} />
                        </Field>
                      </>
                    )}

                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-[var(--txt-dim)]">
                          响应条件表达式 —— 判断这个响应是否命中漏洞
                        </span>
                      </div>
                      <ExprInput
                        value={r.expression}
                        onChange={(v) => patchRule(i, { expression: v })}
                        validate={(v) => api.compileRuleExpr(v)}
                        placeholder={transport === "tcp"
                          ? "response.raw.bcontains(b'@RSYNCD: ')"
                          : "response.status == 200 && response.body.bcontains(b'root:')"}
                      />
                    </div>
                  </div>
                ))}

                <button
                  onClick={() => setRules((rs) => [...rs, blankRule(transport)])}
                  className="flex h-8 w-full items-center justify-center gap-1.5 rounded-lg border border-dashed text-[13px] text-[var(--txt-dim)] transition-colors duration-150 hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  style={{ borderColor: "var(--line-strong)" }}
                >
                  <Plus size={14} /> 添加规则
                </button>
              </div>

              {/* ── 总表达式 ── */}
              <div className="panel space-y-2.5 p-4">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-medium text-[var(--txt-dim)]">
                    总表达式 —— 组合各规则的判定逻辑（只允许 rule 名与 &amp;&amp; / || / !）
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {ruleNames.map((n) => (
                      <TokBtn key={n} onClick={() => setFinalExpr((f) => f + `${n}()`)}>{n}()</TokBtn>
                    ))}
                    <TokBtn onClick={() => setFinalExpr((f) => f + " && ")}>&&</TokBtn>
                    <TokBtn onClick={() => setFinalExpr((f) => f + " || ")}>||</TokBtn>
                    <TokBtn onClick={() => setFinalExpr((f) => f + "!")}>!</TokBtn>
                  </div>
                </div>
                <ExprInput
                  value={finalExpr}
                  onChange={setFinalExpr}
                  validate={(v) => api.compileFinalExpr(v, ruleNames)}
                  placeholder="r0() || r1()"
                />
              </div>

              {/* ── 函数速查 ── */}
              <details className="panel overflow-hidden">
                <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-[13px] font-medium text-[var(--txt-dim)] transition-colors duration-150 hover:bg-[var(--hover)]">
                  <BookOpen size={14} strokeWidth={1.8} /> 表达式函数速查（点击行复制）
                </summary>
                <div className="border-t px-4 py-3" style={{ borderColor: "var(--line)" }}>
                  <Cheatsheet />
                </div>
              </details>

              {/* ── YAML 预览 ── */}
              <details className="panel overflow-hidden" open={showPreview} onToggle={(e) => setShowPreview((e.target as HTMLDetailsElement).open)}>
                <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-[13px] font-medium text-[var(--txt-dim)] transition-colors duration-150 hover:bg-[var(--hover)]">
                  生成的 PWF YAML 预览（保存时以此入库）
                </summary>
                <div className="border-t p-3" style={{ borderColor: "var(--line)" }}>
                  <CodeMirror value={previewYaml} extensions={[yaml()]} theme={cmTheme} editable={false} height="220px" />
                </div>
              </details>
            </>
          )}

          {err && <ErrorBar text={err} />}
          <div className="flex gap-2.5">
            <button onClick={doSave} disabled={busy}
              className={`flex h-9 items-center gap-2 rounded-lg px-6 text-[13px] font-medium transition-colors duration-150 disabled:opacity-40 ${
                saved ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "bg-[var(--accent)] text-white hover:brightness-110"
              }`}>
              {saved ? <Check size={15} strokeWidth={2.5} /> : <Save size={14} strokeWidth={2} />}
              {saved ? "已保存" : mode === "create" ? "保存入库" : "保存修改"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── 子组件 ─────────────────────────────────────────── */

function ExprInput({ value, onChange, validate, placeholder }: {
  value: string;
  onChange: (v: string) => void;
  validate: (v: string) => Promise<void>;
  placeholder?: string;
}) {
  const [status, setStatus] = useState<{ ok: boolean | null; msg: string }>({ ok: null, msg: "" });
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // validate 常为调用方内联箭头（每次 render 新引用）；入 ref 后防抖只随 value 变化重启
  const validateRef = useRef(validate);
  useEffect(() => { validateRef.current = validate; });

  useEffect(() => {
    if (!value.trim()) { setStatus({ ok: null, msg: "" }); return; }
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(async () => {
      try {
        await validateRef.current(value);
        setStatus({ ok: true, msg: "语法正确" });
      } catch (e) {
        setStatus({ ok: false, msg: e instanceof Error ? e.message : String(e) });
      }
    }, 400);
    return () => { clearTimeout(timerRef.current); };
  }, [value]);

  return (
    <div>
      <div className="relative mt-1.5">
        <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
          className={`w-full rounded-lg border bg-[var(--bg-input)] px-3 py-2 pr-8 font-mono-data text-[13px] outline-none transition-colors duration-150 placeholder:text-[var(--txt-faint)] ${
            status.ok === false ? "border-red-500/60" : status.ok === true ? "border-emerald-500/50" : ""
          }`}
          style={status.ok === true || status.ok === false ? undefined : { borderColor: "var(--line)" }} />
        <span className="absolute right-2.5 top-1/2 -translate-y-1/2">
          {status.ok === true && <CheckCheck size={15} className="text-emerald-500" strokeWidth={2.2} />}
          {status.ok === false && <AlertTriangle size={14} className="text-red-500" strokeWidth={2} />}
        </span>
      </div>
      {status.ok === false && status.msg && (
        <div className="mt-1 whitespace-pre-wrap break-all text-[11px] leading-relaxed text-red-500">{status.msg}</div>
      )}
      {status.ok === true && (
        <div className="mt-1 text-[11px] text-emerald-600 dark:text-emerald-400">✓ 表达式可编译</div>
      )}
    </div>
  );
}

const HTTP_EXAMPLES = [
  "response.status == 200",
  "response.status == 200 && response.body.bcontains(b'root:')",
  "response.body.bmatches('root:.*:0:0')",
  "response.content_type.contains('application/json')",
  "response.headers['server'].contains('nginx')",
  "response.body.contains('welcome')",
  "response.elapsed_ms >= 4000",
];
const TCP_EXAMPLES = [
  "response.raw.bcontains(b'@RSYNCD: ')",
  "response.raw.bcontains(b'@RSYNCD: ') && response.raw.bcontains(b'@RSYNCD: EXIT')",
];

function Cheatsheet() {
  const [copied, setCopied] = useState("");
  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text).catch(() => {});
    setCopied(text);
    setTimeout(() => setCopied(""), 1200);
  };
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-1">
      {[["HTTP 响应", HTTP_EXAMPLES], ["TCP 原始收发", TCP_EXAMPLES]].map(([title, list]) => (
        <div key={title as string}>
          <div className="mb-1.5 text-[11px] font-medium text-[var(--txt-dim)]">{title as string}</div>
          {(list as string[]).map((ex) => (
            <button key={ex} onClick={() => copy(ex)}
              className="font-mono-data group flex w-full items-center gap-1.5 rounded px-1.5 py-1 text-left text-[11px] text-slate-600 dark:text-slate-300 transition-colors duration-150 hover:bg-[var(--hover)]">
              <Copy size={11} className="shrink-0 opacity-40 group-hover:opacity-100" />
              <span className="truncate">{copied === ex ? "已复制！" : ex}</span>
            </button>
          ))}
        </div>
      ))}
      <div className="col-span-2 mt-2 border-t pt-2 text-[11px] leading-relaxed text-[var(--txt-faint)]" style={{ borderColor: "var(--line)" }}>
        可用字段：<code className="font-mono-data">response.status / headers / body / content_type / raw / elapsed_ms</code>
        　函数：<code className="font-mono-data">bcontains(b'..') · bmatches('re') · contains · matches · startswith · endswith · tolower</code>
        　正则为 RE2 语法。elapsed_ms 为该规则请求的网络耗时（毫秒），时间盲注用它做阈值判断。
      </div>
    </div>
  );
}

function SegTab({ active, onClick, icon, children }: {
  active: boolean; onClick: () => void; icon: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <button onClick={onClick}
      className={`flex h-8 items-center gap-1.5 rounded-lg px-3.5 text-[13px] transition-colors duration-150 ${
        active ? "bg-[var(--accent)] font-medium text-white" : "text-[var(--txt-dim)] hover:bg-[var(--hover)]"
      }`}>
      {icon}{children}
    </button>
  );
}

function Field({ label, required, hint, children }: {
  label: string; required?: boolean; hint?: string; children: React.ReactNode;
}) {
  return (
    <label className="block text-xs">
      <span className="mb-1.5 block font-medium text-[var(--txt-dim)]">
        {label}{required && <span className="ml-0.5 text-[var(--danger)]">*</span>}
        {hint && <span className="ml-1.5 normal-case opacity-60">{hint}</span>}
      </span>
      {children}
    </label>
  );
}

function SectionTitleIcon({ title }: { title: string }) {
  return <div className="mb-2 text-[11px] font-medium text-[var(--txt-dim)]">{title}</div>;
}

function ErrorBar({ text }: { text: string }) {
  return (
    <div className="rounded-xl border border-red-500/30 bg-red-500/[0.07] p-3.5 text-[13px] text-red-500">
      <div className="flex items-start gap-2">
        <AlertTriangle size={15} className="mt-0.5 shrink-0" strokeWidth={2} />
        <span className="whitespace-pre-wrap break-all">{text}</span>
      </div>
    </div>
  );
}

function VendorInput({ draft, set, inputCls, borderStyle }: {
  draft: Draft;
  set: (patch: Partial<Draft>) => void;
  inputCls: string;
  borderStyle: React.CSSProperties;
}) {
  const [sugs, setSugs] = useState<string[]>([]);
  const [focused, setFocused] = useState(false);
  // 键盘高亮项：↑↓ 移动 / Enter 选中 / Esc 收起
  const [active, setActive] = useState(-1);

  useEffect(() => {
    let alive = true;
    api.suggestVendor(draft.vendor).then((s) => { if (alive) { setSugs(s ?? []); setActive(-1); } }).catch(() => {});
    return () => { alive = false; };
  }, [draft.vendor]);

  const pick = (s: string) => {
    set({ vendor: s });
    setSugs([]);
    setActive(-1);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    const open = focused && draft.vendor.length > 0 && sugs.length > 0;
    if (!open) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(sugs.length - 1, a + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(-1, a - 1)); }
    else if (e.key === "Enter" && active >= 0) { e.preventDefault(); pick(sugs[active]); }
    else if (e.key === "Escape") { setSugs([]); setActive(-1); }
  };

  const open = focused && draft.vendor.length > 0 && sugs.length > 0;

  return (
    <label className="relative block text-xs">
      <span className="mb-1.5 block font-medium text-[var(--txt-dim)]">厂商</span>
      <input
        value={draft.vendor}
        onChange={(e) => set({ vendor: e.target.value })}
        onFocus={() => setFocused(true)}
        onBlur={() => setTimeout(() => setFocused(false), 150)}
        onKeyDown={onKeyDown}
        role="combobox"
        aria-expanded={open}
        aria-autocomplete="list"
        placeholder="输入以检索字典"
        className={`${inputCls}`}
        style={borderStyle}
      />
      {open && (
        <div role="listbox" aria-label="厂商建议"
          className="absolute z-20 mt-1 max-h-36 w-full overflow-auto rounded-lg border shadow-xl"
          style={{ borderColor: "var(--line-strong)", background: "var(--bg-panel)" }}>
          {sugs.map((s, i) => (
            <button key={s} type="button" role="option" aria-selected={i === active}
              onMouseDown={() => pick(s)}
              onMouseEnter={() => setActive(i)}
              className={`block w-full px-3 py-1.5 text-left text-xs text-[var(--txt)] transition-colors duration-150 ${
                i === active ? "bg-[var(--hover)]" : ""
              }`}>
              {s}
            </button>
          ))}
        </div>
      )}
    </label>
  );
}

function TokBtn({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick}
      className="font-mono-data h-6 rounded border px-1.5 text-[11px] text-[var(--txt-dim)] transition-colors duration-150 hover:border-[var(--accent)] hover:text-[var(--accent)]"
      style={{ borderColor: "var(--line-strong)" }}>
      {children}
    </button>
  );
}

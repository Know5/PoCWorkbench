// api.ts —— Wails 绑定的类型化封装。
// window 注入的桥接对象在边界处用 in/typeof 守卫逐层收敛，最终一次具名断言。

interface WailsApp {
  [method: string]: (...args: unknown[]) => Promise<unknown>;
}

interface WailsRuntime {
  EventsOn(event: string, cb: (...data: unknown[]) => void): void;
  EventsOff(event: string, ...more: string[]): void;
}

function wailsApp(): WailsApp | undefined {
  const w: unknown = window;
  if (typeof w !== "object" || w === null || !("go" in w)) return undefined;
  const go: unknown = w.go;
  if (typeof go !== "object" || go === null || !("app" in go)) return undefined;
  const appNS: unknown = go.app;
  if (typeof appNS !== "object" || appNS === null || !("App" in appNS)) return undefined;
  const appObj: unknown = appNS.App;
  if (typeof appObj !== "object" || appObj === null) return undefined;
  // 结构已由上方 in 守卫验证；方法存在性在 call() 内再校验
  return appObj as WailsApp;
}

function wailsRuntime(): WailsRuntime | undefined {
  const w: unknown = window;
  if (typeof w !== "object" || w === null || !("runtime" in w)) return undefined;
  const rt: unknown = w.runtime;
  if (typeof rt !== "object" || rt === null) return undefined;
  if (!("EventsOn" in rt) || !("EventsOff" in rt)) return undefined;
  // EventsOn/EventsOff 存在性已守卫
  return rt as WailsRuntime;
}

export interface Draft {
  uid?: string;
  name: string;
  aliases: string[];
  severity: string;
  category: string;
  vendor: string;
  product: string;
  tags: string[];
  description: string;
  cve: string;
  status: string;
  source: string;
  kind: string;
  specYaml: string;
  warnings?: string[];
}

export interface Summary {
  uid: string; name: string; aliases: string[]; severity: string;
  category: string; vendor: string; product: string; tags: string[];
  cve: string; status: string; source: string; kind: string;
  createdAt: string; updatedAt: string; lastTestedAt: string | null;
}

export interface PagedSummary { items: Summary[]; total: number }

export interface Filter {
  query?: string; vendor?: string; product?: string; severity?: string;
  category?: string; status?: string; source?: string; cve?: string;
}
export interface Page { number: number; size: number; sort: string }

export interface RuleDef {
  request: {
    method?: string; path?: string; headers?: Record<string, string>;
    body?: string; inputs?: { data: string }[]; readTimeout?: number;
  };
  expression: string;
}

export interface PwfSpec {
  transport: string;
  rules: Record<string, RuleDef>;
  expression: string;
}

export interface PwfMetadata {
  uid: string; name: string; aliases: string[]; severity: string;
  category: string; vendor: string; product: string; tags: string[];
  description: string; cve: string; status: string; source: string;
  kind: string; createdAt: string; updatedAt: string; lastTestedAt: string | null;
}

export interface Pwf { metadata: PwfMetadata; spec: PwfSpec; specRaw?: string }

export interface TestRun {
  id: number; pocUid: string; target: string; targetHost: string;
  result: string; log: string; authorized: boolean;
  startedAt: string; endedAt: string | null;
}

export interface Vendor { id: number; canonicalName: string; aliases: string[] }
export interface Product { id: number; vendorId: number; canonicalName: string }

export interface BatchResultRow {
  target: string;
  result: string; // hit|miss|error|timeout|cancelled
}

/** 批量任务启动返回：batchID 与预检剔除的非法目标 */
export interface BatchStart { id: string; invalid: string[] }

export interface DashboardData {
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
  topVendors: { vendor: string; count: number }[];
  totalPocs: number;
  totalTestRuns: number;
}

async function call<T>(method: string, ...args: unknown[]): Promise<T> {
  const a = wailsApp();
  if (!a) throw new Error("后端尚未就绪（Wails 绑定未加载）");
  const fn = a[method];
  if (typeof fn !== "function") throw new Error(`未知后端方法 ${method}`);
  return fn.apply(a, args) as Promise<T>;
}

function isTestRun(v: unknown): v is TestRun {
  return (
    typeof v === "object" && v !== null &&
    "id" in v && typeof v.id === "number" &&
    "result" in v && typeof v.result === "string"
  );
}

export const api = {
  appVersion: () => call<string>("AppVersion"),
  startupError: () => call<string>("StartupError"),
  convertXray: (yamlText: string) => call<Draft>("ConvertXray", yamlText),
  createPoc: (d: Draft) => call<string>("CreatePoc", d),
  updatePocSpec: (uid: string, specYaml: string) => call<void>("UpdatePocSpec", uid, specYaml),
  updatePocMeta: (uid: string, d: Draft) => call<void>("UpdatePocMeta", uid, d),
  listPocs: (f: Filter, p: Page) => call<PagedSummary>("ListPocs", f, p),
  getPoc: (uid: string) => call<Pwf>("GetPoc", uid),
  archivePoc: (uid: string) => call<void>("ArchivePoc", uid),
  restorePoc: (uid: string) => call<void>("RestorePoc", uid),
  deletePoc: (uid: string) => call<void>("DeletePoc", uid),
  setStatus: (uid: string, st: string) => call<void>("SetStatus", uid, st),
  listVendors: () => call<Vendor[]>("ListVendors"),
  listProducts: (vendorId: number) => call<Product[]>("ListProducts", vendorId),
  mergeVendorAlias: (canonical: string, alias: string) => call<void>("MergeVendorAlias", canonical, alias),
  setPocVendorProduct: (uid: string, v: string, p: string) => call<void>("SetPocVendorProduct", uid, v, p),
  suggestVendor: (text: string) => call<string[]>("SuggestVendorProduct", text),
  runTest: (uid: string, target: string, proxy: string, authorized: boolean) =>
    call<number>("RunTest", uid, target, proxy, authorized),
  runTestBatch: (uid: string, targets: string[], proxy: string, authorized: boolean) =>
    call<BatchStart>("RunTestBatch", uid, targets, proxy, authorized),
  cancelBatch: (id: string) => call<void>("CancelBatch", id),
  compileRuleExpr: (expr: string) => call<void>("CompileRuleExpr", expr),
  compileFinalExpr: (final: string, ruleNames: string[]) =>
    call<void>("CompileFinalExpr", final, ruleNames),
  cancelTest: (runId: number) => call<void>("CancelTest", runId),
  listTestRuns: (uid: string) => call<TestRun[]>("ListTestRuns", uid),
  exportPoc: (uid: string) => call<string>("ExportPoc", uid),
  dashboard: () => call<DashboardData>("Dashboard"),
  backupDB: () => call<string>("BackupDB"),

  onTestLog: (cb: (runId: number, line: string) => void) => {
    wailsRuntime()?.EventsOn("test:log", (...data: unknown[]) => {
      const runId = data[0];
      const line = data[1];
      if (typeof runId === "number" && typeof line === "string") cb(runId, line);
    });
  },
  offTestLog: () => wailsRuntime()?.EventsOff("test:log"),
  onTestDone: (cb: (runId: number, tr: TestRun | null, err: string) => void) => {
    wailsRuntime()?.EventsOn("test:done", (...data: unknown[]) => {
      const runId = data[0];
      const errStr = data[2];
      if (typeof runId === "number") {
        cb(runId, isTestRun(data[1]) ? data[1] : null, typeof errStr === "string" ? errStr : "");
      }
    });
  },
  offTestDone: () => wailsRuntime()?.EventsOff("test:done"),

  onBatchLog: (cb: (id: string, line: string) => void) => {
    wailsRuntime()?.EventsOn("batch:log", (...data: unknown[]) => {
      const id = data[0];
      const line = data[1];
      if (typeof id === "string" && typeof line === "string") cb(id, line);
    });
  },
  onBatchResult: (cb: (id: string, row: BatchResultRow) => void) => {
    wailsRuntime()?.EventsOn("batch:result", (...data: unknown[]) => {
      const id = data[0];
      const row = data[1];
      if (
        typeof id === "string" && row && typeof row === "object" &&
        "target" in row && "result" in row &&
        typeof row.target === "string" && typeof row.result === "string"
      ) {
        cb(id, { target: row.target, result: row.result });
      }
    });
  },
  onBatchProgress: (cb: (id: string, done: number, total: number) => void) => {
    wailsRuntime()?.EventsOn("batch:progress", (...data: unknown[]) => {
      const id = data[0];
      const done = data[1];
      const total = data[2];
      if (typeof id === "string" && typeof done === "number" && typeof total === "number") {
        cb(id, done, total);
      }
    });
  },
  onBatchDone: (cb: (id: string, total: number, hits: number, status: string) => void) => {
    wailsRuntime()?.EventsOn("batch:done", (...data: unknown[]) => {
      const id = data[0];
      const total = data[1];
      const hits = data[2];
      const status = data[3];
      if (typeof id === "string") {
        cb(
          id,
          typeof total === "number" ? total : 0,
          typeof hits === "number" ? hits : 0,
          typeof status === "string" ? status : "finished",
        );
      }
    });
  },

  // 后端启动失败推送的错误消息（payload 为字符串）
  onStartupError: (cb: (msg: string) => void) => {
    wailsRuntime()?.EventsOn("startup:error", (...data: unknown[]) => {
      const msg = data[0];
      if (typeof msg === "string") cb(msg);
    });
  },
  offStartupError: () => wailsRuntime()?.EventsOff("startup:error"),
  offBatchEvents: () =>
    wailsRuntime()?.EventsOff("batch:log", "batch:result", "batch:progress", "batch:done"),
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const CATEGORIES = ["rce", "sqli", "fileread", "fileupload", "unauth", "weakpass", "infoleak", "ssrf", "xxe", "other"];
export const STATUSES = ["untested", "tested", "failed", "faked"];

const sevColors: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-400", medium: "bg-yellow-400",
  low: "bg-sky-500", info: "bg-gray-400",
};

const sevTexts: Record<string, string> = {
  critical: "text-red-600", high: "text-orange-600", medium: "text-yellow-600",
  low: "text-sky-600", info: "text-gray-500",
};

export function sevColor(s: string): string {
  return sevColors[s] ?? "bg-gray-400";
}

export function sevText(s: string): string {
  return sevTexts[s] ?? "text-gray-500";
}

const statusColors: Record<string, string> = {
  tested: "text-emerald-600", untested: "text-gray-400",
  failed: "text-red-600", faked: "text-purple-600", archived: "line-through text-gray-400",
};

export function statusColor(s: string): string {
  return statusColors[s] ?? "";
}

// ── 无边框窗口控制（自绘标题栏用）──
interface WindowControls {
  WindowMinimise(): void;
  WindowToggleMaximise(): void;
  Quit(): void;
}

function winControls(): WindowControls | undefined {
  const w: unknown = window;
  if (typeof w !== "object" || w === null || !("runtime" in w)) return undefined;
  const rt: unknown = w.runtime;
  if (typeof rt !== "object" || rt === null) return undefined;
  if (!("WindowMinimise" in rt) || !("Quit" in rt)) return undefined;
  // 方法存在性已由 in 守卫验证
  return rt as WindowControls;
}

export const win = {
  minimize: () => winControls()?.WindowMinimise(),
  toggleMaximize: () => winControls()?.WindowToggleMaximise(),
  close: () => winControls()?.Quit(),
};

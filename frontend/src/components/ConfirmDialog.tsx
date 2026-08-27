import { useEffect, useRef } from "react";
import { AlertTriangle } from "lucide-react";

// 应用内确认弹窗：替代原生 window.confirm（风格统一、可定制按钮语义）。
// Esc / 点击遮罩取消；打开时焦点落在确认键上便于 Enter 直达。
export default function ConfirmDialog({ open, title, children, confirmText = "确认", cancelText = "取消", danger = false, busy = false, onConfirm, onCancel }: {
  open: boolean;
  title: string;
  children: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    confirmRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="w-[400px] space-y-4 rounded-xl border p-5 shadow-2xl"
        style={{ borderColor: "var(--line-strong)", background: "var(--bg-panel)" }}
      >
        <div className={`flex items-start gap-2.5 text-sm font-semibold ${danger ? "text-[var(--danger)]" : "text-[var(--txt)]"}`}>
          <AlertTriangle size={16} className={`mt-0.5 shrink-0 ${danger ? "" : "text-[var(--warn)]"}`} strokeWidth={2} />
          <span>{title}</span>
        </div>
        <div className="whitespace-pre-wrap break-all text-[13px] leading-relaxed text-[var(--txt-dim)]">
          {children}
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button
            onClick={onCancel} disabled={busy}
            className="h-8 rounded-lg border px-3.5 text-[13px] text-[var(--txt-dim)] transition-colors duration-150 hover:bg-[var(--hover)] disabled:opacity-40"
            style={{ borderColor: "var(--line-strong)" }}
          >
            {cancelText}
          </button>
          <button
            ref={confirmRef} onClick={onConfirm} disabled={busy}
            className={`h-8 rounded-lg px-3.5 text-[13px] font-medium text-white transition-colors duration-150 disabled:opacity-40 ${
              danger ? "bg-red-500 hover:brightness-110" : "bg-[var(--accent)] hover:brightness-110"
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

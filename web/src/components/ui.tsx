import { useState, type ReactNode } from 'react';
import { Check, Copy, Loader2, X } from 'lucide-react';
import { SEVERITY_LABEL, STATUS_LABEL, cx } from '../lib';
import type { AlertStatus, Severity } from '../types';

export function SeverityBadge({ severity }: { severity: Severity }) {
  const key = severity || 'unknown';
  return <span className={`badge badge-${key}`}>{SEVERITY_LABEL[key] || key}</span>;
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge badge-${status}`}>{STATUS_LABEL[status] || status}</span>;
}

export function Spinner({ label = '加载中…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-[12px] text-[var(--muted)]">
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}
    </div>
  );
}

export function SkeletonRows({ count = 6 }: { count?: number }) {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton" style={{ width: `${70 + ((i * 13) % 25)}%` }} />
      ))}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="text-[13px] font-medium">{title}</div>
      {children ? <div className="max-w-md text-[11.5px] leading-relaxed text-[var(--muted)]">{children}</div> : null}
    </div>
  );
}

export function ErrorBox({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-[color-mix(in_srgb,var(--danger)_22%,transparent)] bg-[color-mix(in_srgb,var(--danger)_7%,transparent)] px-3 py-2 text-[11.5px] text-[var(--danger-text)]">
      {children}
    </div>
  );
}

export function CopyButton({ value, label = '复制' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-ghost btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? '已复制' : label}
    </button>
  );
}

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-[var(--overlay)] p-4 backdrop-blur-sm"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={cx(
          'max-h-[92vh] w-full overflow-auto rounded-2xl border border-[var(--line)] bg-[var(--panel)] p-5 shadow-2xl',
          wide ? 'max-w-3xl' : 'max-w-xl',
        )}
      >
        <div className="mb-4 flex items-start gap-3">
          <div className="min-w-0">
            <h2 className="text-[16px] font-semibold">{title}</h2>
            {subtitle ? <p className="mt-1 text-[11.5px] leading-relaxed text-[var(--muted)]">{subtitle}</p> : null}
          </div>
          <button className="btn btn-ghost btn-sm ml-auto" onClick={onClose} aria-label="关闭">
            <X className="h-4 w-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Drawer({
  open,
  onClose,
  title,
  eyebrow,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  eyebrow?: ReactNode;
  children: ReactNode;
}) {
  return (
    <>
      <div
        className={cx(
          'fixed inset-0 z-40 bg-[var(--overlay)] backdrop-blur-[2px] transition-opacity',
          open ? 'opacity-100' : 'pointer-events-none opacity-0',
        )}
        onClick={onClose}
      />
      <aside
        className={cx(
          'fixed right-0 top-0 z-40 flex h-screen w-[min(720px,96vw)] flex-col border-l border-[var(--line)] bg-[var(--drawer-bg)] shadow-2xl transition-transform duration-200',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
        aria-hidden={!open}
      >
        <div className="flex items-start gap-3 border-b border-[var(--line-soft)] px-5 py-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[10.5px] text-[var(--dim)]">{eyebrow}</div>
            <h2 className="mt-2 text-[17px] font-semibold leading-snug">{title}</h2>
          </div>
          <button className="btn btn-ghost btn-sm ml-auto" onClick={onClose} aria-label="关闭">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-auto px-5 py-4">{children}</div>
      </aside>
    </>
  );
}

export function StatCard({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="card p-4">
      <div className="text-[10.5px] uppercase tracking-[.8px] text-[var(--dim)]">{label}</div>
      <div className="mt-2 text-[26px] font-semibold leading-none" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {hint ? <div className="mt-2 text-[11px] text-[var(--muted)]">{hint}</div> : null}
    </div>
  );
}

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { Check, Copy, Loader2, X } from 'lucide-react';
import { SEVERITY_LABEL, STATUS_LABEL, cx } from '../lib';
import { useI18n } from '../i18n';
import type { AlertStatus, Severity } from '../types';

// Keep complete class names visible to Tailwind's content scanner.
const severityClasses: Record<Severity, string> = {
  critical: 'badge-critical',
  fatal: 'badge-fatal',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  informational: 'badge-informational',
  unknown: 'badge-unknown',
};
const statusClasses: Record<AlertStatus, string> = {
  open: 'badge-open',
  acknowledged: 'badge-acknowledged',
  suppressed: 'badge-suppressed',
  closed: 'badge-closed',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useI18n();
  const key = severity || 'unknown';
  return (
    <span className={`badge ${severityClasses[key] || severityClasses.unknown}`}>
      {t(SEVERITY_LABEL[key] || key)}
    </span>
  );
}
export function StatusBadge({ status }: { status: AlertStatus }) {
  const { t } = useI18n();
  return (
    <span className={`badge ${statusClasses[status] || severityClasses.unknown}`}>
      {t(STATUS_LABEL[status] || status)}
    </span>
  );
}
export function Spinner({ label = '加载中…' }: { label?: string }) {
  const { t } = useI18n();
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-sm text-[var(--muted)]" role="status">
      <Loader2 className="h-4 w-4 animate-spin" />
      {t(label)}
    </div>
  );
}
export function SkeletonRows({ count = 6 }: { count?: number }) {
  const { t } = useI18n();
  return (
    <div className="space-y-3 p-4" role="status" aria-label={t('加载中…')}>
      {Array.from({ length: count }).map((_, index) => (
        <div key={index} className="skeleton" style={{ width: `${70 + ((index * 13) % 25)}%` }} />
      ))}
    </div>
  );
}
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="text-sm font-medium">{t(title)}</div>
      {children ? <div className="max-w-md text-sm text-[var(--muted)]">{children}</div> : null}
    </div>
  );
}
export function ErrorBox({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  return (
    <div
      role="alert"
      className="rounded-lg border border-[color-mix(in_srgb,var(--danger)_22%,transparent)] bg-[color-mix(in_srgb,var(--danger)_7%,transparent)] px-4 py-3 text-sm text-[var(--danger-text)]"
    >
      {typeof children === 'string' ? t(children) : children}
    </div>
  );
}
export function Notice({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  return (
    <div
      role="status"
      className="flex items-start gap-3 rounded-lg border border-[color-mix(in_srgb,var(--med)_30%,transparent)] bg-[color-mix(in_srgb,var(--med)_9%,transparent)] px-4 py-3 text-sm text-[var(--text)]"
    >
      <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--med)]" aria-hidden="true" />
      <div className="min-w-0">{typeof children === 'string' ? t(children) : children}</div>
    </div>
  );
}
export function CopyButton({ value, label = '复制' }: { value: string; label?: string }) {
  const { t } = useI18n();
  const [status, setStatus] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <button
      type="button"
      className="btn btn-ghost btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setStatus('copied');
        } catch {
          setStatus('failed');
        }
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setStatus('idle'), 1600);
      }}
    >
      {status === 'copied' ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      <span aria-live="polite">
        {t(status === 'copied' ? '已复制' : status === 'failed' ? '复制失败' : label)}
      </span>
    </button>
  );
}

function useDialog(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const dialog = ref.current;
    const focusable = () =>
      Array.from(
        dialog?.querySelectorAll<HTMLElement>(
          'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]',
        ) || [],
      ).filter((element) => element.getClientRects().length > 0);
    (focusable()[0] || dialog)?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeRef.current();
      }
      if (event.key !== 'Tab') return;
      const elements = focusable();
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (!first) {
        event.preventDefault();
        dialog?.focus();
        return;
      }
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener('keydown', onKey);
      previous?.focus();
    };
  }, [open]);
  return ref;
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
  const { t } = useI18n();
  const titleID = useId();
  const ref = useDialog(open, onClose);
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-[var(--overlay)] p-4"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleID}
        tabIndex={-1}
        className={cx(
          'max-h-[92vh] w-full overflow-auto rounded-xl border border-[var(--line)] bg-[var(--panel)] p-6 shadow-2xl',
          wide ? 'max-w-3xl' : 'max-w-xl',
        )}
      >
        <div className="mb-5 flex items-start gap-3">
          <div className="min-w-0">
            <h2 id={titleID} className="text-lg font-semibold">
              {title}
            </h2>
            {subtitle ? <p className="mt-2 text-sm text-[var(--muted)]">{subtitle}</p> : null}
          </div>
          <button className="btn btn-ghost btn-icon ml-auto" onClick={onClose} aria-label={t('关闭')}>
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
  const { t } = useI18n();
  const titleID = useId();
  const ref = useDialog(open, onClose);
  if (!open) return null;
  return (
    <>
      <div className="fixed inset-0 z-40 bg-[var(--overlay)]" onClick={onClose} />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleID}
        tabIndex={-1}
        className="fixed inset-y-0 right-0 z-40 flex w-[min(800px,100vw)] flex-col border-l border-[var(--line)] bg-[var(--panel)] shadow-2xl"
      >
        <div className="flex items-start gap-3 border-b border-[var(--line)] px-6 py-5">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs text-[var(--muted)]">{eyebrow}</div>
            <h2 id={titleID} className="mt-2 text-lg font-semibold leading-snug">
              {title}
            </h2>
          </div>
          <button className="btn btn-ghost btn-icon ml-auto" onClick={onClose} aria-label={t('关闭')}>
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-auto px-6 py-5">{children}</div>
      </div>
    </>
  );
}
export function StatCard({
  label,
  value,
  hint,
  accent,
  onClick,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  accent?: string;
  onClick?: () => void;
}) {
  const content = (
    <>
      <div className="text-sm text-[var(--muted)]">{label}</div>
      <div
        className="mt-3 text-[30px] font-semibold leading-none tracking-tight tabular-nums"
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
      {hint ? <div className="mt-3 text-xs text-[var(--muted)]">{hint}</div> : null}
    </>
  );
  return onClick ? (
    <button className="card stat-card p-5 text-left" onClick={onClick}>
      {content}
    </button>
  ) : (
    <div className="card p-5">{content}</div>
  );
}

import { useState, type ReactNode } from 'react';
import {
  Activity,
  Bell,
  Cloud,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Monitor,
  Moon,
  RefreshCw,
  ShieldCheck,
  Sun,
  Terminal,
} from 'lucide-react';
import { api, logout } from '../api';
import { useTheme, type ThemeMode } from '../lib';
import { useApp } from '../state';
import type { Page } from '../types';
import { Modal } from './ui';

const NAV: Array<{ page: Page; label: string; hint: string; icon: typeof LayoutDashboard }> = [
  { page: 'overview', label: '概览', hint: 'OVERVIEW', icon: LayoutDashboard },
  { page: 'alerts', label: '统一告警', hint: 'ALERTS', icon: Bell },
  { page: 'accounts', label: '云账号', hint: 'SOURCES', icon: Cloud },
  { page: 'health', label: '接入状态', hint: 'HEALTH', icon: Activity },
  { page: 'mcp', label: 'MCP', hint: 'AGENTS', icon: Terminal },
];

const TITLES: Record<Page, { title: string; subtitle: string }> = {
  overview: { title: '概览', subtitle: '所有云厂商的安全告警，在一个视图里。' },
  alerts: { title: '统一告警', subtitle: '跨厂商归一化、去重，保留原始证据。' },
  accounts: { title: '云账号', subtitle: '接入厂商，配置只读凭据和同步策略。' },
  health: { title: '接入状态', subtitle: '同步游标、限流、失败和最近运行。' },
  mcp: { title: 'MCP', subtitle: '让 Agent 通过只读工具查询你的安全数据。' },
};

export function Layout({ children }: { children: ReactNode }) {
  const { me, meta, page, go, toast, refresh } = useApp();
  const { mode, setMode } = useTheme();
  const [passwordOpen, setPasswordOpen] = useState(false);
  const dev = !!me?.dev_mode;

  async function doLogout() {
    try {
      await logout();
    } catch {
      /* cookie may already be gone */
    }
    window.location.reload();
  }

  return (
    <div className="min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[232px] flex-col border-r border-[var(--line-soft)] bg-[color-mix(in_srgb,var(--panel)_72%,transparent)] px-3 py-5 backdrop-blur-md lg:flex">
        <div className="flex items-center gap-3 px-2 pb-7">
          <div className="grid h-9 w-9 place-items-center rounded-xl border border-[var(--accent-border)] bg-[var(--accent-soft)] text-[var(--accent)]">
            <ShieldCheck className="h-[19px] w-[19px]" />
          </div>
          <div>
            <div className="text-[15px] font-semibold tracking-tight">GuiLiu</div>
            <div className="text-[9px] uppercase tracking-[1.8px] text-[var(--dim)]">Security data hub</div>
          </div>
        </div>
        <nav className="space-y-1">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.page}
                className={`nav-link w-full ${page === item.page ? 'active' : ''}`}
                onClick={() => go(item.page)}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{item.label}</span>
                <span className="ml-auto text-[8px] tracking-[1.2px] text-[var(--dim)]">{item.hint}</span>
              </button>
            );
          })}
        </nav>
        <div className="mt-auto space-y-2 px-2 pt-5 text-[10px] text-[var(--dim)]">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-[var(--low)] shadow-[0_0_8px_var(--low)]" />
            服务正常
          </div>
          <div className="font-mono">
            v{meta?.version || '—'} · OCSF {meta?.ocsf_version || '—'}
          </div>
        </div>
      </aside>

      <div className="lg:pl-[232px]">
        <header className="sticky top-0 z-20 border-b border-[var(--line-soft)] bg-[color-mix(in_srgb,var(--bg)_84%,transparent)] px-4 py-3 backdrop-blur-md sm:px-6">
          <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-3">
            <div className="min-w-0">
              <div className="text-[10px] uppercase tracking-[1.6px] text-[var(--dim)]">{TITLES[page].subtitle}</div>
              <h1 className="mt-1 text-[22px] font-semibold tracking-tight">{TITLES[page].title}</h1>
            </div>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <ThemeSwitch mode={mode} setMode={setMode} />
              {meta?.mock ? <span className="pill">Mock 数据</span> : null}
              {dev ? <span className="pill">开发模式</span> : null}
              <span className="pill max-w-[180px] truncate" title={me?.user?.role}>
                <span className={`h-1.5 w-1.5 rounded-full ${dev ? 'bg-[var(--dim)]' : 'bg-[var(--low)]'}`} />
                {dev ? '本地开发' : me?.user?.username || '—'}
              </span>
              {!dev ? (
                <>
                  <button className="btn btn-ghost btn-sm" onClick={() => setPasswordOpen(true)} title="修改密码">
                    <KeyRound className="h-3.5 w-3.5" />
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={doLogout} title="退出登录">
                    <LogOut className="h-3.5 w-3.5" />
                  </button>
                </>
              ) : null}
              <button className="btn btn-sm" onClick={refresh} title="刷新">
                <RefreshCw className="h-3.5 w-3.5" />
                刷新
              </button>
            </div>
          </div>
          <nav className="mx-auto mt-3 flex max-w-[1500px] gap-1 overflow-x-auto lg:hidden">
            {NAV.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.page}
                  className={`btn btn-sm shrink-0 ${page === item.page ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => go(item.page)}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </header>

        <main className="mx-auto max-w-[1500px] px-4 py-5 sm:px-6">{children}</main>
      </div>

      <PasswordModal open={passwordOpen} onClose={() => setPasswordOpen(false)} onDone={() => toast('密码已更新，请重新登录')} />
    </div>
  );
}

function ThemeSwitch({ mode, setMode }: { mode: ThemeMode; setMode: (mode: ThemeMode) => void }) {
  const options: Array<{ mode: ThemeMode; label: string; icon: typeof Sun }> = [
    { mode: 'auto', label: '自动', icon: Monitor },
    { mode: 'light', label: '浅色', icon: Sun },
    { mode: 'dark', label: '深色', icon: Moon },
  ];
  return (
    <div className="inline-flex items-center gap-0.5 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-0.5">
      {options.map((item) => {
        const Icon = item.icon;
        return (
          <button
            key={item.mode}
            type="button"
            title={item.label}
            className={`grid h-7 w-7 place-items-center rounded-md transition ${
              mode === item.mode
                ? 'bg-[var(--accent-soft)] text-[var(--accent)] ring-1 ring-[var(--accent-border)]'
                : 'text-[var(--dim)] hover:bg-[var(--hover)] hover:text-[var(--text)]'
            }`}
            onClick={() => setMode(item.mode)}
          >
            <Icon className="h-3.5 w-3.5" />
          </button>
        );
      })}
    </div>
  );
}

function PasswordModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const { toast } = useApp();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next !== confirm) {
      toast('两次输入的新密码不一致', true);
      return;
    }
    setBusy(true);
    try {
      await api('/auth/password', {
        method: 'POST',
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      setCurrent('');
      setNext('');
      setConfirm('');
      onClose();
      onDone();
      setTimeout(() => window.location.reload(), 700);
    } catch (err: any) {
      if (err?.status !== 401) toast(err?.message || '修改密码失败', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="修改密码" subtitle="更新成功后所有会话会被吊销，需要重新登录。">
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-[11px] text-[var(--muted)]">
          当前密码
          <input className="field mt-1.5 w-full" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </label>
        <label className="block text-[11px] text-[var(--muted)]">
          新密码（至少 12 位）
          <input className="field mt-1.5 w-full" type="password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} />
        </label>
        <label className="block text-[11px] text-[var(--muted)]">
          确认新密码
          <input className="field mt-1.5 w-full" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required minLength={12} />
        </label>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            取消
          </button>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? '更新中…' : '更新密码'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

import { useEffect, useState, type ReactNode } from 'react';
import {
  Activity,
  Bell,
  Cloud,
  KeyRound,
  LayoutDashboard,
  LogOut,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import { api, logout } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import type { HealthResponse, Page } from '../types';
import { Modal } from './ui';
import { Preferences } from './Preferences';
import { GuiLiuMark } from './GuiLiuMark';

const NAV = [
  { page: 'overview', label: '概览', icon: LayoutDashboard },
  { page: 'alerts', label: '统一告警', icon: Bell },
  { page: 'accounts', label: '云账号', icon: Cloud },
  { page: 'health', label: '接入状态', icon: Activity },
  { page: 'mcp', label: 'API 与 MCP', icon: Terminal },
] as const;

export function Layout({ children }: { children: ReactNode }) {
  const { me, meta, page, go, toast, refresh, refreshNonce } = useApp();
  const { t } = useI18n();
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [service, setService] = useState('检查中');
  const dev = !!me?.dev_mode;

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    async function check() {
      try {
        const health = await api<HealthResponse>('/health', { signal: controller.signal });
        if (alive)
          setService(
            health.database !== 'ok' ? '服务不可用' : health.status === 'degraded' ? '同步异常' : '服务可用',
          );
      } catch {
        if (alive) setService('服务不可用');
      }
    }
    void check();
    const timer = window.setInterval(check, 30_000);
    return () => {
      alive = false;
      controller.abort();
      window.clearInterval(timer);
    };
  }, [refreshNonce]);

  async function doLogout() {
    try {
      await logout();
    } catch {
      /* clear client state even if the session expired */
    }
    window.location.reload();
  }

  const navigation = (mobile = false) =>
    NAV.map(({ page: destination, label, icon: Icon }) => (
      <a
        key={destination}
        href={`#/${destination}`}
        aria-current={page === destination ? 'page' : undefined}
        className={
          mobile
            ? `btn btn-sm shrink-0 ${page === destination ? 'btn-primary' : 'btn-ghost'}`
            : `nav-link ${page === destination ? 'active' : ''}`
        }
      >
        <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
        {t(label)}
      </a>
    ));

  return (
    <div className="min-h-screen">
      <aside className="sidebar fixed inset-y-0 left-0 z-30 hidden w-[216px] flex-col border-r border-[var(--line)] bg-[var(--panel)] px-3 py-6 lg:flex">
        <a href="#/overview" className="mb-8 flex items-center gap-3 px-3" aria-label="GuiLiu">
          <GuiLiuMark className="h-9 w-9 shrink-0 text-[var(--accent)]" />
          <span className="text-lg font-semibold tracking-tight">
            GuiLiu<span className="ml-2 text-xs font-normal text-[var(--dim)]">归流</span>
          </span>
        </a>
        <nav aria-label={t('数据访问')} className="space-y-1">
          {navigation()}
        </nav>
        <div className="mt-auto space-y-3 px-3 text-xs text-[var(--muted)]">
          <a href="#/health" className="flex items-center gap-2">
            <span
              className={`status-dot ${service === '服务可用' ? 'status-ok' : service === '检查中' ? '' : 'status-error'}`}
            />
            {t(service)}
          </a>
          <span className="block font-mono text-[11px] text-[var(--dim)]" title={meta?.commit}>
            {meta?.version || '—'}
          </span>
        </div>
      </aside>
      <div className="lg:pl-[216px]">
        <header className="sticky top-0 z-20 border-b border-[var(--line)] bg-[var(--panel)] px-5 py-4 lg:px-8">
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-3">
            <h1 className="mr-auto text-xl font-semibold tracking-tight">
              {t(NAV.find((item) => item.page === page)?.label || '概览')}
            </h1>
            {meta?.mock ? (
              <span className="environment-label">{t('演示数据')}</span>
            ) : dev ? (
              <span className="environment-label">{t('开发模式')}</span>
            ) : null}
            <Preferences />
            <button
              className="btn btn-ghost btn-icon"
              onClick={refresh}
              aria-label={t('刷新')}
              title={t('刷新')}
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <div className="hidden h-5 w-px bg-[var(--line)] sm:block" />
            <span className="max-w-[130px] truncate text-xs text-[var(--muted)]">
              {dev ? t('本地开发') : me?.user?.username}
            </span>
            {!dev ? (
              <>
                <button
                  className="btn btn-ghost btn-icon"
                  onClick={() => setPasswordOpen(true)}
                  aria-label={t('修改密码')}
                  title={t('修改密码')}
                >
                  <KeyRound className="h-4 w-4" />
                </button>
                <button
                  className="btn btn-ghost btn-icon"
                  onClick={doLogout}
                  aria-label={t('退出登录')}
                  title={t('退出登录')}
                >
                  <LogOut className="h-4 w-4" />
                </button>
              </>
            ) : null}
          </div>
          <nav className="mx-auto mt-3 flex max-w-[1600px] gap-1 overflow-x-auto lg:hidden">
            {navigation(true)}
          </nav>
        </header>
        <main className="mx-auto max-w-[1600px] px-5 py-6 lg:px-8">{children}</main>
      </div>
      <PasswordModal
        open={passwordOpen}
        onClose={() => setPasswordOpen(false)}
        onDone={() => toast('密码已更新，请重新登录')}
      />
    </div>
  );
}

function PasswordModal({
  open,
  onClose,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const { toast } = useApp();
  const { t } = useI18n();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
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
      window.setTimeout(() => window.location.reload(), 700);
    } catch (error: any) {
      toast(error?.message || '修改密码失败', true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={open} onClose={onClose} title={t('修改密码')} subtitle={t('更新密码后，所有会话将退出。')}>
      <form onSubmit={submit} className="space-y-4">
        <label className="form-label">
          {t('当前密码')}
          <input
            className="field w-full"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            required
          />
        </label>
        <label className="form-label">
          {t('新密码（至少 12 位）')}
          <input
            className="field w-full"
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            required
            minLength={12}
          />
        </label>
        <label className="form-label">
          {t('确认新密码')}
          <input
            className="field w-full"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            required
            minLength={12}
          />
        </label>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn" onClick={onClose}>
            {t('取消')}
          </button>
          <button className="btn btn-primary" disabled={busy}>
            {t(busy ? '更新中…' : '更新密码')}
          </button>
        </div>
      </form>
    </Modal>
  );
}

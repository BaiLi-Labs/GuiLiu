import { useCallback, useEffect, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { api } from './api';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { Alerts } from './pages/Alerts';
import { Accounts } from './pages/Accounts';
import { Health } from './pages/Health';
import { MCP } from './pages/MCP';
import { AppContext } from './state';
import { isAdmin, useHashPage } from './lib';
import type { Me, Meta, Provider } from './types';

interface ToastState {
  message: string;
  error: boolean;
  id: number;
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [fatal, setFatal] = useState('');
  const [toastState, setToastState] = useState<ToastState | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [page, go] = useHashPage();
  const timer = useRef<number | undefined>(undefined);

  const toast = useCallback((message: string, error = false) => {
    window.clearTimeout(timer.current);
    setToastState({ message, error, id: Date.now() });
    timer.current = window.setTimeout(() => setToastState(null), 3200);
  }, []);

  const boot = useCallback(async () => {
    setLoading(true);
    setFatal('');
    try {
      const current = await api<Me>('/auth/me');
      const nextMeta = await api<Meta>('/meta');
      setMe(current);
      setMeta(nextMeta);
      setProviders(nextMeta.providers || []);
    } catch (e: any) {
      if (e?.status === 401) {
        setMe(null);
      } else {
        setFatal(e?.message || '无法连接服务端');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    boot();
  }, [boot]);

  const value = {
    me,
    meta,
    providers,
    isAdmin: isAdmin(me?.user?.role, me?.dev_mode),
    page,
    go,
    toast,
    refreshNonce,
    refresh: () => setRefreshNonce((n) => n + 1),
  };

  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center text-[var(--muted)]">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  if (fatal) {
    return (
      <div className="grid min-h-screen place-items-center px-4">
        <div className="card max-w-md p-6 text-center">
          <div className="text-[15px] font-semibold">服务暂不可用</div>
          <div className="mt-2 text-[12px] text-[var(--danger-text)]">{fatal}</div>
          <button className="btn btn-primary mt-4" onClick={() => window.location.reload()}>
            重新连接
          </button>
        </div>
      </div>
    );
  }

  if (!me) {
    return (
      <AppContext.Provider value={value}>
        <Login onSuccess={() => boot()} />
      </AppContext.Provider>
    );
  }

  return (
    <AppContext.Provider value={value}>
      <Layout>
        {page === 'overview' ? <Overview /> : null}
        {page === 'alerts' ? <Alerts /> : null}
        {page === 'accounts' ? <Accounts /> : null}
        {page === 'health' ? <Health /> : null}
        {page === 'mcp' ? <MCP /> : null}
      </Layout>
      {toastState ? (
        <div
          className={`toast fixed bottom-6 left-1/2 z-[70] -translate-x-1/2 rounded-lg border px-4 py-2.5 text-[12px] shadow-2xl ${
            toastState.error
              ? 'border-[color-mix(in_srgb,var(--danger)_35%,transparent)] bg-[var(--panel)] text-[var(--danger-text)]'
              : 'border-[var(--line)] bg-[var(--panel)] text-[var(--text)]'
          }`}
        >
          {toastState.message}
        </div>
      ) : null}
    </AppContext.Provider>
  );
}

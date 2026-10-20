import { useState } from 'react';
import { ArrowRight, Loader2, ShieldCheck } from 'lucide-react';
import { login } from '../api';
import type { Me } from '../types';

export function Login({ onSuccess }: { onSuccess: (me: Me) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !password || busy) {
      setError('请输入用户名和密码');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const me = await login(username.trim(), password);
      setPassword('');
      onSuccess(me);
    } catch (err: any) {
      setError(err?.status === 429 ? '尝试过于频繁，请稍后再试' : err?.message || '登录失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-[420px]">
        <div className="mb-6 flex items-center gap-3 px-1">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-[var(--accent-border)] bg-[var(--accent-soft)] text-[var(--accent)]">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[19px] font-semibold tracking-tight">GuiLiu</div>
            <div className="text-[10px] uppercase tracking-[2px] text-[var(--dim)]">Security data hub</div>
          </div>
        </div>
        <form onSubmit={submit} className="card p-6 shadow-2xl">
          <h1 className="text-[19px] font-semibold">登录控制台</h1>
          <p className="mt-1 text-[12px] leading-relaxed text-[var(--muted)]">
            使用管理员或团队成员账号登录。登录态由 HttpOnly Session Cookie 维护。
          </p>
          <div className="mt-5 space-y-3">
            <label className="block">
              <span className="mb-1.5 block text-[11px] text-[var(--muted)]">用户名</span>
              <input
                className="field h-10 w-full"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                autoFocus
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-[11px] text-[var(--muted)]">密码</span>
              <input
                className="field h-10 w-full"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
              />
            </label>
          </div>
          {error ? <div className="mt-3 rounded-lg bg-[color-mix(in_srgb,var(--danger)_8%,transparent)] px-3 py-2 text-[11.5px] text-[var(--danger-text)]">{error}</div> : null}
          <button className="btn btn-primary mt-5 h-10 w-full justify-center" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowRight className="h-4 w-4" />}
            {busy ? '登录中…' : '进入控制台'}
          </button>
          <div className="mt-5 border-t border-[var(--line-soft)] pt-4 text-[11px] leading-relaxed text-[var(--dim)]">
            首次启动：设置 <code className="font-mono">GUILIU_ADMIN_PASSWORD</code> 后启动，或运行
            <code className="ml-1 font-mono">guiliu user add -username admin -role admin</code>。
            <br />
            本地调试可运行 <code className="font-mono">make dev</code>；Mock 模式使用
            <code className="ml-1 font-mono">make mock</code>。
          </div>
        </form>
      </div>
    </div>
  );
}

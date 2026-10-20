import { useState } from 'react';
import { ArrowRight, Loader2 } from 'lucide-react';
import { login } from '../api';
import { useI18n } from '../i18n';
import { Preferences } from '../components/Preferences';
import { GuiLiuMark } from '../components/GuiLiuMark';
import { ErrorBox } from '../components/ui';
import type { Me } from '../types';

export function Login({ onSuccess }: { onSuccess: (me: Me) => void }) {
  const { t } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!username.trim() || !password || busy) {
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
      setError(
        err?.status === 429
          ? '尝试过于频繁，请稍后再试'
          : err?.status === 401
            ? '登录失败'
            : err?.message || '登录失败',
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex min-h-screen flex-col">
      <div className="flex justify-end p-5">
        <Preferences />
      </div>
      <div className="grid flex-1 place-items-center px-5 pb-20">
        <div className="w-full max-w-[400px]">
          <div className="mb-8 flex items-center gap-3">
            <GuiLiuMark className="h-10 w-10 shrink-0 text-[var(--accent)]" />
            <span className="text-2xl font-semibold">
              GuiLiu <span className="text-base font-normal text-[var(--muted)]">归流</span>
            </span>
          </div>
          <form onSubmit={submit} className="card space-y-5 p-7">
            <h1 className="text-xl font-semibold">{t('登录控制台')}</h1>
            <label className="form-label">
              {t('用户名')}
              <input
                className="field h-10 w-full"
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
                autoFocus
              />
            </label>
            <label className="form-label">
              {t('密码')}
              <input
                className="field h-10 w-full"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </label>
            {error ? <ErrorBox>{t(error)}</ErrorBox> : null}
            <button className="btn btn-primary h-10 w-full" disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowRight className="h-4 w-4" />}
              {t(busy ? '登录中…' : '进入控制台')}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

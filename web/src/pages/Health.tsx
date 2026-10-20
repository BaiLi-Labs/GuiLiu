import { useEffect, useState } from 'react';
import { Activity, CheckCircle2, Clock3, RefreshCw } from 'lucide-react';
import { api } from '../api';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { ErrorBox, SkeletonRows, StatCard } from '../components/ui';
import { formatDate, fmtNum, providerShort, relTime } from '../lib';
import type { HealthResponse, SyncRun } from '../types';

export function Health() {
  const { refreshNonce, refresh, toast } = useApp();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [runs, setRuns] = useState<SyncRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const [h, r] = await Promise.all([
        api<HealthResponse>('/health'),
        api<{ runs: SyncRun[] }>('/sync-runs?limit=30'),
      ]);
      setHealth(h);
      setRuns(r.runs || []);
    } catch (e: any) {
      setError(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [refreshNonce]);

  async function syncAll() {
    setBusy(true);
    try {
      await api('/sync', { method: 'POST' });
      toast('已触发全部账号同步');
      setTimeout(load, 1600);
    } catch (e: any) {
      if (e?.status !== 401) toast(e.message || '同步失败', true);
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <SkeletonRows count={10} />;
  if (error) return <ErrorBox>{error}</ErrorBox>;

  const accounts = health?.accounts || [];
  const healthy = accounts.filter((a) => a.sync_state?.healthy).length;
  const pending = accounts.filter((a) => a.sync_state?.pending).length;
  const failing = accounts.filter((a) => (a.sync_state?.consecutive_failures || 0) > 0).length;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="pill"><CheckCircle2 className="h-3 w-3 text-[var(--low)]" /> 数据库 {health?.database || 'ok'}</span>
        <span className="pill"><Activity className="h-3 w-3" /> 运行 {Math.floor((health?.uptime_seconds || 0) / 60)} 分钟</span>
        <button className="btn btn-sm ml-auto" onClick={load} disabled={loading}>
          <RefreshCw className="h-3.5 w-3.5" /> 刷新
        </button>
        <button className="btn btn-sm btn-primary" onClick={syncAll} disabled={busy}>
          {busy ? '同步中…' : '同步全部'}
        </button>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <StatCard label="健康账号" value={`${healthy}/${accounts.length}`} accent="var(--low)" hint="游标和最近同步正常" />
        <StatCard label="续传中" value={fmtNum(pending)} accent="var(--med)" hint="页数预算或限流后的断点恢复" />
        <StatCard label="连续失败" value={fmtNum(failing)} accent={failing ? 'var(--danger)' : 'var(--text)'} hint="仅统计未恢复的连续失败" />
      </div>

      <section className="table-wrap">
        <div className="flex items-center gap-2 border-b border-[var(--line-soft)] px-4 py-3">
          <Activity className="h-4 w-4 text-[var(--accent)]" />
          <h2 className="text-[13px] font-semibold">账号状态</h2>
          <span className="pill ml-auto">{accounts.length} 个账号</span>
        </div>
        {accounts.length ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>账号</th>
                <th style={{ width: 140 }}>厂商</th>
                <th style={{ width: 130 }}>状态</th>
                <th style={{ width: 150 }}>最近成功</th>
                <th style={{ width: 150 }}>游标</th>
                <th style={{ width: 90 }}>上次条数</th>
                <th style={{ width: 90 }}>耗时</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => {
                const st = a.sync_state || {};
                const bad = (st.consecutive_failures || 0) > 0;
                return (
                  <tr key={a.id}>
                    <td>
                      <div className="flex items-center gap-2">
                        <BrandIcon provider={a.provider} size="xs" />
                        <div>
                          <div className="text-[11.5px]">{a.name}</div>
                          <div className="cell-sub font-mono">{a.account_uid || a.id}</div>
                        </div>
                      </div>
                    </td>
                    <td><span className="text-[11px]">{providerShort(a.provider)}</span></td>
                    <td>
                      <span className="inline-flex items-center gap-1.5 text-[11px]">
                        <span className={`h-1.5 w-1.5 rounded-full ${bad ? 'bg-[var(--danger)]' : st.pending ? 'bg-[var(--med)]' : st.last_success_at ? 'bg-[var(--low)]' : 'bg-[var(--dim)]'}`} />
                        {!a.enabled
                          ? '已停用'
                          : bad
                            ? `同步失败${st.pending_count ? ` · 待重试 ${st.pending_count}` : ''}`
                            : st.pending
                              ? '续传中'
                              : st.last_success_at
                                ? '正常'
                                : '等待同步'}
                      </span>
                    </td>
                    <td className="font-mono text-[10.5px] text-[var(--muted)]">{st.last_success_at ? relTime(st.last_success_at) : '—'}</td>
                    <td className="font-mono text-[10.5px] text-[var(--muted)]">{st.cursor_end ? formatDate(st.cursor_end) : '—'}</td>
                    <td className="font-mono text-[11px]">{a.sync_state?.items_last_run ?? 0}</td>
                    <td className="font-mono text-[11px] text-[var(--muted)]">{st.last_duration_ms ? `${st.last_duration_ms}ms` : '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="py-12 text-center text-[12px] text-[var(--dim)]">尚未接入账号</div>
        )}
      </section>

      <section className="table-wrap">
        <div className="flex items-center gap-2 border-b border-[var(--line-soft)] px-4 py-3">
          <Clock3 className="h-4 w-4 text-[var(--accent-2)]" />
          <h2 className="text-[13px] font-semibold">最近同步运行</h2>
          <span className="pill ml-auto">最近 30 条</span>
        </div>
        {runs.length ? (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 140 }}>开始时间</th>
                <th style={{ width: 90 }}>触发</th>
                <th style={{ width: 90 }}>状态</th>
                <th style={{ width: 70 }}>页数</th>
                <th style={{ width: 70 }}>拉取</th>
                <th style={{ width: 70 }}>新增</th>
                <th style={{ width: 70 }}>更新</th>
                <th style={{ width: 70 }}>失败</th>
                <th>错误</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td className="whitespace-nowrap font-mono text-[10.5px] text-[var(--muted)]">{formatDate(r.started_at)}</td>
                  <td><span className="pill">{r.trigger}</span></td>
                  <td><RunStatus status={r.status} /></td>
                  <td className="font-mono text-[11px]">{r.pages ?? 0}</td>
                  <td className="font-mono text-[11px]">{r.fetched ?? 0}</td>
                  <td className="font-mono text-[11px] text-[var(--low)]">{r.created ?? 0}</td>
                  <td className="font-mono text-[11px] text-[var(--info)]">{r.updated ?? 0}</td>
                  <td className="font-mono text-[11px] text-[var(--danger)]">{r.failed ?? 0}</td>
                  <td className="max-w-[300px] truncate text-[10.5px] text-[var(--muted)]" title={r.error}>{r.error || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="py-12 text-center text-[12px] text-[var(--dim)]">还没有同步记录</div>
        )}
      </section>
    </div>
  );
}

function RunStatus({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    success: { label: '成功', cls: 'badge-low' },
    partial: { label: '部分', cls: 'badge-medium' },
    throttled: { label: '限流', cls: 'badge-high' },
    failed: { label: '失败', cls: 'badge-critical' },
    running: { label: '运行中', cls: 'badge-informational' },
  };
  const item = map[status] || { label: status, cls: 'badge-unknown' };
  return <span className={`badge ${item.cls}`}>{item.label}</span>;
}

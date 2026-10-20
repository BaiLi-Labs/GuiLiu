import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { Empty, ErrorBox, SkeletonRows, StatCard } from '../components/ui';
import { accountStatus, formatDate, fmtNum, providerShort, relTime } from '../lib';
import type { HealthResponse, SyncRun } from '../types';

const runStatus: Record<string, { label: string; cls: string }> = {
  success: { label: '成功', cls: 'badge-low' },
  partial: { label: '部分', cls: 'badge-medium' },
  throttled: { label: '限流', cls: 'badge-high' },
  failed: { label: '失败', cls: 'badge-critical' },
  running: { label: '运行中', cls: 'badge-informational' },
};
const triggers: Record<string, string> = { schedule: '定时', manual: '手动', startup: '启动', api: '手动' };

export function Health() {
  const { refreshNonce, meta, isAdmin, toast } = useApp();
  const { t } = useI18n();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [runs, setRuns] = useState<SyncRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    Promise.all([
      api<HealthResponse>('/health', { signal: controller.signal }),
      api<{ runs: SyncRun[] }>('/sync-runs?limit=30', { signal: controller.signal }),
    ])
      .then(([ingestion, history]) => {
        if (alive) {
          setHealth(ingestion);
          setRuns(history.runs || []);
        }
      })
      .catch((err) => {
        if (alive) setError(err.message || '加载失败');
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
      controller.abort();
    };
  }, [refreshNonce, reload]);
  async function syncAll() {
    setBusy(true);
    try {
      await api('/sync', { method: 'POST' });
      toast('已触发全部账号同步');
      setReload((value) => value + 1);
    } catch (err: any) {
      toast(err.message || '同步失败', true);
    } finally {
      setBusy(false);
    }
  }
  const accounts = health?.accounts || [];
  const enabled = accounts.filter((account) => account.enabled);
  const successful = enabled.filter((account) => accountStatus(account) === '已同步').length;
  const pending = enabled.filter((account) => accountStatus(account) === '续传中').length;
  const failing = enabled.filter((account) => accountStatus(account) === '同步失败').length;
  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (loading) return <SkeletonRows count={10} />;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="flex items-center gap-2 text-sm text-[var(--muted)]">
          <span className={`status-dot ${health?.database === 'ok' ? 'status-ok' : 'status-error'}`} />
          {t('数据库')} · {t(health?.database === 'ok' ? '服务可用' : '服务不可用')}
        </span>
        {isAdmin ? (
          <button
            className="btn ml-auto"
            onClick={syncAll}
            disabled={busy || !meta?.sync_enabled || !!meta?.mock}
          >
            <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} />
            {t(busy ? '同步中…' : '同步全部')}
          </button>
        ) : null}
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label={t('最近同步成功')} value={`${successful} / ${enabled.length}`} />
        <StatCard label={t('续传账号')} value={fmtNum(pending)} />
        <StatCard
          label={t('连续失败')}
          value={fmtNum(failing)}
          accent={failing ? 'var(--danger)' : undefined}
        />
      </div>
      <section className="table-wrap">
        <div className="section-heading">
          <h2 className="section-title">{t('账号状态')}</h2>
          <span className="text-xs text-[var(--muted)]">{accounts.length}</span>
        </div>
        {accounts.length ? (
          <table className="data-table min-w-[920px]">
            <thead>
              <tr>
                <th>{t('账号')}</th>
                <th>{t('云厂商')}</th>
                <th>{t('状态')}</th>
                <th>{t('最近成功')}</th>
                <th>{t('数据截至')}</th>
                <th>{t('上次条数')}</th>
                <th>{t('耗时')}</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((account) => {
                const status = accountStatus(account);
                return (
                  <tr key={account.id}>
                    <td>
                      <div className="font-medium">{account.name}</div>
                      <div className="cell-sub max-w-[200px]" title={account.account_uid}>
                        {account.account_uid || account.id}
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <BrandIcon provider={account.provider} size="xs" />
                        {providerShort(account.provider)}
                      </div>
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-2 whitespace-nowrap">
                        <span
                          className={`status-dot ${status === '同步失败' ? 'status-error' : status === '续传中' ? 'status-pending' : status === '已同步' ? 'status-ok' : ''}`}
                        />
                        {t(status)}
                      </span>
                      {account.sync_state?.last_error ? (
                        <div
                          className="cell-sub max-w-[240px] text-[var(--danger)]"
                          title={account.sync_state.last_error}
                        >
                          {account.sync_state.last_error}
                        </div>
                      ) : null}
                    </td>
                    <td className="whitespace-nowrap text-xs" title={account.sync_state?.last_success_at}>
                      {relTime(account.sync_state?.last_success_at)}
                    </td>
                    <td className="whitespace-nowrap text-xs">
                      {formatDate(account.sync_state?.cursor_end)}
                    </td>
                    <td className="tabular-nums">{fmtNum(account.sync_state?.items_last_run)}</td>
                    <td className="text-xs">
                      {account.sync_state?.last_duration_ms
                        ? `${fmtNum(account.sync_state.last_duration_ms)} ms`
                        : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <Empty title="尚未接入账号" />
        )}
      </section>
      <section className="table-wrap">
        <div className="section-heading">
          <h2 className="section-title">{t('最近同步运行')}</h2>
          <span className="text-xs text-[var(--muted)]">{t('最近 {count} 条', { count: 30 })}</span>
        </div>
        {runs.length ? (
          <table className="data-table min-w-[1080px]">
            <thead>
              <tr>
                <th>{t('开始时间')}</th>
                <th>{t('账号')}</th>
                <th>{t('触发')}</th>
                <th>{t('状态')}</th>
                <th>{t('页数')}</th>
                <th>{t('拉取')}</th>
                <th>{t('新增')}</th>
                <th>{t('更新')}</th>
                <th>{t('失败')}</th>
                <th>{t('错误')}</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => {
                const status = runStatus[run.status] || { label: run.status, cls: 'badge-unknown' };
                return (
                  <tr key={run.id}>
                    <td className="whitespace-nowrap text-xs">{formatDate(run.started_at)}</td>
                    <td>
                      {accounts.find((account) => account.id === run.account_id)?.name || run.account_id}
                    </td>
                    <td className="text-xs">{t(triggers[run.trigger] || run.trigger)}</td>
                    <td>
                      <span className={`badge ${status.cls}`}>{t(status.label)}</span>
                    </td>
                    <td>{fmtNum(run.pages)}</td>
                    <td>{fmtNum(run.fetched)}</td>
                    <td>{fmtNum(run.created)}</td>
                    <td>{fmtNum(run.updated)}</td>
                    <td className={run.failed ? 'text-[var(--danger)]' : ''}>{fmtNum(run.failed)}</td>
                    <td className="max-w-[260px] truncate text-xs text-[var(--muted)]" title={run.error}>
                      {run.error || '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <Empty title="还没有同步记录" />
        )}
      </section>
    </div>
  );
}

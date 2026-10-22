import { SourceFailure } from "../components/SourceFailure";
import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { Empty, ErrorBox, SkeletonRows, StatCard } from '../components/ui';
import { accountStatus, formatDate, fmtNum, providerShort, relTime } from '../lib';
import type { Coverage, HealthResponse, IngestFailure, SyncRun } from '../types';

const runStatus: Record<string, { label: string; cls: string }> = {
  success: { label: '成功', cls: 'badge-low' },
  partial: { label: '部分', cls: 'badge-medium' },
  throttled: { label: '限流', cls: 'badge-high' },
  failed: { label: '失败', cls: 'badge-critical' },
  running: { label: '运行中', cls: 'badge-informational' },
};
const triggers: Record<string, string> = { schedule: '定时', manual: '手动', startup: '启动', api: '手动' };
const coverageText: Record<string, string> = {
  upstream_permissions_and_retention: '受上游权限与数据保留期限限制。',
  not_all_vendor_products: '只覆盖接入 API 汇集的产品。',
  no_historical_state_reconciliation: '尚未持续核对全部历史记录的最新状态。',
  query_range_not_bounded: '未指定完整查询时段，无法确认查询覆盖程度。',
  old_finding_state_changes_may_be_outside_collection_window: '旧记录的状态变化可能落在采集窗口之外。',
  query_time_basis_differs_from_source_collection_basis: '查询时间依据与来源采集依据不同，无法按同一水位确认完整性。',
  'vendor alert query window': '厂商告警查询窗口',
  'last occurrence time': '厂商最近发生时间',
  'vendor search time range': '厂商搜索时间范围',
  'created OR last_seen OR modified': '来源创建、最近观测或修改时间',
  event_time: '厂商事件时间',
  'full list; local event/processing time window': '全量列表，再按事件或处理时间筛选',
};

export function Health() {
  const { refreshNonce, meta, isAdmin, toast } = useApp();
  const { t } = useI18n();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [runs, setRuns] = useState<SyncRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const [failureAccount, setFailureAccount] = useState<string | null>(null);
  const [failures, setFailures] = useState<IngestFailure[]>([]);
  const [failureError, setFailureError] = useState('');
  const [failuresLoading, setFailuresLoading] = useState(false);
  useEffect(() => {
    if (!failureAccount) return;
    const controller = new AbortController();
    setFailures([]);
    setFailureError('');
    setFailuresLoading(true);
    api<{ failures: IngestFailure[] }>(`/accounts/${encodeURIComponent(failureAccount)}/failures`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setFailures(result.failures); })
      .catch((err) => { if (!controller.signal.aborted) setFailureError(err.message); })
      .finally(() => { if (!controller.signal.aborted) setFailuresLoading(false); });
    return () => controller.abort();
  }, [failureAccount, reload]);
  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    Promise.all([
      api<Coverage>('/coverage', {signal:controller.signal}),
      api<HealthResponse>('/health', { signal: controller.signal }),
      api<{ runs: SyncRun[] }>('/sync-runs?limit=30', { signal: controller.signal }),
    ])
      .then(([range, ingestion, history]) => {
        if(alive) setCoverage(range);
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
  const failing = enabled.filter((account) => ['同步失败', '同步延迟', '部分失败'].includes(accountStatus(account))).length;
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
          label={t('同步异常')}
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
                <th>{t('待重试')}</th>
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
                          className={`status-dot ${['同步失败', '部分失败'].includes(status) ? 'status-error' : ['续传中', '同步延迟'].includes(status) ? 'status-pending' : status === '已同步' ? 'status-ok' : ''}`}
                        />
                        {t(status)}
                      </span>
                      {account.sync_state?.last_source_error ? <SourceFailure value={account.sync_state.last_source_error} /> : account.sync_state?.last_error ? (
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
                    <td>
                      {account.sync_state?.failed_records ? (
                        <button className="text-[var(--danger)] underline" onClick={() => setFailureAccount(account.id)}>
                          {fmtNum(account.sync_state.failed_records)}
                        </button>
                      ) : '—'}
                    </td>
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
      <section className="card p-5 space-y-3">
        <h2 className="section-title">{t('来源与覆盖范围')}</h2>
        <p className="text-xs text-[var(--muted)]">
          {t('同步成功仅说明当前 API 与授权范围内完成采集，不代表厂商全部产品或历史。')}
        </p>
        {coverage?.accounts.map(account => (
          <details key={account.account_id} className="disclosure">
            <summary>{account.name} · {account.api}</summary>
            <dl className="detail-fields mt-3">
              <dt>API</dt><dd>{account.api_version}</dd>
              <dt>{t('历史起点')}</dt><dd>{formatDate(account.coverage_start || undefined)}</dd>
              <dt>{t('数据截至')}</dt><dd>{formatDate(account.watermark || undefined)}</dd>
              <dt>{t('接入范围')}</dt>
              <dd className="break-all font-mono text-xs">{JSON.stringify(account.scope)}</dd>
              <dt>{t('采集时间依据')}</dt><dd>{t(coverageText[account.time_basis] || account.time_basis)}</dd>
            </dl>
            <ul className="mt-3 list-disc space-y-1 pl-4 text-xs text-[var(--muted)]">
              {account.limitations.map(value => <li key={value}>{t(coverageText[value] || value)}</li>)}
            </ul>
          </details>
        ))}
      </section>
      {failureAccount ? (
        <section className="card p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <h2 className="section-title">{accounts.find((a) => a.id === failureAccount)?.name} · {t('失败记录')}</h2>
            <button className="btn btn-ghost" onClick={() => setFailureAccount(null)}>{t('关闭')}</button>
          </div>
          <p className="text-xs text-[var(--muted)]">{t('每轮同步自动重试最多 100 条，显示最早待重试的 100 条。')}</p>
          {failureError ? <ErrorBox>{failureError}</ErrorBox> : failuresLoading ? <SkeletonRows count={3} /> : failures.map((f) => (
            <details key={f.id} className="border-b border-[var(--border)] py-2">
              <summary className="cursor-pointer text-sm break-words">{f.error} · {t('尝试 {count} 次', { count: f.attempts })}</summary>
              <div className="text-xs text-[var(--muted)] my-2">{f.mapper_version} · {formatDate(f.last_attempt_at)}</div>
              <pre className="code">{JSON.stringify(f.raw, null, 2)}</pre>
            </details>
          ))}
        </section>
      ) : null}
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
                      {run.source_error ? <SourceFailure value={run.source_error} /> : run.error || '—'}
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

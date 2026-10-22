import { useEffect, useState } from 'react';
import { ArrowUpRight } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { FieldDistribution } from '../components/FieldDistribution';
import { Empty, ErrorBox, SeverityBadge, SkeletonRows, StatCard } from '../components/ui';
import {
  RANGE_OPTIONS,
  SEVERITY_ORDER,
  accountStatus,
  fmtNum,
  formatDate,
  providerShort,
  rangeStart,
  relTime,
} from '../lib';
import type { AlertList, HealthResponse, Statistics, StatsResponse } from '../types';

const severityColors: Record<string, string> = {
  critical: 'var(--crit)',
  fatal: 'var(--fatal)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  informational: 'var(--info)',
  unknown: 'var(--dim)',
};

export function Overview() {
  const { refreshNonce, go } = useApp();
  const { t } = useI18n();
  const [range, setRange] = useState('24h');
  const [stats, setStats] = useState<Statistics | null>(null);
  const [recent, setRecent] = useState<AlertList | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState('');

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    const query = new URLSearchParams();
    const start = rangeStart(range);
    if (start) query.set('start', start);
    Promise.all([
      api<StatsResponse>(`/stats?${query}`, { signal: controller.signal }),
      api<AlertList>(`/alerts?${query}&limit=6`, { signal: controller.signal }),
      api<HealthResponse>('/health', { signal: controller.signal }),
    ])
      .then(([statistics, alerts, ingestion]) => {
        if (!alive) return;
        setStats(statistics.statistics);
        setRecent(alerts);
        setHealth(ingestion);
        setLoadedAt(new Date().toISOString());
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
  }, [range, refreshNonce]);

  const severities = stats?.by_severity || {};
  const accounts = health?.accounts || [];
  const enabled = accounts.filter((account) => account.enabled);
  const successful = enabled.filter((account) => accountStatus(account) === '已同步').length;
  const failures = enabled.filter((account) => ['同步失败', '同步延迟', '部分失败'].includes(accountStatus(account))).length;
  const providerIDs = [...new Set(accounts.map((account) => account.provider))];
  const counts = stats?.by_provider || {};
  const high = (severities.critical || 0) + (severities.fatal || 0) + (severities.high || 0);
  const openAlerts = (extra: Record<string, string> = {}) => go('alerts', { range, ...extra });

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-[var(--muted)]">
          {loadedAt ? `${t('更新')} ${formatDate(loadedAt)}` : ''}
        </span>
        <select
          className="field"
          aria-label={t('时间范围')}
          value={range}
          onChange={(event) => setRange(event.target.value)}
        >
          {RANGE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {t(option.label)}
            </option>
          ))}
        </select>
      </div>
      {error ? <ErrorBox>{error}</ErrorBox> : null}
      {loading ? (
        <SkeletonRows count={6} />
      ) : !error ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label={t('告警数量')} value={fmtNum(stats?.total)} onClick={() => openAlerts()} />
            <StatCard
              label={t('高危及以上')}
              value={fmtNum(high)}
              accent="var(--crit)"
              onClick={() => openAlerts({ severity: 'critical,fatal,high' })}
            />
            <StatCard
              label={t('最近同步成功')}
              value={`${successful} / ${enabled.length}`}
              onClick={() => go('health')}
            />
            <StatCard
              label={t('同步异常')}
              value={fmtNum(failures)}
              accent={failures ? 'var(--danger)' : undefined}
              onClick={() => go('health')}
            />
          </div>
          <div className="grid gap-5 xl:grid-cols-2">
            <section className="card p-5">
              <h2 className="section-title mb-5">{t('等级分布')}</h2>
              <div className="space-y-4">
                {SEVERITY_ORDER.filter((severity) => (severities[severity] || 0) > 0).map((severity) => {
                  const count = severities[severity] || 0;
                  const percent = stats?.total ? (count / stats.total) * 100 : 0;
                  return (
                    <button
                      key={severity}
                      className="block w-full text-left"
                      onClick={() => openAlerts({ severity })}
                    >
                      <div className="mb-2 flex items-center gap-3">
                        <SeverityBadge severity={severity} />
                        <span className="ml-auto text-sm tabular-nums">{fmtNum(count)}</span>
                        <span className="w-12 text-right text-xs text-[var(--muted)]">
                          {Math.round(percent)}%
                        </span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-[var(--track)]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${percent}%`,
                            minWidth: count ? 2 : 0,
                            background: severityColors[severity],
                          }}
                        />
                      </div>
                    </button>
                  );
                })}
                {!stats?.total ? <Empty title="暂无数据" /> : null}
              </div>
            </section>
            <section className="card p-5">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="section-title">{t('云厂商')}</h2>
                <span className="text-xs text-[var(--muted)]">
                  {t('已连接 {count} 家云厂商', { count: providerIDs.length })}
                </span>
              </div>
              <div className="space-y-1">
                {providerIDs.map((provider) => (
                  <button
                    key={provider}
                    className="flex w-full items-center gap-3 rounded-md px-2 py-3 text-left hover:bg-[var(--hover)]"
                    onClick={() => openAlerts({ provider })}
                  >
                    <BrandIcon provider={provider} size="sm" />
                    <span className="flex-1 text-sm">{providerShort(provider)}</span>
                    <span className="text-sm tabular-nums">{fmtNum(counts[provider])}</span>
                    <ArrowUpRight className="h-3.5 w-3.5 text-[var(--dim)]" />
                  </button>
                ))}
                {!providerIDs.length ? (
                  <Empty title="尚未接入账号">
                    <button className="btn btn-primary" onClick={() => go('accounts')}>
                      {t('接入云账号')}
                    </button>
                  </Empty>
                ) : null}
              </div>
            </section>
          </div>
          <div className="grid gap-5 xl:grid-cols-2">
            <FieldDistribution label="告警标题分布" distribution={stats?.distributions?.title} />
            <FieldDistribution label="源 IP 分布" distribution={stats?.distributions?.source_ip} />
          </div>
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
            <section className="table-wrap">
              <div className="section-heading">
                <h2 className="section-title">{t('最新告警')}</h2>
                <button className="btn btn-ghost btn-sm" onClick={() => openAlerts()}>
                  {t('查看全部')}
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </button>
              </div>
              {recent?.alerts?.length ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t('时间')}</th>
                      <th>{t('等级')}</th>
                      <th>{t('告警')}</th>
                      <th>{t('来源')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.alerts.map((alert) => (
                      <tr key={alert.id}>
                        <td className="whitespace-nowrap text-xs text-[var(--muted)]">
                          {formatDate(alert.event_time)}
                        </td>
                        <td>
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td>
                          <button
                            className="cell-title text-left font-medium hover:text-[var(--accent)]"
                            onClick={() => openAlerts({ alert: alert.id })}
                          >
                            {alert.title}
                          </button>
                          <div className="cell-sub">{alert.resource?.name || alert.resource?.id || '—'}</div>
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <BrandIcon provider={alert.provider} size="xs" />
                            <span>{providerShort(alert.provider)}</span>
                          </div>
                          <div className="cell-sub">{alert.account_name || alert.account_id}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <Empty title="暂无告警" />
              )}
            </section>
            <section className="card p-5">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="section-title">{t('接入状态')}</h2>
                <button className="btn btn-ghost btn-sm" onClick={() => go('health')}>
                  {t('详情')}
                </button>
              </div>
              <div className="divide-y divide-[var(--line-soft)]">
                {accounts.slice(0, 6).map((account) => (
                  <div key={account.id} className="flex items-center gap-3 py-3">
                    <BrandIcon provider={account.provider} size="xs" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm">{account.name}</div>
                      <div className="mt-1 text-xs text-[var(--muted)]">
                        {relTime(account.sync_state?.last_success_at)}
                      </div>
                    </div>
                    <span
                      className={`text-xs ${accountStatus(account) === '同步失败' ? 'text-[var(--danger)]' : 'text-[var(--muted)]'}`}
                    >
                      {t(accountStatus(account))}
                    </span>
                  </div>
                ))}
                {!accounts.length ? <Empty title="尚未接入账号" /> : null}
              </div>
            </section>
          </div>
        </>
      ) : null}
    </div>
  );
}

import { useEffect, useState } from 'react';
import { Activity, ArrowUpRight, Cloud, ShieldAlert } from 'lucide-react';
import { api } from '../api';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { ErrorBox, SeverityBadge, SkeletonRows, StatCard } from '../components/ui';
import { SEVERITY_ORDER, SEVERITY_LABEL, fmtNum, formatDate, providerShort, relTime } from '../lib';
import type { AlertList, HealthResponse, Statistics, StatsResponse } from '../types';

export function Overview() {
  const { providers, refreshNonce, go } = useApp();
  const [stats, setStats] = useState<Statistics | null>(null);
  const [recent, setRecent] = useState<AlertList | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');
    Promise.all([
      api<StatsResponse>('/stats'),
      api<AlertList>('/alerts?limit=6'),
      api<HealthResponse>('/health'),
    ])
      .then(([s, a, h]) => {
        if (!alive) return;
        setStats(s.statistics);
        setRecent(a);
        setHealth(h);
      })
      .catch((e) => alive && setError(e.message || '加载失败'))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [refreshNonce]);

  if (loading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="card p-4">
            <div className="skeleton w-20" />
            <div className="skeleton mt-4 h-8 w-16" />
          </div>
        ))}
      </div>
    );
  }
  if (error) return <ErrorBox>{error}</ErrorBox>;

  const sev = stats?.by_severity || {};
  const providerCounts = stats?.by_provider || {};
  const accounts = health?.accounts || [];
  const healthy = accounts.filter((a) => a.sync_state?.healthy).length;
  const pending = accounts.filter((a) => a.sync_state?.pending).length;
  const failures = accounts.filter((a) => (a.sync_state?.consecutive_failures || 0) > 0).length;
  const total = stats?.total || 0;
  const high = (sev.critical || 0) + (sev.fatal || 0) + (sev.high || 0);

  return (
    <div className="space-y-5">
      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
        <StatCard label="告警总量" value={fmtNum(total)} hint="全部厂商、全部状态" />
        <StatCard
          label="严重 / 高危"
          value={fmtNum(high)}
          accent="var(--crit)"
          hint={total ? `${Math.round((high / total) * 100)}% 的告警需要优先处理` : '暂无告警'}
        />
        <StatCard
          label="健康账号"
          value={`${healthy}/${accounts.length}`}
          accent="var(--low)"
          hint={pending ? `${pending} 个账号正在续传` : '所有账号游标正常'}
        />
        <StatCard
          label="同步异常"
          value={fmtNum(failures)}
          accent={failures ? 'var(--danger)' : 'var(--text)'}
          hint={failures ? '存在连续失败，请检查健康页' : '没有连续失败'}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.15fr_.85fr]">
        <section className="card p-4">
          <div className="mb-4 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-[var(--accent)]" />
            <h2 className="text-[13px] font-semibold">等级分布</h2>
            <span className="pill ml-auto">{fmtNum(total)} 条</span>
          </div>
          <div className="space-y-3">
            {SEVERITY_ORDER.filter((s) => (sev[s] || 0) > 0).map((s) => {
              const count = sev[s] || 0;
              const pct = total ? Math.max(2, Math.round((count / total) * 100)) : 0;
              const color = s === 'informational' ? 'var(--info)' : s === 'unknown' ? 'var(--dim)' : `var(--${s})`;
              return (
                <div key={s}>
                  <div className="mb-1 flex items-center gap-2 text-[11px]">
                    <SeverityBadge severity={s} />
                    <span className="ml-auto font-mono text-[var(--muted)]">{fmtNum(count)}</span>
                    <span className="w-9 text-right font-mono text-[var(--dim)]">{pct}%</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-[var(--track)]">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
                  </div>
                </div>
              );
            })}
            {!SEVERITY_ORDER.some((s) => (sev[s] || 0) > 0) ? <div className="py-8 text-center text-[12px] text-[var(--dim)]">暂无数据</div> : null}
          </div>
        </section>

        <section className="card p-4">
          <div className="mb-4 flex items-center gap-2">
            <Cloud className="h-4 w-4 text-[var(--accent-2)]" />
            <h2 className="text-[13px] font-semibold">厂商分布</h2>
            <span className="pill ml-auto">{providers.length} 个已接入</span>
          </div>
          <div className="space-y-2.5">
            {providers.map((p) => {
              const count = providerCounts[p.id] || 0;
              const pct = total ? Math.max(2, Math.round((count / total) * 100)) : 0;
              return (
                <button
                  key={p.id}
                  className="flex w-full items-center gap-2.5 rounded-lg px-1 py-1 text-left transition hover:bg-[var(--hover)]"
                  onClick={() => go('alerts')}
                >
                  <BrandIcon provider={p.id} size="sm" />
                  <span className="min-w-0 flex-1 truncate text-[12px]">{providerShort(p.id)}</span>
                  <span className="font-mono text-[10.5px] text-[var(--muted)]">{fmtNum(count)}</span>
                  <span className="w-10 text-right font-mono text-[10px] text-[var(--dim)]">{pct}%</span>
                </button>
              );
            })}
            {!providers.length ? <div className="py-8 text-center text-[12px] text-[var(--dim)]">尚未注册厂商</div> : null}
          </div>
        </section>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_.65fr]">
        <section className="table-wrap">
          <div className="flex items-center gap-2 border-b border-[var(--line-soft)] px-4 py-3">
            <BellIcon />
            <h2 className="text-[13px] font-semibold">最新告警</h2>
            <button className="btn btn-ghost btn-sm ml-auto" onClick={() => go('alerts')}>
              查看全部 <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>
          {recent?.alerts?.length ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 72 }}>时间</th>
                  <th style={{ width: 56 }}>等级</th>
                  <th>告警</th>
                  <th style={{ width: 112 }}>来源</th>
                  <th style={{ width: 160 }}>资产</th>
                </tr>
              </thead>
              <tbody>
                {recent.alerts.map((a) => (
                  <tr key={a.id} className="row-click" onClick={() => go('alerts')}>
                    <td className="whitespace-nowrap font-mono text-[10.5px] text-[var(--muted)]">{formatDate(a.event_time)}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td>
                      <div className="cell-title">{a.title}</div>
                      <div className="cell-sub">{a.alert_type || a.product || '—'}</div>
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <BrandIcon provider={a.provider} size="xs" />
                        <span className="text-[11px]">{providerShort(a.provider)}</span>
                      </div>
                      <div className="cell-sub">{a.account_name || a.account_id}</div>
                    </td>
                    <td>
                      <div className="cell-title text-[11px]">{a.resource?.name || '—'}</div>
                      <div className="cell-sub font-mono">{a.resource?.id || ''}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="py-10 text-center text-[12px] text-[var(--dim)]">暂无告警</div>
          )}
        </section>

        <section className="card p-4">
          <div className="mb-3 flex items-center gap-2">
            <Activity className="h-4 w-4 text-[var(--low)]" />
            <h2 className="text-[13px] font-semibold">接入状态</h2>
            <button className="btn btn-ghost btn-sm ml-auto" onClick={() => go('health')}>
              详情
            </button>
          </div>
          <div className="space-y-2">
            {accounts.slice(0, 6).map((a) => {
              const st = a.sync_state || {};
              const bad = (st.consecutive_failures || 0) > 0;
              return (
                <div key={a.id} className="flex items-center gap-2.5 rounded-lg border border-[var(--line-soft)] bg-[var(--inset)] px-2.5 py-2">
                  <BrandIcon provider={a.provider} size="xs" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[11.5px]">{a.name}</div>
                    <div className="truncate text-[10px] text-[var(--dim)]">
                      {st.pending ? '续传中' : bad ? '同步失败' : `最近 ${relTime(st.last_success_at)}`}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-[11px] ${bad ? 'text-[var(--danger)]' : 'text-[var(--muted)]'}`}>
                      {st.items_last_run ?? 0} 条
                    </div>
                    <div className="text-[9.5px] text-[var(--dim)]">{providerShort(a.provider)}</div>
                  </div>
                </div>
              );
            })}
            {!accounts.length ? <div className="py-8 text-center text-[12px] text-[var(--dim)]">尚未接入账号</div> : null}
          </div>
        </section>
      </div>
    </div>
  );
}

function BellIcon() {
  return <span className="grid h-6 w-6 place-items-center rounded-md bg-[var(--accent-soft)] text-[var(--accent)]">◉</span>;
}

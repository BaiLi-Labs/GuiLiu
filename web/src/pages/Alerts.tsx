import { useEffect, useMemo, useState } from 'react';
import { ChevronLeft, ChevronRight, Download, Filter, Layers, List, RotateCcw, Search, X } from 'lucide-react';
import { api } from '../api';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { CopyButton, Drawer, ErrorBox, SeverityBadge, SkeletonRows, StatusBadge } from '../components/ui';
import {
  RANGE_OPTIONS,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  STATUS_LABEL,
  formatDate,
  formatTime,
  providerShort,
  rangeStart,
  truncate,
} from '../lib';
import type {
  Alert,
  AlertGroup,
  AlertGroupBy,
  AlertGroupList,
  AlertList,
  AlertRevision,
  AlertStatus,
  Severity,
} from '../types';

interface Filters {
  provider: string;
  severity: string;
  status: string;
  range: string;
  q: string;
  ip: string;
}

const EMPTY: Filters = { provider: '', severity: '', status: '', range: '7d', q: '', ip: '' };

function alertParams(filters: Filters, limit: number, offset: number) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('offset', String(offset));
  if (filters.provider) params.set('provider', filters.provider);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.status) params.set('status', filters.status);
  if (filters.q.trim()) params.set('q', filters.q.trim());
  if (filters.ip.trim()) params.set('ip', filters.ip.trim());
  const start = rangeStart(filters.range);
  if (start) params.set('start', start);
  return params;
}

type GroupSelection = { by: AlertGroupBy; key: Record<string, string>; title: string };

export function Alerts() {
  const { providers, isAdmin, refreshNonce, toast } = useApp();
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<AlertList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState<'raw' | 'groups'>('raw');
  const [groupBy, setGroupBy] = useState<AlertGroupBy>('signature');
  const [groupOffset, setGroupOffset] = useState(0);
  const [groups, setGroups] = useState<AlertGroupList | null>(null);
  const [groupLoading, setGroupLoading] = useState(false);
  const [groupError, setGroupError] = useState('');
  const [group, setGroup] = useState<GroupSelection | null>(null);

  const limit = 20;
  const query = useMemo(() => {
    const params = alertParams(applied, limit, offset);
    if (group) {
      params.set('group_by', group.by);
      params.set('group_key', JSON.stringify(group.key));
    }
    return params.toString();
  }, [applied, offset, group]);
  const groupQuery = useMemo(() => {
    const params = alertParams(applied, limit, groupOffset);
    params.set('group_by', groupBy);
    return params.toString();
  }, [applied, groupBy, groupOffset]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');
    api<AlertList>(`/alerts?${query}`)
      .then((d) => alive && setData(d))
      .catch((e) => alive && setError(e.message || '查询失败'))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [query, refreshNonce]);

  useEffect(() => {
    if (view !== 'groups') return;
    let alive = true;
    setGroupLoading(true);
    setGroupError('');
    api<AlertGroupList>(`/alerts/groups?${groupQuery}`)
      .then((d) => alive && setGroups(d))
      .catch((e) => alive && setGroupError(e.message || '分组查询失败'))
      .finally(() => alive && setGroupLoading(false));
    return () => {
      alive = false;
    };
  }, [view, groupQuery, refreshNonce]);

  function apply() {
    setOffset(0);
    setGroupOffset(0);
    setGroup(null);
    setApplied({ ...filters });
  }
  function reset() {
    setFilters(EMPTY);
    setApplied(EMPTY);
    setOffset(0);
    setGroupOffset(0);
    setGroup(null);
  }

  const total = data?.total || 0;
  const pages = Math.max(1, Math.ceil(total / limit));
  const current = Math.floor(offset / limit) + 1;
  const groupTotal = groups?.total || 0;
  const groupPages = Math.max(1, Math.ceil(groupTotal / limit));
  const groupCurrent = Math.floor(groupOffset / limit) + 1;

  function showGroup(g: AlertGroup) {
    setGroup({ by: g.group_by, key: g.key, title: g.title });
    setView('raw');
    setOffset(0);
  }

  return (
    <div className="space-y-4">
      <div className="card p-3">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <div className="flex rounded-lg border border-[var(--line)] p-0.5">
            <button
              className={`btn btn-sm ${view === 'raw' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => { setView('raw'); setGroup(null); }}
            >
              <List className="h-3.5 w-3.5" /> 原始告警
            </button>
            <button
              className={`btn btn-sm ${view === 'groups' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => { setView('groups'); setGroup(null); }}
            >
              <Layers className="h-3.5 w-3.5" /> 聚合视图
            </button>
          </div>
          {view === 'groups' ? (
            <select
              className="field"
              value={groupBy}
              onChange={(e) => { setGroupBy(e.target.value as AlertGroupBy); setGroupOffset(0); }}
            >
              <option value="signature">同类重复</option>
              <option value="asset">按资产</option>
              <option value="source">按攻击源</option>
            </select>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-[11px] text-[var(--muted)]">
            <Filter className="h-3.5 w-3.5" />
            筛选
          </div>
          <select className="field" value={filters.provider} onChange={(e) => setFilters((f) => ({ ...f, provider: e.target.value }))}>
            <option value="">全部云厂商</option>
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <select className="field" value={filters.severity} onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}>
            <option value="">全部等级</option>
            {SEVERITY_ORDER.filter((s) => s !== 'unknown').map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABEL[s]}
              </option>
            ))}
          </select>
          <select className="field" value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}>
            <option value="">全部状态</option>
            {(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
          <select className="field" value={filters.range} onChange={(e) => setFilters((f) => ({ ...f, range: e.target.value }))}>
            {RANGE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input
            className="field w-[150px]"
            placeholder="源/目标 IP"
            value={filters.ip}
            onChange={(e) => setFilters((f) => ({ ...f, ip: e.target.value }))}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
          />
          <div className="relative min-w-[190px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--dim)]" />
            <input
              className="field w-full pl-8"
              placeholder="搜索标题、描述、类型、资产…"
              value={filters.q}
              onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && apply()}
            />
          </div>
          <button className="btn btn-primary" onClick={apply}>
            <Search className="h-3.5 w-3.5" />
            查询
          </button>
          <button className="btn btn-ghost" onClick={reset}>
            <RotateCcw className="h-3.5 w-3.5" />
            重置
          </button>
        </div>
        <div className="mt-2 flex items-center gap-3 text-[10.5px] text-[var(--dim)]">
          {view === 'groups' ? (
            <>
              <span>共 {groupTotal.toLocaleString('zh-CN')} 组</span>
              <span>·</span>
              <span>第 {groupCurrent} / {groupPages} 页</span>
            </>
          ) : (
            <>
              <span>共 {total.toLocaleString('zh-CN')} 条</span>
              <span>·</span>
              <span>第 {current} / {pages} 页</span>
            </>
          )}
          {applied.q || applied.ip ? <span className="text-[var(--accent)]">已应用关键词筛选</span> : null}
        </div>
      </div>

      {view === 'groups' ? (
        <>
          <div className="table-wrap relative">
            {groupLoading ? (
              <SkeletonRows count={7} />
            ) : groupError ? (
              <div className="p-4"><ErrorBox>{groupError}</ErrorBox></div>
            ) : groups?.groups?.length ? (
              <table className="data-table w-full min-w-[760px] table-fixed">
                <thead>
                  <tr>
                    <th>告警分组</th>
                    <th style={{ width: 76 }}>数量</th>
                    <th style={{ width: 86 }}>最高等级</th>
                    <th style={{ width: 150 }}>云厂商</th>
                    <th style={{ width: 120 }}>最近</th>
                    <th style={{ width: 72 }}>成员</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.groups.map((g) => (
                    <tr key={g.id} className="row-click" onClick={() => showGroup(g)}>
                      <td>
                        <div className="cell-title">{g.title}</div>
                        <div className="cell-sub">
                          {g.key.singleton
                            ? '关键字段不完整 · 单条分组'
                            : [g.alert_type, g.source_ip, g.resource_id].filter(Boolean).join(' · ') || '—'}
                        </div>
                      </td>
                      <td className="font-mono text-[12px]">{g.count.toLocaleString('zh-CN')}</td>
                      <td><SeverityBadge severity={g.max_severity} /></td>
                      <td>
                        <div className="flex flex-wrap items-center gap-1.5">
                          {(g.providers || []).slice(0, 3).map((p) => (
                            <span key={p} className="inline-flex items-center gap-1 text-[10.5px] text-[var(--muted)]">
                              <BrandIcon provider={p} size="xs" />
                              {providerShort(p)}
                            </span>
                          ))}
                          {(g.providers || []).length > 3 ? <span className="text-[10px] text-[var(--dim)]">+{(g.providers || []).length - 3}</span> : null}
                          {!(g.providers || []).length ? <span className="text-[10.5px] text-[var(--dim)]">—</span> : null}
                        </div>
                      </td>
                      <td className="font-mono text-[10.5px] text-[var(--muted)]">{formatDate(g.last_seen_at)}</td>
                      <td><span className="btn btn-sm">查看</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-16 text-center text-[12px] text-[var(--dim)]">没有匹配的分组，试试放宽筛选条件</div>
            )}
          </div>
          <div className="flex items-center justify-end gap-2">
            <span className="mr-auto text-[10.5px] text-[var(--dim)]">每页 {limit} 组</span>
            <button className="btn btn-sm" disabled={groupOffset <= 0} onClick={() => setGroupOffset(Math.max(0, groupOffset - limit))}>
              <ChevronLeft className="h-3.5 w-3.5" /> 上一页
            </button>
            <button className="btn btn-sm" disabled={groupOffset + limit >= groupTotal} onClick={() => setGroupOffset(groupOffset + limit)}>
              下一页 <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </>
      ) : null}

      {view === 'raw' ? (
        <>
          {group ? (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--accent)]/30 bg-[var(--accent)]/5 px-3 py-2 text-[11px]">
              <Layers className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span className="text-[var(--muted)]">分组成员</span>
              <span className="font-medium">{group.title}</span>
              <span className="text-[var(--dim)]">{total} 条原始告警</span>
              <button className="btn btn-sm ml-auto" onClick={() => { setGroup(null); setOffset(0); }}>
                <X className="h-3.5 w-3.5" /> 清除分组
              </button>
            </div>
          ) : null}
      <div className="table-wrap relative">
        {loading ? (
          <SkeletonRows count={9} />
        ) : error ? (
          <div className="p-4">
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : data?.alerts?.length ? (
          <table className="data-table w-full min-w-[900px] table-fixed">
            <thead>
              <tr>
                <th style={{ width: 100 }}>时间</th>
                <th style={{ width: 56 }}>等级</th>
                <th>告警</th>
                <th style={{ width: 112 }}>来源</th>
                <th style={{ width: 150 }}>资产</th>
                <th style={{ width: 200 }}>源 → 目标</th>
                <th style={{ width: 92 }}>状态</th>
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.id} className="row-click" onClick={() => setSelected(a.id)}>
                  <td className="whitespace-nowrap font-mono text-[10.5px] text-[var(--muted)]">{formatDate(a.event_time)}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>
                    <div className="cell-title">{a.title}</div>
                    <div className="cell-sub">{a.alert_type || a.product || '—'}</div>
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                      <BrandIcon provider={a.provider} size="xs" />
                      <span className="text-[11px]">{providerShort(a.provider)}</span>
                    </div>
                    <div className="cell-sub">{a.account_name || a.account_id}</div>
                  </td>
                  <td>
                    <div className="cell-title text-[11px]">{a.resource?.name || '—'}</div>
                    <div className="cell-sub font-mono">{truncate(a.resource?.id || '', 38)}</div>
                  </td>
                  <td className="font-mono text-[10.5px]">
                    <div className="max-w-[200px] truncate" title={`${a.source_ip || '—'} → ${a.destination_ip || '—'}`}>
                      {a.source_ip || '—'} <span className="text-[var(--dim)]">→</span> {a.destination_ip || '—'}
                    </div>
                  </td>
                  <td><StatusBadge status={a.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="py-16 text-center text-[12px] text-[var(--dim)]">没有匹配的告警，试试放宽筛选条件</div>
        )}
      </div>

      <div className="flex items-center justify-end gap-2">
        <span className="mr-auto text-[10.5px] text-[var(--dim)]">每页 {limit} 条</span>
        <button className="btn btn-sm" disabled={offset <= 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
          <ChevronLeft className="h-3.5 w-3.5" /> 上一页
        </button>
        <button className="btn btn-sm" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>
          下一页 <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
        </>
      ) : null}

      <AlertDrawer
        id={selected}
        onClose={() => setSelected(null)}
        onChanged={async () => {
          const d = await api<AlertList>(`/alerts?${query}`);
          setData(d);
        }}
        isAdmin={isAdmin}
        toast={toast}
      />
    </div>
  );
}

function AlertDrawer({
  id,
  onClose,
  onChanged,
  isAdmin,
  toast,
}: {
  id: string | null;
  onClose: () => void;
  onChanged: () => void | Promise<void>;
  isAdmin: boolean;
  toast: (message: string, error?: boolean) => void;
}) {
  const [detail, setDetail] = useState<Alert | null>(null);
  const [revisions, setRevisions] = useState<AlertRevision[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!id) return;
    let alive = true;
    setLoading(true);
    setError('');
    setDetail(null);
    setRevisions([]);
    api<Alert>(`/alerts/${encodeURIComponent(id)}`)
      .then((d) => alive && setDetail(d))
      .catch((e) => alive && setError(e.message || '加载失败'))
      .finally(() => alive && setLoading(false));
    api<{ revisions: AlertRevision[] }>(`/alerts/${encodeURIComponent(id)}/revisions?limit=20`)
      .then((d) => alive && setRevisions(d.revisions || []))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [id]);

  async function update(status: AlertStatus) {
    if (!id || busy) return;
    setBusy(true);
    try {
      const next = await api<Alert>(`/alerts/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      setDetail(next);
      await onChanged();
      toast('告警状态已更新');
    } catch (e: any) {
      if (e?.status !== 401) toast(e?.message || '更新失败', true);
    } finally {
      setBusy(false);
    }
  }

  const raw = detail?.raw ? JSON.stringify(detail.raw, null, 2) : '';
  const ocsf = detail?.ocsf ? JSON.stringify(detail.ocsf, null, 2) : '';

  return (
    <Drawer
      open={!!id}
      onClose={onClose}
      title={detail?.title || (loading ? '加载中…' : '告警详情')}
      eyebrow={
        detail ? (
          <>
            <BrandIcon provider={detail.provider} size="xs" />
            <span>{providerShort(detail.provider)}</span>
            <span className="text-[var(--dim)]">·</span>
            <span>{detail.product || 'alert'}</span>
          </>
        ) : (
          'ALERT'
        )
      }
    >
      {loading ? <SkeletonRows count={8} /> : error ? <ErrorBox>{error}</ErrorBox> : detail ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={detail.severity} />
            <StatusBadge status={detail.status} />
            <span className="pill">{detail.mapper_version || 'mapper —'}</span>
            <span className="ml-auto text-[10.5px] text-[var(--dim)]">{formatTime(detail.event_time)}</span>
          </div>

          <div className="grid grid-cols-1 gap-x-5 gap-y-2.5 text-[11.5px] sm:grid-cols-[110px_1fr]">
            <span className="text-[var(--dim)]">告警 ID</span>
            <span className="mono break-all font-mono">{detail.id}</span>
            <span className="text-[var(--dim)]">外部 ID</span>
            <span className="mono break-all font-mono">{detail.external_id || '—'}</span>
            <span className="text-[var(--dim)]">云 / 账号</span>
            <span>
              {providerShort(detail.provider)} · {detail.account_name || detail.account_id}
              {detail.account_uid ? <span className="ml-1 font-mono text-[var(--muted)]">{detail.account_uid}</span> : null}
            </span>
            <span className="text-[var(--dim)]">产品 / 类型</span>
            <span>{detail.product || '—'} · {detail.alert_type || '—'}</span>
            <span className="text-[var(--dim)]">资产</span>
            <span>{detail.resource?.name || '—'} <span className="font-mono text-[var(--muted)]">{detail.resource?.id || ''}</span></span>
            <span className="text-[var(--dim)]">源 → 目标</span>
            <span className="font-mono">{detail.source_ip || '—'} → {detail.destination_ip || '—'}</span>
            <span className="text-[var(--dim)]">首次 / 最近</span>
            <span>{formatTime(detail.first_seen_at)} / {formatTime(detail.last_seen_at)}</span>
            <span className="text-[var(--dim)]">厂商状态</span>
            <span>{detail.vendor_status || '—'} <span className="text-[var(--dim)]">（原始等级 {detail.original_severity || '—'}）</span></span>
            {detail.tactic ? (
              <>
                <span className="text-[var(--dim)]">ATT&amp;CK</span>
                <span className="font-mono">{detail.tactic}{detail.technique ? ` · ${detail.technique}` : ''}</span>
              </>
            ) : null}
          </div>

          {detail.description ? (
            <p className="rounded-lg border border-[var(--line-soft)] bg-[var(--inset)] px-3 py-2.5 text-[12px] leading-relaxed text-[var(--muted)]">
              {detail.description}
            </p>
          ) : null}

          {isAdmin ? (
            <div>
              <div className="mb-2 text-[10px] uppercase tracking-[1.2px] text-[var(--dim)]">生命周期</div>
              <div className="flex flex-wrap gap-1.5">
                {(Object.keys(STATUS_LABEL) as AlertStatus[])
                  .filter((s) => s !== detail.status)
                  .map((s) => (
                    <button key={s} className="btn btn-sm" disabled={busy} onClick={() => update(s)}>
                      标记为{STATUS_LABEL[s]}
                    </button>
                  ))}
              </div>
            </div>
          ) : null}

          <section>
            <div className="mb-2 flex items-center gap-2">
              <div className="text-[10px] uppercase tracking-[1.2px] text-[var(--dim)]">可观测对象</div>
              <span className="pill">{detail.observables?.length || 0}</span>
            </div>
            <div className="space-y-1.5">
              {(detail.observables || []).map((o, i) => (
                <div key={`${o.name}-${i}`} className="flex items-baseline gap-3 rounded-lg border border-[var(--line-soft)] bg-[var(--inset)] px-3 py-2 font-mono text-[11px]">
                  <span className="w-[150px] shrink-0 text-[var(--dim)]">{o.name || o.type || 'observable'}</span>
                  <span className="break-all">{o.value}</span>
                </div>
              ))}
              {!detail.observables?.length ? <div className="text-[11px] text-[var(--dim)]">无</div> : null}
            </div>
          </section>

          <section>
            <div className="mb-2 flex items-center gap-2">
              <div className="text-[10px] uppercase tracking-[1.2px] text-[var(--dim)]">证据</div>
              <span className="pill">{detail.evidences?.length || 0}</span>
            </div>
            <div className="space-y-2">
              {(detail.evidences || []).map((e, i) => (
                <div key={i} className="rounded-lg border border-[var(--line-soft)] bg-[var(--inset)] p-3">
                  <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[.8px] text-[var(--accent)]">{e.type || 'evidence'}</div>
                  <pre className="code max-h-[260px]">{JSON.stringify(e.data || {}, null, 2)}</pre>
                </div>
              ))}
              {!detail.evidences?.length ? <div className="text-[11px] text-[var(--dim)]">无</div> : null}
            </div>
          </section>

          <section>
            <div className="mb-2 flex items-center gap-2">
              <div className="text-[10px] uppercase tracking-[1.2px] text-[var(--dim)]">版本历史</div>
              <span className="pill">{revisions.length}</span>
              <span className="text-[10px] text-[var(--dim)]">只在 vendor payload / 等级变化时新增</span>
            </div>
            <div className="space-y-1.5">
              {revisions.map((r) => (
                <details key={r.id} className="rounded-lg border border-[var(--line-soft)] bg-[var(--inset)]">
                  <summary className="flex flex-wrap cursor-pointer items-center gap-2 px-3 py-2 text-[11px] text-[var(--muted)]">
                    <span className="font-mono text-[var(--accent)]">#{r.revision}</span>
                    <span>{formatTime(r.captured_at)}</span>
                    <SeverityBadge severity={r.severity} />
                    <span>{r.vendor_status || '—'}</span>
                    <span className="ml-auto max-w-[240px] truncate">{r.title || '—'}</span>
                  </summary>
                  <pre className="code max-h-[300px] rounded-none border-x-0 border-b-0">
                    {JSON.stringify({ title: r.title, severity: r.severity, vendor_status: r.vendor_status, raw: r.raw }, null, 2)}
                  </pre>
                </details>
              ))}
              {!revisions.length ? <div className="text-[11px] text-[var(--dim)]">暂无版本记录</div> : null}
            </div>
          </section>

          {raw ? (
            <details className="rounded-lg border border-[var(--line-soft)] bg-[var(--inset)]">
              <summary className="flex cursor-pointer items-center gap-2 px-3 py-2 text-[11px] text-[var(--muted)]">
                原始厂商 JSON
                <span className="ml-auto"><CopyButton value={raw} /></span>
              </summary>
              <pre className="code max-h-[420px] rounded-none border-x-0 border-b-0">{raw}</pre>
            </details>
          ) : null}
          {ocsf ? (
            <details className="rounded-lg border border-[var(--line-soft)] bg-[var(--inset)]">
              <summary className="flex cursor-pointer items-center gap-2 px-3 py-2 text-[11px] text-[var(--muted)]">
                统一 OCSF
                <span className="ml-auto"><CopyButton value={ocsf} /></span>
              </summary>
              <pre className="code max-h-[420px] rounded-none border-x-0 border-b-0">{ocsf}</pre>
            </details>
          ) : null}
          <div className="flex justify-end">
            <a
              className="btn btn-sm"
              href={`/api/v1/alerts/${encodeURIComponent(detail.id)}/raw`}
              target="_blank"
              rel="noreferrer"
            >
              <Download className="h-3.5 w-3.5" />
              打开原始 JSON
            </a>
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

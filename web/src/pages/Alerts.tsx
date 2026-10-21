import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight, Layers, List, RotateCcw, Search } from 'lucide-react';
import { api, sourceText } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { AlertFields } from '../components/AlertFields';
import { AssetContextPanel } from '../components/AssetContext';
import {
  CopyButton,
  Drawer,
  Empty,
  ErrorBox,
  SeverityBadge,
  SkeletonRows,
  StatusBadge,
} from '../components/ui';
import {
  RANGE_OPTIONS,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  STATUS_LABEL,
  fmtNum,
  formatDate,
  formatTime,
  groupTitle,
  providerShort,
  rangeStart,
} from '../lib';
import type {
  Alert,
  AlertGroup,
  AlertGroupBy,
  AlertGroupList,
  AlertList,
  AlertStatus,
  QueryWindow,
} from '../types';

interface Filters {
  provider: string;
  severity: string;
  status: string;
  range: string;
  q: string;
  ip: string;
  observable_type: string;
  observable_value: string;
  rule_id: string;
  finding_kind: string;
  vendor_status: string;
  time_field: string;
}
const EMPTY: Filters = { provider: '', severity: '', status: '', range: '7d', q: '', ip: '', observable_type: '', observable_value: '', rule_id: '', finding_kind: '', vendor_status: '', time_field: 'event_time' };
const filterKeys = Object.keys(EMPTY) as Array<keyof Filters>;

export function readAlertRoute(query: string) {
  const params = new URLSearchParams(query);
  const filters = { ...EMPTY };
  for (const key of filterKeys) if (params.has(key)) filters[key] = params.get(key)!;
  if (!RANGE_OPTIONS.some((option) => option.value === filters.range)) filters.range = EMPTY.range;
  const by = params.get('group_by');
  const groupBy: AlertGroupBy = by === 'signature' || by === 'asset' || by === 'source' ? by : 'type_asset';
  const window: QueryWindow = {};
  const sequence = params.get("snapshot_sequence");
  if (sequence !== null && Number.isSafeInteger(Number(sequence)) && Number(sequence)>=0) window.snapshot_sequence=Number(sequence);
  for (const key of ['start', 'end'] as const) {
    const value = params.get(key);
    if (value && Number.isFinite(Date.parse(value))) window[key] = value;
  }
  if (window.start && window.end && Date.parse(window.start) > Date.parse(window.end)) {
    delete window.start;
    delete window.end;
  }
  let groupKey: Record<string, string> | null = null;
  try {
    const parsed = JSON.parse(params.get('group_key') || 'null');
    if (
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      Object.keys(parsed).length > 0 &&
      Object.values(parsed).every((value) => typeof value === 'string')
    )
      groupKey = parsed;
  } catch {
    /* malformed shared URLs fall back to the normal list */
  }
  const rawOffset = Number(params.get('offset') || 0);
  return {
    filters,
    window,
    groupBy,
    groupKey,
    offset: Number.isSafeInteger(rawOffset) && rawOffset >= 0 ? rawOffset : 0,
    view: params.get('view') === 'groups' ? 'groups' : 'raw',
    selected: params.get('alert'),
  };
}

export function queryFor(filters: Filters, offset: number, window: QueryWindow = {}) {
  const params = new URLSearchParams({ limit: '20', offset: String(offset) });
  for (const key of ['provider', 'severity', 'status', 'q', 'ip', 'observable_type', 'observable_value', 'rule_id', 'finding_kind', 'vendor_status', 'time_field'] as const)
    if (filters[key].trim()) params.set(key, filters[key].trim());
  if(window.snapshot_sequence!==undefined) params.set("snapshot_sequence",String(window.snapshot_sequence));
  const end = window.end || new Date().toISOString();
  const start = window.start || rangeStart(filters.range, end);
  if (start) params.set('start', start);
  params.set('end', end);
  return params;
}

export function Alerts() {
  const { providers, isAdmin, refreshNonce, toast, routeQuery, go } = useApp();
  const { t } = useI18n();
  const route = useMemo(() => readAlertRoute(routeQuery), [routeQuery]);
  const [filters, setFilters] = useState<Filters>(route.filters);
  const [data, setData] = useState<AlertList | null>(null);
  const [groups, setGroups] = useState<AlertGroupList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);
  const responseWindow = useRef<{ filters: string; window: QueryWindow } | null>(null);
  const limit = 20;
  const filterIdentity = JSON.stringify(route.filters);
  const groupIdentity = JSON.stringify(route.groupKey);
  const windowIdentity = JSON.stringify(route.window);
  useEffect(() => setFilters(route.filters), [filterIdentity]);

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    const params = queryFor(route.filters, route.offset, route.window);
    if (route.view === 'groups' || route.groupKey) params.set('group_by', route.groupBy);
    if (route.groupKey && route.view === 'raw') params.set('group_key', JSON.stringify(route.groupKey));
    const promise =
      route.view === 'groups'
        ? api<AlertGroupList>(`/alerts/groups?${params}`, { signal: controller.signal })
        : api<AlertList>(`/alerts?${params}`, { signal: controller.signal });
    promise
      .then((result) => {
        if (!alive) return;
        if (result.window)
          responseWindow.current = { filters: filterIdentity + windowIdentity, window: {...result.window,snapshot_sequence:result.snapshot_sequence} };
        if ('groups' in result) setGroups(result);
        else setData(result);
      })
      .catch((err) => {
        if (alive) setError(err.message || '查询失败');
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
      controller.abort();
    };
  }, [filterIdentity, route.offset, route.view, route.groupBy, groupIdentity, windowIdentity, refreshNonce, reload]);

  function navigate(patch: Record<string, string | null>) {
    const params = Object.fromEntries(new URLSearchParams(routeQuery));
    const snapshot = responseWindow.current;
    if (!('start' in patch) && !('end' in patch) && snapshot?.filters === filterIdentity + windowIdentity) {
      if (snapshot.window.start) params.start = snapshot.window.start;
      if (snapshot.window.end) params.end = snapshot.window.end;
      if(snapshot.window.snapshot_sequence!==undefined) params.snapshot_sequence=String(snapshot.window.snapshot_sequence);
    }
    for (const [key, value] of Object.entries(patch)) {
      if (value === null || value === '') delete params[key];
      else params[key] = value;
    }
    go('alerts', params);
  }
  function apply() {
    navigate({ ...filters, offset: null, group_key: null, alert: null, start: null, end: null, snapshot_sequence:null });
    setReload((value) => value + 1);
  }
  function reset() {
    go('alerts');
    setFilters(EMPTY);
    setReload((value) => value + 1);
  }
  function showGroup(group: AlertGroup) {
    navigate({ view: null, group_by: group.group_by, group_key: JSON.stringify(group.key), offset: null });
  }
  const total = route.view === 'groups' ? groups?.total || 0 : data?.total || 0;
  const current = Math.floor(route.offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  const severityOptions = ['critical,fatal,high', ...SEVERITY_ORDER];
  const shownWindow = (route.view === 'groups' ? groups : data)?.window;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="segmented" aria-label={t('统一告警')}>
          <button
            aria-pressed={route.view === 'raw'}
            className={route.view === 'raw' ? 'selected' : ''}
            onClick={() => navigate({ view: null, group_key: null, offset: null })}
          >
            <List className="h-4 w-4" />
            {t('原始告警')}
          </button>
          <button
            aria-pressed={route.view === 'groups'}
            className={route.view === 'groups' ? 'selected' : ''}
            onClick={() => navigate({ view: 'groups', group_key: null, offset: null })}
          >
            <Layers className="h-4 w-4" />
            {t('聚合视图')}
          </button>
        </div>
        {route.view === 'groups' ? (
          <select
            aria-label={t('分组方式')}
            className="field"
            value={route.groupBy}
            onChange={(event) => navigate({ group_by: event.target.value, offset: null })}
          >
            <option value="type_asset">{t('按类型与资产')}</option>
            <option value="signature">{t('按规则、资产与源 IP')}</option>
            <option value="asset">{t('按资产')}</option>
            <option value="source">{t('按源 IP 与类型')}</option>
          </select>
        ) : null}
      </div>
      <form
        className="card flex flex-wrap items-center gap-2 p-4"
        onSubmit={(event) => {
          event.preventDefault();
          apply();
        }}
      >
        <div className="relative min-w-[230px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--dim)]" />
          <input
            className="field w-full pl-9"
            aria-label={t('搜索标题、描述、类型、资产…')}
            placeholder={t('搜索标题、描述、类型、资产…')}
            value={filters.q}
            onChange={(event) => setFilters((value) => ({ ...value, q: event.target.value }))}
          />
        </div>
        <select
          aria-label={t('云厂商')}
          className="field"
          value={filters.provider}
          onChange={(event) => setFilters((value) => ({ ...value, provider: event.target.value }))}
        >
          <option value="">{t('全部云厂商')}</option>
          {providers.map((provider) => (
            <option key={provider.id} value={provider.id}>
              {provider.name}
            </option>
          ))}
        </select>
        <select
          aria-label={t('等级')}
          className="field"
          value={filters.severity}
          onChange={(event) => setFilters((value) => ({ ...value, severity: event.target.value }))}
        >
          <option value="">{t('全部等级')}</option>
          {severityOptions.map((severity) => (
            <option key={severity} value={severity}>
              {t(
                severity === 'critical,fatal,high'
                  ? '高危及以上'
                  : SEVERITY_LABEL[severity as keyof typeof SEVERITY_LABEL],
              )}
            </option>
          ))}
        </select>
        <select
          aria-label={t('本地标注')}
          className="field"
          value={filters.status}
          onChange={(event) => setFilters((value) => ({ ...value, status: event.target.value }))}
        >
          <option value="">{t('全部状态')}</option>
          <option value="open,acknowledged">{t('未关闭')}</option>
          {Object.entries(STATUS_LABEL).map(([status, label]) => (
            <option key={status} value={status}>
              {t(label)}
            </option>
          ))}
        </select>
        <select
          aria-label={t('时间范围')}
          className="field"
          value={filters.range}
          onChange={(event) => setFilters((value) => ({ ...value, range: event.target.value }))}
        >
          {RANGE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {t(option.label)}
            </option>
          ))}
        </select>
        <input
          aria-label={t('IP 可观测对象')}
          className="field w-[165px]"
          placeholder={t('IP 可观测对象')}
          value={filters.ip}
          onChange={(event) => setFilters((value) => ({ ...value, ip: event.target.value }))}
        />
        <button className="btn btn-primary" type="submit">
          <Search className="h-4 w-4" />
          {t('查询')}
        </button>
        <button
          className="btn btn-ghost btn-icon"
          type="button"
          title={t('重置')}
          aria-label={t('重置')}
          onClick={reset}
        >
          <RotateCcw className="h-4 w-4" />
        </button>
      <details className="disclosure">
        <summary>{t('更多事实筛选')}</summary>
        <div className="mt-3 flex flex-wrap gap-2">
          <select className="field" aria-label={t('时间依据')} value={filters.time_field} onChange={e=>setFilters(v=>({...v,time_field:e.target.value}))}><option value="event_time">{t('发生时间')}</option><option value="source_updated_at">{t('厂商更新时间')}</option><option value="ingested_at">{t('采集时间')}</option></select>
          <select className="field" aria-label={t('发现类别')} value={filters.finding_kind} onChange={e=>setFilters(v=>({...v,finding_kind:e.target.value}))}>
            <option value="">{t('全部类别')}</option>
            {['detection','vulnerability','compliance','incident','other'].map(v=><option key={v} value={v}>{v}</option>)}
          </select>
          <input className="field" aria-label={t('规则 ID')} placeholder={t('规则 ID')} value={filters.rule_id} onChange={e=>setFilters(v=>({...v,rule_id:e.target.value}))}/>
          <input className="field" aria-label={t('厂商状态')} placeholder={t('厂商状态')} value={filters.vendor_status} onChange={e=>setFilters(v=>({...v,vendor_status:e.target.value}))}/>
          <select className="field" aria-label={t('对象类型')} value={filters.observable_type} onChange={e=>setFilters(v=>({...v,observable_type:e.target.value}))}>
            <option value="">{t('全部对象')}</option>
            <option value="1">Hostname</option><option value="2">IP</option><option value="4">User</option><option value="8">Hash</option><option value="10">Resource</option><option value="0">Domain / Other</option>
          </select>
          <input className="field" aria-label={t('对象精确值')} placeholder={t('对象精确值')} value={filters.observable_value} onChange={e=>setFilters(v=>({...v,observable_value:e.target.value}))}/>
        </div>
      </details>
      </form>
      {(route.view==='groups'?groups:data)?.coverage && !(route.view==='groups'?groups:data)?.coverage?.complete ? <p className="text-xs text-[var(--muted)]" role="status">{t('当前查询范围尚未确认完整，请结合覆盖范围与同步水位查看结果。')}</p>:null}
      {route.groupKey ? (
        <div className="flex items-center gap-3 text-sm">
          <button
            className="btn btn-sm"
            onClick={() => navigate({ view: 'groups', group_key: null, offset: null })}
          >
            <ChevronLeft className="h-4 w-4" />
            {t('返回分组')}
          </button>
          <span>{t('分组成员')}</span>
          <span className="truncate text-xs text-[var(--muted)]">
            {route.groupKey.resource_id || route.groupKey.source_ip || route.groupKey.alert_type}
          </span>
        </div>
      ) : null}
      <div className="flex justify-between text-xs text-[var(--muted)]">
        <span aria-live="polite" className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>
            {!loading && !error
              ? t(route.view === 'groups' ? '共 {count} 组' : '共 {count} 条', { count: fmtNum(total) })
              : loading ? t('加载中…') : null}
          </span>
          {!loading && !error && shownWindow?.end ? (
            <span title={[shownWindow.start, shownWindow.end].filter(Boolean).map(formatTime).join(' — ')}>
              {shownWindow.start
                ? `${formatDate(shownWindow.start)} — ${formatDate(shownWindow.end)}`
                : t('截至 {time}', { time: formatDate(shownWindow.end) })}
            </span>
          ) : null}
        </span>
        <span>{t('第 {current} / {pages} 页', { current, pages })}</span>
      </div>
      <div className="table-wrap">
        {loading ? (
          <SkeletonRows count={10} />
        ) : error ? (
          <div className="p-4">
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : total === 0 ? (
          <Empty title={route.view === 'groups' ? '没有匹配的分组' : '没有匹配的告警'}>
            <p>{t('调整筛选条件后重试。')}</p>
            <button className="btn mt-4" onClick={reset}>
              {t('清除筛选')}
            </button>
          </Empty>
        ) : route.view === 'groups' ? (
          <table className="data-table min-w-[800px]">
            <thead>
              <tr>
                <th>{t('告警分组')}</th>
                <th>{t('告警条数')}</th>
                <th title={t('取组内厂商告警的最高等级')}>{t('组内最高等级')}</th>
                <th>{t('云厂商')}</th>
                <th>{t('最近')}</th>
              </tr>
            </thead>
            <tbody>
              {groups?.groups.map((group) => (
                <tr key={group.id}>
                  <td>
                    <button
                      className="cell-title text-left font-medium hover:text-[var(--accent)]"
                      onClick={() => showGroup(group)}
                    >
                      {groupTitle(group)}
                    </button>
                    <div className="cell-sub">
                      {group.key.singleton
                        ? t('字段不完整')
                        : [group.alert_type, group.source_ip].filter(Boolean).join(' · ')}
                    </div>
                  </td>
                  <td className="tabular-nums">{fmtNum(group.finding_count)}</td>
                  <td>
                    <SeverityBadge severity={group.max_severity} />
                  </td>
                  <td>
                    <div className="flex flex-wrap gap-2">
                      {group.providers?.map((provider) => (
                        <span key={provider} className="inline-flex items-center gap-1">
                          <BrandIcon provider={provider} size="xs" />
                          {providerShort(provider)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="whitespace-nowrap text-xs text-[var(--muted)]">
                    {formatDate(group.last_seen_at || undefined)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table className="data-table min-w-[1060px]">
            <thead>
              <tr>
                <th>{t('时间')}</th>
                <th>{t('等级')}</th>
                <th>{t('告警')}</th>
                <th>{t('来源')}</th>
                <th>{t('资产')}</th>
                <th>{t('源 → 目标')}</th>
                <th>{t('本地标注')}</th>
              </tr>
            </thead>
            <tbody>
              {data?.alerts.map((alert) => (
                <tr key={alert.id}>
                  <td className="whitespace-nowrap text-xs text-[var(--muted)]">
                    {formatDate(alert.event_time)}
                  </td>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td>
                    <button
                      className="cell-title max-w-[340px] text-left font-medium hover:text-[var(--accent)]"
                      onClick={() => navigate({ alert: alert.id })}
                      title={alert.title}
                    >
                      {alert.title}
                    </button>
                    <div className="cell-sub">{alert.alert_type || alert.product}</div>
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                      <BrandIcon provider={alert.provider} size="xs" />
                      {providerShort(alert.provider)}
                    </div>
                    <div className="cell-sub">{alert.account_name || alert.account_id}</div>
                  </td>
                  <td>
                    <div className="cell-title max-w-[180px]" title={alert.resource?.name}>
                      {alert.resource?.name || '—'}
                    </div>
                    <div className="cell-sub max-w-[180px] font-mono" title={alert.resource?.id}>
                      {alert.resource?.id}
                    </div>
                  </td>
                  <td className="whitespace-nowrap font-mono text-xs">
                    {alert.source_ip || '—'} <span className="text-[var(--dim)]">→</span>{' '}
                    {alert.destination_ip || '—'}
                  </td>
                  <td>
                    <StatusBadge status={alert.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="flex items-center justify-end gap-2">
        <span className="mr-auto text-xs text-[var(--muted)]">
          {t(route.view === 'groups' ? '每页 {count} 组' : '每页 {count} 条', { count: limit })}
        </span>
        <button
          className="btn btn-sm"
          disabled={loading || route.offset <= 0}
          onClick={() => navigate({ offset: String(Math.max(0, route.offset - limit)) })}
        >
          <ChevronLeft className="h-4 w-4" />
          {t('上一页')}
        </button>
        <button
          className="btn btn-sm"
          disabled={loading || route.offset + limit >= total}
          onClick={() => navigate({ offset: String(route.offset + limit) })}
        >
          {t('下一页')}
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
      <AlertDrawer
        id={route.selected}
        snapshotSequence={route.window.snapshot_sequence ?? (route.view==='groups'?groups:data)?.snapshot_sequence}
        onClose={() => navigate({ alert: null })}
        onChanged={() => setReload((value) => value + 1)}
        isAdmin={isAdmin}
        toast={toast}
      />
    </div>
  );
}

function AlertDrawer({
  id,
  snapshotSequence,
  onClose,
  onChanged,
  isAdmin,
  toast,
}: {
  id: string | null;
  snapshotSequence?:number;
  onClose: () => void;
  onChanged: () => void;
  isAdmin: boolean;
  toast: (message: string, error?: boolean) => void;
}) {
  const { t } = useI18n();
  const { refreshNonce } = useApp();
  const [detail, setDetail] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState('raw');
  const [raw, setRaw] = useState('');
  const [rawError, setRawError] = useState('');
  useEffect(() => {
    if (!id) return;
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setDetail(null);
    setTab('raw');
    api<Alert>(`/alerts/${encodeURIComponent(id)}${snapshotSequence!==undefined?`?snapshot_sequence=${snapshotSequence}`:""}`, { signal: controller.signal })
      .then((result) => {
        if (alive) setDetail(result);
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
  }, [id, refreshNonce, snapshotSequence]);
  useEffect(() => {
    setRaw('');
    setRawError('');
    if (!detail?.raw_url) return;
    const controller = new AbortController();
    sourceText(detail.raw_url, { signal: controller.signal })
      .then(text => { if (!controller.signal.aborted) setRaw(text); })
      .catch(error => { if (!controller.signal.aborted) setRawError(error.message); });
    return () => controller.abort();
  }, [detail?.raw_url]);
  async function update(status: AlertStatus) {
    if (!id || busy) return;
    setBusy(true);
    try {
      const result = await api<Alert>(`/alerts/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      setDetail(result);
      onChanged();
      toast('本地标注已更新');
    } catch (err: any) {
      toast(err?.message || '更新失败', true);
    } finally {
      setBusy(false);
    }
  }
  const ocsf = detail?.ocsf ? JSON.stringify(detail.ocsf, null, 2) : '';
  const labels = [
    ['raw', '原始数据'],
    ['fields', '字段与证据'],
    ['ocsf', 'OCSF'],
  ];
  return (
    <Drawer
      open={!!id}
      onClose={onClose}
      title={detail?.title || t(loading ? '加载中…' : '告警详情')}
      eyebrow={
        detail ? (
          <>
            <BrandIcon provider={detail.provider} size="xs" />
            <span>
              {providerShort(detail.provider)} · {detail.product}
            </span>
          </>
        ) : null
      }
    >
      {loading ? (
        <SkeletonRows count={10} />
      ) : error ? (
        <ErrorBox>{error}</ErrorBox>
      ) : detail ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={detail.severity} />
            <StatusBadge status={detail.status} />
            <span className="ml-auto text-xs text-[var(--muted)]">{formatTime(detail.event_time)}</span>
          </div>
          <div className="detail-tabs" role="tablist" aria-label={t('告警详情')}>
            {labels.map(([key, label]) => (
              <button
                key={key}
                role="tab"
                id={`alert-tab-${key}`}
                aria-controls={`alert-panel-${key}`}
                aria-selected={tab === key}
                tabIndex={tab === key ? 0 : -1}
                onKeyDown={(event) => {
                  const index = labels.findIndex(([value]) => value === key);
                  const next =
                    event.key === 'ArrowRight'
                      ? (index + 1) % labels.length
                      : event.key === 'ArrowLeft'
                        ? (index + labels.length - 1) % labels.length
                        : event.key === 'Home'
                          ? 0
                          : event.key === 'End'
                            ? labels.length - 1
                            : -1;
                  if (next < 0) return;
                  event.preventDefault();
                  setTab(labels[next][0]);
                  document.getElementById(`alert-tab-${labels[next][0]}`)?.focus();
                }}
                onClick={() => setTab(key)}
              >
                {t(label)}
              </button>
            ))}
          </div>
          <div role="tabpanel" id={`alert-panel-${tab}`} aria-labelledby={`alert-tab-${tab}`}>
            {tab === 'raw' ? (
              <div className="space-y-5">
                <AssetContextPanel key={`${detail.id}:${detail.revision}`} detail={detail} isAdmin={isAdmin} />
                {detail.description ? (
                  <p className="whitespace-pre-wrap text-sm leading-relaxed">{detail.description}</p>
                ) : null}
                <dl className="detail-fields">
                  <dt>{t('资产')}</dt>
                  <dd>
                    {detail.resource?.name || '—'}
                    {detail.resource?.id ? (
                      <div className="mt-1 break-all font-mono text-xs text-[var(--muted)]">
                        {detail.resource.id}
                      </div>
                    ) : null}
                  </dd>
                  <dt>{t('源 IP')}</dt>
                  <dd className="font-mono">{detail.source_ip || '—'}</dd>
                  <dt>{t('目标 IP')}</dt>
                  <dd className="font-mono">{detail.destination_ip || '—'}</dd>
                  <dt>{t('云 / 账号')}</dt>
                  <dd>
                    {providerShort(detail.provider)} · {detail.account_name || detail.account_id}
                    <div className="mt-1 font-mono text-xs text-[var(--muted)]">{detail.account_uid}</div>
                  </dd>
                  <dt>{t('产品 / 类型')}</dt>
                  <dd>
                    {detail.product || '—'} · {detail.alert_type || '—'}
                  </dd>
                  <dt>{t('区域')}</dt>
                  <dd>{detail.region || '—'}</dd>
                  <dt>{t('首次发现')}</dt>
                  <dd>{formatTime(detail.first_seen_at)}</dd>
                  <dt>{t('最近发现')}</dt>
                  <dd>{formatTime(detail.last_seen_at)}</dd>
                  <dt>{t('发现类别')}</dt><dd>{detail.finding_kind || '—'}</dd>
                  <dt>{t('规则 ID')}</dt><dd className="font-mono text-xs">{detail.rule_id || '—'}</dd>
                  <dt>{t('厂商更新时间')}</dt><dd>{formatTime(detail.source_updated_at)}</dd>
                  <dt>{t('采集时间')}</dt><dd>{formatTime(detail.ingested_at)}</dd>
                  <dt>{t('厂商状态')}</dt>
                  <dd>{detail.vendor_status || '—'}</dd>
                  <dt>{t('原始等级')}</dt>
                  <dd>{detail.original_severity || '—'}</dd>
                  <dt>{t('告警 ID')}</dt>
                  <dd className="break-all font-mono text-xs">{detail.id}</dd>
                  <dt>{t('外部 ID')}</dt>
                  <dd className="break-all font-mono text-xs">{detail.external_id || '—'}</dd>
                  {detail.tactic || detail.technique ? (
                    <>
                      <dt>ATT&amp;CK</dt>
                      <dd className="font-mono">
                        {detail.tactic} {detail.technique}
                      </dd>
                    </>
                  ) : null}
                </dl>
                {isAdmin ? (
                  <label className="form-label max-w-[260px]">
                    {t('本地标注')}
                    <select
                      className="field"
                      value={detail.status}
                      disabled={busy}
                      onChange={(event) => update(event.target.value as AlertStatus)}
                    >
                      {Object.entries(STATUS_LABEL).map(([status, label]) => (
                        <option key={status} value={status}>
                          {t(label)}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <h3 className="section-title">{t('原始厂商 JSON')}</h3>
                    <CopyButton value={raw} />
                  </div>
                  {rawError ? <ErrorBox>{rawError}</ErrorBox> : <pre className="code">{raw || t('加载中…')}</pre>}
                </div>
                <a
                  className="btn"
                  href={detail.raw_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t('打开原始 JSON')}
                </a>
              </div>
            ) : null}
            {tab === 'fields' ? <AlertFields detail={detail} /> : null}
            {tab === 'ocsf' ? (
              <div className="space-y-5">
                <dl className="detail-fields">
                  <dt>{t('映射版本')}</dt>
                  <dd className="font-mono text-xs">{detail.mapper_version || '—'}</dd>
                </dl>
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <h3 className="section-title">{t('统一 OCSF')}</h3>
                    <CopyButton value={ocsf} />
                  </div>
                  {detail.ocsf ? (
                    <pre className="code">{ocsf}</pre>
                  ) : (
                    <div className="space-y-2 text-sm text-[var(--muted)]">
                      <p>{t('来源信息不足以生成该类别的完整 OCSF，原始记录仍完整保留。')}</p>
                      <p className="font-mono text-xs">{detail.ocsf_omission_reason}</p>
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

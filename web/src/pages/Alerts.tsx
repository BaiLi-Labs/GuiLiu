import { useEffect, useMemo, useState } from 'react';
import { ChevronLeft, ChevronRight, Layers, List, RotateCcw, Search } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
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
const filterKeys = Object.keys(EMPTY) as Array<keyof Filters>;

export function readAlertRoute(query: string) {
  const params = new URLSearchParams(query);
  const filters = { ...EMPTY };
  for (const key of filterKeys) if (params.has(key)) filters[key] = params.get(key)!;
  if (!RANGE_OPTIONS.some((option) => option.value === filters.range)) filters.range = EMPTY.range;
  const by = params.get('group_by');
  const groupBy: AlertGroupBy = by === 'asset' || by === 'source' ? by : 'signature';
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
    groupBy,
    groupKey,
    offset: Number.isSafeInteger(rawOffset) && rawOffset >= 0 ? rawOffset : 0,
    view: params.get('view') === 'groups' ? 'groups' : 'raw',
    selected: params.get('alert'),
  };
}

function queryFor(filters: Filters, offset: number) {
  const params = new URLSearchParams({ limit: '20', offset: String(offset) });
  for (const key of ['provider', 'severity', 'status', 'q', 'ip'] as const)
    if (filters[key].trim()) params.set(key, filters[key].trim());
  const start = rangeStart(filters.range);
  if (start) params.set('start', start);
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
  const limit = 20;
  const filterIdentity = JSON.stringify(route.filters);
  const groupIdentity = JSON.stringify(route.groupKey);
  useEffect(() => setFilters(route.filters), [filterIdentity]);

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    const params = queryFor(route.filters, route.offset);
    if (route.view === 'groups' || route.groupKey) params.set('group_by', route.groupBy);
    if (route.groupKey && route.view === 'raw') params.set('group_key', JSON.stringify(route.groupKey));
    const promise =
      route.view === 'groups'
        ? api<AlertGroupList>(`/alerts/groups?${params}`, { signal: controller.signal })
        : api<AlertList>(`/alerts?${params}`, { signal: controller.signal });
    promise
      .then((result) => {
        if (!alive) return;
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
  }, [filterIdentity, route.offset, route.view, route.groupBy, groupIdentity, refreshNonce, reload]);

  function navigate(patch: Record<string, string | null>) {
    const params = Object.fromEntries(new URLSearchParams(routeQuery));
    for (const [key, value] of Object.entries(patch)) {
      if (value === null || value === '') delete params[key];
      else params[key] = value;
    }
    go('alerts', params);
  }
  function apply() {
    navigate({ ...filters, offset: null, group_key: null, alert: null });
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
            <option value="signature">{t('同类重复')}</option>
            <option value="asset">{t('按资产')}</option>
            <option value="source">{t('按攻击源')}</option>
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
          aria-label={t('归流内状态')}
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
          aria-label={t('源/目标 IP')}
          className="field w-[165px]"
          placeholder={t('源/目标 IP')}
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
      </form>
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
        <span aria-live="polite">
          {!loading
            ? t(route.view === 'groups' ? '共 {count} 组' : '共 {count} 条', { count: fmtNum(total) })
            : t('加载中…')}
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
                <th>{t('数量')}</th>
                <th>{t('最高等级')}</th>
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
                  <td className="tabular-nums">{fmtNum(group.count)}</td>
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
                    {formatDate(group.last_seen_at)}
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
                <th>{t('归流内状态')}</th>
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
  onClose,
  onChanged,
  isAdmin,
  toast,
}: {
  id: string | null;
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
  useEffect(() => {
    if (!id) return;
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setDetail(null);
    setTab('raw');
    api<Alert>(`/alerts/${encodeURIComponent(id)}`, { signal: controller.signal })
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
  }, [id, refreshNonce]);
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
      toast('归流内状态已更新');
    } catch (err: any) {
      toast(err?.message || '更新失败', true);
    } finally {
      setBusy(false);
    }
  }
  const raw = detail?.raw ? JSON.stringify(detail.raw, null, 2) : '';
  const ocsf = detail?.ocsf ? JSON.stringify(detail.ocsf, null, 2) : '';
  const labels = [
    ['raw', '原始数据'],
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
                  <dt>{t('厂商状态')}</dt>
                  <dd>{detail.vendor_status || '—'}</dd>
                  <dt>{t('原始等级')}</dt>
                  <dd>{detail.original_severity || '—'}</dd>
                  <dt>{t('告警 ID')}</dt>
                  <dd className="break-all font-mono text-xs">{detail.id}</dd>
                  <dt>{t('外部 ID')}</dt>
                  <dd className="break-all font-mono text-xs">{detail.external_id || '—'}</dd>
                  {detail.tactic ? (
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
                    {t('归流内状态')}
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
                  <pre className="code">{raw}</pre>
                </div>
                <a
                  className="btn"
                  href={`/api/v1/alerts/${encodeURIComponent(detail.id)}/raw`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t('打开原始 JSON')}
                </a>
              </div>
            ) : null}
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
                  <pre className="code">{ocsf}</pre>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

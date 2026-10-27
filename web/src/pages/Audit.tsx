import { Fragment, useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { formatTime } from '../lib';

export interface AuditEvent {
  sequence: number; request_id: string; parent_sequence?: number; started_at: string; finished_at?: string;
  surface: string; operation: string; tool?: string; path?: string; peer_ip?: string; auth_type: string;
  user_id?: string; username?: string; role?: string; api_key_id?: string; api_key_name?: string;
  outcome: string; http_status?: number; error_code?: string; duration_ms: number; response_bytes?: number;
  parameters: Record<string, unknown>; effective_query?: Record<string, unknown>; summary: Record<string, unknown>;
}
interface AuditPage { events: AuditEvent[]; has_more: boolean; next_cursor: string; retention_days: number }
const outcomes: Record<string, string> = { success: '成功', denied: '拒绝访问', error: '失败', cancelled: '请求已取消', in_progress: '尚未确认完成' };
const blank = { username: '', api_key_id: '', tool: '', request_id: '', surface: '', outcome: '', range: '24h' };

export function auditQuery(filters: typeof blank, end = new Date().toISOString()): string {
  const params = new URLSearchParams({ limit: '20' });
  for (const key of ['username', 'api_key_id', 'tool', 'request_id', 'surface', 'outcome'] as const) if (filters[key]) params.set(key, filters[key]);
  if (filters.range !== 'all') {
    params.set('end', end); params.set('start', new Date(new Date(end).getTime() - (filters.range === '7d' ? 7 : 1) * 86400_000).toISOString());
  }
  return params.toString();
}

export function AuditEventDetails({ event }: { event: AuditEvent }) {
  const { t } = useI18n();
  return <div className="space-y-3 py-3 text-xs">
    <dl className="detail-fields">
      <dt>{t('请求 ID')}</dt><dd className="break-all font-mono">{event.request_id}</dd>
      <dt>{t('父审计序号')}</dt><dd>{event.parent_sequence || '—'}</dd>
      <dt>{t('认证方式')}</dt><dd>{event.auth_type}</dd>
      <dt>{t('用户 ID')}</dt><dd>{event.user_id || '—'}</dd>
      <dt>API Key ID</dt><dd>{event.api_key_id || '—'}</dd>
      <dt>{t('连接对端 IP')}</dt><dd>{event.peer_ip || '—'}</dd>
      <dt>{t('路径')}</dt><dd className="break-all">{event.path || '—'}</dd>
      <dt>{t('完成时间')}</dt><dd>{event.finished_at ? formatTime(event.finished_at) : t('尚未确认完成')}</dd>
      <dt>{t('响应字节数')}</dt><dd>{event.response_bytes ?? '—'}</dd>
      <dt>{t('错误代码')}</dt><dd>{event.error_code || '—'}</dd>
    </dl>
    {([[t('提交的查询条件'), event.parameters], [t('实际查询范围'), event.effective_query], [t('返回引用与计数'), event.summary]] as const).map(([label, value]) => value ? <div key={label}><h4 className="mb-2 font-medium">{label}</h4><pre className="code">{JSON.stringify(value, null, 2)}</pre></div> : null)}
  </div>;
}

export function Audit() {
  const { t } = useI18n(); const { isAdmin, refreshNonce } = useApp();
  const [filters, setFilters] = useState(blank);
  const [submitted, setSubmitted] = useState(blank);
  const query = useMemo(() => auditQuery(submitted), [submitted, refreshNonce]);
  const [cursors, setCursors] = useState<string[]>([]);
  const [data, setData] = useState<AuditPage | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  const before = cursors[cursors.length - 1] || '';
  useEffect(() => { setCursors([]); }, [refreshNonce]);
  useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController(); setBusy(true); setError('');
    const params = new URLSearchParams(query); if (before) params.set('before_sequence', before);
    api<AuditPage>(`/audit-events?${params}`, { signal: controller.signal }).then(setData).catch(err => { if (!controller.signal.aborted) setError(err.message); }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [isAdmin, query, before, refreshNonce]);
  if (!isAdmin) return <p>{t('仅管理员可查看操作审计')}</p>;
  function search(event: React.FormEvent) { event.preventDefault(); setExpanded(null); setCursors([]); setSubmitted({ ...filters }); }
  function trace(id: string) { const next = { ...blank, range: 'all', request_id: id }; setExpanded(null); setFilters(next); setCursors([]); setSubmitted(next); }
  return <div className="space-y-4">
    <p className="text-xs text-[var(--muted)]">{t('记录平台访问与操作；MCP 工具失败单独记录，即使 HTTP 返回 200。')}</p>
    <p className="text-xs text-[var(--muted)]">{t('关键词只保存指纹，凭据与原始证据正文不进入审计。')} {data ? t('审计保留 {days} 天', { days: data.retention_days }) : ''}</p>
    <form onSubmit={search} className="flex flex-wrap gap-2">
      {(['username', 'api_key_id', 'tool', 'request_id'] as const).map((key, i) => <input key={key} className="field" aria-label={t(['用户名', 'API Key ID', 'MCP 工具', '请求 ID'][i])} placeholder={t(['用户名', 'API Key ID', 'MCP 工具', '请求 ID'][i])} value={filters[key]} onChange={e => setFilters(old => ({ ...old, [key]: e.target.value }))} />)}
      <select className="field" aria-label={t('访问入口')} value={filters.surface} onChange={e => setFilters(old => ({ ...old, surface: e.target.value }))}>
        <option value="">{t('全部入口')}</option><option value="rest">REST / Web</option><option value="cli">CLI</option><option value="mcp_http">MCP HTTP</option><option value="mcp_stdio">MCP stdio</option>
      </select>
      <select className="field" aria-label={t('操作结果')} value={filters.outcome} onChange={e => setFilters(old => ({ ...old, outcome: e.target.value }))}>
        <option value="">{t('全部结果')}</option>{Object.entries(outcomes).map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}
      </select>
      <select className="field" aria-label={t('时间范围')} value={filters.range} onChange={e => setFilters(old => ({ ...old, range: e.target.value }))}><option value="24h">{t('最近 24 小时')}</option><option value="7d">{t('最近 7 天')}</option><option value="all">{t('全部时间')}</option></select>
      <button className="btn btn-primary" disabled={busy}>{t('查询')}</button>
    </form>
    {error ? <p role="alert" className="text-sm text-[var(--danger-text)]">{t(error)}</p> : null}
    {busy ? <p role="status" className="text-xs">{t('加载中…')}</p> : null}
    <div className="table-wrap"><table className="data-table min-w-[1000px]"><thead><tr>{['时间', '调用者', '操作', '操作结果', '耗时', '详情'].map(label => <th key={label}>{t(label)}</th>)}</tr></thead><tbody>
      {data?.events.map(event => <Fragment key={event.sequence}><tr>
        <td className="whitespace-nowrap text-xs">{formatTime(event.started_at)}<div className="text-[var(--muted)]">#{event.sequence}</div></td>
        <td className="text-xs">{event.username || event.auth_type}<div className="text-[var(--muted)]">{event.api_key_name || event.auth_type}</div></td>
        <td className="text-xs"><span>{event.tool || event.operation}</span><div className="text-[var(--muted)]">{event.surface}</div></td>
        <td className="text-xs">{t(outcomes[event.outcome] || event.outcome)}{event.http_status ? ` · ${event.http_status}` : ''}</td>
        <td className="whitespace-nowrap text-xs">{event.duration_ms} ms</td>
        <td><button className="btn btn-sm" aria-expanded={expanded === event.sequence} onClick={() => setExpanded(old => old === event.sequence ? null : event.sequence)}>{t('查看详情')}</button><button className="btn btn-sm ml-2" onClick={() => trace(event.request_id)}>{t('查看同一请求')}</button></td>
      </tr>{expanded === event.sequence ? <tr><td colSpan={6}><AuditEventDetails event={event} /></td></tr> : null}</Fragment>)}
      {data && !data.events.length ? <tr><td colSpan={6} className="py-8 text-center text-[var(--muted)]">{t('没有匹配的审计记录')}</td></tr> : null}
    </tbody></table></div>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-xs text-[var(--muted)]">{data ? t('第 {page} 页 · 本页 {count} 条', { page: cursors.length + 1, count: data.events.length }) : ''}{data?.has_more ? ` · ${t('还有更多')}` : ''}</span>
      <div className="flex gap-2"><button className="btn" disabled={busy || !cursors.length} onClick={() => setCursors(old => old.slice(0, -1))}>{t('上一页')}</button><button className="btn" disabled={busy || !data?.has_more} onClick={() => data && setCursors(old => [...old, data.next_cursor])}>{t('下一页')}</button></div>
    </div>
  </div>;
}

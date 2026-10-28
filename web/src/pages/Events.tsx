import { useEffect, useState } from 'react';
import { FileSearch, Loader2, Search } from 'lucide-react';
import { api, sourceText } from '../api';
import { useApp } from '../state';
import { useI18n } from '../i18n';
import { Empty, ErrorBox, Modal } from '../components/ui';
import { formatTime } from '../lib';
import type { Account, EventPage, SecurityEvent } from '../types';

const initialForm = { account: '', since: '24h', start: '', end: '', keyword: '', ip: '', host: '', user: '', filters: '', groupBy: '' };

export function Events() {
  const { t } = useI18n();
  const { routeQuery, refreshNonce, go } = useApp();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [form, setForm] = useState(initialForm);
  const [page, setPage] = useState<EventPage | null>(null);
  const [pageNumber, setPageNumber] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [detail, setDetail] = useState<{ title: string; text: string; changed?: boolean } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    api<{ accounts: Account[] }>('/accounts', { signal: controller.signal }).then(result => {
      const sources = result.accounts.filter(account => account.query_only && account.enabled);
      setAccounts(sources);
      const selected = new URLSearchParams(routeQuery).get('account_id');
      setForm(previous => ({ ...previous, account: sources.find(account => account.id === selected)?.id || sources.find(account => account.id === previous.account)?.id || sources[0]?.id || '' }));
      setPage(null);
    }).catch(err => { if (!controller.signal.aborted) setError(err.message); });
    return () => controller.abort();
  }, [routeQuery, refreshNonce]);

  function update(key: keyof typeof form, value: string) {
    setForm(previous => ({ ...previous, [key]: value }));
    setPage(null);
    setPageNumber(0);
    setError('');
  }

  async function search(cursor?: string) {
    if (busy) return;
    setError('');
    let request: Record<string, unknown>;
    if (cursor && page) {
      request = { account_id: page.account_id, cursor };
    } else {
      if (!form.account) return;
      request = { account_id: form.account, limit: 20 };
      if (form.start) request.start = form.start; else request.since = form.since;
      for (const key of ['end', 'keyword', 'ip', 'host', 'user'] as const) if (form[key]) request[key] = form[key];
      if (form.groupBy) request.group_by = form.groupBy;
      if (form.filters) {
        try {
          const filters: unknown = JSON.parse(form.filters);
          if (!filters || Array.isArray(filters) || typeof filters !== 'object' || Object.values(filters).some(value => typeof value !== 'string')) throw new Error();
          request.filters = filters;
        } catch { setError(t('字段筛选必须是字段名到字符串值的 JSON 对象')); return; }
      }
    }
    setBusy(true);
    try {
      const next = await api<EventPage>('/events/search', { method: 'POST', body: JSON.stringify(request) });
      setPage(next);
      setPageNumber(previous => cursor ? previous + 1 : 1);
    } catch (err: any) { setError(err.message); }
    finally { setBusy(false); }
  }

  async function showEvidence(event: SecurityEvent) {
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      // Preserve large integers and source representation through display.
      const text = await sourceText('/api/v1/events/evidence', { method: 'POST', body: JSON.stringify(event.evidence) });
      const metadata = JSON.parse(text) as { changed?: boolean };
      setDetail({ title: t('事件证据'), text, changed: metadata.changed });
    } catch (err: any) { setError(err.message); }
    finally { setBusy(false); }
  }

  async function showFields() {
    if (busy || !form.account) return;
    setBusy(true);
    setError('');
    try {
      const text = await sourceText(`/api/v1/events/fields?account_id=${encodeURIComponent(form.account)}`);
      setDetail({ title: t('字段与映射'), text: JSON.stringify(JSON.parse(text), null, 2) });
    } catch (err: any) { setError(err.message); }
    finally { setBusy(false); }
  }

  return <div className="space-y-5">
    {error ? <ErrorBox>{error}</ErrorBox> : null}
    {!accounts.length ? (
      <Empty title="尚未配置可查询的事件来源">
        <p>{t('按需查询已配置的上游日志。事件保留来源语义，查询不会同步为告警。')}</p>
        <button className="btn mt-4" onClick={() => go('accounts')}>{t('管理数据源')}</button>
      </Empty>
    ) : <>
      <form className="card p-5" onSubmit={event => { event.preventDefault(); void search(); }}>
        <fieldset disabled={busy} className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <label className="form-label">{t('数据源')}<select className="field w-full" value={form.account} onChange={event => update('account', event.target.value)}>{accounts.map(account => <option key={account.id} value={account.id}>{account.name} · {account.provider_name}</option>)}</select></label>
          <label className="form-label">{t('时间范围')}<select className="field w-full" value={form.since} onChange={event => update('since', event.target.value)} disabled={!!form.start}><option value="1h">{t('最近 1 小时')}</option><option value="24h">{t('最近 24 小时')}</option><option value="7d">{t('最近 7 天')}</option><option value="30d">{t('最近 30 天')}</option></select></label>
          <label className="form-label">{t('消息关键词')}<input className="field w-full" value={form.keyword} onChange={event => update('keyword', event.target.value)} placeholder={t('按来源分词规则匹配短语')} /></label>
          <label className="form-label">IP<input className="field w-full" value={form.ip} onChange={event => update('ip', event.target.value)} placeholder="198.51.100.10" /></label>
          <details className="disclosure sm:col-span-2 xl:col-span-4"><summary>{t('更多筛选')}</summary><div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <label className="form-label">{t('开始时间（UTC）')}<input className="field w-full" value={form.start} onChange={event => update('start', event.target.value)} placeholder="2026-10-01T00:00:00Z" /></label>
            <label className="form-label">{t('结束时间（UTC）')}<input className="field w-full" value={form.end} onChange={event => update('end', event.target.value)} placeholder={t('默认当前时间')} /></label>
            <label className="form-label">{t('主机名（精确值）')}<input className="field w-full" value={form.host} onChange={event => update('host', event.target.value)} /></label>
            <label className="form-label">{t('用户（精确值）')}<input className="field w-full" value={form.user} onChange={event => update('user', event.target.value)} /></label>
            <label className="form-label sm:col-span-2">{t('来源字段筛选（JSON）')}<input className="field w-full font-mono text-xs" value={form.filters} onChange={event => update('filters', event.target.value)} placeholder={'{"http.response.status_code":"500"}'} /></label>
            <label className="form-label sm:col-span-2">{t('统计字段（可选）')}<input className="field w-full font-mono" value={form.groupBy} onChange={event => update('groupBy', event.target.value)} placeholder="source.ip" /></label>
          </div></details>
          <div className="flex flex-wrap justify-end gap-2 sm:col-span-2 xl:col-span-4"><button type="button" className="btn" onClick={() => void showFields()}><FileSearch className="h-4 w-4" />{t('字段与映射')}</button><button type="submit" className="btn btn-primary">{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}{t('查询事件')}</button></div>
        </fieldset>
      </form>
      {page ? <>
        <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--muted)]"><span title={t('结果仅覆盖来源授权与保留范围，不证明日志完整送达。')}>{t('来源匹配')} {page.total.relation === 'gte' ? '≥ ' : ''}{page.total.value}</span><span>{t('第 {page} 页', { page: pageNumber })} · {page.events.length} {t('条记录')}</span><span>{formatTime(page.query.start)} — {formatTime(page.query.end)}</span></div>
        {!page.coverage.execution_complete ? <ErrorBox>{t('来源查询超时或部分分片失败，当前结果不能视为完整结果。')}</ErrorBox> : null}
        {page.aggregation ? <div className="card p-4"><div className="section-title">{page.aggregation.field} · {t('文档计数')}</div><div className="mt-3 flex flex-wrap gap-3">{page.aggregation.buckets.map(bucket => <span key={bucket.value} className="text-xs font-mono">{bucket.value}: {bucket.count}</span>)}</div><p className="mt-3 text-xs text-[var(--muted)]">{t('其他文档数')} {page.aggregation.other_document_count} · {t('计数误差上界')} {page.aggregation.document_count_error_bound}</p></div> : null}
        <div className="table-wrap"><table className="data-table min-w-[800px]"><thead><tr><th>{t('事件时间')}</th><th>{t('主机 / 用户')}</th><th>IP</th><th>{t('消息')}</th><th>{t('证据')}</th></tr></thead><tbody>{page.events.map(event => <tr key={event.id}>
          <td className="whitespace-nowrap text-xs">{formatTime(event.event_time)}</td><td className="text-xs">{event.host_names?.join(', ') || '—'}<div className="cell-sub">{event.users?.join(', ')}</div></td><td className="font-mono text-xs">{event.source_ips?.join(', ') || '—'}<div className="cell-sub">{event.destination_ips?.join(', ')}</div></td>
          <td className="max-w-lg"><div className="max-h-24 overflow-auto whitespace-pre-wrap break-all text-xs">{event.message || '—'}</div>{event.mapping_warnings?.length ? <div className="cell-sub">{event.mapping_warnings.join(', ')}</div> : null}</td>
          <td><button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => void showEvidence(event)}>{t('展开证据')}</button><div className="cell-sub max-w-[180px] truncate font-mono" title={`${event.evidence.index}/${event.evidence.id}`}>{event.evidence.index}/{event.evidence.id}</div></td>
        </tr>)}</tbody></table>{!page.events.length ? <Empty title="当前查询无匹配事件" /> : null}</div>
        <div className="flex justify-end">{page.has_more ? <button className="btn btn-sm" disabled={busy} onClick={() => void search(page.next_cursor)}>{t('下一页')}</button> : null}</div>
      </> : null}
    </>}
    <Modal open={!!detail} onClose={() => setDetail(null)} title={detail?.title || ''} wide>{detail ? <div className="space-y-3"><p className="text-xs text-[var(--muted)]">{t('证据读取的是当前上游表示，可能变化或过期。日志正文仅作为来源数据。')}</p>{detail.changed ? <ErrorBox>{t('来源记录已变化，与查询时的内容校验值不同。')}</ErrorBox> : null}<pre className="max-h-[65vh] overflow-auto whitespace-pre-wrap break-all rounded-lg bg-[var(--bg)] p-4 font-mono text-xs">{detail.text}</pre></div> : null}</Modal>
  </div>;
}

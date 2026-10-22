import { SourceFailure } from "./SourceFailure";
import type { SourceError } from "../types";
import { useEffect, useRef, useState } from 'react';
import { api, jsonBody, sourceText } from '../api';
import { useI18n } from '../i18n';
import { formatTime } from '../lib';
import { VendorFields } from './AlertFields';
import type { Alert } from '../types';
import { ResourceLinks } from './ResourceLinks';
import type { AssetReference } from './ResourceLinks';

export interface Asset {
  id: string; account_id: string; account_uid: string; provider: string; region: string;
  resource_id: string; resource_type: string; name?: string; os?: string; state?: string;
  instance_type?: string; zone?: string; public_ips?: string[] | null; private_ips?: string[] | null;
  vpc_id?: string; subnet_id?: string; security_group_ids?: string[] | null;
  tags?: { key: string; value: string }[] | null; revision: number; observed_at: string;
  last_observed_at: string; synthetic: boolean; provenance: unknown;
  references?: AssetReference[];
  network?: { description?: string; cidr_block?: string; ipv6_cidr_block?: string; mac_address?: string; primary?: boolean; is_default?: boolean; source_created_time?: string };
  components: Record<string, { status: string; reason?: string; source_error?: SourceError; raw_url?: string; raw_hash?: string; source_api?: string; observed_at?: string }>;
}
export interface AssetContext {
  status: string; reason?: string; asset?: Asset; resource_id?: string; refresh_account_id?: string;
  refresh?: { status: string; attempted_at: string; source_error?: SourceError }; refresh_reason?: string; matched_on?: string[]; limitations: string[];
  scope?: { provider: string; account_uid?: string; region?: string; resource_type?: string; resource_id?: string; source_api?: string; api_version?: string };
}

const messages: Record<string, string> = {
  available: '已有本地观测', stale: '本地观测已过期', unavailable: '资产信息不可用',
  provider_not_supported: '该来源尚未接入资产数据',
  no_explicit_primary_host_reference: '告警缺少明确的主机引用',
  resource_scope_incomplete: '资源账号或地域信息不完整',
  resource_identity_ambiguous: '资源身份尚未明确', not_collected: '尚未采集',
  permission_denied: '来源权限不足', authentication_failed: '来源认证失败', access_denied: '来源拒绝访问（原因待确认）', throttled: '来源请求受限', not_found_or_not_visible: '该范围内未查到或无权查看',
  source_request_failed: '来源请求失败', timeout: '来源请求超时', partial: '部分组件未取得',
  cached: '已复用缓存或近期刷新结果', refreshing: '正在刷新', storage_failed: '保存资产失败',
  failed: '读取失败', source_not_connected: '尚未接入该数据源', request_budget_exceeded: '已达到本次查询预算',
  scope_mismatch: '资源不在该连接的配置范围内，未请求云端',
  not_requested: '没有可用的凭据或客户端，未请求云端',
  resource_account_not_connected: '资源所属账号尚未配置连接，无法刷新',
};
const componentLabels: Record<string, string> = { instance: '实例信息', network_interfaces: '网卡信息', software: '软件清单', listening_ports: '监听端口', reachability: '可达性观测' };

export function AssetSummary({ asset }: { asset: Asset }) {
  const { t } = useI18n();
  const list = (values: string[] | null | undefined) => values == null ? t('未知') : values.length ? values.join(', ') : t('无（来源报告）');
  return <>
    {asset.synthetic ? <p className="text-xs text-[var(--muted)]">{t('合成资产数据，未经真实账号验证')}</p> : null}
    <dl className="detail-fields asset-fields">
      <dt>{t('资产')}</dt><dd>{asset.name || asset.resource_id}</dd>
      <dt>ID</dt><dd className="break-all font-mono">{asset.resource_id}</dd>
      <dt>{t('云账号')}</dt><dd>{asset.account_uid}</dd>
      <dt>{t('地域')}</dt><dd>{asset.region} / {asset.zone || '—'}</dd>
      <dt>{t('操作系统')}</dt><dd>{asset.os || t('未知')}</dd>
      <dt>{t('实例规格')}</dt><dd>{asset.instance_type || t('未知')}</dd>
      <dt>{t('厂商状态')}</dt><dd>{asset.state || t('未知')}</dd>
      <dt>{t('公网 IP')}</dt><dd>{list(asset.public_ips)}</dd>
      <dt>{t('私网 IP')}</dt><dd>{list(asset.private_ips)}</dd>
      <dt>VPC / {t('子网')}</dt><dd>{asset.vpc_id || '—'} / {asset.subnet_id || '—'}</dd>
      <dt>{t('安全组')}</dt><dd>{list(asset.security_group_ids)}</dd>
      <dt>{t('标签')}</dt><dd>{list(asset.tags?.map(tag => `${tag.key}=${tag.value}`))}</dd>
      <dt>{t('最近确认时间')}</dt><dd>{formatTime(asset.last_observed_at)}</dd>
      <dt>{t('修订')}</dt><dd>{asset.revision}</dd>
    </dl>
    <p className="text-xs text-[var(--muted)]">{t('当前资产观测不代表告警发生时的状态。安全组规则不等于监听或可达端口。')}</p>
  </>;
}

export function AssetContextPanel({ detail, isAdmin }: { detail: Alert; isAdmin: boolean }) {
  const { t } = useI18n();
  const [value, setValue] = useState<AssetContext | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [evidence, setEvidence] = useState<Record<string, string>>({});
  const [related, setRelated] = useState<{ alerts: Alert[]; has_more: boolean; next_cursor: string; snapshot_sequence: number } | null>(null);
  const [members, setMembers] = useState<Alert[]>([]);
  const controller = useRef<AbortController | null>(null);
  const path = `/alerts/${encodeURIComponent(detail.id)}/asset-context?revision=${detail.revision}`;
  useEffect(() => {
    const current = new AbortController(); controller.current = current;
    api<AssetContext>(path, { signal: current.signal }).then(setValue).catch(err => { if (!current.signal.aborted) setError(err.message); });
    return () => current.abort();
  }, [path]);
  const options = () => ({ signal: controller.current?.signal });
  async function refresh() {
    if (!value?.resource_id || !value.refresh_account_id) return;
    setBusy(true); setError('');
    try {
      const result = await api<{ status: string }>(`/accounts/${encodeURIComponent(value.refresh_account_id)}/assets/refresh`, { ...options(), method: 'POST', body: jsonBody({ resource_id: value.resource_id }) });
      setNotice(result.status); setValue(await api<AssetContext>(path, options())); setEvidence({});
    } catch (err) { if (!controller.current?.signal.aborted) setError((err as Error).message); }
    finally { if (!controller.current?.signal.aborted) setBusy(false); }
  }
  async function readEvidence(key: string, rawURL: string) {
    try { const text = await sourceText(rawURL, options()); setEvidence(old => ({ ...old, [key]: text })); }
    catch (err) { if (!controller.current?.signal.aborted) setError((err as Error).message); }
  }
  async function findRelated() {
    if (!value?.asset) return;
    try {
      const params = new URLSearchParams({ limit: '20' });
      if (related) { params.set('after_id', related.next_cursor); params.set('snapshot_sequence', String(related.snapshot_sequence)); }
      const result = await api<NonNullable<typeof related>>(`/assets/${encodeURIComponent(value.asset.id)}/findings?${params}`, options());
      setMembers(old => [...old, ...result.alerts]); setRelated(result);
    } catch (err) { if (!controller.current?.signal.aborted) setError((err as Error).message); }
  }
  return <section className="space-y-3 rounded border border-[var(--line)] p-4">
    <h3 className="section-title">{t('资产上下文')}</h3>
    {error ? <p role="alert" className="text-xs">{t(error)}</p> : null}
    <p className="text-xs text-[var(--muted)]">{value ? t(messages[value.reason || value.status] || value.reason || value.status) : t('加载中…')}</p>
    {value?.asset ? <>
      <AssetSummary asset={value.asset} />
      <ResourceLinks references={value.asset.references || []} isAdmin={isAdmin} />
      {Object.entries(value.asset.components).map(([key, component]) => <details className="disclosure" key={key}>
        <summary className="break-all">{key.startsWith('security_group:') ? `${t('安全组策略')} · ${key.slice('security_group:'.length)}` : t(componentLabels[key] || key)} · {t(messages[component.status] || component.status)}</summary>
        {component.reason ? <p className="text-xs">{t(messages[component.reason] || component.reason)}</p> : null}
        <SourceFailure value={component.source_error} />
        {component.source_api ? <p className="text-xs text-[var(--muted)]">{component.source_api}</p> : null}
        {component.raw_url ? <>
          <p className="text-xs">{formatTime(component.observed_at)} · SHA-256: <span className="break-all font-mono">{component.raw_hash}</span></p>
          <button className="btn btn-sm mt-2" onClick={() => readEvidence(key, component.raw_url!)}>{t('读取原始证据')}</button>
          {evidence[key] ? <pre className="code mt-2">{evidence[key]}</pre> : null}
        </> : null}
      </details>)}
      <details className="disclosure"><summary>{t('数据溯源')}</summary><VendorFields value={value.asset.provenance} /></details>
      {!related || related.has_more ? <button className="btn btn-sm" onClick={findRelated}>{t(related ? '加载更多' : '查询同一资源的告警')}</button> : null}
      {related ? <p className="text-xs">{t('仅查询本地已保存告警，按完整资源身份匹配。')}</p> : null}
      {members.map(item => <a className="block break-all text-xs underline" key={item.id} href={`#/alerts?alert=${encodeURIComponent(item.id)}`}>{item.title} · {item.external_id}</a>)}
    </> : null}
    {value?.refresh ? <p className="text-xs text-[var(--muted)]">{t('最近刷新')}：{t(messages[value.refresh.status] || value.refresh.status)} · {formatTime(value.refresh.attempted_at)}</p> : null}
    {value?.refresh_reason ? <p className="text-xs text-[var(--muted)]">{t(messages[value.refresh_reason] || value.refresh_reason)}</p> : null}
    {value?.scope && !value.asset ? <p className="text-xs text-[var(--muted)]">{t('尝试范围')}：{[value.scope.provider, value.scope.region || t('未限定地域'), value.scope.resource_type, value.scope.resource_id, value.scope.source_api].filter(Boolean).join(' · ')}</p> : null}
    <SourceFailure value={value?.refresh?.source_error} />
    {notice ? <p role="status" className="text-xs">{t(messages[notice] || notice)}</p> : null}
    {isAdmin && value?.refresh_account_id && value.resource_id ? <>
      <button className="btn btn-sm" disabled={busy} onClick={refresh}>{t(busy ? '加载中…' : '从云端刷新资产')}</button>
      <p className="text-xs text-[var(--muted)]">{t('显式刷新最多请求 10 次云 API，超时 15 秒，5 分钟内复用结果；需配置真实账号 UID 和地域。')}</p>
    </> : null}
  </section>;
}

import { SourceFailure } from "./SourceFailure";
import type { SourceError } from "../types";
import { useEffect, useRef, useState } from 'react';
import { api, jsonBody, sourceText } from '../api';
import { useI18n } from '../i18n';
import { formatTime } from '../lib';
import { VendorFields } from './AlertFields';
import type { Asset } from './AssetContext';

export interface AssetReference {
  provider: string; account_id: string; account_uid: string; region: string;
  resource_type: string; resource_id: string; relation: string;
  source_component: string; source_path: string; lookup_url?: string;
}
interface Lookup { status: string; asset?: Asset; refresh?: { status: string; attempted_at: string; source_error?: SourceError } }
const resourceLabels: Record<string, string> = { vpc: 'VPC', subnet: '子网', security_group: '安全组', nic: '网卡', cvm: '云主机', ecs: '云主机', ec2: '云主机', gce: '云主机', vm: '云主机' };
const statusLabels: Record<string, string> = { available: '已有本地观测', stale: '本地观测已过期', not_collected: '尚未采集', partial: '部分组件未取得', permission_denied: '来源权限不足', authentication_failed: '来源认证失败', access_denied: '来源拒绝访问（原因待确认）', throttled: '来源请求受限', timeout: '来源请求超时', source_request_failed: '来源请求失败', not_found_or_not_visible: '该范围内未查到或无权查看', storage_failed: '保存资产失败', cached: '已复用缓存或近期刷新结果', refreshing: '正在刷新' };

export function resourceLookupPath(ref: AssetReference): string {
  return `/assets/lookup?${new URLSearchParams({ provider: ref.provider, account_id: ref.account_id, account_uid: ref.account_uid, region: ref.region, resource_type: ref.resource_type, resource_id: ref.resource_id })}`;
}

export function NetworkSummary({ asset }: { asset: Asset }) {
  const { t } = useI18n();
  return <>
    {asset.synthetic ? <p className="text-xs text-[var(--muted)]">{t('合成资产数据，未经真实账号验证')}</p> : null}
    <dl className="detail-fields asset-fields">
      <dt>{t('名称')}</dt><dd>{asset.name || t('未知')}</dd>
      <dt>ID</dt><dd>{asset.resource_id}</dd>
      <dt>{t('云账号')}</dt><dd>{asset.account_uid}</dd>
      <dt>{t('地域')}</dt><dd>{asset.region}</dd>
      {asset.resource_type === 'vpc' || asset.resource_type === 'subnet' ? <>
        <dt>CIDR</dt><dd>{asset.network?.cidr_block || t('未知')}</dd>
        <dt>IPv6 CIDR</dt><dd>{asset.network?.ipv6_cidr_block || t('未知')}</dd>
      </> : null}
      {asset.resource_type === 'security_group' ? <><dt>{t('说明')}</dt><dd>{asset.network?.description || t('未知')}</dd></> : null}
      {asset.resource_type === 'subnet' ? <><dt>VPC</dt><dd>{asset.vpc_id || t('未知')}</dd><dt>{t('可用区')}</dt><dd>{asset.zone || t('未知')}</dd></> : null}
      {asset.resource_type === 'nic' ? <>
        <dt>VPC</dt><dd>{asset.vpc_id || t('未知')}</dd>
        <dt>{t('子网')}</dt><dd>{asset.subnet_id || t('未知')}</dd>
        <dt>{t('私网 IP')}</dt><dd>{asset.private_ips?.length ? asset.private_ips.join(', ') : t('未知')}</dd>
        <dt>{t('公网 IP')}</dt><dd>{asset.public_ips?.length ? asset.public_ips.join(', ') : t('来源未提供')}</dd>
        <dt>{t('安全组')}</dt><dd>{asset.security_group_ids?.length ? asset.security_group_ids.join(', ') : t('未知')}</dd>
        <dt>MAC</dt><dd>{asset.network?.mac_address || t('未知')}</dd>
        <dt>{t('主网卡')}</dt><dd>{asset.network?.primary === undefined ? t('未知') : t(asset.network.primary ? '是' : '否')}</dd>
      </> : null}
      {asset.resource_type === 'vpc' || asset.resource_type === 'subnet' ? <><dt>{t('默认资源')}</dt><dd>{asset.network?.is_default === undefined ? t('未知') : t(asset.network.is_default ? '是' : '否')}</dd></> : null}
      <dt>{t('标签')}</dt><dd>{asset.tags == null ? t('未知') : asset.tags.length ? asset.tags.map(tag => `${tag.key}=${tag.value}`).join(', ') : t('无（来源报告）')}</dd>
      <dt>{t('厂商创建时间原值')}</dt><dd>{asset.network?.source_created_time || t('未知')}</dd>
      <dt>{t('最近确认时间')}</dt><dd>{formatTime(asset.last_observed_at)}</dd>
      <dt>{t('修订')}</dt><dd>{asset.revision}</dd>
    </dl>
  </>;
}

export function ResourceLinks({ references, isAdmin, depth = 0 }: { references: AssetReference[]; isAdmin: boolean; depth?: number }) {
  const { t } = useI18n();
  if (!references.length || depth > 1) return null;
  return <section className="space-y-2">
    <h4 className="text-xs font-medium">{t('关联网络资源')}</h4>
    {references.map(ref => <ResourceDetail key={`${ref.provider}:${ref.account_uid}:${ref.region}:${ref.resource_type}:${ref.resource_id}`} reference={ref} isAdmin={isAdmin} depth={depth} />)}
  </section>;
}

function ResourceDetail({ reference, isAdmin, depth }: { reference: AssetReference; isAdmin: boolean; depth: number }) {
  const { t } = useI18n();
  const [value, setValue] = useState<Lookup | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [evidence, setEvidence] = useState<Record<string, string>>({});
  const controller = useRef<AbortController | null>(null);
  useEffect(() => { const c = new AbortController(); controller.current = c; return () => c.abort(); }, []);
  const options = () => ({ signal: controller.current?.signal });
  async function load() {
    setBusy(true); setError('');
    try { setValue(await api<Lookup>(resourceLookupPath(reference), options())); }
    catch (err) { if (!controller.current?.signal.aborted) setError((err as Error).message); }
    finally { if (!controller.current?.signal.aborted) setBusy(false); }
  }
  async function refresh() {
    setBusy(true); setError('');
    try {
      const result = await api<{ status: string }>(`/accounts/${encodeURIComponent(reference.account_id)}/assets/refresh`, { ...options(), method: 'POST', body: jsonBody({ resource_type: reference.resource_type, resource_id: reference.resource_id }) });
      setNotice(result.status); setEvidence({}); setValue(await api<Lookup>(resourceLookupPath(reference), options()));
    } catch (err) { if (!controller.current?.signal.aborted) setError((err as Error).message); }
    finally { if (!controller.current?.signal.aborted) setBusy(false); }
  }
  async function readEvidence(key: string, url: string) {
    try { const text = await sourceText(url, options()); setEvidence(old => ({ ...old, [key]: text })); }
    catch (err) { if (!controller.current?.signal.aborted) setError((err as Error).message); }
  }
  return <details className="disclosure" onToggle={event => { if (event.currentTarget.open && !value && !busy) void load(); }}>
    <summary className="break-all">{t(resourceLabels[reference.resource_type] || reference.resource_type)} · {reference.resource_id}</summary>
    <div className="mt-3 space-y-3">
      {error ? <p role="alert" className="text-xs">{t(error)}</p> : null}
      {busy ? <p className="text-xs">{t('加载中…')}</p> : null}
      {value ? <p className="text-xs text-[var(--muted)]">{t(statusLabels[value.status] || value.status)}</p> : null}
      {value?.asset ? <>
        <NetworkSummary asset={value.asset} />
        {Object.entries(value.asset.components).map(([key, component]) => <details className="disclosure" key={key}>
          <summary>{t(key === 'policies' ? '安全组策略' : '资源详情')} · {component.source_api}</summary>
          <p className="text-xs">{t(statusLabels[component.status] || component.status)} {component.reason || ''} · {formatTime(component.observed_at)}</p>
          <SourceFailure value={component.source_error} />
          {component.raw_url ? <><button className="btn btn-sm" onClick={() => readEvidence(key, component.raw_url!)}>{t('读取原始证据')}</button>
            {evidence[key] ? <pre className="code mt-2">{evidence[key]}</pre> : null}</> : null}
        </details>)}
        <details className="disclosure"><summary>{t('数据溯源')}</summary><VendorFields value={value.asset.provenance} /></details>
        <ResourceLinks references={value.asset.references || []} isAdmin={isAdmin} depth={depth + 1} />
      </> : null}
      {value?.refresh ? <p className="text-xs">{t('最近刷新')}：{t(statusLabels[value.refresh.status] || value.refresh.status)} · {formatTime(value.refresh.attempted_at)}</p> : null}
      <p className="break-all text-xs text-[var(--muted)]">{t('引用来源')}：{reference.source_component}{reference.source_path}</p>
      <SourceFailure value={value?.refresh?.source_error} />
    {notice ? <p role="status" className="text-xs">{t(statusLabels[notice] || notice)}</p> : null}
      {isAdmin ? <><button className="btn btn-sm" disabled={busy} onClick={refresh}>{t('刷新此网络资源')}</button>
        <p className="text-xs text-[var(--muted)]">{t('显式刷新单个网络资源最多请求 2 次云 API，5 分钟内复用结果。')}</p></> : null}
    </div>
  </details>;
}

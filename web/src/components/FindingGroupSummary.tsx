import { useState } from 'react';
import { sourceText } from '../api';
import { useI18n } from '../i18n';
import { fmtNum, formatTime } from '../lib';
import type { AlertGroup, AlertGroupList } from '../types';
import { ResourceLinks } from './ResourceLinks';

export function relationEvidencePath(edge: NonNullable<AlertGroup['relation_evidence']>[number]) {
  return `/api/v1/assets/${encodeURIComponent(edge.source_asset_id)}/revisions/${edge.source_revision}/components/${encodeURIComponent(edge.reference.source_component)}/raw`;
}

export function FindingGroupSummary({ group, isAdmin, onMembers }: {
  group: AlertGroup; isAdmin: boolean; onMembers: (title?: string) => void;
}) {
  const { t } = useI18n();
  const [evidence,setEvidence]=useState<Record<string,string>>({});
  const [error,setError]=useState('');
  async function readRelation(index:number) {
    const edge=group.relation_evidence?.[index];if(!edge)return;
    try { const path=relationEvidencePath(edge);const text=await sourceText(path);setEvidence(old=>({...old,[path]:text})); }
    catch(err){setError((err as Error).message)}
  }
  return <div className="space-y-4 py-3">
    <p className="text-xs text-[var(--muted)]">{t('当前资产观测，不代表告警发生时配置。网络关系不表示流量路径或规则放行。')}</p>
    <div className="grid gap-4 md:grid-cols-2">
      <section className="space-y-2">
        <h4 className="text-xs font-medium">{t('厂商告警名称分布（最多 5 项）')}</h4>
        {(group.top_titles || []).map(item => <button key={item.key} className="flex w-full items-start justify-between gap-4 text-left text-sm hover:text-[var(--accent)]" onClick={() => onMembers(item.key)}>
          <span className="break-words">{item.key}</span><span className="tabular-nums">{fmtNum(item.count)}</span>
        </button>)}
        <button className="btn btn-sm" onClick={() => onMembers()}>{t('查看全部成员')}</button>
      </section>
      <section className="space-y-3">
        <h4 className="text-xs font-medium">{t('资产观测摘要（最多 5 台）')}</h4>
        {!(group.assets || []).length ? <p className="text-xs text-[var(--muted)]">{t('没有匹配的已保存资产观测；可在告警详情查看缺失原因或显式刷新。')}</p> : null}
        {(group.assets || []).map(asset => <div key={asset.id} className="space-y-2 border-t border-[var(--line)] pt-2 text-xs">
          {asset.synthetic ? <p className="text-[var(--muted)]">{t('合成资产数据，未经真实账号验证')}</p> : null}
          <p className="break-all font-medium">{asset.name || asset.resource_id} · {asset.resource_id}</p>
          <p className="text-[var(--muted)]">{t('观测时间')}：{formatTime(asset.observed_at)} · {t('修订')} {asset.revision}</p>
          <ResourceLinks references={asset.references || []} isAdmin={isAdmin} />
        </div>)}
      </section>
    </div>
    {group.relation_evidence?.length ? <details className="disclosure">
      <summary>{t('关系依据（最多 5 项）')}</summary>
      {error ? <p role="alert">{error}</p> : null}
      {group.relation_evidence.map((edge,index)=><div className="space-y-2 border-t border-[var(--line)] py-2 text-xs" key={`${edge.source_asset_id}:${edge.reference.source_path}`}>
        <p className="break-all">{edge.reference.resource_id} · {edge.reference.relation}</p>
        <p className="break-all">{t('引用来源')}：{edge.source_asset_id} · {t('修订')} {edge.source_revision} · {edge.reference.source_component}{edge.reference.source_path}</p>
        <button className="btn btn-sm" onClick={()=>readRelation(index)}>{t('读取原始证据')}</button>
        {evidence[relationEvidencePath(edge)] ? <pre className="code max-h-[420px] overflow-auto">{evidence[relationEvidencePath(edge)]}</pre> : null}
      </div>)}
    </details> : null}
  </div>;
}

export function GroupingCoverage({ summary }: { summary: NonNullable<AlertGroupList['summary']> }) {
  const { t } = useI18n();
  return <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-[var(--muted)]" role="status">
    <span>{t('独立告警')} {fmtNum(summary.finding_count)}</span>
    <span>{t('已关联资产观测')} {fmtNum(summary.asset_context_finding_count)}</span>
    <span>{t('缺少分组依据')} {fmtNum(summary.ungrouped_finding_count)}</span>
    <span>{t('分组成员合计（可重复）')} {fmtNum(summary.membership_count)}</span>
    <p className="w-full">{t('仅使用已保存的明确资源引用；同一告警可能属于多个安全组或网卡视角，各组数量不可直接相加。')}</p>
  </div>;
}

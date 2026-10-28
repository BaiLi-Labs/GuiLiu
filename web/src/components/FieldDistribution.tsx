import { useI18n } from '../i18n';
import { fmtNum } from '../lib';
import type { FieldDistribution as Distribution } from '../types';

// Exact value counts; a constant field is not assigned a quality verdict.
export function FieldDistribution({label, distribution}: {label:string;distribution?:Distribution}) {
  const { t } = useI18n();
  if (!distribution) return null;
  return <details className="card p-5">
    <summary className="cursor-pointer">
      <span className="section-title">{t(label)}</span>
    </summary>
    <div className="mt-3 flex flex-wrap gap-x-4 text-xs text-[var(--muted)]">
      <span>{t('不同值')} {fmtNum(distribution.distinct_count)}</span>
      <span>{t('字段缺失')} {fmtNum(distribution.missing_count)}</span>
    </div>
    <table className="data-table mt-3">
      <thead><tr><th>{t('字段值')}</th><th title={t('按来源字段原值计数，不代表对象身份或安全结论。')}>{t('告警记录数')}</th></tr></thead>
      <tbody>{distribution.top.map(item=><tr key={`${item.key}\u0000${item.severity || ''}`}><td className="break-all">{item.key}{item.severity ? ` · ${item.severity}` : ''}</td><td className="tabular-nums">{fmtNum(item.count)}</td></tr>)}</tbody>
    </table>
    {distribution.has_more ? <p className="mt-3 text-xs text-[var(--muted)]">{t('未展示值对应的记录数')} {fmtNum(distribution.other_count)}</p> : null}
  </details>;
}

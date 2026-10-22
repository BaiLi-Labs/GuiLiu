import type { SourceError } from '../types';
import { useI18n } from '../i18n';

const reasons: Record<string, string> = {
  auth: '来源认证失败，请检查密钥、令牌及签名配置。',
  permission: '来源未授权本次查询，请检查该接口在当前资源范围内的只读授权。',
  access_denied: '来源拒绝本次访问，请按错误码核对权限、服务开通或账号状态。',
  throttled: '来源请求达到频率或配额限制。',
  not_found: '该范围内未查到或无权查看',
  transient: '来源暂时不可用或请求超时。',
  permanent: '来源请求失败',
};

export function sourceFailureReason(kind: string): string {
  return reasons[kind] || '来源请求失败';
}

export function SourceFailure({ value }: { value?: SourceError }) {
  const { t } = useI18n();
  if (!value) return null;
  return <div role="status" className="space-y-1 break-words text-xs text-[var(--danger)]">
    <p>{t(sourceFailureReason(value.kind))}</p>
    <p className="break-all font-mono">{[value.source_api, value.code, value.http_status ? `HTTP ${value.http_status}` : ''].filter(Boolean).join(' · ')}</p>
  </div>;
}

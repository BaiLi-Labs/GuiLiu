import { useEffect, useState } from 'react';
import type { Account, AlertGroup, AlertStatus, Page, Severity } from './types';
import { getLocale, t } from './i18n';

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  fatal: '致命',
  high: '高危',
  medium: '中危',
  low: '低危',
  informational: '提示',
  unknown: '未知',
};

export const SEVERITY_ORDER: Severity[] = [
  'critical',
  'fatal',
  'high',
  'medium',
  'low',
  'informational',
  'unknown',
];

export const STATUS_LABEL: Record<AlertStatus, string> = {
  open: '待处理',
  acknowledged: '已确认',
  suppressed: '已抑制',
  closed: '已关闭',
};

export const PROVIDER_SHORT: Record<string, string> = {
  elasticsearch: 'Elasticsearch',
  tencent: 'Tencent',
  aliyun: 'Alibaba',
  huawei: 'Huawei',
  aws: 'AWS',
  gcp: 'Google Cloud',
  azure: 'Microsoft Azure',
};

export const PROVIDER_LABEL: Record<string, string> = {
  elasticsearch: 'Elasticsearch',
  tencent: 'Tencent Cloud',
  aliyun: 'Alibaba Cloud',
  huawei: 'Huawei Cloud',
  aws: 'AWS',
  gcp: 'Google Cloud',
  azure: 'Microsoft Azure',
};

export function providerShort(id: string): string {
  return PROVIDER_SHORT[id] || id;
}

export function formatTime(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(getLocale(), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatDate(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(getLocale(), {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export function relTime(value?: string): string {
  if (!value) return '—';
  const diff = new Date(value).getTime() - Date.now();
  if (!Number.isFinite(diff)) return '—';
  const formatter = new Intl.RelativeTimeFormat(getLocale(), { numeric: 'auto' });
  const absolute = Math.abs(diff);
  if (absolute < 60_000) return formatter.format(0, 'second');
  const unit = absolute < 3600_000 ? 'minute' : absolute < 86400_000 ? 'hour' : 'day';
  const divisor = unit === 'minute' ? 60_000 : unit === 'hour' ? 3600_000 : 86400_000;
  return formatter.format(Math.round(diff / divisor), unit);
}

export function fmtNum(value?: number): string {
  return Number(value || 0).toLocaleString(getLocale());
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function cx(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

export function rangeStart(range: string, end = new Date().toISOString()): string | undefined {
  if (!range || range === 'all') return undefined;
  const hours: Record<string, number> = { '10m': 10 / 60, '1h': 1, '24h': 24, '7d': 24 * 7, '30d': 24 * 30 };
  const h = hours[range];
  if (!h) return undefined;
  return new Date(new Date(end).getTime() - h * 3600_000).toISOString();
}

export const RANGE_OPTIONS = [
  { value: '10m', label: '最近 10 分钟' },
  { value: '1h', label: '最近 1 小时' },
  { value: '24h', label: '最近 24 小时' },
  { value: '7d', label: '最近 7 天' },
  { value: '30d', label: '最近 30 天' },
  { value: 'all', label: '全部时间' },
];

export type RouteParams = Record<string, string>;

export function parseHashPage(hash: string): Page {
  const raw = hash.replace(/^#\/?/, '').split(/[/?]/)[0];
  const pages: Page[] = ['overview', 'alerts', 'events', 'accounts', 'health', 'mcp', 'audit'];
  return pages.includes(raw as Page) ? (raw as Page) : 'overview';
}

export function useHashPage(): [Page, (page: Page, params?: RouteParams) => void, string] {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  const go = (next: Page, params: RouteParams = {}) => {
    const search = new URLSearchParams(Object.entries(params).filter(([, value]) => value !== '')).toString();
    const nextHash = `#/${next}${search ? `?${search}` : ''}`;
    window.location.hash = nextHash;
    setHash(nextHash);
  };
  return [parseHashPage(hash), go, hash.split('?')[1] || ''];
}

// One status definition for account lists, overview, and ingestion details.
export function accountStatus(account: Account): string {
  if (!account.enabled) return '已停用';
  if (account.query_only) return '按需查询';
  const state = account.sync_state;
  if (account.push_only) {
    const pushLabels = {
      healthy: '接收正常', failed: '接收失败', pending: '等待推送',
      never_synced: '等待推送', stale: '近期无推送', partial: '部分记录失败',
    };
    return state?.status ? pushLabels[state.status] : state?.last_success_at ? '接收正常' : '等待推送';
  }
  if (state?.status) {
    const labels = {
      healthy: '已同步', failed: '同步失败', pending: '续传中',
      never_synced: '等待首次同步', stale: '同步延迟', partial: '部分失败',
    };
    return labels[state.status];
  }
  if ((state?.consecutive_failures || 0) > 0) return '同步失败';
  if (state?.pending) return '续传中';
  return state?.last_success_at ? '已同步' : '等待首次同步';
}

export function groupTitle(
  group: Pick<AlertGroup, 'key' | 'group_by' | 'resource_name' | 'resource_id' | 'source_ip' | 'alert_type' | 'title'>,
): string {
  if (group.title) return group.title;
    if (group.key.singleton) return `${t('未归并告警')} · ${group.resource_name || group.resource_id || group.alert_type || t('未知类型')}`;
  if (group.group_by === 'asset') return group.resource_name || group.resource_id || t('未命名资产');
  if (group.group_by === 'source')
    return `${group.source_ip || t('未知来源')} · ${group.alert_type || t('未知类型')}`;
  return [group.resource_name || group.resource_id || group.source_ip || t('未命名资产'), group.alert_type]
    .filter(Boolean)
    .join(' · ');
}

export type ThemeMode = 'auto' | 'light' | 'dark';
const THEME_KEY = 'guiliu_theme';

export function useTheme() {
  const [mode, setMode] = useState<ThemeMode>(() => {
    let saved: string | null = null;
    try {
      saved = localStorage.getItem(THEME_KEY);
    } catch {
      /* storage unavailable */
    }
    return saved === 'light' || saved === 'dark' || saved === 'auto' ? saved : 'auto';
  });

  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: light)');
    const apply = () => {
      const light = mode === 'light' || (mode === 'auto' && query.matches);
      const actual = light ? 'light' : 'dark';
      const root = document.documentElement;
      root.setAttribute('data-theme', actual);
      root.style.colorScheme = actual;
      const meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', light ? '#f4f7fb' : '#080b11');
    };
    apply();
    if (mode !== 'auto') return;
    query.addEventListener?.('change', apply);
    return () => query.removeEventListener?.('change', apply);
  }, [mode]);

  const update = (next: ThemeMode) => {
    setMode(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* use in-memory preference */
    }
  };
  return { mode, setMode: update };
}

export function isAdmin(role?: string, devMode?: boolean): boolean {
  return !!devMode || role === 'admin';
}

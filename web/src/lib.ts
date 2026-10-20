import { useEffect, useState } from 'react';
import type { AlertStatus, Page, Severity } from './types';

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  fatal: '致命',
  high: '高危',
  medium: '中危',
  low: '低危',
  informational: '提示',
  unknown: '未知',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'fatal', 'high', 'medium', 'low', 'informational', 'unknown'];

export const STATUS_LABEL: Record<AlertStatus, string> = {
  open: '待处理',
  acknowledged: '已确认',
  suppressed: '已抑制',
  closed: '已关闭',
};

export const PROVIDER_SHORT: Record<string, string> = {
  tencent: 'Tencent',
  aliyun: 'Alibaba',
  huawei: 'Huawei',
  aws: 'AWS',
  gcp: 'Google Cloud',
};

export const PROVIDER_LABEL: Record<string, string> = {
  tencent: 'Tencent Cloud',
  aliyun: 'Alibaba Cloud',
  huawei: 'Huawei Cloud',
  aws: 'AWS',
  gcp: 'Google Cloud',
};

export function providerShort(id: string): string {
  return PROVIDER_SHORT[id] || id;
}

export function formatTime(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('zh-CN', {
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
  return d.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export function relTime(value?: string): string {
  if (!value) return '—';
  const diff = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(diff) || diff < 0) return formatDate(value);
  const min = Math.floor(diff / 60000);
  if (min < 1) return '刚刚';
  if (min < 60) return `${min} 分钟前`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} 小时前`;
  return `${Math.floor(h / 24)} 天前`;
}

export function fmtNum(value?: number): string {
  return Number(value || 0).toLocaleString('zh-CN');
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function cx(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

export function rangeStart(range: string): string | undefined {
  if (!range || range === 'all') return undefined;
  const hours: Record<string, number> = { '10m': 10 / 60, '1h': 1, '24h': 24, '7d': 24 * 7, '30d': 24 * 30 };
  const h = hours[range];
  if (!h) return undefined;
  return new Date(Date.now() - h * 3600_000).toISOString();
}

export const RANGE_OPTIONS = [
  { value: '10m', label: '最近 10 分钟' },
  { value: '1h', label: '最近 1 小时' },
  { value: '24h', label: '最近 24 小时' },
  { value: '7d', label: '最近 7 天' },
  { value: '30d', label: '最近 30 天' },
  { value: 'all', label: '全部时间' },
];

export function parseHashPage(hash: string): Page {
  const raw = hash.replace(/^#\/?/, '').split('/')[0];
  const pages: Page[] = ['overview', 'alerts', 'accounts', 'health', 'mcp'];
  return pages.includes(raw as Page) ? (raw as Page) : 'overview';
}

export function useHashPage(): [Page, (page: Page) => void] {
  const [page, setPage] = useState<Page>(() => parseHashPage(window.location.hash));
  useEffect(() => {
    const onChange = () => setPage(parseHashPage(window.location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  const go = (next: Page) => {
    window.location.hash = `#/${next}`;
    setPage(next);
  };
  return [page, go];
}

export type ThemeMode = 'auto' | 'light' | 'dark';
const THEME_KEY = 'guiliu_theme';

export function useTheme() {
  const [mode, setMode] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem(THEME_KEY);
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
    localStorage.setItem(THEME_KEY, next);
  };
  return { mode, setMode: update };
}

export function isAdmin(role?: string, devMode?: boolean): boolean {
  return !!devMode || role === 'admin';
}

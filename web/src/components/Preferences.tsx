import { Globe2, Moon, Sun, Monitor } from 'lucide-react';
import { useI18n, type Locale } from '../i18n';
import { useTheme, type ThemeMode } from '../lib';

export function Preferences() {
  const { locale, setLocale, t } = useI18n();
  const { mode, setMode } = useTheme();
  const Icon = mode === 'dark' ? Moon : mode === 'light' ? Sun : Monitor;
  return (
    <div className="flex items-center gap-2">
      <label className="preference-control">
        <Globe2 className="h-3.5 w-3.5" aria-hidden="true" />
        <select
          aria-label={t('语言')}
          value={locale}
          onChange={(event) => setLocale(event.target.value as Locale)}
        >
          <option value="zh-CN">简体中文</option>
          <option value="en-US">English</option>
        </select>
      </label>
      <label className="preference-control">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        <select
          aria-label={t('外观')}
          value={mode}
          onChange={(event) => setMode(event.target.value as ThemeMode)}
        >
          <option value="auto">{t('跟随系统')}</option>
          <option value="light">{t('浅色')}</option>
          <option value="dark">{t('深色')}</option>
        </select>
      </label>
    </div>
  );
}

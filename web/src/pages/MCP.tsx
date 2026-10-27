import { useEffect, useState } from 'react';
import { Loader2, Plus, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { CopyButton, Empty, ErrorBox } from '../components/ui';
import { formatDate } from '../lib';
import type { APIKey } from '../types';

const TOOLS = [
 ['search_events', '按需查询上游事件，返回统一字段、证据引用和查询范围'],
 ['get_event_fields', '读取上游字段类型及当前映射'],
 ['get_event_evidence', '展开当前上游事件证据并比较内容校验值'],
 ['get_asset_by_reference', '按来源账号、地域、类型和原生 ID 查询关联网络资源'],
 ['list_assets', '查询本地已保存资产，不访问云端'],
 ['get_asset', '读取资产基础信息、组件状态与精确修订'],
 ['get_alert_asset_context', '按完整资源身份取得告警的当前资产上下文'],
 ['list_asset_findings', '查询同一明确资源身份的已保存告警'],
 ['get_asset_component', '按修订读取资产组件的精确原始证据'],
 ['list_alert_changes', '按持久序号读取新增与变化，支持断点续读'],
 ['get_data_coverage', '查询来源范围、历史起点、同步水位与完整性限制'],
 ['get_alert_revisions', '分页读取全部修订与对应原始证据'],
 ['get_provider_mapping', '读取版本化字段映射与来源路径'],
  ['list_cloud_accounts', '列出云账号与同步健康状态（不含凭据）'],
  ['list_alerts', '按云厂商、等级、状态、资产、关键词查询归一化告警'],
  ['list_alert_groups', '按字段精确分组，返回告警条数、组内最高等级与时间范围'],
  ['get_alert_group', '展开一个分组的原始告警成员'],
  ['get_alert', '获取单条告警的完整 OCSF 与原始厂商 JSON'],
  ['get_alert_evidence', '获取证据、可观测对象与原始载荷'],
  ['search_alerts_by_ip', '按源/目标 IP 检索（默认最近 7 天）'],
  ['search_alerts_by_asset', '按资产 ID 或名称检索（默认最近 7 天）'],
  ['get_alert_statistics', '按等级、厂商、状态、日期、资产聚合统计'],
  ['get_connector_health', '查看游标、最近成功、错误与同步运行'],
];

export function MCP() {
  const { me, meta, toast } = useApp();
  const { t } = useI18n();
  const dev = !!me?.dev_mode;
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [newKey, setNewKey] = useState<{ id: string; token: string } | null>(null);
  const [name, setName] = useState('');
  const [expiry, setExpiry] = useState('90');
  const [transport, setTransport] = useState('http');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(!dev);
  const [error, setError] = useState('');
  async function loadKeys() {
    if (dev) return;
    try {
      const result = await api<{ keys: APIKey[] | null }>('/auth/keys');
      setKeys(result.keys || []);
    } catch (err: any) {
      setError(err.message || '加载 API Key 失败');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void loadKeys();
  }, [dev]);
  const endpoint = `${window.location.origin}/mcp`;
  const token = newKey?.token || '<API_KEY>';
  const httpConfig = {
    mcpServers: {
      guiliu: {
        type: 'http',
        url: endpoint,
        ...(!dev ? { headers: { Authorization: `Bearer ${token}` } } : {}),
      },
    },
  };
  const stdioConfig = {
    mcpServers: { guiliu: { command: 'gl-cli', args: ['mcp', '-config', '/etc/guiliu/guiliu.json'] } },
  };
  const config = JSON.stringify(transport === 'http' ? httpConfig : stdioConfig, null, 2);
  const curl = `curl -s '${endpoint}' \\\n  ${!dev ? `-H 'Authorization: Bearer ${token}' \\\n  ` : ''}-H 'Content-Type: application/json' \\\n  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`;
  async function createKey(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !name.trim()) return;
    setBusy(true);
    setError('');
    try {
      const result = await api<{ key: string; api_key: APIKey }>('/auth/keys', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), expires_in_days: Number(expiry) }),
      });
      setNewKey({ id: result.api_key.id, token: result.key });
      setName('');
      await loadKeys();
      toast('API Key 已创建，只显示一次');
    } catch (err: any) {
      setError(err.message || '创建失败');
    } finally {
      setBusy(false);
    }
  }
  async function revoke(key: APIKey) {
    if (
      busy ||
      !window.confirm(t('吊销 API Key「{name}」？使用它的客户端将立即失去访问权限。', { name: key.name }))
    )
      return;
    setBusy(true);
    try {
      await api(`/auth/keys/${encodeURIComponent(key.id)}`, { method: 'DELETE' });
      if (newKey?.id === key.id) setNewKey(null);
      await loadKeys();
      toast('API Key 已吊销');
    } catch (err: any) {
      setError(err.message || '操作失败');
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-5">
      <section className="card">
        <div className="section-heading">
          <h2 className="section-title">{t('API Keys')}</h2>
          <span className="text-xs text-[var(--muted)]">{t('只读')}</span>
        </div>
        <div className="space-y-4 p-5">
          <p className="text-xs text-[var(--muted)]">{t('访问范围：当前实例的全部云账号。')}</p>
          {error ? <ErrorBox>{error}</ErrorBox> : null}
          {newKey ? (
            <div className="rounded-lg border border-[var(--accent-border)] bg-[var(--accent-soft)] p-4">
              <div className="mb-3 text-sm font-medium">{t('新 Key 只显示一次')}</div>
              <div className="flex flex-wrap items-center gap-3">
                <code className="min-w-0 flex-1 break-all text-xs">{newKey.token}</code>
                <CopyButton value={newKey.token} />
                <button className="btn btn-sm" onClick={() => setNewKey(null)}>
                  {t('关闭')}
                </button>
              </div>
            </div>
          ) : null}
          {dev ? (
            <p className="py-2 text-sm text-[var(--muted)]">
              {t(meta?.mock ? '演示模式不签发 API Key。' : '开发模式不签发 API Key。')}
            </p>
          ) : (
            <>
              <form onSubmit={createKey} className="flex flex-wrap items-center gap-2">
                <input
                  className="field min-w-[220px] flex-1"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  aria-label={t('名称')}
                  placeholder={t('Key 名称，例如 claude-code')}
                  required
                />
                <select
                  className="field"
                  aria-label={t('过期时间')}
                  value={expiry}
                  onChange={(event) => setExpiry(event.target.value)}
                >
                  <option value="30">30 {t('天')}</option>
                  <option value="90">90 {t('天')}</option>
                  <option value="365">365 {t('天')}</option>
                </select>
                <button className="btn btn-primary" disabled={busy}>
                  {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                  {t('创建 API Key')}
                </button>
              </form>
              {loading ? (
                <div className="py-4 text-sm">{t('加载中…')}</div>
              ) : keys.length ? (
                <div className="table-wrap">
                  <table className="data-table min-w-[740px]">
                    <thead>
                      <tr>
                        <th>{t('名称')}</th>
                        <th>{t('前缀')}</th>
                        <th>{t('状态')}</th>
                        <th>{t('创建时间')}</th>
                        <th>{t('最后使用')}</th>
                        <th>{t('过期时间')}</th>
                        <th>{t('操作')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {keys.map((key) => {
                        const revoked = !!key.revoked_at;
                        const expired = !!key.expires_at && new Date(key.expires_at).getTime() <= Date.now();
                        return (
                          <tr key={key.id}>
                            <td>{key.name}</td>
                            <td className="font-mono text-xs">{key.prefix}</td>
                            <td>{t(revoked ? '已吊销' : expired ? '已过期' : '有效')}</td>
                            <td className="text-xs">{formatDate(key.created_at)}</td>
                            <td className="text-xs">
                              {key.last_used_at ? formatDate(key.last_used_at) : t('从未')}
                            </td>
                            <td className="text-xs">{formatDate(key.expires_at)}</td>
                            <td>
                              <button
                                className="btn btn-ghost btn-sm text-[var(--danger)]"
                                disabled={busy || revoked}
                                onClick={() => revoke(key)}
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                                {t('吊销')}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty title="尚未创建 API Key" />
              )}
            </>
          )}
        </div>
      </section>
      <section className="card p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="section-title">{t('接入配置')}</h2>
          <select
            className="field"
            aria-label={t('传输方式')}
            value={transport}
            onChange={(event) => setTransport(event.target.value)}
          >
            <option value="http">Streamable HTTP</option>
            <option value="stdio">stdio</option>
          </select>
        </div>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <code className="break-all text-xs text-[var(--muted)]">
            {transport === 'http' ? endpoint : 'gl-cli mcp'}
          </code>
          <CopyButton value={config} label="复制配置" />
        </div>
        <pre className="code">{config}</pre>
        <p className="mt-3 text-xs text-[var(--muted)]">
          {t(
            transport === 'stdio'
              ? '使用当前系统用户权限访问本机数据。'
              : dev
                ? '生产环境需要 API Key；演示模式无需认证。'
                : '配置中的占位符需要替换为 API Key。',
          )}
        </p>
      </section>
      <details className="disclosure">
        <summary>
          {t('工具目录')} <span className="ml-2 text-xs text-[var(--muted)]">{TOOLS.length}</span>
        </summary>
        <div className="table-wrap mt-4">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('工具')}</th>
                <th>{t('用途')}</th>
              </tr>
            </thead>
            <tbody>
              {TOOLS.map(([name, description]) => (
                <tr key={name}>
                  <td className="font-mono text-xs">{name}</td>
                  <td>{t(description)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <details className="disclosure">
        <summary>{t('验证请求')}</summary>
        <div className="mt-4">
          <pre className="code">{curl}</pre>
          <div className="mt-2 flex justify-end">
            <CopyButton value={curl} />
          </div>
        </div>
      </details>
    </div>
  );
}

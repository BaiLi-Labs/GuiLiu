import { useEffect, useMemo, useState } from 'react';
import { KeyRound, Loader2, Plus, ShieldCheck, Terminal, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useApp } from '../state';
import { CopyButton, Empty, ErrorBox } from '../components/ui';
import { formatDate } from '../lib';
import type { APIKey } from '../types';

const TOOLS = [
  ['list_cloud_accounts', '列出云账号与同步健康状态（不含凭据）'],
  ['list_alerts', '按云厂商、等级、状态、资产、关键词查询归一化告警'],
  ['list_alert_groups', '按同类重复、资产或攻击源分组，返回数量与最高等级'],
  ['get_alert_group', '展开一个分组的原始告警成员'],
  ['get_alert', '获取单条告警的完整 OCSF 与原始厂商 JSON'],
  ['get_alert_evidence', '获取证据、可观测对象与原始载荷'],
  ['search_alerts_by_ip', '按源/目标 IP 检索（默认最近 7 天）'],
  ['search_alerts_by_asset', '按资产 ID 或名称检索（默认最近 7 天）'],
  ['get_alert_statistics', '按等级、厂商、状态、日期、资产聚合统计'],
  ['get_connector_health', '查看游标、最近成功、错误与同步运行'],
];

export function MCP() {
  const { me, toast } = useApp();
  const dev = !!me?.dev_mode;
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [newKey, setNewKey] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function loadKeys() {
    if (dev) return;
    try {
      const d = await api<{ keys: APIKey[] | null }>('/auth/keys');
      setKeys(d.keys || []);
    } catch (e: any) {
      if (e?.status !== 401) setError(e.message || '加载 API Key 失败');
    }
  }

  useEffect(() => {
    loadKeys();
  }, [dev]);

  const endpoint = `${window.location.origin}/mcp`;
  const token = newKey || '<API_KEY>';
  const config = useMemo(
    () =>
      JSON.stringify(
        {
          mcpServers: {
            guiliu: {
              type: 'http',
              url: endpoint,
              headers: { Authorization: `Bearer ${token}` },
            },
          },
        },
        null,
        2,
      ),
    [endpoint, token],
  );
  const stdio = JSON.stringify(
    {
      mcpServers: {
        guiliu: {
          command: 'guiliu',
          args: ['mcp', '-config', '/etc/guiliu/guiliu.json'],
        },
      },
    },
    null,
    2,
  );
  const curl = `curl -s ${endpoint} \\
  -H 'Authorization: Bearer ${token}' \\
  -H 'Content-Type: application/json' \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`;

  async function createKey() {
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      const d = await api<{ key: string; api_key: APIKey }>('/auth/keys', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim() || 'default' }),
      });
      setNewKey(d.key);
      setName('');
      await loadKeys();
      toast('API Key 已创建，只显示一次');
    } catch (e: any) {
      if (e?.status !== 401) setError(e.message || '创建失败');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(key: APIKey) {
    if (!window.confirm(`吊销 API Key「${key.name}」？使用它的客户端会立即失效。`)) return;
    try {
      await api(`/auth/keys/${encodeURIComponent(key.id)}`, { method: 'DELETE' });
      if (newKey) setNewKey('');
      await loadKeys();
      toast('API Key 已吊销');
    } catch (e: any) {
      if (e?.status !== 401) toast(e.message || '吊销失败', true);
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-2">
        <div className="card p-4">
          <div className="mb-2 flex items-center gap-2">
            <Terminal className="h-4 w-4 text-[var(--accent)]" />
            <h2 className="text-[13px] font-semibold">HTTP 接入（推荐）</h2>
            <span className="pill ml-auto">Streamable HTTP</span>
          </div>
          <div className="mb-2 flex flex-wrap gap-1.5">
            <span className="pill">POST {endpoint}</span>
            <span className="pill">Bearer API Key</span>
            <span className="pill">只读</span>
          </div>
          <pre className="code">{config}</pre>
          <div className="mt-2 flex justify-end"><CopyButton value={config} /></div>
          <p className="mt-2 text-[10.5px] leading-relaxed text-[var(--dim)]">
            使用下方创建的 API Key 认证，不要使用浏览器 Session Cookie。
          </p>
        </div>
        <div className="card p-4">
          <div className="mb-2 flex items-center gap-2">
            <Terminal className="h-4 w-4 text-[var(--accent-2)]" />
            <h2 className="text-[13px] font-semibold">stdio 接入</h2>
            <span className="pill ml-auto">MCP 2025-06-18</span>
          </div>
          <pre className="code">{stdio}</pre>
          <div className="mt-2 flex justify-end"><CopyButton value={stdio} /></div>
          <p className="mt-2 text-[10.5px] leading-relaxed text-[var(--dim)]">
            由本机 OS 用户直接启动，不经过 HTTP 认证；不要在共享机器上运行。
          </p>
        </div>
      </div>

      <div className="card p-4">
        <div className="mb-3 flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-[var(--med)]" />
          <h2 className="text-[13px] font-semibold">API Keys</h2>
          <span className="pill ml-auto">{keys.length} 个活跃 Key</span>
        </div>
        {error ? <div className="mb-3"><ErrorBox>{error}</ErrorBox></div> : null}
        {newKey ? (
          <div className="mb-3 rounded-xl border border-[var(--accent-border)] bg-[var(--accent-soft)] p-3">
            <div className="mb-2 text-[10px] uppercase tracking-[1px] text-[var(--accent)]">新 Key 只显示一次</div>
            <div className="flex flex-wrap items-center gap-2">
              <code className="min-w-[220px] flex-1 break-all font-mono text-[11px]">{newKey}</code>
              <CopyButton value={newKey} />
              <button className="btn btn-sm btn-ghost" onClick={() => setNewKey('')}>关闭</button>
            </div>
          </div>
        ) : null}
        {dev ? (
          <Empty title="开发 / Mock 模式">
            REST 与 MCP 都不需要认证，也不会签发 API Key。生产模式启动后在这里创建 Key 供 Agent 使用。
          </Empty>
        ) : (
          <>
            <div className="mb-3 flex flex-wrap gap-2">
              <input className="field min-w-[200px] flex-1" value={name} onChange={(e) => setName(e.target.value)} placeholder="Key 名称，例如 claude-code" />
              <button className="btn btn-primary" onClick={createKey} disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                创建 API Key
              </button>
            </div>
            {keys.length ? (
              <div className="table-wrap">
                <table className="data-table">
                  <thead><tr><th>名称</th><th>前缀</th><th>创建时间</th><th>最后使用</th><th style={{ width: 80 }}></th></tr></thead>
                  <tbody>
                    {keys.filter((k) => !k.revoked_at).map((k) => (
                      <tr key={k.id}>
                        <td className="text-[11.5px]">{k.name}</td>
                        <td className="font-mono text-[11px]">{k.prefix}</td>
                        <td className="font-mono text-[10.5px] text-[var(--muted)]">{formatDate(k.created_at)}</td>
                        <td className="font-mono text-[10.5px] text-[var(--muted)]">{k.last_used_at ? formatDate(k.last_used_at) : '从未'}</td>
                        <td>
                          <button className="btn btn-sm btn-danger" onClick={() => revoke(k)}>
                            <Trash2 className="h-3 w-3" /> 吊销
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-8 text-center text-[12px] text-[var(--dim)]">还没有 API Key，创建一个后填入上面的 Authorization 头。</div>
            )}
          </>
        )}
      </div>

      <div className="card p-4">
        <div className="mb-2 flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-[var(--low)]" />
          <h2 className="text-[13px] font-semibold">工具清单</h2>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th style={{ width: 250 }}>工具</th><th>用途</th></tr></thead>
            <tbody>
              {TOOLS.map(([name, desc]) => (
                <tr key={name}>
                  <td className="font-mono text-[11px] text-[var(--accent)]">{name}</td>
                  <td className="text-[11.5px] text-[var(--muted)]">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-[10.5px] leading-relaxed text-[var(--dim)]">
          所有工具默认只读，限制返回数量（≤200）与时间范围（≤90 天），不暴露 SQL、云 API 凭据或封禁能力。
        </p>
      </div>

      <div className="card p-4">
        <h2 className="mb-2 text-[13px] font-semibold">手动验证</h2>
        <pre className="code">{curl}</pre>
        <div className="mt-2 flex justify-end"><CopyButton value={curl} /></div>
      </div>
    </div>
  );
}

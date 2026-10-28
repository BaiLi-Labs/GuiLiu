import { SourceFailure, sourceFailureReason } from "../components/SourceFailure";
import { useEffect, useMemo, useState } from 'react';
import { Check, KeyRound, Loader2, Pencil, Play, Plus, RefreshCw, Search, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { CopyButton, Empty, ErrorBox, Modal, SkeletonRows } from '../components/ui';
import { accountStatus, fmtNum, formatDate, providerShort, relTime } from '../lib';
import type { Account, AccountPayload, Provider } from '../types';

interface FormState {
  name: string;
  provider: string;
  account_uid: string;
  region: string;
  enabled: boolean;
  credentials: Record<string, string>;
  options: Record<string, string>;
}
interface PushTokenResult {
  account_name: string;
  push_token: string;
  webhook_path?: string;
}
function blankForm(provider?: Provider): FormState {
  return {
    name: '',
    provider: provider?.id || '',
    account_uid: '',
    region: '',
    enabled: true,
    credentials: {},
    options: {},
  };
}

export function Accounts() {
  const { providers, meta, isAdmin, refreshNonce, toast } = useApp();
  const { t } = useI18n();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<Account | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [busy, setBusy] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [pushToken, setPushToken] = useState<PushTokenResult | null>(null);
  const syncAvailable = !meta?.mock && !!meta?.sync_enabled;
  async function load() {
    setLoading(true);
    setError('');
    try {
      const result = await api<{ accounts: Account[] }>('/accounts');
      setAccounts(result.accounts || []);
    } catch (err: any) {
      setError(err.message || '加载失败');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, [refreshNonce]);
  function connect() {
    setEditing(null);
    setModalOpen(true);
  }
  async function action(id: string, path: string, method: string, message: string, body?: unknown) {
    if (busy) return;
    setBusy(id);
    try {
      await api(path, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
      toast(message);
      await load();
    } catch (err: any) {
        toast(err.sourceError ? `${t(sourceFailureReason(err.sourceError.kind))} ${[err.sourceError.source_api, err.sourceError.code].filter(Boolean).join(' · ')}` : err.message || '操作失败', true);
    } finally {
      setBusy('');
    }
  }
  async function remove(account: Account) {
    if (!window.confirm(t('删除云账号「{name}」？已采集的告警会保留。', { name: account.name }))) return;
    await action(account.id, `/accounts/${encodeURIComponent(account.id)}`, 'DELETE', '账号已删除');
  }
  async function rotatePushToken(account: Account) {
    if (busy) return;
    if (account.push_configured && !window.confirm(t('轮换后旧推送 Token 立即失效，请同步更新发送端。是否继续？'))) return;
    setBusy(account.id);
    try {
      const result = await api<PushTokenResult>(`/accounts/${encodeURIComponent(account.id)}/push-token`, { method: 'POST' });
      setPushToken(result);
      await load();
    } catch (err: any) {
      toast(err.message || t('生成推送 Token 失败'), true);
    } finally {
      setBusy('');
    }
  }
  const visible = accounts.filter(
    (account) =>
      (!status || accountStatus(account) === status) &&
      [
        account.name,
        account.provider,
        account.provider_name,
        account.account_uid,
        account.region,
        providerShort(account.provider),
      ]
        .join(' ')
        .toLowerCase()
        .includes(search.toLowerCase().trim()),
  );
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--dim)]" />
          <input
            className="field w-full pl-9"
            aria-label={t('搜索账号、厂商、区域…')}
            placeholder={t('搜索账号、厂商、区域…')}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <select
          className="field"
          aria-label={t('接入状态')}
          value={status}
          onChange={(event) => setStatus(event.target.value)}
        >
          <option value="">{t('所有接入状态')}</option>
          {['已同步', '同步失败', '部分失败', '同步延迟', '续传中', '等待首次同步', '接收正常', '接收失败', '等待推送', '近期无推送', '部分记录失败', '按需查询', '已停用'].map((value) => (
            <option key={value} value={value}>
              {t(value)}
            </option>
          ))}
        </select>
        {isAdmin ? (
          <>
            <button
              className="btn"
              disabled={!!busy || !syncAvailable}
              onClick={() => action('all', '/sync', 'POST', '已触发全部账号同步')}
            >
              <RefreshCw className="h-4 w-4" />
              {t('同步全部')}
            </button>
            <button className="btn btn-primary" onClick={connect}>
              <Plus className="h-4 w-4" />
              {t('接入云账号')}
            </button>
          </>
        ) : (
          <span className="text-xs text-[var(--muted)]">{t('仅管理员可管理云账号')}</span>
        )}
      </div>
      {error ? <ErrorBox>{error}</ErrorBox> : null}
      <div className="table-wrap">
        {loading ? (
          <SkeletonRows count={8} />
        ) : !accounts.length ? (
          <Empty title="还没有接入任何云账号">
            {isAdmin ? (
              <button className="btn btn-primary" onClick={connect}>
                {t('接入第一个账号')}
              </button>
            ) : null}
          </Empty>
        ) : !visible.length ? (
          <Empty title="无匹配账号">
            <button
              className="btn"
              onClick={() => {
                setSearch('');
                setStatus('');
              }}
            >
              {t('清除筛选')}
            </button>
          </Empty>
        ) : (
          <table className="data-table min-w-[1000px]">
            <thead>
              <tr>
                <th>{t('账号')}</th>
                <th>{t('云厂商')}</th>
                <th>{t('区域')}</th>
                <th>{t('状态')}</th>
                <th>{t('最近同步')}</th>
                <th>{t('数据截至')}</th>
                <th>{t('上次条数')}</th>
                {isAdmin ? <th className="text-right">{t('操作')}</th> : null}
              </tr>
            </thead>
            <tbody>
              {visible.map((account) => {
                const state = accountStatus(account);
                return (
                  <tr key={account.id}>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="font-medium" title={account.account_uid || undefined}>
                          {account.name}
                        </span>
                        {account.push_only ? (
                          <span className="text-xs text-[var(--muted)]">{t('推送接入')}</span>
                        ) : null}
                        {account.query_only ? (
                          <a
                            className="text-xs text-[var(--accent)]"
                            href={`#/events?account_id=${encodeURIComponent(account.id)}`}
                          >
                            {t('查询事件')}
                          </a>
                        ) : null}
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <BrandIcon provider={account.provider} size="xs" />
                        {providerShort(account.provider)}
                      </div>
                    </td>
                    <td className="whitespace-nowrap text-xs">{account.region || '—'}</td>
                    <td>
                      <span className="inline-flex items-center gap-2 whitespace-nowrap">
                        <span
                          className={`status-dot ${['同步失败', '部分失败', '接收失败', '部分记录失败'].includes(state) ? 'status-error' : ['已同步', '接收正常'].includes(state) ? 'status-ok' : ['续传中', '同步延迟', '近期无推送'].includes(state) ? 'status-pending' : ''}`}
                        />
                        {t(state)}
                      </span>
                      {account.sync_state?.last_source_error ? <SourceFailure value={account.sync_state.last_source_error} /> : account.sync_state?.last_error ? (
                        <div
                          className="cell-sub max-w-[200px] text-[var(--danger)]"
                          title={account.sync_state.last_error}
                        >
                          {account.sync_state.last_error}
                        </div>
                      ) : null}
                    </td>
                    <td className="whitespace-nowrap text-xs" title={account.sync_state?.last_success_at}>
                      {relTime(account.sync_state?.last_success_at)}
                    </td>
                    <td className="whitespace-nowrap text-xs text-[var(--muted)]">
                      {formatDate(account.sync_state?.cursor_end)}
                    </td>
                    <td className="tabular-nums">{fmtNum(account.sync_state?.items_last_run)}</td>
                    {isAdmin ? (
                      <td>
                        <div className="flex justify-end gap-1">
                          {!account.push_only ? <><button
                            className="btn btn-ghost btn-icon"
                            aria-label={`${t('验证连接')} · ${account.name}`}
                            title={t('验证连接')}
                            disabled={!!busy || !!meta?.mock}
                            onClick={() =>
                              action(
                                account.id,
                                `/accounts/${encodeURIComponent(account.id)}/check`,
                                'POST',
                                account.query_only ? '事件查询验证成功；字段元数据权限尚未验证' : '告警查询验证成功；资产和网络权限尚未验证',
                              )
                            }
                          >
                            {busy === account.id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Check className="h-4 w-4" />
                            )}
                          </button>
                          {!account.query_only ? <button
                            className="btn btn-ghost btn-icon"
                            aria-label={`${t('同步')} · ${account.name}`}
                            title={t('同步')}
                            disabled={!!busy || !syncAvailable || !account.enabled}
                            onClick={() =>
                              action(
                                account.id,
                                `/accounts/${encodeURIComponent(account.id)}/sync`,
                                'POST',
                                '同步已触发',
                              )
                            }
                          >
                            <Play className="h-4 w-4" />
                          </button> : null}</> : null}
                          {providers.find((provider) => provider.id === account.provider)?.push_formats?.includes('webhook') ? (
                            <button
                              className="btn btn-ghost btn-icon"
                              aria-label={`${t('推送 Token')} · ${account.name}`}
                              title={t(account.push_token_managed_by_config ? '推送 Token 由配置文件管理' : account.push_configured ? '轮换推送 Token' : '生成推送 Token')}
                              disabled={!!busy || !!meta?.mock || !!account.push_token_managed_by_config}
                              onClick={() => rotatePushToken(account)}
                            >
                              <KeyRound className="h-4 w-4" />
                            </button>
                          ) : null}
                          <button
                            className="btn btn-ghost btn-icon"
                            aria-label={`${t('编辑')} · ${account.name}`}
                            title={t('编辑')}
                            disabled={!!busy}
                            onClick={() => {
                              setEditing(account);
                              setModalOpen(true);
                            }}
                          >
                            <Pencil className="h-4 w-4" />
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            disabled={!!busy}
                            onClick={() =>
                              action(
                                account.id,
                                `/accounts/${encodeURIComponent(account.id)}`,
                                'PATCH',
                                account.enabled ? '账号已停用' : '账号已启用',
                                { enabled: !account.enabled },
                              )
                            }
                          >
                            {t(account.enabled ? '停用' : '启用')}
                          </button>
                          <button
                            className="btn btn-ghost btn-icon text-[var(--danger)]"
                            aria-label={`${t('删除')} · ${account.name}`}
                            title={t('删除')}
                            disabled={!!busy}
                            onClick={() => remove(account)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <details className="disclosure">
        <summary>{t('可用连接器')}</summary>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {providers.map((provider) => (
            <div
              key={provider.id}
              className="flex items-center gap-3 rounded-lg border border-[var(--line)] p-4"
            >
              <BrandIcon provider={provider.id} size="sm" />
              <div className="min-w-0">
                <div className="text-sm font-medium">{provider.name}</div>
                <div className="mt-1 text-xs text-[var(--muted)]">{t(provider.product)}</div>
              </div>
            </div>
          ))}
        </div>
      </details>
      <AccountModal
        open={modalOpen}
        editing={editing}
        providers={providers}
        onClose={() => setModalOpen(false)}
        onSaved={() => {
          setModalOpen(false);
          void load();
        }}
        onPushToken={setPushToken}
      />
      <Modal open={!!pushToken} onClose={() => setPushToken(null)} title={t('推送 Token')}>
        {pushToken ? <div className="space-y-4">
          <p className="text-sm text-[var(--muted)]">{t('Token 仅显示一次，关闭前请保存，并在发送端使用 Bearer 认证。')}</p>
          <label className="form-label">
            {t('接收地址')}
            <input className="field w-full font-mono text-xs" readOnly value={`${window.location.origin}${pushToken.webhook_path || `/ingest/${encodeURIComponent(pushToken.account_name)}`}`} />
          </label>
          <label className="form-label">
            {t('推送 Token')}
            <input className="field w-full font-mono text-xs" readOnly value={pushToken.push_token} autoComplete="off" />
          </label>
          <div className="flex items-center justify-end gap-2">
            <CopyButton value={pushToken.push_token} />
            <button className="btn btn-primary" onClick={() => setPushToken(null)}>{t('已保存')}</button>
          </div>
        </div> : null}
      </Modal>
    </div>
  );
}

function AccountModal({
  open,
  editing,
  providers,
  onClose,
  onSaved,
  onPushToken,
}: {
  open: boolean;
  editing: Account | null;
  providers: Provider[];
  onClose: () => void;
  onSaved: () => void;
  onPushToken: (result: PushTokenResult) => void;
}) {
  const { toast } = useApp();
  const { t } = useI18n();
  const [form, setForm] = useState<FormState>(() => blankForm(providers[0]));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const isEdit = !!editing;
  useEffect(() => {
    if (!open) return;
    setError('');
    setForm(
      editing
        ? {
            name: editing.name,
            provider: editing.provider,
            account_uid: editing.account_uid || '',
            region: editing.region || '',
            enabled: editing.enabled,
            credentials: {},
            options: { ...editing.options },
          }
        : blankForm(providers[0]),
    );
  }, [open, editing, providers]);
  const provider = useMemo(
    () => providers.find((item) => item.id === form.provider),
    [providers, form.provider],
  );
  const credentialFields = provider?.credential_fields || [];
  const optionFields = provider?.option_fields || [];
  const requiredOptions = optionFields.filter((field) => field.required || field.name === 'auth_type');
  const optionalOptions = optionFields.filter((field) => !field.required && field.name !== 'endpoint' && field.name !== 'auth_type');
  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((previous) => ({ ...previous, [key]: value }));
  }
  function setCredential(key: string, value: string) {
    setForm((previous) => ({ ...previous, credentials: { ...previous.credentials, [key]: value } }));
  }
  function setOption(key: string, value: string) {
    setForm((previous) => ({ ...previous, options: { ...previous.options, [key]: value } }));
  }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (!form.name.trim()) {
      setError(t('请填写 {field}', { field: t('账号名称') }));
      return;
    }
    if (!provider) {
      setError('请选择云厂商');
      return;
    }
    for (const field of requiredOptions)
      if (!form.options[field.name]?.trim()) {
        setError(t('请填写 {field}', { field: t(field.label) }));
        return;
      }
    if (!isEdit)
      for (const field of credentialFields)
        if (field.required && !form.credentials[field.name]?.trim()) {
          setError(t('请填写 {field}', { field: t(field.label) }));
          return;
        }
    const body: AccountPayload = {
      name: form.name.trim(),
      account_uid: form.account_uid.trim(),
      region: form.region.trim(),
      options: Object.fromEntries(Object.entries(form.options).map(([key, value]) => [key, value.trim()])),
    };
    for (const [key, value] of Object.entries(form.credentials)) if (value.trim()) body[key] = provider.query_only && credentialFields.find(field => field.name === key)?.secret ? value : value.trim();
    setBusy(true);
    setError('');
    try {
      if (editing) {
        await api(`/accounts/${encodeURIComponent(editing.id)}`, {
          method: 'PATCH',
          body: JSON.stringify(body),
        });
        toast('账号已更新');
      } else {
        const created = await api<Account & { push_token?: string }>('/accounts', {
          method: 'POST',
          body: JSON.stringify({ ...body, provider: form.provider, enabled: form.enabled }),
        });
        if (created.push_token) onPushToken({ account_name: created.name, push_token: created.push_token });
        toast('账号已接入');
      }
      onSaved();
    } catch (err: any) {
      setError(err.message || '保存失败');
    } finally {
      setBusy(false);
    }
  }
  const optionInput = (field: NonNullable<Provider['option_fields']>[number]) => (
    <label key={field.name} className={`form-label ${field.multiline ? 'sm:col-span-2' : ''}`}>
      {t(field.label)}
      {field.required ? ' *' : ''}
      {field.choices ? <select className="field w-full" value={form.options[field.name] || field.default || ''} onChange={event => setOption(field.name, event.target.value)}>
        {field.choices.map(choice => <option key={choice} value={choice}>{choice}</option>)}
      </select> : field.multiline ? <textarea className="field w-full font-mono text-xs" rows={4} spellCheck={false} value={form.options[field.name] || ''} onChange={event => setOption(field.name, event.target.value)} placeholder={field.placeholder} /> : <input
        className="field w-full"
        type={field.name === 'rate_limit' || field.name === 'max_pages' ? 'number' : 'text'}
        min={field.name === 'rate_limit' || field.name === 'max_pages' ? 1 : undefined}
        step={field.name === 'rate_limit' ? 'any' : undefined}
        value={form.options[field.name] || ''}
        onChange={(event) => setOption(field.name, event.target.value)}
        placeholder={t(field.placeholder || '')}
        required={field.required}
      />}
      {field.help ? <span className="field-help">{t(field.help)}</span> : null}
    </label>
  );
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? t('编辑账号 · {name}', { name: editing.name }) : t('接入云账号')}
      wide
    >
      <form className="space-y-5" onSubmit={submit}>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="form-label">
            {t('云厂商')}
            <select
              className="field w-full"
              value={form.provider}
              disabled={isEdit}
              onChange={(event) =>
                setForm((previous) => ({
                  ...previous,
                  provider: event.target.value,
                  credentials: {},
                  options: {},
                }))
              }
            >
              {providers.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {t(item.product)}
                </option>
              ))}
            </select>
          </label>
          <label className="form-label">
            {t('账号名称')}
            <input
              className="field w-full"
              value={form.name}
              onChange={(event) => set('name', event.target.value)}
              placeholder={t('例如 prod-aws')}
              required
            />
          </label>
          {!provider?.query_only ? <label className="form-label">
            {t('云账号 ID / 项目 ID（可选）')}
            <input
              className="field w-full"
              value={form.account_uid}
              onChange={(event) => set('account_uid', event.target.value)}
            />
          </label> : null}
          {!provider?.query_only ? <label className="form-label">
            {t('Region（可选）')}
            <input
              className="field w-full"
              value={form.region}
              onChange={(event) => set('region', event.target.value)}
              placeholder={t('例如 us-east-1')}
            />
          </label> : null}
          {requiredOptions.map(optionInput)}
        </div>
        <section className="border-t border-[var(--line)] pt-5">
          <h3 className="section-title">{t('凭据')}</h3>
          <p className="mb-4 mt-2 text-xs text-[var(--muted)]">{t('使用只读凭据。凭据将加密保存。')}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            {credentialFields.map((field) => (
              <label key={field.name} className={`form-label ${field.multiline ? 'sm:col-span-2' : ''}`}>
                {t(field.label)}
                {field.required && !isEdit ? ' *' : ''}
                {field.multiline ? (
                  <textarea
                    className="field w-full font-mono"
                    value={form.credentials[field.name] || ''}
                    onChange={(event) => setCredential(field.name, event.target.value)}
                    placeholder={isEdit ? t('留空保持现有凭据') : undefined}
                    required={field.required && !isEdit}
                    spellCheck={false}
                  />
                ) : (
                  <input
                    className="field w-full"
                    type={field.secret ? 'password' : 'text'}
                    value={form.credentials[field.name] || ''}
                    onChange={(event) => setCredential(field.name, event.target.value)}
                    placeholder={isEdit ? t('留空保持现有凭据') : undefined}
                    autoComplete="off"
                    required={field.required && !isEdit}
                  />
                )}
                {field.help ? <span className="field-help">{t(field.help)}</span> : null}
              </label>
            ))}
            {!credentialFields.length ? (
              <span className="text-sm text-[var(--muted)]">{t('该连接器不需要凭据')}</span>
            ) : null}
          </div>
        </section>
        <details className="disclosure">
          <summary>{t('高级选项')}</summary>
          <div className="mt-4 grid gap-4 sm:grid-cols-2">
            {!requiredOptions.some(field => field.name === 'endpoint') ? optionInput({
              name: 'endpoint',
              label: provider?.id === 'azure' ? 'ARM Endpoint' : 'Endpoint',
              placeholder: '默认官方 endpoint',
            }) : null}
            {!provider?.query_only ? optionInput({ name: 'rate_limit', label: '限速 QPS', placeholder: '默认按厂商' }) : null}
            {!provider?.query_only ? optionInput({ name: 'max_pages', label: '每轮最大页数', placeholder: '默认 10' }) : null}
            {optionalOptions.map(optionInput)}
          </div>
        </details>
        {error ? <ErrorBox>{error}</ErrorBox> : null}
        <div className="flex items-center justify-end gap-2 border-t border-[var(--line)] pt-4">
          {!isEdit ? (
            <label className="mr-auto flex items-center gap-2 text-sm text-[var(--muted)]">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(event) => set('enabled', event.target.checked)}
              />
              {t(provider?.push_only ? '启用推送接入' : '启用定时同步')}
            </label>
          ) : null}
          <button className="btn" type="button" onClick={onClose}>
            {t('取消')}
          </button>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            {t(busy ? '保存中…' : isEdit ? '保存修改' : '接入账号')}
          </button>
        </div>
      </form>
    </Modal>
  );
}

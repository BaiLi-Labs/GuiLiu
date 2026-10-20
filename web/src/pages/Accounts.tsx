import { useEffect, useMemo, useState } from 'react';
import { Check, Cloud, Loader2, Pencil, Play, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useApp } from '../state';
import { BrandIcon } from '../components/BrandIcons';
import { Empty, ErrorBox, Modal, SkeletonRows } from '../components/ui';
import { formatDate, relTime } from '../lib';
import type { Account, AccountPayload, Provider } from '../types';

interface FormState {
  name: string;
  provider: string;
  account_uid: string;
  region: string;
  enabled: boolean;
  endpoint: string;
  rate_limit: string;
  max_pages: string;
  credentials: Record<string, string>;
  options: Record<string, string>;
}

function blankForm(provider: Provider | undefined): FormState {
  return {
    name: '',
    provider: provider?.id || '',
    account_uid: '',
    region: '',
    enabled: true,
    endpoint: '',
    rate_limit: '',
    max_pages: '',
    credentials: {},
    options: {},
  };
}

function editForm(a: Account): FormState {
  return {
    name: a.name,
    provider: a.provider,
    account_uid: a.account_uid || '',
    region: a.region || '',
    enabled: a.enabled,
    endpoint: a.options?.endpoint || '',
    rate_limit: a.options?.rate_limit || '',
    max_pages: a.options?.max_pages || '',
    credentials: {},
    options: { ...(a.options || {}) },
  };
}

export function Accounts() {
  const { providers, meta, isAdmin: admin, refreshNonce, toast } = useApp();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<Account | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [busyId, setBusyId] = useState('');
  const [syncingAll, setSyncingAll] = useState(false);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const d = await api<{ accounts: Account[] }>('/accounts');
      setAccounts(d.accounts || []);
    } catch (e: any) {
      setError(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [refreshNonce]);

  async function action(id: string, path: string, method: string, message: string) {
    setBusyId(id);
    try {
      await api(path, { method });
      toast(message);
      await load();
    } catch (e: any) {
      if (e?.status !== 401) toast(e.message || '操作失败', true);
    } finally {
      setBusyId('');
    }
  }

  async function remove(a: Account) {
    if (!window.confirm(`删除云账号「${a.name}」？关联告警不会自动删除。`)) return;
    setBusyId(a.id);
    try {
      await api(`/accounts/${encodeURIComponent(a.id)}`, { method: 'DELETE' });
      toast('账号已删除');
      await load();
    } catch (e: any) {
      if (e?.status !== 401) toast(e.message || '删除失败', true);
    } finally {
      setBusyId('');
    }
  }

  async function toggleCorrect(a: Account) {
    setBusyId(a.id);
    try {
      await api(`/accounts/${encodeURIComponent(a.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !a.enabled }),
      });
      toast(a.enabled ? '账号已停用' : '账号已启用');
      await load();
    } catch (e: any) {
      if (e?.status !== 401) toast(e.message || '操作失败', true);
    } finally {
      setBusyId('');
    }
  }

  async function syncAll() {
    if (syncingAll) return;
    setSyncingAll(true);
    try {
      await api('/sync', { method: 'POST' });
      toast('已触发全部账号同步');
      setTimeout(load, 1600);
    } catch (e: any) {
      if (e?.status !== 401) toast(e.message || '同步失败', true);
    } finally {
      setSyncingAll(false);
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        {admin ? (
          <>
            <button
              className="btn btn-primary"
              onClick={() => {
                setEditing(null);
                setModalOpen(true);
              }}
            >
              <Plus className="h-4 w-4" /> 接入云账号
            </button>
            <button className="btn" onClick={syncAll} disabled={syncingAll}>
              {syncingAll ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              同步全部
            </button>
          </>
        ) : (
          <span className="pill">只读账号：仅管理员可变更云账号</span>
        )}
        <span className="pill ml-auto">AK/SK 使用 AES-256-GCM 加密存储</span>
      </div>

      {loading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="card p-4"><SkeletonRows count={3} /></div>
          ))}
        </div>
      ) : error ? (
        <ErrorBox>{error}</ErrorBox>
      ) : accounts.length ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {accounts.map((a) => (
            <AccountCard
              key={a.id}
              account={a}
              busy={busyId === a.id}
              admin={admin}
              onCheck={() => action(a.id, `/accounts/${encodeURIComponent(a.id)}/check`, 'POST', '连接正常，凭据与权限有效')}
              onSync={() => action(a.id, `/accounts/${encodeURIComponent(a.id)}/sync`, 'POST', '同步已触发')}
              onEdit={() => {
                setEditing(a);
                setModalOpen(true);
              }}
              onToggle={() => toggleCorrect(a)}
              onDelete={() => remove(a)}
            />
          ))}
        </div>
      ) : (
        <div className="card">
          <Empty title="还没有接入任何云账号">
            接入云厂商后，平台会按增量游标自动拉取、归一化并去重告警。
            <div className="mt-4">
              <button className="btn btn-primary" onClick={() => { setEditing(null); setModalOpen(true); }}>
                接入第一个账号
              </button>
            </div>
          </Empty>
        </div>
      )}

      <section>
        <div className="mb-2 flex items-center gap-2">
          <Cloud className="h-4 w-4 text-[var(--accent-2)]" />
          <h2 className="text-[11px] uppercase tracking-[1.2px] text-[var(--dim)]">已内置连接器</h2>
          {admin ? <span className="pill">Mock 模式使用合成数据</span> : null}
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {providers.map((p) => (
            <ProviderCard key={p.id} provider={p} mock={!!meta?.mock} />
          ))}
        </div>
      </section>

      <AccountModal
        open={modalOpen}
        editing={editing}
        providers={providers}
        onClose={() => setModalOpen(false)}
        onSaved={async () => {
          setModalOpen(false);
          await load();
        }}
      />
    </div>
  );
}

function AccountCard({
  account: a,
  busy,
  admin,
  onCheck,
  onSync,
  onEdit,
  onToggle,
  onDelete,
}: {
  account: Account;
  busy: boolean;
  admin: boolean;
  onCheck: () => void;
  onSync: () => void;
  onEdit: () => void;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const st = a.sync_state || {};
  const failures = st.consecutive_failures || 0;
  const health = !a.enabled ? '已停用' : st.pending ? '续传中' : failures ? '同步失败' : st.last_success_at ? '正常' : '等待首次同步';
  const dot = !a.enabled ? 'bg-[var(--dim)]' : failures ? 'bg-[var(--danger)]' : st.pending ? 'bg-[var(--med)]' : 'bg-[var(--low)]';
  return (
    <div className="card p-4">
      <div className="flex items-start gap-3">
        <div className="relative shrink-0">
          <BrandIcon provider={a.provider} size="md" />
          <span className={`absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--panel)] ${dot}`} />
        </div>
        <div className="min-w-0">
          <div className="truncate text-[14px] font-semibold">{a.name}</div>
          <div className="mt-1 truncate text-[10.5px] text-[var(--dim)]">
            {a.provider_name || a.provider} · {a.account_uid || '未填写账号 ID'}{a.region ? ` · ${a.region}` : ''}
          </div>
        </div>
        <span className="pill ml-auto shrink-0">{a.access_key_hint || '—'}</span>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2">
        <Mini label="最近同步" value={relTime(st.last_success_at)} />
        <Mini label="上次条数" value={String(st.items_last_run ?? 0)} />
        <Mini label="耗时" value={st.last_duration_ms ? `${st.last_duration_ms}ms` : '—'} />
      </div>
      <div className="mt-3 flex items-center justify-between text-[10px] text-[var(--dim)]">
        <span>游标 {st.cursor_end ? formatDate(st.cursor_end) : '—'}</span>
        <span>{health}</span>
      </div>
      {st.last_error ? <div className="mt-2 truncate text-[10px] text-[var(--danger-text)]">{st.last_error}</div> : null}
      {admin ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          <button className="btn btn-sm btn-primary" onClick={onCheck} disabled={busy}>
            {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />} 检测
          </button>
          <button className="btn btn-sm" onClick={onSync} disabled={busy}>
            <Play className="h-3 w-3" /> 同步
          </button>
          <button className="btn btn-sm" onClick={onEdit} disabled={busy}>
            <Pencil className="h-3 w-3" /> 编辑
          </button>
          <button className="btn btn-sm" onClick={onToggle} disabled={busy}>
            {a.enabled ? '停用' : '启用'}
          </button>
          <button className="btn btn-sm btn-danger ml-auto" onClick={onDelete} disabled={busy}>
            <Trash2 className="h-3 w-3" />
          </button>
        </div>
      ) : null}
    </div>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[var(--line-soft)] bg-[var(--inset)] px-2.5 py-2">
      <div className="text-[9.5px] text-[var(--dim)]">{label}</div>
      <div className="mt-0.5 truncate text-[11px]">{value}</div>
    </div>
  );
}

function ProviderCard({ provider: p, mock }: { provider: Provider; mock: boolean }) {
  return (
    <div className="card flex flex-col gap-2.5 p-4">
      <div className="flex items-center gap-2.5">
        <BrandIcon provider={p.id} />
        <div className="min-w-0">
          <div className="text-[13px] font-semibold">{p.name}</div>
          <div className="truncate text-[10.5px] text-[var(--dim)]">{p.product} · API {p.api_version || '—'}</div>
        </div>
        <span className="pill ml-auto">{mock ? 'Mock · ' : ''}{p.mapper_version || 'mapper —'}</span>
      </div>
      <div className="flex flex-wrap gap-1">
        {(p.products || []).map((x) => (
          <span key={x.code} className="pill">{x.name}</span>
        ))}
      </div>
      <div className="text-[10.5px] text-[var(--dim)]">
        凭据字段：{(p.credential_fields || []).map((f) => f.label).join('、') || '无'}
      </div>
    </div>
  );
}

function AccountModal({
  open,
  editing,
  providers,
  onClose,
  onSaved,
}: {
  open: boolean;
  editing: Account | null;
  providers: Provider[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useApp();
  const [form, setForm] = useState<FormState>(() => blankForm(providers[0]));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const isEdit = !!editing;

  useEffect(() => {
    if (!open) return;
    setError('');
    setForm(editing ? editForm(editing) : blankForm(providers[0]));
  }, [open, editing, providers]);

  const provider = useMemo(() => providers.find((p) => p.id === form.provider), [providers, form.provider]);
  const optionFields = provider?.option_fields || [];
  const credentialFields = provider?.credential_fields || [];

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function setCredential(name: string, value: string) {
    setForm((f) => ({ ...f, credentials: { ...f.credentials, [name]: value } }));
  }
  function setOption(name: string, value: string) {
    setForm((f) => ({ ...f, options: { ...f.options, [name]: value } }));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!form.name.trim()) {
      setError('账号名称不能为空');
      return;
    }
    if (!form.provider) {
      setError('请选择云厂商');
      return;
    }
    if (!isEdit) {
      for (const f of credentialFields) {
        if (f.required && !form.credentials[f.name]?.trim()) {
          setError(`请填写 ${f.label}`);
          return;
        }
      }
      for (const f of optionFields) {
        if (f.required && !form.options[f.name]?.trim()) {
          setError(`请填写 ${f.label}`);
          return;
        }
      }
    }
    setBusy(true);
    setError('');
    const options: Record<string, string> = {
      ...form.options,
      ...(form.endpoint.trim() ? { endpoint: form.endpoint.trim() } : {}),
      ...(form.rate_limit.trim() ? { rate_limit: form.rate_limit.trim() } : {}),
      ...(form.max_pages.trim() ? { max_pages: form.max_pages.trim() } : {}),
    };
    const body: AccountPayload = {
      name: form.name.trim(),
      account_uid: form.account_uid.trim(),
      region: form.region.trim(),
      options,
    };
    for (const [key, value] of Object.entries(form.credentials)) {
      if (value.trim()) body[key] = value.trim();
    }
    try {
      if (isEdit && editing) {
        await api(`/accounts/${encodeURIComponent(editing.id)}`, { method: 'PATCH', body: JSON.stringify(body) });
        toast('账号已更新');
      } else {
        await api('/accounts', {
          method: 'POST',
          body: JSON.stringify({ ...body, provider: form.provider, enabled: form.enabled }),
        });
        toast('账号已接入');
      }
      onSaved();
    } catch (err: any) {
      setError(err?.message || '保存失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? `编辑账号 · ${editing?.name}` : '接入云账号'}
      subtitle="凭据会加密存储，仅用于只读拉取厂商告警。"
      wide
    >
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <div className="mb-1.5 text-[11px] text-[var(--muted)]">账号名称</div>
            <input className="field w-full" value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="例如 prod-aws" required />
          </label>
          <label className="block">
            <div className="mb-1.5 text-[11px] text-[var(--muted)]">云厂商</div>
            <select
              className="field w-full"
              value={form.provider}
              disabled={isEdit}
              onChange={(e) => {
                set('provider', e.target.value);
                setForm((f) => ({ ...f, credentials: {}, options: {}, endpoint: '', rate_limit: '', max_pages: '' }));
              }}
            >
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} · {p.product}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <div className="mb-1.5 text-[11px] text-[var(--muted)]">云账号 ID / 项目 ID（可选）</div>
            <input className="field w-full" value={form.account_uid} onChange={(e) => set('account_uid', e.target.value)} placeholder="可选" />
          </label>
          <label className="block">
            <div className="mb-1.5 text-[11px] text-[var(--muted)]">Region（可选）</div>
            <input className="field w-full" value={form.region} onChange={(e) => set('region', e.target.value)} placeholder="例如 us-east-1" />
          </label>
        </div>

        <div className="rounded-xl border border-[var(--line-soft)] bg-[var(--inset)] p-3">
          <div className="mb-3 text-[10px] uppercase tracking-[1px] text-[var(--dim)]">凭据</div>
          <div className="grid gap-3 sm:grid-cols-2">
            {credentialFields.map((f) => (
              <label key={f.name} className={f.multiline ? 'block sm:col-span-2' : 'block'}>
                <div className="mb-1.5 text-[11px] text-[var(--muted)]">
                  {f.label} {f.required ? <span className="text-[var(--danger)]">*</span> : null}
                </div>
                {f.multiline ? (
                  <textarea
                    className="field w-full font-mono text-[11px]"
                    value={form.credentials[f.name] || ''}
                    onChange={(e) => setCredential(f.name, e.target.value)}
                    placeholder={isEdit ? '留空保持现有凭据' : f.help || ''}
                  />
                ) : (
                  <input
                    className="field w-full"
                    type={f.secret ? 'password' : 'text'}
                    value={form.credentials[f.name] || ''}
                    onChange={(e) => setCredential(f.name, e.target.value)}
                    placeholder={isEdit ? '留空保持现有凭据' : f.help || ''}
                    autoComplete="off"
                  />
                )}
                {f.help ? <div className="mt-1 text-[10px] text-[var(--dim)]">{f.help}</div> : null}
              </label>
            ))}
            {!credentialFields.length ? <div className="text-[11px] text-[var(--dim)]">该连接器不需要凭据</div> : null}
          </div>
        </div>

        <div className="rounded-xl border border-[var(--line-soft)] bg-[var(--inset)] p-3">
          <div className="mb-3 text-[10px] uppercase tracking-[1px] text-[var(--dim)]">高级选项</div>
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="block">
              <div className="mb-1.5 text-[11px] text-[var(--muted)]">Endpoint</div>
              <input className="field w-full" value={form.endpoint} onChange={(e) => set('endpoint', e.target.value)} placeholder="默认官方 endpoint" />
            </label>
            <label className="block">
              <div className="mb-1.5 text-[11px] text-[var(--muted)]">限速 QPS</div>
              <input className="field w-full" type="number" min="1" value={form.rate_limit} onChange={(e) => set('rate_limit', e.target.value)} placeholder="默认按厂商" />
            </label>
            <label className="block">
              <div className="mb-1.5 text-[11px] text-[var(--muted)]">每轮最大页数</div>
              <input className="field w-full" type="number" min="1" value={form.max_pages} onChange={(e) => set('max_pages', e.target.value)} placeholder="默认 10" />
            </label>
          </div>
          {optionFields.length ? (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {optionFields.map((f) => (
                <label key={f.name} className="block">
                  <div className="mb-1.5 text-[11px] text-[var(--muted)]">
                    {f.label} {f.required ? <span className="text-[var(--danger)]">*</span> : null}
                  </div>
                  <input
                    className="field w-full"
                    value={form.options[f.name] || ''}
                    onChange={(e) => setOption(f.name, e.target.value)}
                    placeholder={f.placeholder || f.help || ''}
                  />
                  {f.help ? <div className="mt-1 text-[10px] text-[var(--dim)]">{f.help}</div> : null}
                </label>
              ))}
            </div>
          ) : null}
        </div>

        {error ? <ErrorBox>{error}</ErrorBox> : null}
        <div className="flex items-center justify-end gap-2">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            取消
          </button>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            {isEdit ? '保存修改' : '接入账号'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

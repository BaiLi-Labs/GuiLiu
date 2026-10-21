import { useEffect, useState } from 'react';
import { useI18n } from '../i18n';
import { api } from '../api';
import { formatTime } from '../lib';
import type { Alert, AlertRevision } from '../types';

// Preserve vendor names and values. Nested payloads render only when opened.
export function VendorFields({ value }: { value: unknown }) {
  if (value === null || typeof value !== 'object')
    return <span className="whitespace-pre-wrap break-all">{String(value)}</span>;
  const entries = Object.entries(value);
  if (!entries.length) return <span>{Array.isArray(value) ? '[]' : '{}'}</span>;
  return (
    <dl className="space-y-2 text-xs">
      {entries.map(([key, item]) => (
        <div key={key} className="rounded border border-[var(--line)] p-3">
          <VendorField name={key} value={item} />
        </div>
      ))}
    </dl>
  );
}

function VendorField({ name, value }: { name: string; value: unknown }) {
  const [open, setOpen] = useState(false);
  if (value !== null && typeof value === 'object')
    return (
      <>
        <dt>
          <button
            className="w-full break-all text-left font-mono font-medium"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            {open ? '▾' : '▸'} {name} ({Object.keys(value).length})
          </button>
        </dt>
        {open ? <dd className="mt-2"><VendorFields value={value} /></dd> : null}
      </>
    );
  return (
    <>
      <dt className="break-all font-mono text-[var(--muted)]">{name}</dt>
      <dd className="mt-1 whitespace-pre-wrap break-all">{value === null ? 'null' : String(value)}</dd>
    </>
  );
}

export function AlertFields({ detail }: { detail: Alert }) {
  const { t } = useI18n();
  const resources = detail.resources?.length ? detail.resources : detail.resource ? [detail.resource] : [];
  return (
    <div className="space-y-5">
      <section>
        <h3 className="section-title mb-2">{t('受影响资产')}</h3>
        <dl className="space-y-2 text-xs">
          {resources.map((resource, index) => (
            <div key={index} className="rounded border border-[var(--line)] p-3">
              <dt className="break-all">{resource.name || resource.id || '—'}</dt>
              <dd className="mt-1 break-all font-mono text-[var(--muted)]">
                {resource.id} {resource.type}
              </dd>
            </div>
          ))}
        </dl>
      </section>
      <section>
        <h3 className="section-title mb-2">{t('可观测对象')}</h3>
        {detail.observables?.length ? (
          <dl className="space-y-2 text-xs">
            {detail.observables.map((item, index) => (
              <div key={index} className="rounded border border-[var(--line)] p-3">
                <dt className="break-all font-mono text-[var(--muted)]">{item.name || item.type || item.type_id}</dt>
                <dd className="mt-1 whitespace-pre-wrap break-all font-mono">{item.value}</dd>
              </div>
            ))}
          </dl>
        ) : <span className="text-xs text-[var(--muted)]">—</span>}
      </section>
      <section>
        <h3 className="section-title mb-2">{t('厂商证据')}</h3>
        <VendorFields value={detail.evidences || []} />
      </section>
      <section>
        <h3 className="section-title mb-2">{t('数据溯源')}</h3>
        <dl className="detail-fields"><dt>SHA-256</dt><dd className="break-all font-mono text-xs">{detail.raw_hash || '—'}</dd><dt>{t('修订')}</dt><dd>{detail.revision}</dd><dt>{t('映射版本')}</dt><dd>{detail.mapper_version}</dd></dl>
        <VendorFields value={detail.provenance || {}} />
      </section>
      <RevisionHistory key={detail.id} id={detail.id} />
      <section>
        <h3 className="section-title mb-2">{t('全部厂商字段')}</h3>
        <VendorFields value={detail.raw ?? null} />
      </section>
    </div>
  );
}

function RevisionHistory({ id }: { id: string }) {
  const { t } = useI18n();
  const [items, setItems] = useState<AlertRevision[]>([]);
  const [before, setBefore] = useState(0);
  const [next, setNext] = useState(0);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    api<{ revisions: AlertRevision[]; next_before_revision: number }>(
      `/alerts/${encodeURIComponent(id)}/revisions?limit=20${before ? `&before_revision=${before}` : ''}`,
      { signal: controller.signal },
    ).then(result => {
      setItems(items => before ? [...items, ...result.revisions] : result.revisions);
      setNext(result.next_before_revision);
      setError('');
    }).catch(error => {
      if (!controller.signal.aborted) setError(error.message);
    });
    return () => controller.abort();
  }, [id, before]);

  return (
    <section>
      <h3 className="section-title mb-2">{t('修订历史')}</h3>
      {error ? <p role="alert">{error}</p> : null}
      {items.map(revision => (
        <details key={revision.revision} className="disclosure mt-2">
          <summary>#{revision.revision} · {formatTime(revision.captured_at)}</summary>
          <VendorFields value={revision.record || revision.raw} />
          {revision.record?.raw_url ? (
            <a className="btn btn-sm mt-2" href={revision.record.raw_url} target="_blank" rel="noreferrer">
              {t('打开原始 JSON')}
            </a>
          ) : null}
        </details>
      ))}
      {next > 0 ? (
        <button className="btn btn-sm mt-2" onClick={() => setBefore(next)}>{t('加载更早修订')}</button>
      ) : null}
    </section>
  );
}

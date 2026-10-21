import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import ts from 'typescript';

// Compile the production sources in memory. No DOM library or test-only implementation is needed.
const require = createRequire(import.meta.url);
const webRoot = fileURLToPath(new URL('..', import.meta.url));
const storage = new Map();
const events = new Map();
const rootAttributes = new Map();
let responseText = '';
const browser = {
  fetch: async () => ({ ok: true, text: async () => responseText }),
  localStorage: {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
  },
  navigator: { languages: ['en-US'], language: 'en-US' },
  document: {
    documentElement: {
      set lang(value) {
        rootAttributes.set('lang', value);
      },
    },
  },
  window: {
    location: { hash: '' },
    addEventListener: (name, listener) => events.set(name, listener),
    removeEventListener() {},
  },
};
const modules = new Map();
function load(relative) {
  const filename = path.resolve(webRoot, relative);
  if (modules.has(filename)) return modules.get(filename).exports;
  const module = { exports: {} };
  modules.set(filename, module);
  const source = readFileSync(filename, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2020,
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.ReactJSX,
      esModuleInterop: true,
    },
  }).outputText;
  const localRequire = (specifier) => {
    if (!specifier.startsWith('.')) return require(specifier);
    const base = path.resolve(path.dirname(filename), specifier);
    const resolved = ['.ts', '.tsx']
      .map((extension) => base + extension)
      .find((file) => {
        try {
          readFileSync(file);
          return true;
        } catch {
          return false;
        }
      });
    if (!resolved) throw new Error(`Unresolved source import: ${specifier}`);
    return load(path.relative(webRoot, resolved));
  };
  vm.runInNewContext(
    output,
    {
      ...browser,
      module,
      exports: module.exports,
      require: localRequire,
      Intl,
      Date,
      URLSearchParams,
      AbortController,
      console,
      setTimeout,
      clearTimeout,
    },
    { filename },
  );
  return module.exports;
}
const i18n = load('src/i18n.ts');
const lib = load('src/lib.ts');
const { readAlertRoute, queryFor } = load('src/pages/Alerts.tsx');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');

test('asset summary shows scoped source facts, freshness and synthetic limits in both languages', () => {
  const { AssetSummary } = load('src/components/AssetContext.tsx');
  const asset = { id: 'a', account_id: 'connection', account_uid: '100000000001', provider: 'tencent', region: 'ap-guangzhou', resource_id: 'ins-demo', resource_type: 'cvm', name: 'source-name', os: 'source-os', security_group_ids: ['sg-demo'], tags: [{ key: '原始标签', value: 'prod' }], revision: 2, observed_at: new Date().toISOString(), last_observed_at: new Date().toISOString(), synthetic: true, components: {}, provenance: {} };
  i18n.setLocale('en-US');
  let html = renderToStaticMarkup(React.createElement(AssetSummary, { asset }));
  for (const text of ['source-name', 'source-os', 'sg-demo', '原始标签=prod', '100000000001', 'Synthetic asset data', 'do not prove listening or reachability', 'Unknown']) assert.ok(html.includes(text), text);
  assert.ok(!html.includes('Nginx'));
  i18n.setLocale('zh-CN');
  html = renderToStaticMarkup(React.createElement(AssetSummary, { asset }));
  assert.ok(html.includes('合成资产数据'));
  assert.ok(html.includes('不代表告警发生时的状态'));
});

test('source JSON text preserves exact bytes and large integer precision', async () => {
  const { sourceText } = load('src/api.ts');
  responseText = '{\n  "unknownVendorField": 9007199254740993\n}';
  assert.equal(await sourceText('/api/v1/alerts/id/revisions/1/raw'), responseText);
});

function sourceFiles(folder) {
  return readdirSync(folder, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? sourceFiles(path.join(folder, entry.name))
      : /\.[jt]sx?$/.test(entry.name)
        ? [path.join(folder, entry.name)]
        : [],
  );
}

test('browser language detection respects explicit preferences and safely falls back', () => {
  assert.equal(i18n.detectLocale(null, ['zh-TW', 'en-US']), 'zh-CN');
  assert.equal(i18n.detectLocale(null, ['fr-FR']), 'en-US');
  assert.equal(i18n.detectLocale('zh-CN', ['en-US']), 'zh-CN');
  assert.equal(i18n.detectLocale('invalid', []), 'en-US');
});

test('language changes persist, update the document, and preserve vendor content', () => {
  i18n.setLocale('en-US');
  assert.equal(i18n.t('第 {current} / {pages} 页', { current: 2, pages: 5 }), 'Page 2 of 5');
  assert.equal(i18n.t('任意厂商返回的告警正文'), '任意厂商返回的告警正文');
  assert.equal(storage.get('guiliu_locale'), 'en-US');
  assert.equal(rootAttributes.get('lang'), 'en-US');
  i18n.setLocale('zh-CN');
  assert.equal(i18n.t('统一告警'), '统一告警');
  events.get('storage')({ key: 'guiliu_locale', newValue: 'en-US' });
  assert.equal(i18n.getLocale(), 'en-US');
});

test('numbers and relative times follow the selected language', () => {
  i18n.setLocale('en-US');
  assert.equal(lib.fmtNum(12345), '12,345');
  assert.match(lib.relTime(new Date(Date.now() - 120000).toISOString()), /2 minutes ago/);
  i18n.setLocale('zh-CN');
  assert.match(lib.relTime(new Date(Date.now() - 120000).toISOString()), /2分钟前/);
  assert.equal(lib.relTime('bad-date'), '—');
});

test('shareable alert links retain filters, pagination, Unicode, and selection', () => {
  const query = new URLSearchParams({
    provider: 'aws',
    severity: 'critical,fatal,high',
    status: 'open,acknowledged',
    range: '24h',
    q: '反弹 shell & web',
    offset: '20',
    alert: 'alert-123',
  }).toString();
  assert.equal(lib.parseHashPage(`#/alerts?${query}`), 'alerts');
  const route = readAlertRoute(query);
  assert.equal(route.filters.provider, 'aws');
  assert.equal(route.filters.q, '反弹 shell & web');
  assert.equal(route.filters.status, 'open,acknowledged');
  assert.equal(route.filters.severity, 'critical,fatal,high');
  assert.equal(route.filters.range, '24h');
  assert.equal(route.offset, 20);
  assert.equal(route.selected, 'alert-123');
});

test('malformed shared URLs have safe pagination and group defaults', () => {
  assert.equal(readAlertRoute('').groupBy, 'type_asset');
  assert.equal(readAlertRoute('group_by=signature').groupBy, 'signature');
  assert.equal(readAlertRoute('group_by=invalid').groupBy, 'type_asset');
  assert.equal(readAlertRoute('offset=-20&range=bad&group_key=invalid').offset, 0);
  assert.equal(readAlertRoute('offset=Infinity').offset, 0);
  assert.equal(readAlertRoute('group_key=%7B%7D').groupKey, null);
  assert.equal(readAlertRoute('offset=1.5').offset, 0);
  assert.equal(readAlertRoute('range=bad').filters.range, '7d');
  assert.equal(readAlertRoute('group_key=%5B%22a%22%5D').groupKey, null);
  assert.equal(readAlertRoute('group_key=%7B%22source_ip%22%3A123%7D').groupKey, null);
  const grouped = readAlertRoute(
    new URLSearchParams({
      view: 'groups',
      group_by: 'source',
      group_key: JSON.stringify({ source_ip: '203.0.113.1' }),
    }).toString(),
  );
  assert.equal(grouped.view, 'groups');
  assert.equal(grouped.groupBy, 'source');
  assert.equal(grouped.groupKey.source_ip, '203.0.113.1');
});

test('group pagination and expansion reuse absolute query time bounds', () => {
  const start = '2026-10-01T00:00:00.123Z';
  const end = '2026-10-08T00:00:00.123Z';
  const route = readAlertRoute(new URLSearchParams({ range: '7d', group_by: 'type_asset', time_field: 'ingested_at', snapshot_sequence: '1234567', start, end }).toString());
  const first = queryFor(route.filters, 0, route.window);
  const next = queryFor(route.filters, 20, route.window);
  assert.equal(first.get('start'), start);
  assert.equal(first.get('end'), end);
  assert.equal(next.get('start'), start);
  assert.equal(next.get('end'), end);
  assert.equal(next.get('snapshot_sequence'), '1234567');
  assert.equal(next.get('time_field'), 'ingested_at');
  const endOnly = queryFor(route.filters, 0, { end });
  assert.equal(endOnly.get('start'), start);
  const all = queryFor({ ...route.filters, range: 'all' }, 0, { end });
  assert.equal(all.has('start'), false);
  assert.equal(all.get('end'), end);
  assert.equal(Object.keys(readAlertRoute('start=bad&end=bad').window).length, 0);
  assert.equal(Object.keys(readAlertRoute(`start=${end}&end=${start}`).window).length, 0);
});

test('account status handles disabled, failed, pending, and never-synced accounts consistently', () => {
  assert.equal(
    lib.accountStatus({ enabled: false, sync_state: { pending: true, consecutive_failures: 1 } }),
    '已停用',
  );
  assert.equal(
    lib.accountStatus({ enabled: true, sync_state: { pending: true, consecutive_failures: 1 } }),
    '同步失败',
  );
  assert.equal(lib.accountStatus({ enabled: true, sync_state: { pending: true } }), '续传中');
  assert.equal(lib.accountStatus({ enabled: true }), '等待首次同步');
  assert.equal(lib.accountStatus({ enabled: true, sync_state: { status: 'stale' } }), '同步延迟');
  assert.equal(lib.accountStatus({ enabled: true, sync_state: { status: 'partial', failed_records: 1 } }), '部分失败');
  assert.equal(
    lib.accountStatus({ enabled: true, sync_state: { last_success_at: '2026-10-20T00:00:00Z' } }),
    '已同步',
  );
});

test('login and badges render in both languages without developer setup text', () => {
  const { Login } = load('src/pages/Login.tsx');
  const { SeverityBadge, StatusBadge } = load('src/components/ui.tsx');
  i18n.setLocale('en-US');
  let html = renderToStaticMarkup(React.createElement(Login, { onSuccess() {} }));
  assert.match(html, /Sign in/);
  assert.match(html, /aria-label="Language"/);
  assert.doesNotMatch(html, /HttpOnly|GUILIU_ADMIN_PASSWORD|make dev/);
  assert.match(
    renderToStaticMarkup(React.createElement(SeverityBadge, { severity: 'critical' })),
    /Critical/,
  );
  i18n.setLocale('zh-CN');
  html = renderToStaticMarkup(React.createElement(Login, { onSuccess() {} }));
  assert.match(html, /登录控制台/);
  assert.match(renderToStaticMarkup(React.createElement(StatusBadge, { status: 'closed' })), /已关闭/);
});

test('all source-language literals passed to t have English translations', () => {
  const missing = [];
  for (const filename of sourceFiles(path.join(webRoot, 'src'))) {
    if (filename.endsWith('i18n.ts')) continue;
    const ast = ts.createSourceFile(
      filename,
      readFileSync(filename, 'utf8'),
      ts.ScriptTarget.Latest,
      true,
      filename.endsWith('tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
    );
    function visit(node) {
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === 't' &&
        node.arguments[0] &&
        ts.isStringLiteral(node.arguments[0])
      ) {
        const message = node.arguments[0].text;
        if (/[\u3400-\u9fff]/.test(message) && !i18n.en[message])
          missing.push(`${path.relative(webRoot, filename)}: ${message}`);
      }
      ts.forEachChild(node, visit);
    }
    visit(ast);
  }
  assert.deepEqual(missing, []);
});

test('alert fields expose secondary resources, observables, and unrecognized vendor fields', () => {
  const { AlertFields, VendorFields } = load('src/components/AlertFields.tsx');
  i18n.setLocale('en-US');
  const html = renderToStaticMarkup(React.createElement(AlertFields, { detail: {
    resources: [{ id: 'first' }, { id: 'second', name: 'secondary-resource' }],
    observables: [{ name: 'entity.ip', type_id: 2, value: '203.0.113.2' }],
    evidences: [{ type: 'vendor' }],
    raw: { futureVendorField: 'preserved <script>alert(1)</script>', unknownNested: { anything: true } },
  } }));
  assert.match(html, /secondary-resource/);
  assert.match(html, /203\.0\.113\.2/);
  assert.match(html, /futureVendorField/);
  assert.match(html, /unknownNested/);
  assert.match(html, /aria-expanded="false"/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  const scalars = renderToStaticMarkup(React.createElement(VendorFields, { value: { no: false, zero: 0, nil: null } }));
  assert.match(scalars, /false/);
  assert.match(scalars, />0</);
  assert.match(scalars, />null</);
});

test('connector-provided Chinese form labels and help are translated', () => {
  const connectorRoot = path.join(webRoot, '..', 'internal', 'connector');
  const missing = [];
  for (const provider of ['tencent', 'aliyun', 'huawei', 'aws', 'gcp', 'azure']) {
    const source = readFileSync(path.join(connectorRoot, provider, `${provider}.go`), 'utf8');
    for (const match of source.matchAll(/(?:Label|Help|Placeholder):\s*"([^"]*)"/g)) {
      if (/[\u3400-\u9fff]/.test(match[1]) && !i18n.en[match[1]]) missing.push(`${provider}: ${match[1]}`);
    }
  }
  const mockSource = readFileSync(path.join(connectorRoot, '..', 'mock', 'mock.go'), 'utf8');
  for (const match of mockSource.matchAll(/(?:Label|Help|Placeholder):\s*"([^"]*)"/g)) {
    if (/[\u3400-\u9fff]/.test(match[1]) && !i18n.en[match[1]]) missing.push(`mock: ${match[1]}`);
  }
  assert.deepEqual(missing, []);
});

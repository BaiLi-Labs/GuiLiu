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
let responseStatus = 200;
const browser = {
  fetch: async () => ({ ok: responseStatus < 400, status: responseStatus, statusText: '', text: async () => responseText }),
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

test('audit query pins time bounds and details distinguish caller identity from result evidence', () => {
  const { auditQuery, AuditEventDetails } = load('src/pages/Audit.tsx');
  const end = '2026-10-21T12:00:00.000Z';
  const params = new URLSearchParams(auditQuery({ username: 'operator', api_key_id: 'key-id', tool: 'get_alert', request_id: 'request-id', surface: 'mcp_http', outcome: 'error', range: '24h' }, end));
  assert.equal(params.get('start'), '2026-10-20T12:00:00.000Z'); assert.equal(params.get('end'), end); assert.equal(params.get('api_key_id'), 'key-id');
  assert.equal(lib.parseHashPage('#/audit'), 'audit');
  const event = { sequence: 2, parent_sequence: 1, request_id: 'request-id', started_at: end, surface: 'mcp_http', operation: 'tools/call', tool: 'get_alert', auth_type: 'api_key', api_key_id: 'key-id', user_id: 'user-id', outcome: 'error', duration_ms: 5, parameters: { alert_id: 'finding-id' }, effective_query: { snapshot_sequence: 56 }, summary: { revision: 3 } };
  i18n.setLocale('en-US');
  let html = renderToStaticMarkup(React.createElement(AuditEventDetails, { event }));
  for (const text of ['request-id', 'key-id', 'user-id', 'finding-id', 'Completion unconfirmed', 'Resolved query scope', 'snapshot_sequence']) assert.ok(html.includes(text), text);
  i18n.setLocale('zh-CN'); html = renderToStaticMarkup(React.createElement(AuditEventDetails, { event }));
  assert.ok(html.includes('尚未确认完成')); assert.ok(html.includes('提交的查询条件'));
});

test('network references preserve scope and summaries distinguish unknown from source false and empty', () => {
  const { resourceLookupPath, NetworkSummary, ResourceLinks } = load('src/components/ResourceLinks.tsx');
  const reference = { provider: 'tencent', account_id: 'connection & demo', account_uid: '100000000001', region: 'ap-guangzhou', resource_id: 'subnet-synthetic', resource_type: 'subnet', relation: 'in_subnet', source_component: 'instance', source_path: '/VirtualPrivateCloud/SubnetId' };
  const params = new URLSearchParams(resourceLookupPath(reference).split('?')[1]);
  for (const key of ['provider', 'account_id', 'account_uid', 'region', 'resource_id', 'resource_type']) assert.equal(params.get(key), reference[key]);
  const asset = { ...reference, id: 'a', revision: 1, name: 'source-subnet', vpc_id: 'vpc-synthetic', zone: 'source-zone', tags: [], network: { cidr_block: '10.0.0.0/24', is_default: false }, last_observed_at: new Date().toISOString(), synthetic: true, components: {}, provenance: {} };
  i18n.setLocale('en-US');
  let html = renderToStaticMarkup(React.createElement(NetworkSummary, { asset }));
  for (const text of ['source-subnet', 'source-zone', '10.0.0.0/24', 'vpc-synthetic', 'None (source reported)', 'Synthetic asset data', '>No<']) assert.ok(html.includes(text), text);
  html = renderToStaticMarkup(React.createElement(NetworkSummary, { asset: { ...asset, tags: null, network: {} } }));
  assert.ok(html.includes('Unknown')); assert.ok(!html.includes('None (source reported)')); assert.ok(!html.includes('>No<'));
  html = renderToStaticMarkup(React.createElement(ResourceLinks, { references: [reference], isAdmin: false }));
  assert.ok(html.includes('subnet-synthetic')); assert.ok(!html.includes('Refresh this network resource'));
  i18n.setLocale('zh-CN');
  html = renderToStaticMarkup(React.createElement(NetworkSummary, { asset }));
  assert.ok(html.includes('可用区')); assert.ok(html.includes('>否<'));
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
  assert.equal(readAlertRoute('').groupBy, 'asset');
  assert.equal(readAlertRoute('group_by=signature').groupBy, 'signature');
  assert.equal(readAlertRoute('group_by=invalid').groupBy, 'asset');
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

test('push sources distinguish delivery freshness from polling progress', () => {
  assert.equal(lib.accountStatus({ enabled: true, push_only: true }), '等待推送');
  for (const [status, label] of Object.entries({ healthy: '接收正常', stale: '近期无推送', partial: '部分记录失败', failed: '接收失败' })) {
    assert.equal(lib.accountStatus({ enabled: true, push_only: true, sync_state: { status } }), label);
  }
  assert.equal(lib.accountStatus({ enabled: false, push_only: true }), '已停用');
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

test('network grouping routes preserve both watermarks and exact source titles', () => {
  for (const mode of ['asset', 'name_asset', 'vpc', 'subnet', 'security_group', 'nic']) {
    const route = readAlertRoute(new URLSearchParams({ view:'groups', group_by:mode, snapshot_sequence:'123', asset_snapshot_sequence:'0', vendor_title:' Exact title ', start:'2026-10-01T00:00:00Z',end:'2026-10-02T00:00:00Z' }).toString());
    assert.equal(route.groupBy, mode);
    const page = queryFor(route.filters, 20, route.window);
    assert.equal(page.get('snapshot_sequence'), '123');
    assert.equal(page.get('asset_snapshot_sequence'), '0');
    assert.equal(page.get('vendor_title'), ' Exact title ');
  }
  assert.equal(readAlertRoute('asset_snapshot_sequence=-1').window.asset_snapshot_sequence, undefined);
  assert.equal(readAlertRoute('asset_snapshot_sequence=1.5').window.asset_snapshot_sequence, undefined);
});

test('group summary distinguishes source title statistics, evidence revisions and missing observations', () => {
  const { FindingGroupSummary } = load('src/components/FindingGroupSummary.tsx');
  const group = { id:'group',key:{},group_by:'asset',title:'Synthetic host',finding_count:5,asset_count:1,top_titles:[{key:'vendor <script> title',count:3}],assets:[{id:'asset',resource_id:'ins-synthetic',name:'Synthetic host',revision:2,observed_at:'2026-10-22T00:00:00Z',security_group_ids:[],references:[{provider:'tencent',account_id:'connection',account_uid:'100000000001',region:'ap-guangzhou',resource_type:'security_group',resource_id:'sg-synthetic',relation:'attached_security_group',source_component:'instance',source_path:'/SecurityGroupIds/0'}]}] };
  i18n.setLocale('en-US');
  let html = renderToStaticMarkup(React.createElement(FindingGroupSummary, {group,isAdmin:false,onMembers:()=>{}}));
  for (const text of ['Source finding titles','Observed hosts','Revision','sg-synthetic','ins-synthetic','do not prove traffic paths','vendor &lt;script&gt; title','View all members']) assert.ok(html.includes(text),text);
  assert.ok(!html.includes('<script>'));
  html = renderToStaticMarkup(React.createElement(FindingGroupSummary, {group:{...group,assets:[]},isAdmin:false,onMembers:()=>{}}));
  assert.ok(html.includes('No matching saved asset observation'));
  i18n.setLocale('zh-CN');
  html = renderToStaticMarkup(React.createElement(FindingGroupSummary,{group,isAdmin:false,onMembers:()=>{}}));
  assert.ok(html.includes('不代表告警发生时配置'));
});

test('group coverage exposes unique, observed, missing and overlapping counts separately', () => {
  const { GroupingCoverage } = load('src/components/FindingGroupSummary.tsx');
  i18n.setLocale('en-US');
  const html = renderToStaticMarkup(React.createElement(GroupingCoverage,{summary:{finding_count:7,asset_context_finding_count:2,ungrouped_finding_count:5,membership_count:9}}));
  for(const text of ['Unique Findings','With asset observations','Missing grouping fields','Group memberships (may overlap)','group counts must not be added']) assert.ok(html.includes(text),text);
  for(const value of [7,2,5,9]) assert.ok(html.includes(String(value)),value);
});

test('network relationship proof points to the declaring immutable asset revision', () => {
  const { relationEvidencePath } = load('src/components/FindingGroupSummary.tsx');
  const edge = {source_asset_id:'nic-observation',source_revision:3,reference:{source_component:'details'}};
  assert.equal(relationEvidencePath(edge),'/api/v1/assets/nic-observation/revisions/3/components/details/raw');
  assert.notEqual(relationEvidencePath(edge),relationEvidencePath({...edge,source_revision:4}));
});

test('source failures distinguish invalid credentials, explicit authorization and ambiguous denial in both languages', () => {
  const { SourceFailure } = load('src/components/SourceFailure.tsx');
  i18n.setLocale('zh-CN');
  const value = {provider:'tencent',kind:'permission',code:'UnauthorizedOperation',source_api:'VPC DescribeSecurityGroupPolicies'};
  let html = renderToStaticMarkup(React.createElement(SourceFailure,{value}));
  assert.match(html,/来源未授权本次查询/);
  assert.match(html,/VPC DescribeSecurityGroupPolicies/);
  assert.match(html,/UnauthorizedOperation/);
  html = renderToStaticMarkup(React.createElement(SourceFailure,{value:{...value,kind:'auth',code:'AuthFailure.SignatureFailure'}}));
  assert.match(html,/来源认证失败/);
  assert.doesNotMatch(html,/只读授权/);
  html = renderToStaticMarkup(React.createElement(SourceFailure,{value:{provider:'huawei',kind:'access_denied',code:'Ecs.0003',http_status:403}}));
  assert.match(html,/服务开通或账号状态/);
  assert.match(html,/HTTP 403/);
  i18n.setLocale('en-US');
  html = renderToStaticMarkup(React.createElement(SourceFailure,{value}));
  assert.match(html,/not authorized/);
  assert.equal(renderToStaticMarkup(React.createElement(SourceFailure,{})),'');
  i18n.setLocale('zh-CN');
});

test('API errors retain structured SDK diagnostics without confusing cloud refusal with platform authorization', async () => {
  const { api, ApiError } = load('src/api.ts');
  const detail = {provider:'tencent',kind:'permission',code:'UnauthorizedOperation',source_api:'CSIP DescribeAlertList'};
  responseStatus = 422;
  responseText = JSON.stringify({error:{code:'connector_error',message:'source authorization failed',source_error:detail}});
  try {
    await assert.rejects(api('/accounts/synthetic/check',{method:'POST'}), err => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.code,'connector_error');
      assert.equal(err.status,422);
      assert.equal(err.sourceError.code,detail.code);
      assert.equal(err.sourceError.source_api,detail.source_api);
      return true;
    });
  } finally { responseStatus=200; responseText=''; }
});

test('field distributions expose counts without data-quality verdicts', () => {
  const { FieldDistribution } = load('src/components/FieldDistribution.tsx');
  const distribution = { distinct_count: 1, missing_count: 2, other_count: 0, has_more: false, top_n: 20, top: [{ key: '<source-value>', count: 8 }] };
  i18n.setLocale('en-US');
  let html = renderToStaticMarkup(React.createElement(FieldDistribution, { label: '源 IP 分布', distribution }));
  assert.match(html, /Distinct values/);
  assert.match(html, /Missing values/);
  assert.match(html, /&lt;source-value&gt;/);
  assert.match(html, /no identity or security conclusion/);
  assert.doesNotMatch(html, /unusable|low quality|high risk/i);
  assert.doesNotMatch(html, /Findings with other values/);
  i18n.setLocale('zh-CN');
  html = renderToStaticMarkup(React.createElement(FieldDistribution, { label: '告警标题分布', distribution: { ...distribution, has_more: true, other_count: 3 } }));
  assert.match(html, /未展示值对应的记录数/);
  assert.match(html, /字段缺失/);
  assert.equal(renderToStaticMarkup(React.createElement(FieldDistribution, { label: '告警标题分布' })), '');
});

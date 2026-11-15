// SPDX-License-Identifier: AGPL-3.0-only
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createCanvasRestReader } from '../src/canvas-rest-reader.mjs';
import { CanvasReadError, prepareRequirement, normalizeObservation } from '../src/canvas-rest-contract.mjs';
import { canvasOrigin, validateAddresses, approvedPrivateAddresses, pinnedLookup, resolveAddress } from '../src/canvas-rest-network.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const TOKEN = 'synthetic_canvas_oauth_token_0000000000000001';
const SCOPE = { courseId: '17', userId: '29', activityId: '31', factType: 'canvas.assignment_score' };
let fixture;
before(async () => { fixture = await httpsFixture(); });
after(async () => { await fixture.close(); });
const client = (extra = {}) => createCanvasRestReader({ canvasOrigin: fixture.origin, accessToken: TOKEN,
  ca: fixture.ca, allowedPrivateAddresses: ['127.0.0.1', '::1'], ...extra });
const submission = () => ({ id: '45', assignment_id: '31', user_id: '29', course_id: '17',
  workflow_state: 'graded', score: 18, grade_matches_current_submission: true, excused: false,
  graded_at: '2026-11-01T09:20:00-07:00', body: 'private essay', user: { email: 'synthetic@invalid.test' } });
const assignment = () => ({ id: '31', course_id: '17', points_possible: 20, description: 'private provider field' });
function serve(record = submission(), denominator = assignment()) {
  fixture.setHandler((req, res) => json(res, req.url.endsWith('/submissions/29') ? record : denominator));
}
function error(code) {
  return actual => {
    assert.ok(actual instanceof CanvasReadError);
    assert.equal(actual.code, code);
    for (const secret of [TOKEN, 'private essay', 'synthetic@invalid.test', fixture?.origin]) {
      if (secret) assert.ok(!`${actual.stack}\n${JSON.stringify(actual)}`.includes(secret));
    }
    return true;
  };
}
for (const factType of ['canvas.assignment_score', 'canvas.quiz_score']) test(`scoped REST score and exact denominator: ${factType}`, async () => {
  serve();
  const result = await client().readRequirement({ ...SCOPE, factType });
  assert.deepEqual(fixture.seen.map(({ method, url }) => [method, url]), [
    ['GET', '/api/v1/courses/17/assignments/31/submissions/29'],
    ['GET', '/api/v1/courses/17/assignments/31'],
  ]);
  assert.equal(result.fact_type, factType);
  assert.deepEqual(result.assertion, { completed: true, score: 18, score_maximum: 20, score_percent: 90,
    provider_state: 'graded', requirement_count: null, requirement_completed_count: null });
  assert.equal(result.effective_at, '2026-11-01T16:20:00.000Z');
  assert.ok(Number.isFinite(Date.parse(result.observed_at)));
  assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.scope)); assert.ok(Object.isFrozen(result.assertion));
  for (const req of fixture.seen) {
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(req.headers.accept, 'application/json+canvas-string-ids');
    assert.equal(req.headers['x-api-key'], undefined);
    assert.equal(req.headers['x-organization-id'], undefined);
    assert.equal(req.headers.cookie, undefined);
    assert.ok(!req.url.includes(TOKEN));
  }
  for (const forbidden of [TOKEN, 'private essay', 'synthetic@invalid.test', 'private provider field', '"VERIFIED"']) {
    assert.ok(!JSON.stringify(result).includes(forbidden));
  }
});
test('explicit unsubmitted response is negative, not an exception', async () => {
  serve({ ...submission(), workflow_state: 'unsubmitted', score: null, graded_at: null });
  const result = await client().readRequirement(SCOPE);
  assert.equal(result.assertion.completed, false);
  assert.equal(result.assertion.score_percent, null);
});
for (const [label, patch] of [['stale grade', { grade_matches_current_submission: false }],
  ['excused assignment', { excused: true }], ['ungraded resubmission', { workflow_state: 'submitted' }]]) {
  test(`${label} cannot produce a passing score`, async () => {
    serve({ ...submission(), ...patch });
    const result = await client().readRequirement(SCOPE);
    assert.equal(result.assertion.score, null); assert.equal(result.assertion.score_percent, null);
  });
}
for (const [score, maximum, percent] of [[0, 20, 0], [25, 20, 125], [-1, 20, -5], ['18.5', '20', 92.5], [0, 0, null]]) {
  test(`score normalization ${score}/${maximum}`, async () => {
    serve({ ...submission(), score }, { ...assignment(), points_possible: maximum });
    assert.equal((await client().readRequirement(SCOPE)).assertion.score_percent, percent);
  });
}
test('module completion uses student state rather than active module workflow', async () => {
  fixture.setHandler((_req, res) => json(res, { id: '42', workflow_state: 'active', state: 'completed', completed_at: null }));
  const result = await client().readRequirement({ factType: 'canvas.module_completion', courseId: '17', moduleId: '42', userId: '29' });
  assert.equal(fixture.seen[0].url, '/api/v1/courses/17/modules/42?student_id=29');
  assert.equal(result.assertion.completed, true);
  assert.equal(result.assertion.provider_state, 'completed');
});
for (const state of ['locked', 'unlocked', 'started']) test(`module ${state} is a confirmed negative`, async () => {
  fixture.setHandler((_req, res) => json(res, { id: 42, workflow_state: 'active', state, completed_at: null }));
  assert.equal((await client().readRequirement({ factType: 'canvas.module_completion', courseId: '17', moduleId: '42', userId: '29' })).assertion.completed, false);
});
for (const [required, completed, expected] of [[3, 3, true], [3, 2, false], [0, 0, false], [3, 4, true]]) {
  test(`course completion ${completed}/${required}`, async () => {
    fixture.setHandler((_req, res) => json(res, { requirement_count: required, requirement_completed_count: completed, completed_at: null,
      next_requirement_url: 'https://untrusted.invalid/not-followed' }));
    const result = await client().readRequirement({ factType: 'canvas.course_completion', courseId: '17', userId: '29' });
    assert.equal(fixture.seen[0].url, '/api/v1/courses/17/users/29/progress');
    assert.equal(result.assertion.completed, expected);
    assert.ok(!JSON.stringify(result).includes('untrusted.invalid'));
  });
}
for (const [field, value] of [['user_id', '99'], ['assignment_id', '99'], ['course_id', '99'], ['user_id', 9007199254740992]]) {
  test(`submission binding rejects ${field} mismatch before denominator fetch`, async () => {
    serve({ ...submission(), [field]: value });
    await assert.rejects(client().readRequirement(SCOPE), error('resource_binding_mismatch'));
    assert.equal(fixture.seen.length, 1);
  });
}
for (const patch of [{ id: '99' }, { course_id: '99' }]) test(`assignment binding rejects ${JSON.stringify(patch)}`, async () => {
  serve(submission(), { ...assignment(), ...patch });
  await assert.rejects(client().readRequirement(SCOPE), error('resource_binding_mismatch'));
});
test('embedded assignment cannot replace authoritative exact assignment read', async () => {
  serve({ ...submission(), assignment: { id: '99', course_id: '17', points_possible: 1 } });
  assert.equal((await client().readRequirement(SCOPE)).assertion.score_percent, 90);
  assert.equal(fixture.seen.length, 2);
});
for (const id of ['..', '1/2', '%2f', 'self', 'sis_user_id:a', '', '01', '-1', '0', '18446744073709551616', 9007199254740992]) {
  test(`invalid resource identity is rejected: ${JSON.stringify(id)}`, async () => {
    serve();
    await assert.rejects(client().readRequirement({ ...SCOPE, userId: id }), error('invalid_resource_id'));
    assert.equal(fixture.seen.length, 0);
  });
}
test('64-bit Canvas identifiers retain their exact string representation', async () => {
  const userId = '9007199254740993';
  fixture.setHandler((req, res) => json(res, req.url.includes('/submissions/') ? { ...submission(), user_id: userId } : assignment()));
  const result = await client().readRequirement({ ...SCOPE, userId });
  assert.equal(result.scope.user_id, userId);
  assert.ok(fixture.seen[0].url.endsWith(userId));
});
for (const extra of [{ url: '/internal/anything' }, { headers: { Authorization: 'other' } },
  { organizationId: 'other' }, { accessToken: 'other' }, { method: 'POST' }, { moduleId: '42' }]) {
  test(`caller cannot override request authority: ${Object.keys(extra)[0]}`, async () => {
    serve();
    await assert.rejects(client().readRequirement({ ...SCOPE, ...extra }), error('invalid_requirement'));
    assert.equal(fixture.seen.length, 0);
  });
}
for (const status of [301, 302, 303, 307, 308]) test(`Canvas redirect ${status} is never followed`, async () => {
  fixture.setHandler((_req, res) => { res.writeHead(status, { Location: 'https://example.invalid/collect' }); res.end(); });
  await assert.rejects(client().readRequirement(SCOPE), error('redirect_denied'));
  assert.equal(fixture.seen.length, 1);
});
for (const [status, code] of [[401, 'reauthorization_required'], [403, 'access_denied'], [404, 'resource_unavailable'],
  [429, 'rate_limited'], [500, 'provider_unavailable'], [503, 'provider_unavailable'], [204, 'unexpected_status'], [206, 'unexpected_status']]) {
  test(`HTTP ${status} is an error, never a negative observation or an automatic retry`, async () => {
    fixture.setHandler((_req, res) => json(res, { errors: [TOKEN] }, status));
    await assert.rejects(client().readRequirement(SCOPE), actual => { error(code)(actual); assert.equal(actual.status, status); return true; });
    assert.equal(fixture.seen.length, 1);
  });
}
for (const [header, expected] of [['12', 12], ['9999999999', 86400], ['-1', undefined], ['token-private', undefined], ['1.5', undefined]]) {
  test(`bounded Retry-After ${header}`, async () => {
    fixture.setHandler((_req, res) => json(res, { error: TOKEN }, 429, { 'Retry-After': header }));
    await assert.rejects(client().readRequirement(SCOPE), actual => {
      error('rate_limited')(actual); assert.equal(actual.retryAfterSeconds, expected); return true;
    });
  });
}
test('Retry-After accepts bounded HTTP dates', async () => {
  fixture.setHandler((_req, res) => json(res, {}, 429, { 'Retry-After': new Date(Date.now() + 10000).toUTCString() }));
  await assert.rejects(client().readRequirement(SCOPE), actual => { error('rate_limited')(actual); assert.ok(actual.retryAfterSeconds >= 9 && actual.retryAfterSeconds <= 10); return true; });
});
test('denominator failure cannot publish an already read score', async () => {
  fixture.setHandler((req, res) => json(res, req.url.includes('/submissions/') ? submission() : {}, req.url.includes('/submissions/') ? 200 : 503));
  await assert.rejects(client().readRequirement(SCOPE), error('provider_unavailable'));
  assert.equal(fixture.seen.length, 2);
});
test('TLS trust and hostname checks run before credentials are sent', async () => {
  serve();
  await assert.rejects(client({ ca: undefined }).readRequirement(SCOPE), error('transport_error'));
  await assert.rejects(client({ canvasOrigin: fixture.origin.replace('localhost', '127.0.0.1') }).readRequirement(SCOPE), error('transport_error'));
  assert.equal(fixture.seen.length, 0);
});
test('private DNS answers require explicit exact operator allowlisting', async () => {
  serve();
  await assert.rejects(client({ allowedPrivateAddresses: [] }).readRequirement(SCOPE), error('address_denied'));
  assert.equal(fixture.seen.length, 0);
});
test('absolute deadline covers slow response body and cancels the request', async () => {
  fixture.setHandler((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
    const interval = setInterval(() => res.write(' '), 10);
    res.on('close', () => clearInterval(interval));
  });
  await assert.rejects(client({ timeoutMs: 80 }).readRequirement(SCOPE), error('timeout'));
});
test('one deadline spans both submission and assignment requests', async () => {
  fixture.setHandler((req, res) => {
    const timer = setTimeout(() => json(res, req.url.includes('/submissions/') ? submission() : assignment()), 250);
    res.on('close', () => clearTimeout(timer));
  });
  await assert.rejects(client({ timeoutMs: 400 }).readRequirement(SCOPE), error('timeout'));
  assert.equal(fixture.seen.length, 2);
});
test('aborted DNS scope cannot start a request', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(resolveAddress(fixture.origin, ['127.0.0.1'], controller.signal), error('timeout'));
});
test('response bytes and pagination are bounded', async () => {
  fixture.setHandler((_req, res) => json(res, { text: 'x'.repeat(4000) }));
  await assert.rejects(client({ maxResponseBytes: 128 }).readRequirement(SCOPE), error('response_too_large'));
  fixture.setHandler((_req, res) => json(res, submission(), 200, { Link: '<https://untrusted.invalid/>; rel="next"' }));
  await assert.rejects(client().readRequirement(SCOPE), error('unexpected_pagination'));
  assert.equal(fixture.seen.length, 1);
});
for (const [type, encoding, body, code] of [['text/html', undefined, 'login', 'invalid_content_type'],
  ['application/json;charset=iso-8859-1', undefined, '{}', 'invalid_content_type'],
  ['application/json', 'gzip', '{}', 'invalid_content_type'], ['application/json', undefined, '{', 'invalid_json'],
  ['application/json', undefined, Buffer.from([0xff]), 'invalid_json'], ['application/json', undefined, '[]', 'invalid_payload']]) {
  test(`invalid response ${type}/${encoding ?? 'identity'}/${code}`, async () => {
    fixture.setHandler((_req, res) => { res.writeHead(200, { 'Content-Type': type, ...(encoding ? { 'Content-Encoding': encoding } : {}) }); res.end(body); });
    await assert.rejects(client().readRequirement(SCOPE), error(code));
  });
}
const plan = prepareRequirement(SCOPE);
for (const [label, record, denominator, code = 'invalid_payload'] of [
  ['empty', {}, assignment(), 'invalid_payload'],
  ['provider errors', { errors: ['private'] }, assignment()],
  ['unknown state', { ...submission(), workflow_state: 'future-state' }, assignment()],
  ['missing score', { ...submission(), score: undefined }, assignment()],
  ['invalid score', { ...submission(), score: 'Infinity' }, assignment()],
  ['boolean score', { ...submission(), score: true }, assignment()],
  ['missing current-grade flag', { ...submission(), grade_matches_current_submission: undefined }, assignment()],
  ['bad excused flag', { ...submission(), excused: 'false' }, assignment()],
  ['missing denominator', submission(), { ...assignment(), points_possible: null }],
  ['negative denominator', submission(), { ...assignment(), points_possible: -20 }],
  ['invalid timestamp', { ...submission(), graded_at: '2026-02-30T12:00:00Z' }, assignment()],
  ['missing timezone', { ...submission(), graded_at: '2026-11-01T12:00:00' }, assignment()],
  ['nonfinite ratio', { ...submission(), score: 1e308 }, { ...assignment(), points_possible: 1e-300 }],
]) test(`malformed ${label} is not evidence`, () => {
  assert.throws(() => normalizeObservation(plan, record, denominator, 'https://canvas.example.test'), error(code));
});
for (const [factType, record, extra, code] of [
  ['canvas.module_completion', { id: '42', workflow_state: 'active' }, { moduleId: '42' }, 'invalid_payload'],
  ['canvas.module_completion', { id: '42', state: 'started', completed_at: '2026-11-01T12:00:00Z' }, { moduleId: '42' }, 'inconsistent_completion'],
  ['canvas.module_completion', { id: '42', state: 'completed', workflow_state: 'deleted' }, { moduleId: '42' }, 'resource_unavailable'],
  ['canvas.course_completion', { requirement_count: '3', requirement_completed_count: 3 }, {}, 'invalid_payload'],
  ['canvas.course_completion', { requirement_count: 3 }, {}, 'invalid_payload'],
  ['canvas.course_completion', { requirement_count: 3, requirement_completed_count: -1 }, {}, 'invalid_payload'],
  ['canvas.course_completion', { requirement_count: 3, requirement_completed_count: 2, completed_at: '2026-11-01T12:00:00Z' }, {}, 'inconsistent_completion'],
]) test(`invalid ${factType}/${code}/${JSON.stringify(record)}`, () => {
  assert.throws(() => normalizeObservation(prepareRequirement({ factType, courseId: '17', userId: '29', ...extra }), record, undefined, 'https://canvas.example.test'), error(code));
});
for (const address of ['127.0.0.1', '10.0.0.1', '172.16.0.2', '192.168.1.1', '169.254.169.254', '100.100.100.200',
  'fd00:ec2::254', 'fd00:ec2::23', '0.0.0.0', '224.0.0.1', '255.255.255.255', '192.0.2.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1',
  '2001:db8::1', '2002:7f00:1::', '64:ff9b::7f00:1']) {
  test(`default network policy denies ${address}`, () => {
    assert.throws(() => validateAddresses([{ address, family: address.includes(':') ? 6 : 4 }]), error('address_denied'));
  });
}
test('public and private DNS mixture fails closed', () => {
  assert.throws(() => validateAddresses([{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]), error('address_denied'));
});
test('exact allowlist permits self-managed addresses but never metadata or CIDRs', () => {
  assert.deepEqual(validateAddresses([{ address: '10.0.0.5', family: 4 }], approvedPrivateAddresses(['10.0.0.5'])), { address: '10.0.0.5', family: 4 });
  for (const bad of [['169.254.169.254'], ['10.0.0.0/8'], ['100.100.100.200'], ['::ffff:127.0.0.1'], ['fd00:ec2::254'], ['fd00:0ec2:0:0:0:0:0:0254']]) assert.throws(() => approvedPrivateAddresses(bad), error('invalid_private_address_allowlist'));
});
test('public addresses remain valid', () => {
  for (const [address, family] of [['8.8.8.8', 4], ['2606:4700:4700::1111', 6]]) assert.deepEqual(validateAddresses([{ address, family }]), { address, family });
});
test('socket lookup is pinned to the reviewed hostname and address', () => {
  const value = { address: '8.8.8.8', family: 4 };
  const pinned = pinnedLookup('canvas.example.test', value);
  value.address = '127.0.0.1';
  pinned('canvas.example.test', {}, (err, address, family) => { assert.equal(err, null); assert.equal(address, '8.8.8.8'); assert.equal(family, 4); });
  pinned('canvas.example.test', { all: true }, (err, records) => { assert.equal(err, null); assert.deepEqual(records, [{ address: '8.8.8.8', family: 4 }]); });
  pinned('other.example.test', {}, actual => error('address_denied')(actual));
});
for (const origin of ['http://canvas.example.test', 'https://user:pass@canvas.example.test', 'https://canvas.example.test/path',
  'https://canvas.example.test/?secret=x', 'https://canvas.example.test/#x', 'https://canvas.example.test\\@evil.test',
  'https://gateway:8000', 'https://issuance:8000', 'https://postgres', 'https://x.svc.cluster.local', ' https://canvas.example.test',
  'https://canvas.example.test/%2e%2e', 'https://api.svc.cluster.local.']) {
  test(`reject noncanonical/provider-bypass origin ${origin}`, () => assert.throws(() => canvasOrigin(origin), error('invalid_canvas_origin')));
}
test('configuration cannot inject a transport, headers or Gateway authority', () => {
  for (const extra of [{ apiKey: TOKEN }, { gatewayOrigin: fixture.origin }, { request: () => {} }, { headers: {} },
    { rejectUnauthorized: false }, { lookup: () => {} }, { accessToken: 'bad\nvalue' }]) {
    assert.throws(() => client(extra), error(Object.hasOwn(extra, 'accessToken') ? 'invalid_access_token' : 'invalid_configuration'));
  }
  assert.equal(JSON.stringify(client()), '{}');
});
test('configuration getters are not executed', () => {
  let executed = false;
  assert.throws(() => createCanvasRestReader({ get canvasOrigin() { executed = true; return fixture.origin; } }), error('invalid_configuration'));
  assert.equal(executed, false);
});


test('truncated bodies fail without producing an observation', async () => {
  fixture.setHandler((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 1000 });
    res.write('{"assignment_id":"31"');
    setImmediate(() => res.destroy());
  });
  await assert.rejects(client().readRequirement(SCOPE), actual => {
    assert.ok(['transport_error', 'invalid_json'].includes(actual.code)); return true;
  });
});
test('request scope is snapshotted before asynchronous I/O', async () => {
  serve();
  const input = { ...SCOPE };
  const reading = client().readRequirement(input);
  input.userId = '999'; input.courseId = '999'; input.activityId = '999';
  const observation = await reading;
  assert.equal(observation.scope.user_id, '29');
  assert.ok(fixture.seen.every(req => !req.url.includes('999')));
});
test('unsupported provider facts cannot dispatch HTTP', async () => {
  serve();
  await assert.rejects(client().readRequirement({ ...SCOPE, factType: 'canvas.issue_credential' }), error('unsupported_fact_type'));
  assert.equal(fixture.seen.length, 0);
});

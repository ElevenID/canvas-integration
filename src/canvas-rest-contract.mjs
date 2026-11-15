// SPDX-License-Identifier: AGPL-3.0-only
// Provider observations only. No core EvidenceFact, approval, or signing authority.
export class CanvasReadError extends Error {
  constructor(code, status, retryAfterSeconds) {
    super(`Canvas evidence read failed: ${code}`);
    this.name = 'CanvasReadError';
    this.code = code;
    if (status !== undefined) this.status = status;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}
export const fail = code => { throw new CanvasReadError(code); };
export function exactRecord(value, allowed, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.includes(key)
        || !('value' in Object.getOwnPropertyDescriptor(value, key))) fail(code);
  }
}
export function canvasId(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('invalid_resource_id');
    value = String(value);
  }
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value)
      || BigInt(value) > 18446744073709551615n) fail('invalid_resource_id');
  return value;
}
export function prepareRequirement(input) {
  exactRecord(input, ['factType', 'courseId', 'userId', 'activityId', 'moduleId'], 'invalid_requirement');
  const { factType } = input;
  const scope = { course_id: canvasId(input.courseId), user_id: canvasId(input.userId) };
  let path;
  let assignmentPath;
  if (factType === 'canvas.assignment_score' || factType === 'canvas.quiz_score') {
    if (input.moduleId !== undefined) fail('invalid_requirement');
    scope.activity_id = canvasId(input.activityId);
    assignmentPath = `/api/v1/courses/${scope.course_id}/assignments/${scope.activity_id}`;
    path = `${assignmentPath}/submissions/${scope.user_id}`;
  } else if (factType === 'canvas.module_completion') {
    if (input.activityId !== undefined) fail('invalid_requirement');
    scope.module_id = canvasId(input.moduleId);
    path = `/api/v1/courses/${scope.course_id}/modules/${scope.module_id}?student_id=${scope.user_id}`;
  } else if (factType === 'canvas.course_completion') {
    if (input.activityId !== undefined || input.moduleId !== undefined) fail('invalid_requirement');
    path = `/api/v1/courses/${scope.course_id}/users/${scope.user_id}/progress`;
  } else fail('unsupported_fact_type');
  return Object.freeze({ factType, scope: Object.freeze(scope), path, assignmentPath });
}
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length === 0 || Object.hasOwn(value, 'errors') || Object.hasOwn(value, 'error')) fail('invalid_payload');
}
function bound(value, expected) {
  let id;
  try { id = canvasId(value); } catch { fail('resource_binding_mismatch'); }
  if (id !== expected) fail('resource_binding_mismatch');
}
function optionalBinding(record, key, expected) {
  if (Object.hasOwn(record, key)) bound(record[key], expected);
}
export function validateSubmission(record, scope) {
  object(record);
  bound(record.assignment_id, scope.activity_id);
  bound(record.user_id, scope.user_id);
  optionalBinding(record, 'course_id', scope.course_id);
}
function numeric(value) {
  if (typeof value === 'string' && /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(value)) value = Number(value);
  if (typeof value !== 'number' || !Number.isFinite(value)) fail('invalid_payload');
  return value;
}
function timestamp(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') fail('invalid_payload');
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (!match) fail('invalid_payload');
  const [y, m, d, h, minute, second, oh, om] = match.slice(1).map(value => Number(value ?? 0));
  const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
  if (y < 1000 || m < 1 || m > 12 || d < 1 || d > days || h > 23 || minute > 59 || second > 59 || oh > 23 || om > 59) fail('invalid_payload');
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail('invalid_payload');
  return new Date(parsed).toISOString();
}
function booleanField(record, key, fallback) {
  if (!Object.hasOwn(record, key)) return fallback;
  if (typeof record[key] !== 'boolean') fail('invalid_payload');
  return record[key];
}
/** Normalize a complete successful read. Errors must never be converted to negative facts. */
export function normalizeObservation(plan, record, assignment, canvasOrigin) {
  object(record);
  const assertion = { completed: false, score: null, score_maximum: null, score_percent: null,
    provider_state: null, requirement_count: null, requirement_completed_count: null };
  const payload = {};
  let effectiveAt = null;
  if (plan.assignmentPath) {
    validateSubmission(record, plan.scope);
    object(assignment);
    bound(assignment.id, plan.scope.activity_id);
    bound(assignment.course_id, plan.scope.course_id);
    const state = record.workflow_state;
    if (!['unsubmitted', 'submitted', 'pending_review', 'graded'].includes(state)) fail('invalid_payload');
    const maximum = numeric(assignment.points_possible);
    if (maximum < 0) fail('invalid_payload');
    const excused = booleanField(record, 'excused', false);
    const current = booleanField(record, 'grade_matches_current_submission', undefined);
    const rawScore = record.score === null ? null : numeric(record.score);
    if (rawScore !== null && current === undefined) fail('invalid_payload');
    // Excused/stale/ungraded work cannot provide a passing score.
    const score = state === 'graded' && !excused && current === true ? rawScore : null;
    const percent = score === null || maximum === 0 ? null : score / maximum * 100;
    if (percent !== null && !Number.isFinite(percent)) fail('invalid_payload');
    Object.assign(assertion, { completed: state !== 'unsubmitted' && !excused,
      score, score_maximum: maximum, score_percent: percent, provider_state: state });
    Object.assign(payload, { assignment_id: plan.scope.activity_id, score, points_possible: maximum,
      workflow_state: state, excused, grade_matches_current_submission: current ?? null });
    for (const key of ['graded_at', 'submitted_at', 'updated_at']) {
      const value = timestamp(record[key]);
      if (value !== null) { payload[key] = value; effectiveAt ??= value; }
    }
  } else if (plan.factType === 'canvas.module_completion') {
    bound(record.id, plan.scope.module_id);
    optionalBinding(record, 'course_id', plan.scope.course_id);
    optionalBinding(record, 'student_id', plan.scope.user_id);
    // workflow_state='active' is the module lifecycle, NOT learner progress.
    if (!['locked', 'unlocked', 'started', 'completed'].includes(record.state)) fail('invalid_payload');
    if (record.workflow_state !== undefined && record.workflow_state !== 'active') fail('resource_unavailable');
    const completedAt = timestamp(record.completed_at);
    if (completedAt !== null && record.state !== 'completed') fail('inconsistent_completion');
    assertion.completed = record.state === 'completed';
    assertion.provider_state = record.state;
    Object.assign(payload, { id: plan.scope.module_id, state: record.state, completed_at: completedAt });
    effectiveAt = completedAt;
  } else {
    optionalBinding(record, 'course_id', plan.scope.course_id);
    optionalBinding(record, 'user_id', plan.scope.user_id);
    const required = record.requirement_count;
    const completed = record.requirement_completed_count;
    if (!Number.isSafeInteger(required) || required < 0 || !Number.isSafeInteger(completed) || completed < 0) fail('invalid_payload');
    assertion.completed = required > 0 && completed >= required;
    const completedAt = timestamp(record.completed_at);
    if (completedAt !== null && !assertion.completed) fail('inconsistent_completion');
    assertion.requirement_count = required;
    assertion.requirement_completed_count = completed;
    Object.assign(payload, { requirement_count: required, requirement_completed_count: completed, completed_at: completedAt });
    effectiveAt = completedAt;
  }
  // Whitelist output: no submission body, learner names/emails, tokens or provider URLs.
  return Object.freeze({ schema: 'elevenid.canvas-rest-observation/v1', source: 'canvas_rest',
    fact_type: plan.factType, canvas_origin: canvasOrigin, scope: plan.scope,
    assertion: Object.freeze(assertion), source_payload: Object.freeze(payload),
    verification_method: 'CANVAS_OAUTH_API_READ', observed_at: new Date().toISOString(), effective_at: effectiveAt });
}

# Public Gateway ownership client

`src/gateway-ownership-client.mjs` is a server-only adapter for Core's generic
application-ownership API. It is not mounted in the connector listener yet.
The corresponding Core implementation is on
`marty-ui/feat/external-application-association`; it must be qualified and merged
before this client can use the API on a deployed Gateway. The adapter has no
fallback to the legacy provider-coupled bootstrap or private service paths.

The constructor accepts a fixed HTTPS Gateway origin, configured administrator
Origin, one session-cookie name, optional private CA and one absolute deadline.
There is no URL, transport, header or credential override. Requests can invoke
only `propose`, `confirm`, `revoke`, `inspect` or `receipt` for a bounded canonical
application identifier under the public Gateway ownership namespace.

Before every operation, the adapter reads `/v1/auth/me` through the Gateway.
It derives the organization and actor from that authenticated session, then
checks the same session again before returning a result. Actor or tenant changes
suppress disclosure. An optional organization-intent header is compared with
the canonical session; it cannot select a tenant. Caller identity headers and
other cookies are never forwarded. Incoming producer API keys or Authorization
headers are rejected. No Canvas credential or organization API key is used by
this client.

Core independently requires `application:manage-ownership` for proposal and
revocation. Confirmation is limited to the proposed authenticated user. This
client does not grant a permission, infer ownership from provider identifiers,
create an application or copy canonical subject/application authority into
connector storage. Fresh ownership and historical receipts remain distinct
typed results. Neither grants provider association or evidence authority.

For writes, the caller supplies and retains the original operation UUID and
revision preconditions before dispatch. Every failed or malformed post-dispatch
result is conservatively `ownership_commit_unknown`, including permission loss,
deadline, redirects and a changed session after commit. No write is automatically
retried. Reconcile the original operation; do not generate a replacement UUID.

Receipt recovery takes the expected original action and resulting revision as
local metadata. These expectations are checked against the receipt and never
sent to the strict Core API:

```js
const result = await client.execute(incoming, {
  applicationId: 'application-one', action: 'receipt',
  body: { operation_id: originalOperationId },
  expectedReceipt: { action: 'propose', revision: originalExpectedRevision + 1 },
});
```

Verified TLS, redirect rejection, response size/framing bounds, strict original
JSON decoding and an absolute timeout apply across the complete session/read or
mutation/session sequence. Mutations additionally require a matching original
receipt action, application, operation and resulting revision. The adapter keeps
no authority cache, session store or automatic application/binding selection.

Local HTTPS tests cover fixed paths and cookie isolation, rejected authority and
credential fields, lost committed replies, exact receipt recovery, wrong receipt
version/action/application, current/history substitution, final actor/tenant
changes, deadline, redirect and malformed responses. These synthetic Gateway
peers qualify the client wire contract, not the real identity provider or a
deployed Core. Full Gateway/connector browser composition, canonical learner
consent, approved-source challenges and existing-AWS end-to-end qualification
remain in the active split goal.

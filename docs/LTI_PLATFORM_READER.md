# Canvas LTI trust and fresh platform keys

`src/canvas-lti-platform.mjs` extracts provider trust selection and JWKS acquisition
from Core into the independent connector. It is an internal server-only component;
no package export, route, database migration, automatic registration or deployment
activation is added. Existing Core callers remain until the complete replacement
is qualified and migrated.

An operator selects `hosted_global` with an explicit `production`, `beta` or `test`
environment. Issuer, authorization endpoint and JWKS URI are fixed to Canvas's
documented environment-specific services. Recognized Instructure hostnames cannot
be paired with a conflicting environment. Custom hosted domains require the
operator's explicit environment; no unsigned login parameter selects it.

`self_managed_same_origin` requires an exact origin in a separate server-owned
allowlist. All endpoints and issuer remain on that origin. Operators must configure
the self-hosted Canvas issuer in `config/security.yml`; a self-hosted instance that
still claims the hosted-global issuer will fail validation. The allowlist approves
the origin, while private-IP access separately requires explicit approved addresses.

Registration captures client/deployment/target and trusted additional audiences
before any await. Requests accept only the original token and server-held nonce.
Every validation resolves and checks all DNS answers, pins the selected address,
performs a fresh verified-TLS GET to the fixed JWKS path and validates the JWT with
the trusted registration. No metadata/discovery URL or JWT-specified endpoint is
followed. There are no retries or cached keys. Canvas tokens, Marty API keys, session
cookies and the launch token are never sent to the JWKS endpoint.

The entire call has one absolute deadline across DNS, TLS, bounded streaming and
validation, with an elapsed-time check after cryptographic work. Redirects, encoded
bodies, pagination, invalid UTF-8 and responses above128KiB fail closed. Strict JSON
and public-key validation are delegated to the resource-link verifier. Transport
failure reports `canvas_lti_platform_unavailable`; invalid launches/keys report
`invalid_lti_launch`. Errors never reflect tokens, configuration or key contents.

This reader intentionally does not consume a nonce. A repeated valid token can
pass the primitive again. Before enabling an endpoint, the adapter must enforce
current registration/revision, expiring durable login state, browser binding,
atomic nonce consumption and a stable receipt. Successful protocol authentication
provides no canonical Marty subject, grant, evidence verification or issuance
authority. All subsequent Marty operations must use the public Common Gateway.

References read November16,2026:

- [Canvas registration](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.lti_dev_key_config): hosted production/beta/test JWKS endpoints.
- [Canvas launch overview](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.lti_launch_overview): issuer, self-hosted issuer configuration, environment-specific authorization endpoints and browser state requirements.
- [LTI security framework](https://www.imsglobal.org/spec/security/v1p1#authentication-response-validation): trusted issuer, signature, audience, time and nonce validation.

Synthetic HTTPS tests cover fixed credential-free paths, fresh key reads, captured
registration/request inputs, wrong issuer, JWT-directed discovery denial,
redirect/status/type/encoding/size/UTF-8/ambiguous-key failures, private DNS denial,
untrusted TLS and stalled/trickling deadlines. Actual hosted Canvas registration,
deployed Gateway/learner association and network isolation remain unqualified.

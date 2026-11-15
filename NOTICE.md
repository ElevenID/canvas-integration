# Source provenance

The operation names, public URL shapes, allowed write fields and list response
normalization in `src/operations.mjs` and `src/gateway-client.mjs` are adapted
from ElevenID/marty-ui `ui/src/services/canvasIntegrationsApi.js`, Git blob
`72c90987ddd08f7443c5aa0bd4f6aa4ef361fdee`, reviewed on 2026-11-15.
The original source is available in that repository, including at commit
`8ff6cefaa2856ab8a00be7e449981198943960dd`.

The source repository and this repository carry the same AGPL version 3 license
file (Git blob `0ad25db4bd1d86c452db3f9602ccdbe172438f52`). Existing notices and
licenses remain applicable. No unrelated repository history, customer data,
private deployment records or credential material has been imported.

This is a deliberately reduced, server-side compatibility client, not a copy
of the complete Canvas implementation. Unknown response shapes fail instead
of silently producing an empty list. Approval, signing, secret management,
OAuth callbacks, correction-review writes, and mirror batch controls are not
exported. The original console module remains in Marty-ui until replacement
UI and provider behavior are independently qualified.

## REST provider extraction baseline (2026-11-15)

The route selection, exact assignment denominator read, normalized observation
concept and negative-observation/error distinction in `src/canvas-rest-*.mjs`
are adapted from these Marty-ui files at commit
`58ec9e79150e6a1d05af061445d4c761cce42e8e`:

- `rust/services/issuance/src/canvas_sync_provider_http.rs`, blob
  `98784a7363b9669e95022fd739101fcb3294b384` (REST read/provider boundary).
- `rust/services/issuance/src/canvas_sync_processor.rs`, blob
  `d2565f6aa88726a9c36117fc1256f0a9822406ef` (observation/assertion projection).

The standalone JavaScript implementation imports none of those files, crates,
repositories, signing/OAuth services or database models. Instructure's public
REST contracts are referenced in `docs/REST_PROVIDER.md`. That document records
intentional stricter validation and module-state/grade corrections; no complete
legacy parity or production cutover is claimed. Existing AGPL notices remain
applicable. The original implementation and historical oracles are retained.

## OAuth lifecycle extraction baseline (2026-11-15)

The Canvas OAuth authorization-code state machine, capability/scope mapping,
configuration-version checks, secret-reference lifecycle and token refresh
semantics in `src/canvas-oauth*.mjs` are adapted from ElevenID/marty-ui at
commit `58ec9e79150e6a1d05af061445d4c761cce42e8e`:

- `rust/services/issuance/src/canvas_oauth.rs`, blob
  `fbf1769cd3da2ee38e64ab275d748e16647a65d2` (OAuth lifecycle and capability
  allowlist).
- `rust/services/issuance/src/canvas_oauth_postgres.rs`, blob
  `954db9139de460e096f774d66905baf0c54ce610` (existing durable state,
  one-time authorization consumption, refresh/revocation lease patterns).

The connector implementation is an independent JavaScript adaptation. It does
not import those Rust files or crates and does not use Marty database tables,
integration-secret vaults, service credentials or private HTTP routes. It
replaces the old core-owned secret references with connector-owned vault
references. Existing AGPL notices remain applicable; the original implementation
and historical tests are retained in Marty-ui pending independent qualification.

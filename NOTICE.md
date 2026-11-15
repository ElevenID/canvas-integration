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

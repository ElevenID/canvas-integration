# Contributing

Use a branch and pull request. Run `npm run check` from a clean checkout.
Preserve AGPL source notices. Keep fixtures synthetic; generated TLS keys belong
only in temporary test directories. Do not check in environment files or logs.

The public Common Gateway/API-key boundary is mandatory. New operations require
an explicit route, scope, request/response contract and negative authorization
tests. New dependencies and runtime modules require review of the architecture
gate. Never relax the gate just to make a test pass. Existing customer-visible
behavior must be qualified before retiring its previous implementation.

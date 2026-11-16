# LTI resource-link validation extraction

`src/canvas-lti-launch.mjs` is an internal, network-free Node22 primitive. It
authenticates a Canvas LTI1.3 resource-link message using a caller-supplied trusted
registration, original nonce, clock and fresh platform JWKS text. It imports only
public RSA components, fixes RS256/PKCS1 signatures, rejects ambiguous encodings,
duplicate JSON members/key IDs, private key material and JWT-directed discovery.

Exact issuer/client/deployment/target and nonce comparisons precede returning
minimal frozen protocol identifiers. Additional audiences require an explicit
registration allowlist and matching `azp`. Expiry and not-before are strict. The
connector's launch age policy is five minutes with 30 seconds of future issued-at
tolerance; the platform's longer expiration does not extend that age. JWTs are
bounded to64KiB, JWKS to128KiB/32keys, JSON depth16 and RSA2048–8192bits. Anonymous
launches and other message types, including Deep Linking, are unsupported here.
Unknown payload claims are ignored; roles/names/email/service URLs are not returned.
Nonempty roles must contain a standard AppendixA principal or sub-role, with
custom role URIs allowed alongside it; empty roles are valid. Identifiers use a
connector policy of nonempty visible ASCII without spaces, at most255characters;
this is stricter than LTI's general ASCII compatibility allowance. Deprecated
simple-name/URN role aliases are unsupported. These restrictions must be checked
against real Canvas registrations before deployment.

This primitive is not connected to the HTTPS runtime or exported from the package.
It does not fetch JWKS, consume a nonce or authenticate a browser. The internal
[platform reader](LTI_PLATFORM_READER.md) adds server-selected trust profiles and
fresh pinned DNS/TLS key acquisition. The next stateful adapter must own current
registration revisions, durable expiring
login state, browser binding and atomic consume/receipt semantics before enabling
an endpoint. A successful call alone must never create a session or evidence.
Canvas `sub` remains a provider identifier; learner association requires a separate
canonical Marty identity flow through the public Gateway. Roles are not Marty
permissions. No Core database, internal service, evidence verification, approval,
signing or issuance operation is introduced. Existing Core LTI code remains until
the replacement is qualified and callers/deployment wiring migrate.

Implementation references read November16,2026:

- [1EdTech security framework1.1 §5.1.3](https://www.imsglobal.org/spec/security/v1p1#authentication-response-validation): signature, issuer/audience/authorized party, expiry, issued-at and nonce checks. Launch age is a connector policy allowed by this section.
- [LTI1.3 §4.3 and §5.3–5.4](https://www.imsglobal.org/spec/lti/v1p3): forward-compatible claims, resource-link message/version/deployment/target/resource/subject/roles/context semantics.
- [Canvas registration](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.lti_dev_key_config): deployment IDs and production/beta/test platform JWKS endpoints. Registration/discovery extraction is still pending.
- [Node22 crypto](https://nodejs.org/docs/latest-v22.x/api/crypto.html): public JWK import, modulus inspection and explicit RSA PKCS1 signature verification. CI's exact Node22 image remains authoritative.

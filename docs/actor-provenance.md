# Actor provenance

The passwordless flow now exposes a structural model for preserving authorization provenance across delegated work.

## Evidence path

`HumanProof → IntentProof → DelegationProof → ActorChain → WorkloadProof → ActionEvidence`

- **Human proof** references the WebAuthn verification result.
- **Intent proof** identifies the exact operation authorized by the human.
- **Delegation proof** records the grant from one actor to the next.
- **Actor chain** records ordered participants without packing the chain into OAuth `sub`.
- **Workload proof** references workload identity evidence, such as mTLS peer identity.
- **Action evidence** records the operation, intent, actor chain, workload actor, outcome and time.

DPoP key-possession evidence should be represented as its own evidence envelope and verified by the OAuth authorization boundary; it is deliberately not treated as a substitute for WebAuthn, delegation policy, or workload identity.

## API

Import `ProvenanceBundle`, `ProvenancePolicy`, and `validateProvenanceStructure` from the package entry point. The validator checks shape, unique evidence IDs, evidence references, allowed kinds, timestamps, actor uniqueness and hop limits.

The validator is **not** a cryptographic verifier. Before authorizing an action, the runtime must separately validate WebAuthn signatures and challenges, OAuth audience/scope and expiry, DPoP binding and nonce/replay rules, delegation constraints, mTLS/workload identity, revocation, and any channel/session binding required by policy. Never store private keys, raw access tokens, or magic-link secrets in evidence artifacts; use immutable references or digests.

## Security invariants

1. Authentication, authorization, session protection and action evidence are separate concerns.
2. A successful WebAuthn operation does not automatically authorize arbitrary actions.
3. The actor chain is bounded by both the bundle and local policy hop limits.
4. Each action references the exact intent and actor-chain IDs used for authorization.
5. Cryptographic verification must happen before a structurally valid bundle is trusted.
6. Use separate key domains for client attestation and DPoP by default; document any deliberate exception.
7. Keep algorithm and evidence version metadata explicit to support crypto-agility.

## Scope

This change adds types and structural validation only. It does not claim to implement OAuth Actor Chain, DPoP, client attestation, mTLS, condition-bound keys, or post-quantum cryptography. Experimental drafts must not become production dependencies without a separate protocol review.

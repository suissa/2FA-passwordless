/**
 * Actor provenance for delegated passwordless workflows.
 *
 * These structures describe evidence; they do not themselves verify WebAuthn,
 * DPoP, mTLS, OAuth tokens, or signatures. Bind each evidence reference to a
 * cryptographic verifier at the runtime boundary before authorizing an action.
 */

export type EvidenceRef = string & { readonly __evidence_ref__: unique symbol };
export type ActorKind = "human" | "intent" | "agent" | "workload" | "service";
export type ProofKind =
  | "webauthn"
  | "intent"
  | "delegation"
  | "dpop"
  | "mtls"
  | "workload-identity"
  | "action";

export interface EvidenceEnvelope {
  readonly id: EvidenceRef;
  readonly kind: ProofKind;
  readonly issuedAt: string;
  readonly expiresAt?: string;
  /** Digest or immutable store reference; never place private keys or bearer tokens here. */
  readonly artifactRef: string;
  readonly algorithm?: string;
  readonly version: number;
}

export interface ActorRecord {
  readonly actorId: string;
  readonly kind: ActorKind;
  /** Identity of the immediate actor, not a serialized actor chain. */
  readonly subject: string;
  readonly evidence: EvidenceRef;
}

export interface ActorChain {
  readonly chainId: string;
  readonly actors: readonly ActorRecord[];
  readonly createdAt: string;
  readonly maxHops: number;
}

export interface AuthorizationProvenance {
  readonly humanProof: EvidenceRef;
  readonly intentProof: EvidenceRef;
  readonly delegationProof: EvidenceRef;
  readonly actorChain: ActorChain;
  readonly workloadProof: EvidenceRef;
}

export interface ActionEvidence {
  readonly actionId: string;
  readonly actionType: string;
  readonly intentId: string;
  readonly actorChainId: string;
  readonly workloadActorId: string;
  readonly outcome: "allowed" | "denied" | "failed";
  readonly occurredAt: string;
  readonly evidence: EvidenceRef;
}

export interface ProvenanceBundle {
  readonly evidence: readonly EvidenceEnvelope[];
  readonly authorization: AuthorizationProvenance;
  readonly action: ActionEvidence;
}

export interface ProvenancePolicy {
  readonly maxHops: number;
  readonly allowedActorKinds: readonly ActorKind[];
  readonly allowedProofKinds: readonly ProofKind[];
}

/**
 * Performs structural and referential validation only. Cryptographic proof
 * validation, expiry policy, revocation, audience, nonce and channel binding
 * must be checked by dedicated WebAuthn/OAuth/DPoP/mTLS verifiers.
 */
export function validateProvenanceStructure(
  bundle: ProvenanceBundle,
  policy: ProvenancePolicy,
): void {
  const { evidence, authorization, action } = bundle;
  if (!Number.isInteger(policy.maxHops) || policy.maxHops < 1) {
    throw new Error("Provenance policy maxHops must be a positive integer");
  }

  const evidenceById = new Map<string, EvidenceEnvelope>();
  for (const item of evidence) {
    if (!item.id || evidenceById.has(item.id)) {
      throw new Error("Evidence IDs must be non-empty and unique");
    }
    if (!Number.isInteger(item.version) || item.version < 1) {
      throw new Error(`Invalid evidence version: ${item.id}`);
    }
    if (!Number.isFinite(Date.parse(item.issuedAt))) {
      throw new Error(`Invalid evidence issuedAt: ${item.id}`);
    }
    if (item.expiresAt && !Number.isFinite(Date.parse(item.expiresAt))) {
      throw new Error(`Invalid evidence expiresAt: ${item.id}`);
    }
    if (!item.artifactRef.trim()) {
      throw new Error(`Evidence artifactRef is required: ${item.id}`);
    }
    if (!policy.allowedProofKinds.includes(item.kind)) {
      throw new Error(`Proof kind is not allowed: ${item.kind}`);
    }
    evidenceById.set(item.id, item);
  }

  const requireEvidence = (id: EvidenceRef, expected: ProofKind): void => {
    const item = evidenceById.get(id);
    if (!item) throw new Error(`Missing evidence: ${id}`);
    if (item.kind !== expected) {
      throw new Error(`Evidence ${id} must have kind ${expected}`);
    }
  };

  requireEvidence(authorization.humanProof, "webauthn");
  requireEvidence(authorization.intentProof, "intent");
  requireEvidence(authorization.delegationProof, "delegation");
  requireEvidence(authorization.workloadProof, "workload-identity");
  requireEvidence(action.evidence, "action");

  const chain = authorization.actorChain;
  if (!chain.chainId || !Number.isInteger(chain.maxHops) || chain.maxHops < 1) {
    throw new Error("Actor chain requires an ID and a positive maxHops");
  }
  if (chain.maxHops > policy.maxHops || chain.actors.length > chain.maxHops) {
    throw new Error("Actor chain exceeds the configured hop limit");
  }
  if (chain.actors.length === 0) throw new Error("Actor chain cannot be empty");
  if (!Number.isFinite(Date.parse(chain.createdAt))) {
    throw new Error("Actor chain createdAt must be an ISO-compatible date");
  }

  const actorIds = new Set<string>();
  for (const actor of chain.actors) {
    if (!actor.actorId || !actor.subject) {
      throw new Error("Each actor requires actorId and subject");
    }
    if (actorIds.has(actor.actorId)) {
      throw new Error(`Duplicate actorId in chain: ${actor.actorId}`);
    }
    actorIds.add(actor.actorId);
    if (!policy.allowedActorKinds.includes(actor.kind)) {
      throw new Error(`Actor kind is not allowed: ${actor.kind}`);
    }
    if (!evidenceById.has(actor.evidence)) {
      throw new Error(`Actor references missing evidence: ${actor.evidence}`);
    }
  }

  if (action.actorChainId !== chain.chainId) {
    throw new Error("Action evidence references a different actor chain");
  }
  if (!actorIds.has(action.workloadActorId)) {
    throw new Error("Action workloadActorId must exist in the actor chain");
  }
  if (!action.actionId || !action.actionType || !action.intentId) {
    throw new Error("Action evidence requires actionId, actionType and intentId");
  }
  if (!Number.isFinite(Date.parse(action.occurredAt))) {
    throw new Error("Action occurredAt must be an ISO-compatible date");
  }
}

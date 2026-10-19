import test from "node:test";
import assert from "node:assert/strict";
import {
  validateProvenanceStructure,
  type EvidenceRef,
  type ProvenanceBundle,
  type ProvenancePolicy,
} from "../src/provenance.ts";

const ref = (value: string) => value as EvidenceRef;
const policy: ProvenancePolicy = {
  maxHops: 4,
  allowedActorKinds: ["human", "intent", "agent", "workload", "service"],
  allowedProofKinds: [
    "webauthn", "intent", "delegation", "dpop", "mtls",
    "workload-identity", "action",
  ],
};

function fixture(): ProvenanceBundle {
  const evidence = [
    ["human-proof", "webauthn"],
    ["intent-proof", "intent"],
    ["delegation-proof", "delegation"],
    ["workload-proof", "workload-identity"],
    ["action-proof", "action"],
  ] as const;
  return {
    evidence: evidence.map(([id, kind]) => ({
      id: ref(id), kind, issuedAt: "2026-10-19T12:00:00.000Z",
      artifactRef: `sha256:${id}`, version: 1,
    })),
    authorization: {
      humanProof: ref("human-proof"),
      intentProof: ref("intent-proof"),
      delegationProof: ref("delegation-proof"),
      workloadProof: ref("workload-proof"),
      actorChain: {
        chainId: "chain-1",
        createdAt: "2026-10-19T12:00:00.000Z",
        maxHops: 3,
        actors: [
          { actorId: "human-1", kind: "human", subject: "person:opaque-1", evidence: ref("human-proof") },
          { actorId: "agent-1", kind: "agent", subject: "agent:opaque-1", evidence: ref("delegation-proof") },
          { actorId: "workload-1", kind: "workload", subject: "workload:opaque-1", evidence: ref("workload-proof") },
        ],
      },
    },
    action: {
      actionId: "action-1", actionType: "read-record", intentId: "intent-1",
      actorChainId: "chain-1", workloadActorId: "workload-1",
      outcome: "allowed", occurredAt: "2026-10-19T12:00:01.000Z",
      evidence: ref("action-proof"),
    },
  };
}

test("accepts a structurally valid bounded provenance bundle", () => {
  assert.doesNotThrow(() => validateProvenanceStructure(fixture(), policy));
});

test("rejects duplicate evidence IDs", () => {
  const bundle = fixture();
  assert.throws(() => validateProvenanceStructure({
    ...bundle, evidence: [...bundle.evidence, bundle.evidence[0]],
  }, policy), /unique/);
});

test("rejects actor chains over policy limit", () => {
  const bundle = fixture();
  assert.throws(() => validateProvenanceStructure({
    ...bundle,
    authorization: {
      ...bundle.authorization,
      actorChain: { ...bundle.authorization.actorChain, maxHops: 5 },
    },
  }, policy), /hop limit/);
});

test("rejects action evidence bound to another chain", () => {
  const bundle = fixture();
  assert.throws(() => validateProvenanceStructure({
    ...bundle, action: { ...bundle.action, actorChainId: "different-chain" },
  }, policy), /different actor chain/);
});

test("rejects references to missing required evidence", () => {
  const bundle = fixture();
  assert.throws(() => validateProvenanceStructure({
    ...bundle,
    authorization: { ...bundle.authorization, humanProof: ref("missing") },
  }, policy), /Missing evidence/);
});

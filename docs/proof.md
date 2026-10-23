---
title: VXP Proof
description: The signed chain that records what was asked, approved, executed and read back, and how anyone verifies it.
---

## What it records

Each operation produces a chain of signed statements. Each statement names the previous one by its digest,
and is signed by the role that observed it ([[proof|§6]]):

| `kind` | Signed by | What it records |
|---|---|---|
| `request` | operator | What was asked, and by which agent (`client_id`) |
| `terms` | company | Each revision: the digest of the exact terms, the commitment (`firm` or `conditional`), the expiry, what will be read back |
| `counter` | operator | A counter-proposal from the agent |
| `user_approval` | operator | Approval of the latest revision, and its method |
| `company_review` | company | A decision by a person at the company, when its rule requires one |
| `execution` | operator | The single execution, on the approved revision |
| `read_back` | operator | What the company's system showed afterwards, term by term |
| `outcome` | company | `succeeded`, `failed`, `cancelled`, `expired` or `unknown` |
| `correction`, `revocation` | company | What became known after the final state |

Here is the chain the reference implementation produced in a native-only run:

<!--json:prove.chain title="Proof chain (payload bodies, processed)"-->

## The rules that make it worth something

- **Binding by digest** ([[P1]]): approval, execution and outcome all cite the digest of the exact
  revision. Terms that change after approval no longer match.
- **No success without reading the system** ([[P6]], [[O7]]): a capability that cannot be read back never
  signs `succeeded`.
- **Unknown is signed, not hidden** ([[P3]]): if it is not known whether the effect happened, the company
  signs `unknown`, and a later fact goes in as a `correction` ([[P4]]).
- **Contradictions stop** ([[P5]]): if the system shows something other than what was approved, the
  read-back says so, the result stays `unknown`, and nothing is retried.
- **The verifier derives the level** ([[P7]]): the issuer never declares how strong its own evidence is.

## Formats

- One SD-JWT per statement (RFC 9901), ES256, header `typ: vxp-stmt+sd-jwt` and `kid` = RFC 7638 thumbprint.
- Payload in JCS (RFC 8785). Personal data travels only as selective disclosures.
- The trust members, meaning whose keys these are, where they are published, who holds the company's key and
  which log is used, are published in the issuer's RFC 8414 metadata as `vxp_proof`, never inside the package.

Details: [[proof-statement-format|§6, format]], [[proof-chain-rules|§6, chain rules]].

## Fetching a proof

In the native profile, the agent fetches the package of its own request:

```http title="Fetch the proof"
GET /v1/requests/{request_id}/proof
Authorization: DPoP <token>
DPoP: <proof>
```

The package is `{v, company, op, statements[], log}`. Someone else's request and a missing one answer the
same way: `404 request_not_found`.

## Verifying a proof

Anyone can verify a package with the company's public material: the issuer's metadata and the key sets it
names. The [verifier guide](guides/verifier.md) shows how, offline or live. This is the verdict for the chain
above:

<!--json:prove.verdict title="Verifier verdict"-->

Read it with the table in [[reading-a-verdict|§10, reading a verdict]]:
- `valid` is integrity;
- `company`, `anchor` and `key_source` are provenance;
- `approval` is the method of approval;
- `final_state` is what the company asserts;
- `derived_assurance`, `single_root` and `logged` are how much supports it.

Here `single_root: operator` and `logged: false`: an attestation signed by the operator, intact and ordered,
not an independent confirmation.

## Keys and time

Proofs are only as durable as the keys that verify them. Keep proof keys persistent. When you rotate, keep
the earlier public key published for as long as proofs signed with it are to be verified ([[key-rotation|§10, key rotation]]).
A proof whose key was retired still verifies against public material saved while that key was published.

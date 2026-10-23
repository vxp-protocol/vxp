# VXP Proof

> The signed chain that records what was asked, approved, executed and read back, and how anyone verifies it.

## What it records

Each operation produces a chain of signed statements. Each statement names the previous one by its digest,
and is signed by the role that observed it ([§6](https://vxpprotocol.org/spec/#proof)):

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

```json
[
  {
    "seq": 0,
    "kind": "request",
    "signer": "operator",
    "prev": null,
    "body": {
      "channel": "vxp",
      "client_id": "https://agent.example/agent.json",
      "request_digest": "sha-256:mfJleoso5oEyt_pqJS3OtbmYam7cyncRBrAcqbKfIrI"
    }
  },
  {
    "seq": 1,
    "kind": "terms",
    "signer": "company",
    "prev": "sha-256:kAO5f-JoCSonqCQnG_1vki1T01wmqh4wDS5YK74U0v4",
    "body": {
      "capability": "pedido.reprogramar_despacho",
      "commitment": {
        "mode": "firm",
        "requires": []
      },
      "company_review_required": false,
      "expires_at": "2026-10-22T22:45:29.356Z",
      "read_back_terms": [
        "pedido",
        "despacho_nuevo"
      ],
      "revision": 1,
      "terms_digest": "sha-256:LexccQ2IrXTwkx-zM3KJ3m2Sf5-YHsqzs-po_QCxAC0",
      "user_approval_required": true
    }
  },
  {
    "seq": 2,
    "kind": "user_approval",
    "signer": "operator",
    "prev": "sha-256:lCNrubnR6MLwUhwhcNUCWaqAKxFGOVWIlx3Rafs8v08",
    "body": {
      "method": "agent_asserted",
      "revision": 1,
      "terms_digest": "sha-256:LexccQ2IrXTwkx-zM3KJ3m2Sf5-YHsqzs-po_QCxAC0"
    }
  },
  {
    "seq": 3,
    "kind": "execution",
    "signer": "operator",
    "prev": "sha-256:wk4J9m_VE1zzlLhc1QEZ7l3m7USokQiF9gtICMNft5U",
    "body": {
      "attempt": 1,
      "capability": "pedido.reprogramar_despacho",
      "release": "sha-256:u1TBBxJXTKta36K5UI_j_myhQaHzbPP2HcF4rBKGxPA",
      "revision": 1,
      "terms_digest": "sha-256:LexccQ2IrXTwkx-zM3KJ3m2Sf5-YHsqzs-po_QCxAC0"
    }
  },
  {
    "seq": 4,
    "kind": "read_back",
    "signer": "operator",
    "prev": "sha-256:Gs2GOu4azZ6aE1VaKjm2Edj91Zya-VP4zP9Fbc71VJw",
    "body": {
      "matches_terms": true,
      "method": "system_read_back",
      "observed": {
        "_sd": [
          "g1MZFKspn_fcTPBy5COpYIVc6rPjeQYv9bF7QBCrv5g"
        ],
        "despacho_nuevo": "2026-10-28",
        "pedido": "P-1042"
      },
      "source": "company_system"
    }
  },
  {
    "seq": 5,
    "kind": "outcome",
    "signer": "company",
    "prev": "sha-256:jfSCFRNR4QjvnD9VjmaNWdhfAg4ftVxMWy5xLrrT6Jo",
    "body": {
      "claimed_assurance": [
        "issuer_key_attested",
        "operator_observed",
        "operator_reported_read_back",
        "operator_reported_agent_approval"
      ],
      "result_summary_digest": "sha-256:aKs3uy77c1osgD7qSgTqNJ0_YITroc5iwoYHqFmSl6s",
      "revision": 1,
      "state": "succeeded",
      "terms_digest": "sha-256:LexccQ2IrXTwkx-zM3KJ3m2Sf5-YHsqzs-po_QCxAC0",
      "third_party": []
    }
  }
]
```

## The rules that make it worth something

- **Binding by digest** ([P1](https://vxpprotocol.org/spec/#p1)): approval, execution and outcome all cite the digest of the exact
  revision. Terms that change after approval no longer match.
- **No success without reading the system** ([P6](https://vxpprotocol.org/spec/#p6), [O7](https://vxpprotocol.org/spec/#o7)): a capability that cannot be read back never
  signs `succeeded`.
- **Unknown is signed, not hidden** ([P3](https://vxpprotocol.org/spec/#p3)): if it is not known whether the effect happened, the company
  signs `unknown`, and a later fact goes in as a `correction` ([P4](https://vxpprotocol.org/spec/#p4)).
- **Contradictions stop** ([P5](https://vxpprotocol.org/spec/#p5)): if the system shows something other than what was approved, the
  read-back says so, the result stays `unknown`, and nothing is retried.
- **The verifier derives the level** ([P7](https://vxpprotocol.org/spec/#p7)): the issuer never declares how strong its own evidence is.

## Formats

- One SD-JWT per statement (RFC 9901), ES256, header `typ: vxp-stmt+sd-jwt` and `kid` = RFC 7638 thumbprint.
- Payload in JCS (RFC 8785). Personal data travels only as selective disclosures.
- The trust members, meaning whose keys these are, where they are published, who holds the company's key and
  which log is used, are published in the issuer's RFC 8414 metadata as `vxp_proof`, never inside the package.

Details: [§6, format](https://vxpprotocol.org/spec/#proof-statement-format), [§6, chain rules](https://vxpprotocol.org/spec/#proof-chain-rules).

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
names. The [verifier guide](https://vxpprotocol.org/docs/guides/verifier/) shows how, offline or live. This is the verdict for the chain
above:

```json
{
  "valid": true,
  "final_state": "succeeded",
  "revision": 1,
  "approval": "agent_asserted",
  "derived_assurance": [
    "issuer_key_attested",
    "operator_observed",
    "operator_reported_read_back",
    "operator_reported_agent_approval"
  ],
  "single_root": "operator",
  "custody_declared": "operator_hosted",
  "logged": false,
  "company": "https://store.example/e/ferreteria-demo",
  "anchor": "issuer",
  "key_source": "issuer_metadata_live",
  "profile": "issuer",
  "statements": 6,
  "log_inclusion": "ok",
  "tree_size": 6,
  "live_tree_size": 6,
  "consistency": "ok",
  "witnesses": 0,
  "operation": "matches"
}
```

Read it with the table in [§10, reading a verdict](https://vxpprotocol.org/spec/#reading-a-verdict):
- `valid` is integrity;
- `company`, `anchor` and `key_source` are provenance;
- `approval` is the method of approval;
- `final_state` is what the company asserts;
- `derived_assurance`, `single_root` and `logged` are how much supports it.

Here `single_root: operator` and `logged: false`: an attestation signed by the operator, intact and ordered,
not an independent confirmation.

## Keys and time

Proofs are only as durable as the keys that verify them. Keep proof keys persistent. When you rotate, keep
the earlier public key published for as long as proofs signed with it are to be verified ([§10, key rotation](https://vxpprotocol.org/spec/#key-rotation)).
A proof whose key was retired still verifies against public material saved while that key was published.

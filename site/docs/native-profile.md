# Native profile and discovery

> How an agent finds a company that speaks VXP, identifies itself, gets authority for one request, and drives an operation through the /v1 endpoints.

The native profile is VXP's own way to carry an operation. It needs neither Poppy nor PACT ([§8, native-only gateway](https://vxpprotocol.org/spec/#native-only)).
It is **experimental**, and `vxp.json` says so with `"status": "experimental"`.

## 1. Discover

The agent fetches `https://<company domain>/.well-known/vxp.json` ([§8, discovery](https://vxpprotocol.org/spec/#native-discovery)):

```json
{
  "protocol": "vxp",
  "version": "0.1",
  "organization": {
    "name": "Ferretería Demo",
    "domain": "store.example"
  },
  "issuer": "https://store.example/e/ferreteria-demo",
  "endpoint": "https://store.example/e/ferreteria-demo/v1",
  "capabilities": [
    {
      "id": "pedido.consultar",
      "effect": "read",
      "access": "delegated",
      "admission": "static",
      "authorization_details_type": "https://vxpprotocol.org/rar/capability"
    },
    {
      "id": "pedido.reprogramar_despacho",
      "effect": "write",
      "access": "delegated",
      "admission": "dynamic",
      "authorization_details_type": "https://vxpprotocol.org/rar/capability",
      "commitment_modes": [
        "firm",
        "conditional"
      ],
      "outcome_proof": true
    }
  ],
  "limits": {
    "max_revisions": 3,
    "proposal_ttl_seconds": 900,
    "max_accept_attempts": 3
  },
  "outcome_proof": {
    "version": "0.1",
    "trust": "issuer_metadata"
  },
  "status": "experimental",
  "vxp": {
    "version": "0.1",
    "relationship": {
      "authorization_details_type": "https://vxpprotocol.org/rar/relationship",
      "company_initiated_actions": [
        "despacho.proponer_cambio",
        "incidencia.avisar",
        "alerta.confirmar_o_bloquear"
      ]
    },
    "proof": {
      "trust": "issuer_metadata"
    }
  }
}
```

- `organization.domain` must be the host that served the document.
- `issuer` is the company's issuer; its RFC 8414 metadata lives at
  `/.well-known/oauth-authorization-server` + the issuer path, and its `issuer` must match character by
  character.
- `capabilities` lists only what the company offers to external agents. `access` is `public` or
  `delegated`; `admission` is `static` (the grant is enough) or `dynamic` (decided per request: owner,
  precondition, policy).
- `vxp.json` never carries keys. The verifier takes them from the issuer metadata (`vxp_proof`).

VXP has no global registry of companies. An agent starts from domains it already knows, or that the
person names.

## 2. Identify

The agent is an OAuth client identified by a Client ID Metadata Document at its own `client_id` URL, with
its JWKS. It authenticates with `private_key_jwt` and binds its token to a DPoP key (RFC 9449, ES256). The
user ID it holds for the person travels as an RFC 7523 assertion, and every native request carries
`resource` = the `endpoint` from `vxp.json` (RFC 8707) ([§8, authorization](https://vxpprotocol.org/spec/#native-authorization)).

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
  "client_id": "https://agent.example/agent.json",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "eyJhbGciOi…",
  "assertion": "eyJhbGciOi…"
}
```

## 3. Get authority for this request

Asking without authority is safe: the company holds the request and says exactly what is missing ([O2](https://vxpprotocol.org/spec/#o2)).

```json
{
  "request_id": "req_eSTKa7J-MERu",
  "operation": "pedido.reprogramar_despacho",
  "target": {
    "order_ref": "P-1042"
  },
  "state": "authorization_required",
  "projections": {
    "poppy": null,
    "a2a": "TASK_STATE_AUTH_REQUIRED"
  },
  "authorization": {
    "error": "authorization_required",
    "authorization_details": [
      {
        "type": "https://vxpprotocol.org/rar/capability",
        "actions": [
          "pedido.reprogramar_despacho"
        ],
        "identifier": "P-1042"
      }
    ],
    "device_authorization_endpoint": "https://store.example/e/ferreteria-demo/oauth/device",
    "resource": "https://store.example/e/ferreteria-demo/v1"
  }
}
```

The agent starts a device authorization (RFC 8628) with those `authorization_details` (RFC 9396). The person
approves on the company's own page, after linking their account through an authentication the company
controls ([ID1](https://vxpprotocol.org/spec/#id1)). The token that follows carries exactly what was granted ([O2](https://vxpprotocol.org/spec/#o2)).

## 4. Keep the context

The agent repeats the same request, with the same `Idempotency-Key`. It is the same request, re-evaluated
with the new authority ([§8, idempotency](https://vxpprotocol.org/spec/#native-idempotency)):

```json
{
  "request_id": "req_eSTKa7J-MERu",
  "state": "proposed",
  "projections": {
    "poppy": "proposed",
    "a2a": "TASK_STATE_INPUT_REQUIRED"
  },
  "operation_id": "op_XzdILOmlgiae"
}
```

- Same key and same body: the same request. Same key and another body: `409 idempotency_key_reused`.
- No key: `400 idempotency_key_required`.

## 5. Operate

The company answers with a proposal: a revision with exact terms, signed into the proof, and its commitment
([§8, commitment](https://vxpprotocol.org/spec/#commitment)).

```json
{
  "id": "prop_op_XzdILOmlgiae_r1",
  "revision": 1,
  "state": "proposed",
  "summary": "Cambiar el despacho del pedido P-1042 (Taladro percutor 800 W) del 2026-10-24 al 2026-10-28, a Calle Ejemplo 100, Santiago, sin costo.",
  "terms": {
    "pedido": "P-1042",
    "producto": "Taladro percutor 800 W",
    "despacho_actual": "2026-10-24",
    "despacho_nuevo": "2026-10-28",
    "direccion": "Calle Ejemplo 100, Santiago",
    "costo": {
      "amount": "0",
      "currency": "CLP"
    },
    "vxp_salt": "hRQxNKbVg-MdR_aCsFbHYQ"
  },
  "commitment": {
    "mode": "firm",
    "requires": []
  },
  "expires_at": "2026-10-22T22:45:29.356Z",
  "user_approval_required": true,
  "limits": {
    "max_revisions": 3,
    "revisions_left": 2,
    "max_accept_attempts": 3,
    "accept_attempts_left": 3
  }
}
```

The agent may counter (`POST /v1/proposals/{id}/counter`), which produces a new revision. Accepting a
superseded revision gets `409 terms_changed` and runs nothing ([O4](https://vxpprotocol.org/spec/#o4)). Accepting the current one runs it
**once** ([O6](https://vxpprotocol.org/spec/#o6)), and success is declared only after the company reads its system back ([O7](https://vxpprotocol.org/spec/#o7)):

```http title="Accept the current revision"
POST /v1/proposals/{proposal_id}/accept
Authorization: DPoP <token>
DPoP: <proof>
Content-Type: application/json

{ "approved_by": "user" }
```

`approved_by: "user"` is the agent stating that the person approved: the proof records it as
`agent_asserted` ([P2](https://vxpprotocol.org/spec/#p2)).

## 6. Prove, and keep the relationship

`GET /v1/requests/{id}/proof` returns the package (see [VXP Proof](https://vxpprotocol.org/docs/proof/)). If the person also approved a
relationship, the company can later start a request toward the agent (see [VXP Relationship](https://vxpprotocol.org/docs/relationship/)).

## Endpoints

| Method and path | What it does |
|---|---|
| `POST /v1/requests` | Create a request `{operation, target, parameters}`, with `Idempotency-Key` |
| `GET /v1/requests/{id}` | State, projections, proposal, effects, result, `proof_url` |
| `GET /v1/requests/{id}/events` | Transitions |
| `POST /v1/requests/{id}/cancel` | Ask to stop ([§8, cancellation](https://vxpprotocol.org/spec/#cancellation)) |
| `GET /v1/requests/{id}/proof` | The proof package |
| `POST /v1/proposals/{id}/accept` | Accept that revision |
| `POST /v1/proposals/{id}/counter` | Counter-proposal |
| `GET`, `DELETE /v1/relationships/{id}` | Read or revoke the agent's relationship |
| `POST /v1/relationships/{id}/replies` | Answer a closed question ([R17](https://vxpprotocol.org/spec/#r17)) |

All of them take `Authorization: DPoP` and a DPoP proof. Full responses and errors:
[§8, endpoints](https://vxpprotocol.org/spec/#native-endpoints).

## States

Inside, a request moves through `received`, `authorization_required`, `proposed`, `accepted`,
`waiting_human`, `executing`, `pending_verification` and the final `succeeded`, `failed`, `cancelled` and
`expired` ([E1](https://vxpprotocol.org/spec/#e1)). Each response also shows the projection onto Poppy's and A2A's enums ([E2](https://vxpprotocol.org/spec/#e2)). A request
never moves to `failed` while it is unknown whether its effect happened.

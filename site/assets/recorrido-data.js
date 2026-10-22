// Generado por captura/construir_datos.py desde captura/recorrido.json. No editar a mano.
export const RECORRIDO = {
 "captured": "2026-10-22, evening run",
 "source": "Reference implementation (reference/), native-only gateway (no Poppy, no PACT), persistent keys, test company «Ferretería Demo»",
 "steps": [
  {
   "id": "discover",
   "request": "GET /.well-known/vxp.json",
   "response": {
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
  },
  {
   "id": "identify",
   "request": "POST /e/ferreteria-demo/oauth/token",
   "form": {
    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "client_id": "https://agent.example/agent.json",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": "eyJhbGciOi…",
    "assertion": "eyJhbGciOi…"
   },
   "headers": {
    "DPoP": "eyJ0eXAiOiJkcG9wK2p3dC…"
   },
   "response": {
    "access_token": "nt_UtuI…",
    "token_type": "DPoP",
    "expires_in": 3600
   }
  },
  {
   "id": "authority",
   "request": "POST /e/ferreteria-demo/v1/requests",
   "body": {
    "operation": "pedido.reprogramar_despacho",
    "target": {
     "order_ref": "P-1042"
    },
    "parameters": {
     "delivery_date": "2026-10-28"
    }
   },
   "response": {
    "request_id": "req_-vyAp7zx7DAE",
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
   },
   "device": {
    "authorization_details": "[{\"type\":\"https://vxpprotocol.org/rar/capability\",\"actions\":[\"pedido.reprogramar_despacho\"],\"identifier\":\"P-1042\"},{\"type\":\"https://vxpprotocol.org/rar/relationship\",\"actions\":[\"despacho.proponer_cambio\"],\"identifier\":\"relationship\",\"limits\":{\"max_per_day\":2,\"duration_seconds\":3600}}]"
   },
   "token": {
    "access_token": "nt_-dzl…",
    "token_type": "DPoP",
    "expires_in": 3600,
    "authorization_details": [
     {
      "type": "https://vxpprotocol.org/rar/capability",
      "actions": [
       "pedido.reprogramar_despacho"
      ],
      "identifier": "P-1042"
     }
    ],
    "relationships": [
     {
      "relationship_id": "rel_ayzZTfb3pINy",
      "state": "active",
      "actions": [
       "despacho.proponer_cambio"
      ],
      "limits": {
       "max_per_day": 2
      },
      "expires_at": "2026-10-22T23:09:52.000Z",
      "agreement": "eyJhbGciO…"
     }
    ]
   }
  },
  {
   "id": "context",
   "request": "POST /e/ferreteria-demo/v1/requests  (same Idempotency-Key)",
   "response": {
    "request_id": "req_-vyAp7zx7DAE",
    "state": "proposed",
    "projections": {
     "poppy": "proposed",
     "a2a": "TASK_STATE_INPUT_REQUIRED"
    },
    "operation_id": "op_aYpChVup-9Cw"
   }
  },
  {
   "id": "operate",
   "request": "POST /e/ferreteria-demo/v1/proposals/{id}/accept",
   "proposal": {
    "id": "prop_op_aYpChVup-9Cw_r1",
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
     "vxp_salt": "p2ej7qNL99V3o8lvKGQ2MA"
    },
    "commitment": {
     "mode": "firm",
     "requires": []
    },
    "expires_at": "2026-10-22T22:24:52.047Z",
    "user_approval_required": true,
    "limits": {
     "max_revisions": 3,
     "revisions_left": 2,
     "max_accept_attempts": 3,
     "accept_attempts_left": 3
    }
   },
   "body": {
    "approved_by": "user"
   }
  },
  {
   "id": "prove",
   "response": {
    "state": "succeeded",
    "effects": [
     {
      "system": "erp",
      "change": "despacho 2026-10-24 → 2026-10-28",
      "applied": true
     }
    ],
    "result": {
     "summary": "Listo: el pedido P-1042 se despacha el 2026-10-28 (antes 2026-10-24). Verificado en el sistema de Ferretería Demo.",
     "data": {
      "pedido": "P-1042",
      "despacho": "2026-10-28",
      "verificado": "lectura_del_sistema",
      "effects": [
       {
        "system": "erp",
        "change": "despacho 2026-10-24 → 2026-10-28",
        "applied": true
       }
      ]
     }
    },
    "reason": "read_back_matches",
    "proof_url": "https://store.example/e/ferreteria-demo/v1/requests/req_-vyAp7zx7DAE/proof"
   },
   "chain": [
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
     "prev": "sha-256:cqjp7_jwKGs9M62p1ve9doGfv3UH4c6bmsw_a-JEiD0",
     "body": {
      "capability": "pedido.reprogramar_despacho",
      "commitment": {
       "mode": "firm",
       "requires": []
      },
      "company_review_required": false,
      "expires_at": "2026-10-22T22:24:52.047Z",
      "read_back_terms": [
       "pedido",
       "despacho_nuevo"
      ],
      "revision": 1,
      "terms_digest": "sha-256:qGM1Z7pJRDYnsRlDNFA0RcuouxQLU9Eu9Fsa3H00I-I",
      "user_approval_required": true
     }
    },
    {
     "seq": 2,
     "kind": "user_approval",
     "signer": "operator",
     "prev": "sha-256:rn-zRY18ZNpTclvZWr45HXGMSw0YBzpbeo1O88oE8UI",
     "body": {
      "method": "agent_asserted",
      "revision": 1,
      "terms_digest": "sha-256:qGM1Z7pJRDYnsRlDNFA0RcuouxQLU9Eu9Fsa3H00I-I"
     }
    },
    {
     "seq": 3,
     "kind": "execution",
     "signer": "operator",
     "prev": "sha-256:N6SEdktNzLwm_tsJrxtjVEkg3PILszucEochXOxcIlY",
     "body": {
      "attempt": 1,
      "capability": "pedido.reprogramar_despacho",
      "release": "sha-256:u1TBBxJXTKta36K5UI_j_myhQaHzbPP2HcF4rBKGxPA",
      "revision": 1,
      "terms_digest": "sha-256:qGM1Z7pJRDYnsRlDNFA0RcuouxQLU9Eu9Fsa3H00I-I"
     }
    },
    {
     "seq": 4,
     "kind": "read_back",
     "signer": "operator",
     "prev": "sha-256:OpYdkWqWVTiASFXItE8Vo0d4IkD4vAeuPGvCBIfAkkk",
     "body": {
      "matches_terms": true,
      "method": "system_read_back",
      "observed": {
       "_sd": [
        "NFzOJz6ouQ75UiPZGE_mmLihy4yFL5L4Lu57b7reCg4"
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
     "prev": "sha-256:0bN89b_4AjQkH2sualzrsxn65lvMZ1EYxdjLyw5EMA8",
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
      "terms_digest": "sha-256:qGM1Z7pJRDYnsRlDNFA0RcuouxQLU9Eu9Fsa3H00I-I",
      "third_party": []
     }
    }
   ],
   "verdict": {
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
  },
  {
   "id": "relate",
   "relationship": {
    "relationship_id": "rel_ayzZTfb3pINy",
    "state": "active",
    "actions": [
     "despacho.proponer_cambio"
    ],
    "limits": {
     "max_per_day": 2
    },
    "expires_at": "2026-10-22T23:09:52.000Z",
    "agreement": "eyJhbGciO…"
   },
   "outbox": {
    "outbox_id": "out_wORHkFRMVtz6",
    "delivery": "entregado",
    "http": 202,
    "content": {
     "request_id": "req_E7B4ubQ9OKNH",
     "request_url": "https://store.example/e/ferreteria-demo/v1/requests/req_E7B4ubQ9OKNH",
     "proposal_id": "prop_op_Qz06acebNGWJ_r1",
     "operation_id": "op_Qz06acebNGWJ",
     "summary": "Cambiar el despacho del pedido P-1043 (Escalera de aluminio 6 peldaños) del 2026-10-27 al 2026-10-30, a Calle Ejemplo 100, Santiago, sin costo.",
     "terms_digest": "sha-256:x2gr6M6U_AmbsawG13Cj7pl3DUuetAxLpovH8sPjAxw"
    }
   },
   "accepted": {
    "state": "succeeded",
    "effects": [
     {
      "system": "erp",
      "change": "despacho 2026-10-27 → 2026-10-30",
      "applied": true
     }
    ],
    "reason": "read_back_matches"
   }
  }
 ]
};

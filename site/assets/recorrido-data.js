// Generado por captura/construir_datos.py desde captura/recorrido.json. No editar a mano.
export const RECORRIDO = {
 "captured": "2026-10-22",
 "source": "Reference implementation (reference/), native profile, test company «Ferretería Demo»",
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
    "access_token": "nt_6E1g…",
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
    "request_id": "req_AQFXz9wmuQpS",
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
    "access_token": "nt_hbbt…",
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
      "relationship_id": "rel_JFmlHKqmlCA7",
      "state": "active",
      "actions": [
       "despacho.proponer_cambio"
      ],
      "limits": {
       "max_per_day": 2
      },
      "expires_at": "2026-10-22T07:09:18.000Z",
      "agreement": "eyJhbGciO…"
     }
    ]
   }
  },
  {
   "id": "context",
   "request": "POST /e/ferreteria-demo/v1/requests  (same Idempotency-Key)",
   "response": {
    "request_id": "req_AQFXz9wmuQpS",
    "state": "proposed",
    "projections": {
     "poppy": "proposed",
     "a2a": "TASK_STATE_INPUT_REQUIRED"
    },
    "operation_id": "op_B6__ICZlCe_c"
   }
  },
  {
   "id": "operate",
   "request": "POST /e/ferreteria-demo/v1/proposals/{id}/accept",
   "proposal": {
    "id": "prop_op_B6__ICZlCe_c_r1",
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
     "vxp_salt": "bWCQmiSHNOYk-wXlrNRRSw"
    },
    "commitment": {
     "mode": "firm",
     "requires": []
    },
    "expires_at": "2026-10-22T06:24:18.141Z",
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
    "proof_url": "https://store.example/e/ferreteria-demo/v1/requests/req_AQFXz9wmuQpS/proof"
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
     "prev": "sha-256:oq0I675QY_V6b1b3FEjWtOQU5Aq92yhHUd0bBelTpdM",
     "body": {
      "capability": "pedido.reprogramar_despacho",
      "commitment": {
       "mode": "firm",
       "requires": []
      },
      "company_review_required": false,
      "expires_at": "2026-10-22T06:24:18.141Z",
      "read_back_terms": [
       "pedido",
       "despacho_nuevo"
      ],
      "revision": 1,
      "terms_digest": "sha-256:Bzey-n1cnkgQgkXMl7paOcbWV13hZ2LMgyWQd0lKDoE",
      "user_approval_required": true
     }
    },
    {
     "seq": 2,
     "kind": "user_approval",
     "signer": "operator",
     "prev": "sha-256:SJeiKmU1vdiXcKielWp9JoqvtQ_NY3MytuNOmqpW4e0",
     "body": {
      "method": "agent_asserted",
      "revision": 1,
      "terms_digest": "sha-256:Bzey-n1cnkgQgkXMl7paOcbWV13hZ2LMgyWQd0lKDoE"
     }
    },
    {
     "seq": 3,
     "kind": "execution",
     "signer": "operator",
     "prev": "sha-256:6Xnb9LZkwF9AY3TbmNSKBX37g7WnCecK6VyVrM9TU_I",
     "body": {
      "attempt": 1,
      "capability": "pedido.reprogramar_despacho",
      "release": "sha-256:u1TBBxJXTKta36K5UI_j_myhQaHzbPP2HcF4rBKGxPA",
      "revision": 1,
      "terms_digest": "sha-256:Bzey-n1cnkgQgkXMl7paOcbWV13hZ2LMgyWQd0lKDoE"
     }
    },
    {
     "seq": 4,
     "kind": "read_back",
     "signer": "operator",
     "prev": "sha-256:YODOxyFcs7NEMSud9v7eDJqGvptF9PCf4aGL6BEEPfM",
     "body": {
      "matches_terms": true,
      "method": "system_read_back",
      "observed": {
       "_sd": [
        "3dZK7r9IlLqVnsEb1FgqYMfInwyVFUSjhkgNh6Yu68w"
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
     "prev": "sha-256:wBMpHI0fyUske4OnhBHjSe-5m6377OQ6GIR5E4012Oc",
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
      "terms_digest": "sha-256:Bzey-n1cnkgQgkXMl7paOcbWV13hZ2LMgyWQd0lKDoE",
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
    "relationship_id": "rel_JFmlHKqmlCA7",
    "state": "active",
    "actions": [
     "despacho.proponer_cambio"
    ],
    "limits": {
     "max_per_day": 2
    },
    "expires_at": "2026-10-22T07:09:18.000Z",
    "agreement": "eyJhbGciO…"
   },
   "outbox": {
    "outbox_id": "out_fQu1FIVuaYQN",
    "delivery": "entregado",
    "http": 202,
    "content": {
     "request_id": "req_lXXONI2mL8vd",
     "request_url": "https://store.example/e/ferreteria-demo/v1/requests/req_lXXONI2mL8vd",
     "proposal_id": "prop_op_NBbN47CrhrtM_r1",
     "operation_id": "op_NBbN47CrhrtM",
     "summary": "Cambiar el despacho del pedido P-1043 (Escalera de aluminio 6 peldaños) del 2026-10-27 al 2026-10-30, a Calle Ejemplo 100, Santiago, sin costo.",
     "terms_digest": "sha-256:oduNxopNIIA-Iv1iqMDfnh_6QOQXtz0Zg6h34VN2z0g"
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

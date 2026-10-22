# VXP Proof web verifier: what it checks

`vxp-verify.js` is an independent implementation of the VXP Proof 0.1 verifier (VXP spec §4 and the normative annex §9, see `site/spec/index.html`). It runs in the browser and in Node ≥ 20 with no dependencies: WebCrypto (`crypto.subtle`) for ECDSA P-256/SHA-256 and HMAC, plus its own RFC 8785 (JCS) canonicalization. It gives the same verdicts and error codes as the reference verifier `verifier/verificar_paquete.py` (abbreviated `ref` below, with line numbers). It applies the same checks in the same order, so when an input breaks several rules, both report the same first failure.

It works only with public material that was downloaded beforehand (the reference's `material` mode) and never fetches anything over the network.

## API

| Function | Reference equivalent |
|---|---|
| `verifyPackage({package, material, operation?, aud?, receipt?, naming?})` | `verificar_paquete.py material ...` (ref:918-945, 1091-1107) |
| `verifyChain(statements, keys, company, custody?, {aud?, naming?})` | `verificar_cadena` (ref:377-547) |
| `verifyVectors(json)` | `verificar_paquete.py vectores` (ref:967-1046); returns the same report lines |
| `verifyPactVectors(json)` | `verificar_paquete.py pact` (ref:1049-1065) |
| `explain(verdict)` | returns one short pass/fail line per control (below) |
| `verdictJson(verdict)` | the exact JSON line the reference prints |

Inputs can be JSON text or JS values. Pass the text: the verifier then parses it with Python's `json` rules, which tell `1` apart from `1.0` and keep member order. `JSON.parse` loses both, and either one can change a verdict.

**Naming.** By default it uses the VXP identifiers of VXP spec §8.1 (`vxp-stmt+sd-jwt`, `vxp-checkpoint+jwt`, `vxp_proof`, `vxp_salt`, `vxpprotocol.org/proof`, `https://vxpprotocol.org/ext/proof/v0.1`). `naming: "legacy-0.1"` is an explicit, labeled mode for proofs issued before the 22-oct-2026 rename (`sovras-*`, `sovras_outcome_proof`, `sovras.io/outcome-proof`). It matches the pre-rename reference verifier (not published), which differs from the current one only in those identifiers. The verifier never guesses: with the wrong naming, a proof fails with `issuer_not_anchored`.

**One deliberate difference.** On some malformed inputs the reference raises an uncaught Python exception (traceback, exit 1) instead of an error code. In those cases this module returns `{valid: false, error: "malformed_input", seq: null, python_exception: "<Type>"}` at the same point.

## Controls, in verification order

Each row lists what the control proves and what it does **not** prove.

| # | Control | Reference | Proves | Does NOT prove |
|---|---|---|---|---|
| 1 | **Anchor** (`issuer_not_anchored`, `discovery_without_extension`, `no_anchor`) | ref:703-752, 646-700, 636-643 | The issuer and its keys come from an anchor the verifier knows on its own: the Poppy domain (`organization.domain` = host, `poppy_domains` lists it), the PACT brand domain or authorization server (bound in both directions), or a known issuer. The RFC 8414 metadata `issuer` must be identical. The trust block's `jwks_uri` must sit under the issuer, and the profile copy must equal the trust members. | That the company is who it claims to be in the real world, or that the domain owner is honest. It only proves the documents are consistent with each other and with the chosen anchor. |
| 2 | **Keys** | ref:800-804 | Company and operator JWKS come from the anchored metadata, never from the package (`key_source: issuer_metadata_live`). | That those keys were the ones in force when each statement was signed. 0.1 has no key history (SPEC 9.6). |
| 3 | **Package header** (`bad_version`, `company_mismatch`, `no_outcome`, `op_mismatch` with `seq: null`) | ref:921-931 | `v` is 0.1, `company` is the anchored issuer, `op` matches the chain, and there are statements. | Anything about the content. |
| 4 | **Statement format** (`not_sd_jwt`, `non_canonical_encoding`, `bad_header`, `duplicate_member`) | ref:329-353, 73-83, 131-141 | Compact SD-JWT with canonical unpadded base64url. Header `typ` = `vxp-stmt+sd-jwt`, `alg` = ES256, no `crit`. No duplicate JSON members. | Nothing semantic. |
| 5 | **Issuer and key** (`unknown_issuer`, `unknown_key`) | ref:354-360 | `iss` is the company or the operator. `kid` is in the anchored JWKS and is its RFC 7638 thumbprint. | Who controls that key. With `custody: operator_hosted`, the operator holds the company key. |
| 6 | **Signature** (`signature_invalid`) | ref:361, 148-159 | ES256 over `header.payload` verifies with that key. High-S signatures are accepted, as in the reference. The statement digest covers only `header.payload`, so a malleated signature leaves it unchanged (SPEC 9.2). | **A valid signature does not prove the statement is true.** It proves only that the keyholder signed those bytes. |
| 7 | **Canonical payload** (`non_canonical_payload`, `number_out_of_profile`, `lone_surrogate`) | ref:363, 94-118 | The payload bytes are exactly their JCS form (RFC 8785, profile 0.1: safe integers only, no floats). | — |
| 8 | **Role** (`role_mismatch`) | ref:365-366, 44-47 | Each kind is signed by its role: the company signs `terms`, `company_review`, `outcome`, `correction` and `revocation`; the operator signs `request`, `counter`, `user_approval`, `execution` and `read_back`. | That the company itself signed when its key is operator-hosted. |
| 9 | **Selective disclosure** (`bad_sd_alg`, `disclosure_*`, `weak_salt`, `sd_digest_repeated`, `bad_sd`) | ref:243-324 | RFC 9901 §7.1 processing. Only sha-256. Salts of at least 128 bits. No repeated digests or disclosures, no reserved names, no overwriting a claim, no unused disclosures. Each disclosed value goes back in its place. | Anything about undisclosed claims; decoy digests are ignored by design. |
| 10 | **Chain binding** (`bad_version`, `company_mismatch`, `op_mismatch`, `aud_mismatch`, `user_mismatch`, `seq_error`, `chain_broken`, `bad_body`) | ref:396-415 | Every statement has the same `v`, `company`, `op`, `aud` and `user`. `seq` is its position and `prev` is the digest of the previous statement. Optional `aud` pins the verifying agent (anti-replay). | That no statement was withheld after the last one; see control 15. |
| 11 | **Order** (`after_final`, `order_violation`) | ref:418-421, 432-459, 500-504 | `request` comes first and only first. Nothing but `read_back`, `correction` or `revocation` follows a final statement. Approval, review and execution appear only where the protocol allows. | — |
| 12 | **Terms and approval** (`revision_error`, `bad_terms`, `approval_not_latest_revision`, `approval_terms_mismatch`, `bad_approval_method`, `display_code_mismatch`, `bad_decision`) | ref:422-457 | Revisions are consecutive. The terms declare `company_review_required` and `read_back_terms`. The approval names the latest revision and its digest. For `company_channel`, `display_code` is derived from the terms digest (SPEC 6.3). | **That the user approved anything.** The approval is the operator's statement. |
| 13 | **Execution and read-back** (`execution_terms_mismatch`, `bad_read_back`) | ref:458-477 | The execution names the approved terms. It comes after the required company review, never after a denial. The read-back method and `matches_terms` are well-formed. | That the effect happened in the company system. |
| 14 | **Final state** (`outcome_terms_mismatch`, `bad_state`, `outcome_after_denial`, `succeeded_without_matching_read_back`, `read_back_incomplete`, `correction_without_read_back`, `no_outcome`) | ref:478-523, 370-374 | The outcome names the latest revision. `succeeded` needs an execution and a matching `system_read_back` that observes every term in `read_back_terms`. A correction to `succeeded` cites a later matching read-back. After a denial the only outcome allowed is `failed`. The current state is the **last** final statement. | That the observed values are true: the operator reports them. |
| 15 | **Transparency log** (`checkpoint_signature_invalid`, `log_origin_mismatch`, `log_inclusion_missing`, `log_bad_leaf`, `log_inclusion_failed`, `equivocation_detected`) | ref:820-865, 168-238 | If the package carries `log`, every statement has an RFC 9162 inclusion proof in a checkpoint signed by the anchored log key (`vxp-checkpoint+jwt`). The live checkpoint in the material is the same tree or a consistent extension of it. | That the log is honest or complete. **Without an external witness co-signature, `logged` stays `false`** (0.1 has no co-signature format; `witnesses` is reported as a count). A package with no `log` is reported as `log_inclusion: "absent"`, not as a failure. |
| 16 | **Operation match** (`operation_id_mismatch`, `operation_revision_unknown`, `operation_terms_mismatch`, `weak_terms_salt`, `read_back_terms_mismatch`, `operation_state_mismatch`, `operation_result_mismatch`) | ref:868-915 | Optional, when given the operation the agent saw. It hashes to the signed `terms_digest`. Its terms carry a salt of at least 128 bits (`vxp_salt`). Observed values equal the terms with the same name. Its visible state is the **last** final statement (SPEC 4 P8), and its result summary matches the signed digest. | That the agent saw that operation at that time. |
| 17 | **PACT receipt** (`pact_receipt_mismatch`, `pact_receipt_not_anchored`, `pact_receipt_invalid`) | ref:755-797 | If the request cites a PACT receipt, `argsHash` equals `request_digest`. A presented receipt must be ES256-signed by the anchored PACT authorization server and match `grantId`, `brand`, `pa` and `argsHash`. Without a PACT anchor it is rejected. | That the PACT grant was used as described beyond those fields. |
| 18 | **Derived assurance** | ref:524-546 | **The verifier derives the level and never takes it from the issuer.** `claimed_assurance` in the outcome is ignored. The levels are named after their real root: `issuer_key_attested`, `operator_observed`, `operator_reported_read_back`, and `operator_reported_channel_approval` or `operator_reported_agent_approval`. | `single_root` is always `"operator"`: 0.1 defines no verifiable evidence of a second independent root, and with no external witness the evidence is an operator-signed attestation, ordered and intact, but not independent of the operator (SPEC 4 P7). `logged`, `time_stamped`, `third_party_*` and `user_confirmed` are never granted in 0.1. |

## Python semantics reproduced on purpose

These change verdicts, and the differential fuzz confirmed each one:

- `json.loads` on bytes: encoding detection (UTF-8 with or without BOM, UTF-16, UTF-32), `surrogatepass`, `NaN`/`Infinity`, ints vs floats, the 4300-digit integer limit, and duplicate members rejected at object close.
- Non-strict `base64.urlsafe_b64decode`, used for salts, keys and log material: it discards characters outside the alphabet.
- Python equality (`True == 1 == 1.0`), truthiness, and dict and set membership. An unhashable value raises an exception.
- `urllib.parse.urlparse` (scheme, netloc, `;params`, query, fragment) in `bajo` and in the RFC 8414 well-known URL.

## Evidence

- `test-vxp-verify.mjs` runs the reference on both vector files, line by line, and on the captured real proofs, as captured and altered, in material mode. Log: `evidencia/corridas-22oct/16-verificador-web.log`.
- `fuzz-vxp-verify.mjs` with `fuzz_vxp_gen.py` compares random chains against the reference `verificar_cadena`. The chains come from three sources: the generator of `scripts/fuzz-diferencial.py` unchanged, guided protocol chains, and mutated chains that reach the parsers. It also compares `b64d` and `leer_json` directly. Log: `evidencia/corridas-22oct/17-fuzz-web.log`.

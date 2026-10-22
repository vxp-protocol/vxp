// Generator of the VXP Proof 0.1 test vectors (normative annex, appendix A).
// node:crypto only. TEST keys derived from a public phrase: never use them outside this.
// Usage: node vectors/generar.mjs > vectors/vectores-0.1.json
//
// Round 1 fix (20-Oct-2026): every digest is JCS (strings too, SPEC 9.3); the digest of
// a statement covers `encabezado.payload` and not the signature (SPEC 9.2); levels named after their
// root (SPEC 9.7); new negatives N10–N30 and anchoring cases D1–D8 (SPEC 9.9.1).
//
// Round 3 fix (20-Oct-2026, red team): `terms` declares `company_review_required` and
// `read_back_terms`; `observed` uses the term names (`despacho_nuevo`); terms carry
// `vxp_salt`; the level `agent_asserted_approval` becomes `operator_reported_agent_approval`.
// Negatives N32–N35, chain V4 (with the company's review required) and operation cases O1–O2.
import { createECDH, createPrivateKey, createHash, createHmac, sign } from "node:crypto";

// ---------- utilities ----------
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (data) => createHash("sha256").update(data).digest();
const digBytes = (data) => "sha-256:" + b64u(sha256(data));
/** Digest of any JSON value (object or string): that of its JCS (SPEC 9.3). */
const dig = (x) => digBytes(Buffer.from(jcs(x), "utf8"));
/** Digest of a statement: SHA-256 of `encabezado.payload` (SPEC 9.2). */
const digJwt = (jwt) => digBytes(Buffer.from(jwt.slice(0, jwt.lastIndexOf(".")), "ascii"));
const N_P256 = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/** JCS (RFC 8785) restricted to the 0.1 profile: no non-integer numbers. */
export function jcs(v) {
	if (v === null) return "null";
	if (typeof v === "boolean") return v ? "true" : "false";
	if (typeof v === "number") {
		if (!Number.isSafeInteger(v)) throw new Error("perfil 0.1: sólo enteros seguros");
		return JSON.stringify(v);
	}
	if (typeof v === "string") {
		if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(v)) throw new Error("surrogate suelto");
		return JSON.stringify(v);
	}
	if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
	if (typeof v === "object") {
		return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
	}
	throw new Error("tipo no JSON: " + typeof v);
}

function llave(frase) {
	let d = BigInt("0x" + sha256(frase).toString("hex")) % N_P256;
	if (d === 0n) d = 1n;
	const dBuf = Buffer.from(d.toString(16).padStart(64, "0"), "hex");
	const ecdh = createECDH("prime256v1");
	ecdh.setPrivateKey(dBuf);
	const pub = ecdh.getPublicKey(null, "uncompressed");
	const jwk = { kty: "EC", crv: "P-256", x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
	const kid = b64u(sha256(jcs(jwk))); // RFC 7638: required members in lexicographic order
	const privateKey = createPrivateKey({ key: { ...jwk, d: b64u(dBuf) }, format: "jwk" });
	return { publicJwk: { ...jwk, kid, alg: "ES256", use: "sig" }, d: b64u(dBuf), privateKey, kid };
}

/** Issues a statement: compact JWS with a JCS payload, plus its SD-JWT disclosures. */
function emitir(key, payload, disclosures = [], { noCanonico = false } = {}) {
	const header = { alg: "ES256", kid: key.kid, typ: "vxp-stmt+sd-jwt" };
	const h = b64u(jcs(header));
	const pBytes = noCanonico ? JSON.stringify(payload, null, 1) : jcs(payload);
	const p = b64u(pBytes);
	const sig = sign("sha256", Buffer.from(h + "." + p, "ascii"), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
	const jwt = h + "." + p + "." + b64u(sig);
	const sdjwt = jwt + "~" + disclosures.map((x) => x + "~").join("");
	return { jwt, sdjwt, digest: digJwt(jwt), payload };
}

function divulgacion(nombreSal, claim, valor) {
	const salt = b64u(sha256("sal-de-prueba:" + nombreSal)).slice(0, 22);
	const d = b64u(JSON.stringify([salt, claim, valor]));
	return { disclosure: d, digest: b64u(sha256(Buffer.from(d, "ascii"))) };
}

// ---------- self-checks against the RFCs ----------
// String from RFC 8785 §3.2.2: U+20AC $ U+000F U+000A A ' B " \ \ " /
const cadenaRfc = String.fromCharCode(0x20ac, 0x24, 0x0f, 0x0a, 0x41, 0x27, 0x42, 0x22, 0x5c, 0x5c, 0x22, 0x2f);
const muestraJcs = { numbers: [1, 2], string: cadenaRfc, literals: [null, true, false] };
if (jcs(muestraJcs) !== '{"literals":[null,true,false],"numbers":[1,2],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
	throw new Error("JCS no coincide con RFC 8785 §3.2.3 (parte de strings y orden)");
const rfcDisc = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
if (b64u(sha256(Buffer.from(rfcDisc, "ascii"))) !== "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0")
	throw new Error("hash de divulgación no coincide con RFC 9901 §4.2.3");

// ---------- scenario ----------
const EMPRESA = "https://auth.sovras.io/e/ferreteria-demo";
const OPERADOR = "https://sovras.io/operador";
const AGENTE = "https://pa.example/agent.json";
const USUARIO = "u_9d2c41"; // Poppy User ID: a pseudonym stable only for this company
const OP = "op_P1042_desp";
const t = (iso) => Math.floor(Date.parse(iso) / 1000);

const kEmpresa = llave("SOVRAS-PROOF-0.1 PRUEBA llave de empresa ferreteria-demo");
const kOperador = llave("SOVRAS-PROOF-0.1 PRUEBA llave del operador");
const kOtra = llave("SOVRAS-PROOF-0.1 PRUEBA llave de empresa libreria-demo");
const kAtacante = llave("SOVRAS-PROOF-0.1 PRUEBA llave de un tercero que se hace pasar por la empresa");
const kTag = sha256("SOVRAS-PROOF-0.1 PRUEBA llave de etiqueta ferreteria-demo");

const base = (seq, iss, iat, prev, kind, body) => ({
	v: "0.1", kind, iss, company: EMPRESA, op: OP, seq, prev, iat, aud: AGENTE, user: USUARIO, body,
});

const solicitud = {
	binding: "poppy.openapi",
	method: "POST",
	target: "https://agentes.ferreteria-demo.example/api/pedidos/P-1042/despacho",
	body: { nueva_fecha: "2026-10-27" },
};
const idempotencia = "4f1c2e8a-9b7d-4c3e-a5f6-0d8b1e2c3a4f";
const cierreRelease = "closure:rel-2026-10-20.1";
const terminos1 = {
	company: EMPRESA, operation_id: OP, revision: 1,
	summary: "Cambiar el despacho del pedido P-1042 (Taladro percutor 800 W) del 2026-10-24 al 2026-10-27, despacho express con cargo de $3.990.",
	terms: { pedido: "P-1042", despacho_actual: "2026-10-24", despacho_nuevo: "2026-10-27", cargo: { amount: "3990", currency: "CLP" } },
	expires_at: "2026-10-20T15:16:00Z", user_approval_required: true,
};
const contra = { base_revision: 1, proposed_terms: { despacho_nuevo: "2026-10-28", cargo: { amount: "0", currency: "CLP" } }, note: "Sin cargo, puede ser un día después." };
const terminos2 = {
	company: EMPRESA, operation_id: OP, revision: 2,
	summary: "Cambiar el despacho del pedido P-1042 (Taladro percutor 800 W) del 2026-10-24 al 2026-10-28, sin costo.",
	terms: { pedido: "P-1042", despacho_actual: "2026-10-24", despacho_nuevo: "2026-10-28", cargo: { amount: "0", currency: "CLP" } },
	expires_at: "2026-10-20T15:19:00Z", user_approval_required: true,
};
// Round 3 (m2): 128-bit salt in the terms; deterministic here so the vectors are reproducible.
const salTerminos = (n) => b64u(sha256("sal-de-terminos:" + n).subarray(0, 16));
terminos1.terms.vxp_salt = salTerminos(1);
terminos2.terms.vxp_salt = salTerminos(2);
const LECTURA = ["pedido", "despacho_nuevo"];
const td1 = dig(terminos1);
const td2 = dig(terminos2);
const codigo = (td) => String(sha256(td).readUInt32BE(0) % 1000000).padStart(6, "0");

const dTexto = divulgacion("whatsapp-texto", "inbound_text", "APROBAR " + codigo(td2));
const dMsg = divulgacion("whatsapp-id", "provider_message_id", "wamid.PRUEBA.0001");
const dDir = divulgacion("direccion", "direccion", "Calle Ejemplo 100, Santiago");
const resumenResultado = "Listo: el pedido P-1042 se despacha el 2026-10-28, sin costo.";
const nota = "El despacho se reagendó por falta de stock.";
const NIVELES_V1 = ["issuer_key_attested", "operator_observed", "operator_reported_read_back", "operator_reported_channel_approval"];

const S = [];
const push = (key, p, disc) => { const s = emitir(key, p, disc); S.push(s); return s; };
const prevOf = () => (S.length ? S[S.length - 1].digest : null);

push(kOperador, base(0, OPERADOR, t("2026-10-20T15:00:00Z"), null, "request", {
	channel: "poppy", client_id: AGENTE, request_digest: dig(solicitud), idempotency_key_digest: dig(idempotencia),
}));
push(kEmpresa, base(1, EMPRESA, t("2026-10-20T15:01:00Z"), prevOf(), "terms", {
	revision: 1, terms_digest: td1, capability: "pedido.reprogramar_despacho", expires_at: terminos1.expires_at, user_approval_required: true,
	company_review_required: false, read_back_terms: LECTURA,
}));
push(kOperador, base(2, OPERADOR, t("2026-10-20T15:02:00Z"), prevOf(), "counter", {
	base_revision: 1, counter_digest: dig(contra), from: "personal_agent",
}));
push(kEmpresa, base(3, EMPRESA, t("2026-10-20T15:04:00Z"), prevOf(), "terms", {
	revision: 2, terms_digest: td2, capability: "pedido.reprogramar_despacho", expires_at: terminos2.expires_at, user_approval_required: true, company_review_required: false, read_back_terms: LECTURA, answers: S[2].digest,
}));
push(kOperador, base(4, OPERADOR, t("2026-10-20T15:06:00Z"), prevOf(), "user_approval", {
	revision: 2, terms_digest: td2, method: "company_channel", channel: "whatsapp", display_code: codigo(td2),
	evidence: { _sd: [dTexto.digest, dMsg.digest].sort() }, poppy_confirmation: { approved_by: "user", confirmed_at: "2026-10-20T15:06:20Z" },
}), [dTexto.disclosure, dMsg.disclosure]);
push(kOperador, base(5, OPERADOR, t("2026-10-20T15:06:21Z"), prevOf(), "execution", {
	revision: 2, terms_digest: td2, capability: "pedido.reprogramar_despacho", release: dig(cierreRelease), attempt: 1,
}));
push(kOperador, base(6, OPERADOR, t("2026-10-20T15:06:24Z"), prevOf(), "read_back", {
	method: "system_read_back", source: "company_system", matches_terms: true,
	observed: { pedido: "P-1042", despacho_nuevo: "2026-10-28", _sd: [dDir.digest] },
}), [dDir.disclosure]);
push(kEmpresa, base(7, EMPRESA, t("2026-10-20T15:06:25Z"), prevOf(), "outcome", {
	state: "succeeded", revision: 2, terms_digest: td2, result_summary_digest: dig(resumenResultado),
	claimed_assurance: NIVELES_V1, third_party: [],
}));

/** Extends a chain (array of issued statements) with steps [key, kind, body, disclosures]. */
function extender(prefijo, pasos, iat = "2026-10-23T12:00:00Z") {
	const c = [...prefijo];
	for (const [k, kind, body, disc = [], extra = {}] of pasos) {
		const iss = k === kOperador ? OPERADOR : EMPRESA;
		c.push(emitir(k, { ...base(c.length, iss, t(iat), c.at(-1).digest, kind, body), ...extra }, disc));
	}
	return c;
}
const sd = (c) => c.map((s) => s.sdjwt);
const outcomeDe = (state, extra = {}) => ({ state, revision: 2, terms_digest: td2, result_summary_digest: dig(resumenResultado), claimed_assurance: [], third_party: [], ...extra });
const lecturaOk = (extra = {}) => ({ method: "system_read_back", source: "company_system", matches_terms: true, observed: { pedido: "P-1042", despacho_nuevo: "2026-10-28" }, ...extra });

// V2: V1 + a correction after the final state.
const V2 = extender(S, [[kEmpresa, "correction", { corrects: S[7].digest, state: "failed", reason: "company_system_reverted", note_digest: dig(nota) }]]);
// V3: V2 + a new read-back + a correction to succeeded that cites it (SPEC 11.1).
const V3a = extender(V2, [[kOperador, "read_back", lecturaOk()]], "2026-10-24T09:00:00Z");
const V3 = extender(V3a, [[kEmpresa, "correction", { corrects: V2[8].digest, state: "succeeded", reason: "company_system_restored", read_back: V3a[9].digest }]], "2026-10-24T09:00:05Z");

// Malleated outcome signature: (r, n − s) is also valid; the digest does not change (SPEC 9.2).
const [mh, mp, ms] = S[7].jwt.split(".");
const msig = Buffer.from(ms, "base64url");
const sAlto = (N_P256 - BigInt("0x" + msig.subarray(32).toString("hex"))).toString(16).padStart(64, "0");
const jwtMaleado = mh + "." + mp + "." + b64u(Buffer.concat([msig.subarray(0, 32), Buffer.from(sAlto, "hex")]));

// ---------- transparency log (RFC 9162 §2.1.1) ----------
const leafInput = (s) => {
	const salt = sha256("sal-de-hoja:" + s.payload.seq);
	const commit = sha256(Buffer.concat([salt, Buffer.from(s.jwt, "ascii")]));
	const tag = createHmac("sha256", kTag).update(OP + "|" + s.payload.seq).digest();
	return { salt: b64u(salt), leaf_input: b64u(Buffer.concat([commit, tag])) };
};
const hLeaf = (d) => sha256(Buffer.concat([Buffer.from([0]), d]));
const hNode = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]));
const mth = (D) => {
	if (D.length === 1) return hLeaf(D[0]);
	let k = 1; while (k * 2 < D.length) k *= 2;
	return hNode(mth(D.slice(0, k)), mth(D.slice(k)));
};
const path = (m, D) => { // RFC 9162 §2.1.3.1
	if (D.length === 1) return [];
	let k = 1; while (k * 2 < D.length) k *= 2;
	return m < k ? [...path(m, D.slice(0, k)), mth(D.slice(k))] : [...path(m - k, D.slice(k)), mth(D.slice(0, k))];
};
const hojas = S.map(leafInput);
const D = hojas.map((h) => Buffer.from(h.leaf_input, "base64url"));

// ---------- negative vectors ----------
const neg = [];
{ // N1: payload tampered with, not re-signed
	const [h, p, s] = S[3].jwt.split(".");
	const pl = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
	pl.body.terms_digest = td1;
	neg.push({ id: "N1", expect: "signature_invalid", replace: { seq: 3, jwt: h + "." + b64u(jcs(pl)) + "." + s } });
}
{ // N2: approval signed over revision 1 when the latest is 2
	const p = { ...S[4].payload, body: { ...S[4].payload.body, revision: 1, terms_digest: td1, display_code: codigo(td1) } };
	neg.push({ id: "N2", expect: "approval_not_latest_revision", replace: { seq: 4, jwt: emitir(kOperador, p).jwt }, note: "Los statements siguientes conservan prev hacia la aprobación original; el verificador debe reportar este error antes que chain_broken." });
}
neg.push({ id: "N3", expect: "unknown_key", replace: { seq: 7, jwt: emitir(kOtra, S[7].payload).jwt } });
neg.push({ id: "N4", expect: "non_canonical_payload", replace: { seq: 7, jwt: emitir(kEmpresa, S[7].payload, [], { noCanonico: true }).jwt } });
neg.push({ id: "N5", expect: "chain_broken", replace: { seq: 7, jwt: emitir(kEmpresa, { ...S[7].payload, prev: S[5].digest }).jwt } });
neg.push({ id: "N6", expect: "op_mismatch", replace: { seq: 7, jwt: emitir(kEmpresa, { ...S[7].payload, op: "op_P1043_desp" }).jwt } });
{ // N7: tampered disclosure
	const bad = b64u(JSON.stringify([JSON.parse(Buffer.from(dDir.disclosure, "base64url").toString("utf8"))[0], "direccion", "Calle Ejemplo 200, Concepción"]));
	neg.push({ id: "N7", expect: "disclosure_digest_mismatch", replace_disclosure: { seq: 6, index: 0, disclosure: bad } });
}
{ // N8: the outcome claims succeeded with a read-back that did not match
	const p6 = { ...S[6].payload, body: { ...S[6].payload.body, matches_terms: false } };
	const s6 = emitir(kOperador, p6, [dDir.disclosure]);
	const s7 = emitir(kEmpresa, { ...S[7].payload, prev: s6.digest });
	neg.push({ id: "N8", expect: "succeeded_without_matching_read_back", replace_many: [{ seq: 6, jwt: s6.jwt }, { seq: 7, jwt: s7.jwt }] });
}
{ // N9: the execution uses a digest different from the approved one
	const p5 = { ...S[5].payload, body: { ...S[5].payload.body, terms_digest: td1 } };
	const s5 = emitir(kOperador, p5);
	const s6 = emitir(kOperador, { ...S[6].payload, prev: s5.digest }, [dDir.disclosure]);
	const s7 = emitir(kEmpresa, { ...S[7].payload, prev: s6.digest });
	neg.push({ id: "N9", expect: "execution_terms_mismatch", replace_many: [{ seq: 5, jwt: s5.jwt }, { seq: 6, jwt: s6.jwt }, { seq: 7, jwt: s7.jwt }] });
}
// Validation round 1 (cryptographic standards): A1–A9.
const nc = (id, expect, chain, note) => neg.push({ id, expect, chain: sd(chain), note });
{
	const c = extender(S.slice(0, 6), [[kEmpresa, "outcome", outcomeDe("unknown")]]);
	nc("N10", "correction_without_read_back", extender(c, [[kEmpresa, "correction", { corrects: c[6].digest, state: "succeeded", reason: "x" }]]), "A1: unknown y después una corrección a succeeded sin lectura de vuelta");
}
nc("N11", "bad_state", extender(S, [[kEmpresa, "correction", { corrects: S[7].digest, state: "lo_que_sea", reason: "x" }]]), "A2: estado fuera del enum en la corrección");
nc("N12", "order_violation", extender(S.slice(0, 7), [[kEmpresa, "company_review", { revision: 2, terms_digest: td2, decision: "approved", role: "revisor" }]]), "A3a: revisión de la empresa después de ejecutar");
nc("N13", "outcome_after_denial", extender(S.slice(0, 5), [[kEmpresa, "company_review", { revision: 2, terms_digest: td2, decision: "denied", role: "revisor" }], [kEmpresa, "outcome", outcomeDe("cancelled")]]), "A3b: tras un denied sólo cabe failed");
nc("N14", "outcome_terms_mismatch", extender(S.slice(0, 4), [[kEmpresa, "outcome", outcomeDe("cancelled", { revision: 99, terms_digest: "sha-256:INVENTADA" })]]), "A3c: el resultado siempre nombra la última revisión, aunque no haya aprobación");
nc("N15", "succeeded_without_matching_read_back", extender(S.slice(0, 6), [[kOperador, "read_back", lecturaOk({ method: "none" })], [kEmpresa, "outcome", outcomeDe("succeeded")]]), "A4: method none no respalda succeeded");
nc("N16", "order_violation", extender(V2, [[kEmpresa, "correction", { corrects: S[7].digest, state: "cancelled", reason: "x" }]]), "A5: corrects debe apuntar a la última declaración final, no al outcome");
{ // N17–N22: disclosure processing per RFC 9901 §7.1 (A6, A7) and _sd_alg
	const dPed = divulgacion("pedido-repetido", "pedido", "P-9999");
	const dSd = divulgacion("nombre-sd", "_sd", ["x"]);
	const dPunt = divulgacion("nombre-puntos", "...", "x");
	const rb = (observed, extra = {}) => lecturaOk({ observed, ...extra });
	const tras = (paso, disc) => extender(S.slice(0, 6), [[kOperador, "read_back", paso, disc]]);
	nc("N17", "sd_digest_repeated", tras(rb({ despacho_nuevo: "2026-10-28", _sd: [dPed.digest, dPed.digest] }), [dPed.disclosure]), "RFC 9901 7.1 paso 4: huella repetida");
	nc("N18", "disclosure_repeated", tras(rb({ despacho_nuevo: "2026-10-28", _sd: [dPed.digest] }), [dPed.disclosure, dPed.disclosure]), "La misma divulgación dos veces");
	nc("N19", "disclosure_claim_exists", tras(rb({ pedido: "P-1042", _sd: [dPed.digest] }), [dPed.disclosure]), "RFC 9901 7.1 paso 3.c.ii.3: el nombre ya existe en el objeto (A6)");
	nc("N20", "disclosure_bad_name", tras(rb({ pedido: "P-1042", _sd: [dSd.digest] }), [dSd.disclosure]), "RFC 9901 7.1 paso 3.c.ii.2: nombre _sd (A7)");
	nc("N21", "disclosure_bad_name", tras(rb({ pedido: "P-1042", _sd: [dPunt.digest] }), [dPunt.disclosure]), "RFC 9901 7.1 paso 3.c.ii.2: nombre ...");
	nc("N22", "bad_sd_alg", extender(S.slice(0, 6), [[kOperador, "read_back", lecturaOk(), [], { _sd_alg: "sha-512" }]]), "Perfil 0.1: _sd_alg sólo sha-256");
	nc("N23", "bad_sd_alg", tras(rb({ pedido: "P-1042", _sd_alg: "sha-256" })), "RFC 9901 4.1.1: _sd_alg sólo en el nivel superior");
}
{ // N24: non-canonical base64url in the signature (A8b)
	const [h, p, s] = S[7].jwt.split(".");
	const alf = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const i = alf.indexOf(s.at(-1));
	const otro = alf[(i & ~0b1111) | ((i + 1) & 0b1111)];
	if (!Buffer.from(s.slice(0, -1) + otro, "base64url").equals(Buffer.from(s, "base64url"))) throw new Error("N24: los bytes deberían ser iguales");
	neg.push({ id: "N24", expect: "non_canonical_encoding", replace: { seq: 7, jwt: h + "." + p + "." + s.slice(0, -1) + otro }, note: "A8b: mismos bytes, otra cadena" });
}
nc("N25", "aud_mismatch", extender(S.slice(0, 7), [[kEmpresa, "outcome", outcomeDe("succeeded"), [], { aud: "https://otro-agente.example/agent.json" }]]), "Replay hacia otro agente (SPEC 9.5 regla 5)");
nc("N26", "user_mismatch", extender(S.slice(0, 7), [[kEmpresa, "outcome", outcomeDe("succeeded"), [], { user: "u_otro" }]]), "Replay hacia otro usuario");
nc("N27", "order_violation", extender(S.slice(0, 5), [[kOperador, "user_approval", { ...S[4].payload.body, evidence: {} }]]), "Una sola user_approval");
nc("N28", "display_code_mismatch", extender(S.slice(0, 4), [[kOperador, "user_approval", { ...S[4].payload.body, evidence: {}, display_code: "000000" }]]), "display_code que no sale de la huella");
nc("N29", "order_violation", extender(S.slice(0, 6), [[kOperador, "execution", S[5].payload.body]]), "Una sola execution");
nc("N30", "order_violation", extender(S.slice(0, 5), [[kOperador, "counter", { base_revision: 2, counter_digest: dig(contra), from: "personal_agent" }]]), "No hay contrapropuesta después de aprobar");
// Round 3 (red team).
nc("N32", "read_back_incomplete", extender(S.slice(0, 6), [[kOperador, "read_back", lecturaOk({ observed: { pedido: "P-1042" } })], [kEmpresa, "outcome", outcomeDe("succeeded")]]), "M1: la lectura de vuelta no observa el término del efecto (despacho_nuevo)");
{
	const { company_review_required: _x, ...sinRegla } = S[1].payload.body;
	nc("N33", "bad_terms", extender(S.slice(0, 1), [[kEmpresa, "terms", sinRegla]]), "m3: terms sin company_review_required");
}
const terminos2Revision = { ...S[3].payload.body, company_review_required: true };
const aprobacion2 = [kOperador, "user_approval", S[4].payload.body, [dTexto.disclosure, dMsg.disclosure]];
nc("N34", "order_violation", extender(S.slice(0, 3), [[kEmpresa, "terms", terminos2Revision], aprobacion2, [kOperador, "execution", S[5].payload.body]]), "m3: la empresa exige su revisión y se ejecuta sin ella");
{
	const c = extender(V2, [[kOperador, "read_back", lecturaOk({ observed: { pedido: "P-1042" } })]], "2026-10-24T09:00:00Z");
	nc("N35", "read_back_incomplete", extender(c, [[kEmpresa, "correction", { corrects: V2[8].digest, state: "succeeded", reason: "x", read_back: c[9].digest }]], "2026-10-24T09:00:05Z"), "M1: una corrección a succeeded cita una lectura que no observa el efecto");
}
// V4 (valid): the company requires its review on revision 2 and approves it before executing.
const V4 = extender(S.slice(0, 3), [
	[kEmpresa, "terms", terminos2Revision], aprobacion2,
	[kEmpresa, "company_review", { revision: 2, terms_digest: td2, decision: "approved", role: "revisor_empresa" }],
	[kOperador, "execution", S[5].payload.body], [kOperador, "read_back", S[6].payload.body, [dDir.disclosure]],
	[kEmpresa, "outcome", S[7].payload.body],
], "2026-10-20T15:10:00Z");
// Operation cases (SPEC 9.9 step 4): the chain alongside the Poppy operation the agent saw.
const operacion2 = { operation_id: OP, revision: 2, state: "succeeded", summary: terminos2.summary, terms: terminos2.terms, expires_at: terminos2.expires_at, user_approval_required: true, confirmation: { revision: 2, approved_by: "user", confirmed_at: "2026-10-20T15:06:20Z" }, result: { summary: resumenResultado } };
const lecturaVieja = extender(S.slice(0, 6), [[kOperador, "read_back", { ...S[6].payload.body, observed: { ...S[6].payload.body.observed, despacho_nuevo: "2026-10-24" } }, [dDir.disclosure]], [kEmpresa, "outcome", S[7].payload.body]], "2026-10-20T15:06:24Z");
const casosOperacion = [
	{ id: "O1", expect: "valid", chain: sd(S), operation: operacion2, note: "V1 con la operación que vio el agente: términos, estado, resumen y lo observado calzan" },
	{ id: "O2", expect: "read_back_terms_mismatch", seq: 6, chain: sd(lecturaVieja), operation: operacion2, note: "M1 (ronda 3): matches_terms true con la fecha vieja en despacho_nuevo" },
	{ id: "O3", expect: "operation_terms_mismatch", chain: sd(S), operation: { ...operacion2, terms: { ...terminos2.terms, despacho_nuevo: "2026-10-30" } }, note: "Términos distintos de los firmados" },
];
{ // O4 (m2, round 3): terms signed without salt; the digest matches, but it would confirm the address to anyone who guesses it.
	const { vxp_salt: _s, ...sinSal } = terminos1.terms;
	const t1 = { ...terminos1, terms: { ...sinSal, direccion: "Calle Ejemplo 100, Santiago" } };
	const c = extender(S.slice(0, 1), [
		[kEmpresa, "terms", { ...S[1].payload.body, terms_digest: dig(t1) }],
		[kEmpresa, "outcome", { state: "cancelled", revision: 1, terms_digest: dig(t1), result_summary_digest: dig("Cancelado."), claimed_assurance: [], third_party: [] }],
	], "2026-10-20T15:02:00Z");
	casosOperacion.push({ id: "O4", expect: "weak_terms_salt", chain: sd(c), operation: { operation_id: OP, revision: 1, state: "cancelled", summary: t1.summary, terms: t1.terms, expires_at: t1.expires_at, user_approval_required: true, confirmation: null, result: { summary: "Cancelado." } }, note: "Términos sin vxp_salt (SPEC 9.3)" });
}
nc("N31", "bad_approval_method", extender(S.slice(0, 4), [[kOperador, "user_approval", { revision: 2, terms_digest: td2, method: "lo_dijo_alguien", evidence: {} }]]), "Método de aprobación fuera del enum");

// ---------- discovery and anchoring (SPEC 9.9.1) ----------
const DOMINIO = "agentes.ferreteria-demo.example";
const metaUrl = (iss) => { const u = new URL(iss); return `${u.origin}/.well-known/oauth-authorization-server${u.pathname.replace(/\/$/, "")}`; };
const confianza = {
	version: "0.1", company: EMPRESA, jwks_uri: `${EMPRESA}/sovras/proof-jwks.json`,
	operator: { issuer: OPERADOR, jwks_uri: `${OPERADOR}/proof-jwks.json` }, custody: "operator_hosted",
	log: { origin: "log.sovras.io/proof/v0", checkpoint_url: "https://log.sovras.io/proof/v0/checkpoint", consistency_url: "https://log.sovras.io/proof/v0/consistency", jwks_uri: "https://log.sovras.io/proof/v0/jwks.json", witnesses: [] },
};
const bloque = { ...confianza, endpoint: `https://${DOMINIO}/sovras/proof`, approval_channels: ["whatsapp"], capabilities: [{ name: "pedido.reprogramar_despacho", effect: "write", max_assurance: NIVELES_V1, third_party: [] }] };
const docs = {
	[`https://${DOMINIO}/.well-known/poppy.json`]: { protocol_version: "0.2", organization: { name: "Ferretería Demo", domain: DOMINIO }, auth: { issuer: EMPRESA }, extensions: { "vxpprotocol.org/proof": bloque } },
	[metaUrl(EMPRESA)]: { issuer: EMPRESA, poppy_domains: [DOMINIO], vxp_proof: confianza },
	[confianza.jwks_uri]: { keys: [kEmpresa.publicJwk] },
	[confianza.operator.jwks_uri]: { keys: [kOperador.publicJwk] },
	"https://provider.sovras.io/a2a/t_ferreteria_demo/.well-known/agent-card.json": { name: "Ferretería Demo", capabilities: { extensions: [{ uri: "https://vxpprotocol.org/ext/proof/v0.1", required: false, params: bloque }] } },
	// B1: a third party publishes on its domain an Agent Card that claims to be Ferretería Demo, with its own keys and custody customer_managed.
	"https://atacante.example/.well-known/agent-card.json": { name: "Ferretería Demo", capabilities: { extensions: [{ uri: "https://vxpprotocol.org/ext/proof/v0.1", required: false, params: { ...bloque, jwks_uri: "https://atacante.example/e.json", operator: { issuer: "https://atacante.example/op", jwks_uri: "https://atacante.example/op/jwks.json" }, custody: "customer_managed" } }] } },
	"https://atacante.example/e.json": { keys: [kAtacante.publicJwk] },
	// A document copied to another domain, and one that claims Demo's issuer from a domain the issuer does not list.
	"https://copia.example/.well-known/poppy.json": { protocol_version: "0.2", organization: { name: "Ferretería Demo", domain: DOMINIO }, auth: { issuer: EMPRESA }, extensions: { "vxpprotocol.org/proof": bloque } },
	"https://ferreteria-falsa.example/.well-known/poppy.json": { protocol_version: "0.2", organization: { name: "Ferretería Demo", domain: "ferreteria-falsa.example" }, auth: { issuer: EMPRESA }, extensions: { "vxpprotocol.org/proof": bloque } },
	// Misconfigured issuers.
	[metaUrl("https://auth.sovras.io/e/llave-ajena")]: { issuer: "https://auth.sovras.io/e/llave-ajena", vxp_proof: { ...confianza, company: "https://auth.sovras.io/e/llave-ajena", jwks_uri: "https://cdn.otro.example/jwks.json" } },
	[metaUrl("https://auth.sovras.io/e/otro-issuer")]: { issuer: "https://auth.sovras.io/e/distinto", vxp_proof: { ...confianza, company: "https://auth.sovras.io/e/otro-issuer" } },
	[metaUrl("https://auth.sovras.io/e/sin-bloque")]: { issuer: "https://auth.sovras.io/e/sin-bloque" },
};
const casos = [
	{ id: "D1", expect: "valid", anchor: { domain: DOMINIO }, note: "Poppy: dominio → poppy.json → issuer → metadata RFC 8414 → llaves" },
	{ id: "D2", expect: "valid", anchor: { issuer: EMPRESA, card: "https://provider.sovras.io/a2a/t_ferreteria_demo/.well-known/agent-card.json" }, note: "A2A: issuer conocido + Agent Card del proveedor, cuya copia coincide con la metadata" },
	{ id: "D3", expect: "issuer_not_anchored", anchor: { issuer: EMPRESA, card: "https://atacante.example/.well-known/agent-card.json" }, note: "B1: la Agent Card de un tercero no es la copia del issuer" },
	{ id: "D4", expect: "issuer_not_anchored", anchor: { domain: "copia.example" }, note: "Poppy 3 regla 1: organization.domain no es el host que sirvió el documento" },
	{ id: "D5", expect: "issuer_not_anchored", anchor: { domain: "ferreteria-falsa.example" }, note: "Poppy 3 regla 2: el issuer no lista ese dominio en poppy_domains" },
	{ id: "D6", expect: "issuer_not_anchored", anchor: { issuer: "https://auth.sovras.io/e/llave-ajena" }, note: "jwks_uri fuera del issuer" },
	{ id: "D7", expect: "issuer_not_anchored", anchor: { issuer: "https://auth.sovras.io/e/otro-issuer" }, note: "RFC 8414 3.3: la metadata trae otro issuer" },
	{ id: "D8", expect: "issuer_not_anchored", anchor: { issuer: "https://auth.sovras.io/e/sin-bloque" }, note: "La metadata del issuer no publica vxp_proof" },
	{ id: "D9", expect: "issuer_not_anchored", anchor: { issuer: "https://auth.sovras.io/e/sin-metadata" }, note: "Ronda 2 (m4): la metadata del issuer no existe (404); el verificador responde issuer_not_anchored, no se cae" },
];

const veredicto = (final_state, extra = {}) => ({ valid: true, final_state, revision: 2, approval: "company_channel", derived_assurance: NIVELES_V1, single_root: "operator", custody_declared: "operator_hosted", logged: false, ...extra });
const salida = {
	aviso: "VECTORES DE PRUEBA. Llaves derivadas de frases públicas: no usar fuera de pruebas.",
	perfil: "VXP 0.1, prueba de resultado (corrección ronda 3, 20-oct-2026)",
	keys: {
		company: { jwks: { keys: [kEmpresa.publicJwk] }, custody: "operator_hosted", d_TEST_ONLY: kEmpresa.d, issuer: EMPRESA },
		operator: { jwks: { keys: [kOperador.publicJwk] }, d_TEST_ONLY: kOperador.d, issuer: OPERADOR },
		other_company: { jwks: { keys: [kOtra.publicJwk] }, d_TEST_ONLY: kOtra.d, issuer: "https://auth.sovras.io/e/libreria-demo" },
		attacker: { jwks: { keys: [kAtacante.publicJwk] }, d_TEST_ONLY: kAtacante.d },
	},
	inputs: { solicitud, idempotency_key: idempotencia, release_closure: cierreRelease, terminos1, contra, terminos2, resumenResultado, nota, jcs_terms2: jcs(terminos2), terms_digest_1: td1, terms_digest_2: td2, display_code_2: codigo(td2) },
	chain_v1: S.map((s) => ({ seq: s.payload.seq, kind: s.payload.kind, sdjwt: s.sdjwt, digest: s.digest, payload_jcs: jcs(s.payload) })),
	expected_v1: veredicto("succeeded"),
	expected_processed_observed_seq6: { pedido: "P-1042", despacho_nuevo: "2026-10-28", direccion: "Calle Ejemplo 100, Santiago" },
	malleated_outcome: { jwt: jwtMaleado, note: "Misma declaración que seq 7 con la firma (r, n − s): también válida; la huella es la misma porque no cubre la firma." },
	chain_v2: { extra: sd(V2.slice(8)), digests: V2.slice(8).map((s) => s.digest), expected: veredicto("failed") },
	chain_v3: { extra: sd(V3.slice(8)), digests: V3.slice(8).map((s) => s.digest), expected: veredicto("succeeded") },
	chain_v4: { chain: sd(V4), digests: V4.map((s) => s.digest), expected: veredicto("succeeded") },
	operation_cases: casosOperacion,
	log: {
		hash: "RFC9162_SHA256",
		leaves: hojas.map((h, i) => ({ seq: i, ...h, leaf_hash: b64u(hLeaf(D[i])) })),
		tag_key_TEST_ONLY: b64u(kTag),
		tree_size: D.length,
		root_hash: b64u(mth(D)),
		inclusion_of_seq7: path(7, D).map(b64u),
		inclusion_of_seq3: path(3, D).map(b64u),
	},
	negative: neg,
	discovery: { docs, cases: casos },
};
process.stdout.write(JSON.stringify(salida, null, 2) + "\n");

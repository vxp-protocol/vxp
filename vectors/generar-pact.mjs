// Vectors for the PACT profile of VXP Proof 0.1 (normative annex §9.9.1 and appendix A.9): anchoring with what
// PACT gives an agent (brand domain or PACT authorization server) and cross-checking the chain against
// the PACT receipt of the turn that proposed (`request.body.pact_proposal_receipt`).
// Validation round 2 fix (interoperability, 20-Oct-2026): findings M1 and M3.
// node:crypto only. TEST keys derived from public phrases: never use them outside this.
// The company and operator keys are the same as in vectores-0.1.json (same phrase).
// Usage: node vectors/generar-pact.mjs > vectors/vectores-pact-0.1.json
import { createECDH, createHash, createPrivateKey, sign } from "node:crypto";

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (data) => createHash("sha256").update(data).digest();
const N_P256 = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

function jcs(v) {
	if (v === null) return "null";
	if (typeof v === "boolean") return v ? "true" : "false";
	if (typeof v === "number") {
		if (!Number.isSafeInteger(v)) throw new Error("perfil 0.1: sólo enteros seguros");
		return JSON.stringify(v);
	}
	if (typeof v === "string") return JSON.stringify(v);
	if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
	if (typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
	throw new Error("tipo no JSON");
}
const dig = (x) => "sha-256:" + b64u(sha256(Buffer.from(jcs(x), "utf8")));
const digJwt = (jwt) => "sha-256:" + b64u(sha256(Buffer.from(jwt.slice(0, jwt.lastIndexOf(".")), "ascii")));
const codigo = (td) => String(sha256(td).readUInt32BE(0) % 1000000).padStart(6, "0");

function llave(frase) {
	let d = BigInt("0x" + sha256(frase).toString("hex")) % N_P256;
	if (d === 0n) d = 1n;
	const dBuf = Buffer.from(d.toString(16).padStart(64, "0"), "hex");
	const ecdh = createECDH("prime256v1");
	ecdh.setPrivateKey(dBuf);
	const pub = ecdh.getPublicKey(null, "uncompressed");
	const jwk = { kty: "EC", crv: "P-256", x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
	const kid = b64u(sha256(jcs(jwk)));
	return { publicJwk: { ...jwk, kid, alg: "ES256", use: "sig" }, kid, privateKey: createPrivateKey({ key: { ...jwk, d: b64u(dBuf) }, format: "jwk" }) };
}
const jws = (key, header, payload) => {
	const h = b64u(jcs(header));
	const p = b64u(jcs(payload));
	return h + "." + p + "." + b64u(sign("sha256", Buffer.from(h + "." + p, "ascii"), { key: key.privateKey, dsaEncoding: "ieee-p1363" }));
};

const kEmpresa = llave("VXP-PROOF-0.1 PRUEBA llave de empresa ferreteria-demo");
const kOperador = llave("VXP-PROOF-0.1 PRUEBA llave del operador");
const kAs = llave("VXP-PROOF-0.1 PRUEBA llave del servidor de autorizacion PACT de ferreteria-demo");
const kOtro = llave("VXP-PROOF-0.1 PRUEBA llave de otro proveedor que se presenta como la marca");

const EMPRESA = "https://auth.operator.example/e/ferreteria-demo";
const OPERADOR = "https://operator.example/op";
const MARCA = "ferreteria-demo.example";
const IFACE = "https://provider.operator.example/a2a/t_ferreteria_demo";
const AS = IFACE + "/oauth";
const AGENTE = "https://pa.example"; // PACT: the agent's client_id = its issuer (PACT §5.4)
const USUARIO = "cli_a_demo"; // PACT: the delegation's `sub` (SPEC §6.2)
const OP = "op_P1042_pact";
const GRANT = "a2agrant_PRUEBA_0001";
const EXT = "https://vxpprotocol.org/ext/proof/v0.1";
const t = (iso) => Math.floor(Date.parse(iso) / 1000);
const metaUrl = (iss) => { const u = new URL(iss); return `${u.origin}/.well-known/oauth-authorization-server${u.pathname.replace(/\/$/, "")}`; };

const texto = "Cambia el despacho del P-1042 al 2026-10-28";
const solicitud = { binding: "pact.message", text: texto };
const requestDigest = dig(solicitud);
const terminos = {
	company: EMPRESA, operation_id: OP, revision: 1,
	summary: "Cambiar el despacho del pedido P-1042 (Taladro percutor 800 W) del 2026-10-24 al 2026-10-28, sin costo.",
	// Round 3 (m2): 128-bit salt in the terms (deterministic in the vectors).
	terms: { pedido: "P-1042", despacho_actual: "2026-10-24", despacho_nuevo: "2026-10-28", costo: { amount: "0", currency: "CLP" }, vxp_salt: b64u(sha256("sal-de-terminos:pact").subarray(0, 16)) },
	expires_at: "2026-10-20T16:15:00Z", user_approval_required: true,
};
const td = dig(terminos);
const disc = (sal, nombre, valor) => {
	const d = b64u(JSON.stringify([b64u(sha256("sal-pact:" + sal)).slice(0, 22), nombre, valor]));
	return { d, h: b64u(sha256(Buffer.from(d, "ascii"))) };
};
const dTexto = disc("texto", "inbound_text", "APROBAR " + codigo(td));

/** Full PACT chain; `cita` is what the `request` says about the receipt of the turn that proposed. */
function cadena(cita) {
	const S = [];
	const push = (k, iss, iat, kind, body, ds = []) => {
		const payload = { v: "0.1", kind, iss, company: EMPRESA, op: OP, seq: S.length, prev: S.length ? S.at(-1).digest : null, iat: t(iat), aud: AGENTE, user: USUARIO, body };
		const jwt = jws(k, { alg: "ES256", kid: k.kid, typ: "vxp-stmt+sd-jwt" }, payload);
		S.push({ jwt, sdjwt: jwt + "~" + ds.map((x) => x + "~").join(""), digest: digJwt(jwt) });
	};
	push(kOperador, OPERADOR, "2026-10-20T16:00:00Z", "request", { channel: "pact", client_id: AGENTE, request_digest: requestDigest, pact_proposal_receipt: cita });
	push(kEmpresa, EMPRESA, "2026-10-20T16:00:01Z", "terms", { revision: 1, terms_digest: td, capability: "pedido.reprogramar_despacho", expires_at: terminos.expires_at, user_approval_required: true, company_review_required: false, read_back_terms: ["pedido", "despacho_nuevo"] });
	push(kOperador, OPERADOR, "2026-10-20T16:02:00Z", "user_approval", { revision: 1, terms_digest: td, method: "company_channel", channel: "whatsapp", display_code: codigo(td), evidence: { _sd: [dTexto.h] } }, [dTexto.d]);
	push(kOperador, OPERADOR, "2026-10-20T16:02:01Z", "execution", { revision: 1, terms_digest: td, capability: "pedido.reprogramar_despacho", release: dig("closure:rel-2026-10-20.1"), attempt: 1 });
	push(kOperador, OPERADOR, "2026-10-20T16:02:02Z", "read_back", { method: "system_read_back", source: "company_system", matches_terms: true, observed: { pedido: "P-1042", despacho_nuevo: "2026-10-28" } });
	push(kEmpresa, EMPRESA, "2026-10-20T16:02:03Z", "outcome", { state: "succeeded", revision: 1, terms_digest: td, result_summary_digest: dig("Listo: el pedido P-1042 se despacha el 2026-10-28."), claimed_assurance: [], third_party: [] });
	return { v: "0.1", company: EMPRESA, op: OP, statements: S.map((s) => s.sdjwt) };
}
const paquete = cadena({ grantId: GRANT, argsHash: requestDigest });

/** PACT §5.6 receipt of the turn that proposed: compact `jws` of `claims`, with the PACT AS key. */
const reciboDe = (k, cambios = {}) => {
	const claims = {
		grantId: GRANT, user: USUARIO, pa: AGENTE, brand: IFACE, scopesUsed: ["pedidos:modificar"],
		actions: [{ tool: "pedido.reprogramar_despacho.preparar", argsHash: requestDigest }], ts: "2026-10-20T16:00:01Z", ...cambios,
	};
	return { jws: jws(k, { alg: "ES256", kid: k.kid }, claims), claims };
};
const recibo = reciboDe(kAs);
const OTRO_HASH = "sha-256:" + b64u(sha256("una huella que no sale de lo pedido"));
const [rh, , rs] = recibo.jws.split(".");
const reciboAlterado = { jws: rh + "." + b64u(jcs({ ...recibo.claims, grantId: "a2agrant_OTRO" })) + "." + rs, claims: { ...recibo.claims, grantId: "a2agrant_OTRO" } };

// ---------- public documents ----------
const confianza = {
	version: "0.1", company: EMPRESA, jwks_uri: `${EMPRESA}/vxp/proof-jwks.json`,
	operator: { issuer: OPERADOR, jwks_uri: `${OPERADOR}/proof-jwks.json` }, custody: "operator_hosted",
	log: { origin: "log.operator.example/proof/v0.1", checkpoint_url: "https://log.operator.example/proof/v0.1/checkpoint", consistency_url: "https://log.operator.example/proof/v0.1/consistency", jwks_uri: "https://log.operator.example/proof/v0.1/jwks.json", witnesses: [] },
	domains: [MARCA],
	pact: [{ interface: IFACE, authorization_server: AS }],
};
const bloque = { ...confianza, endpoint: `${IFACE}/vxp/proof`, approval_channels: ["whatsapp"], capabilities: [{ name: "pedido.reprogramar_despacho", effect: "write", max_assurance: ["issuer_key_attested", "operator_observed", "operator_reported_read_back", "operator_reported_channel_approval"], third_party: [] }] };
const card = (iface, params) => ({
	name: "Ferretería Demo",
	supportedInterfaces: [{ url: iface, protocolBinding: "HTTP+JSON", protocolVersion: "1.0" }],
	capabilities: { extensions: [{ uri: EXT, required: false, params }] },
	securitySchemes: { userDelegation: { oauth2SecurityScheme: { oauth2MetadataUrl: `${iface}/oauth/.well-known/oauth-authorization-server` } } },
});
// Another provider that publishes a Card with the brand's name, with its own issuer, self-consistent.
const OTRO = "https://otro-proveedor.example";
const OTRA_EMPRESA = `${OTRO}/e/demo`;
const OTRA_IFACE = `${OTRO}/a2a/demo`;
const confianzaOtra = { ...confianza, company: OTRA_EMPRESA, jwks_uri: `${OTRA_EMPRESA}/vxp/proof-jwks.json`, operator: { issuer: `${OTRO}/op`, jwks_uri: `${OTRO}/op/proof-jwks.json` }, domains: ["otro-proveedor.example"], pact: [{ interface: OTRA_IFACE, authorization_server: `${OTRA_IFACE}/oauth` }] };
const AS_FALSO = `${OTRO}/a2a/demo-falso/oauth`;

const docs = {
	[`https://${MARCA}/.well-known/agent-card.json`]: card(IFACE, bloque),
	[metaUrl(EMPRESA)]: { issuer: EMPRESA, vxp_proof: confianza },
	[metaUrl(AS)]: { issuer: AS, jwks_uri: `${AS}/jwks.json`, vxp_proof: confianza },
	[`${AS}/jwks.json`]: { keys: [kAs.publicJwk] },
	[confianza.jwks_uri]: { keys: [kEmpresa.publicJwk] },
	[confianza.operator.jwks_uri]: { keys: [kOperador.publicJwk] },
	// PD3: a faithful copy of Demo's Card served on a domain Demo does not list.
	"https://demo-falsa.example/.well-known/agent-card.json": card(IFACE, bloque),
	// PD4: an authorization server that claims to be Demo's, which Demo does not list in `pact`.
	[metaUrl(AS_FALSO)]: { issuer: AS_FALSO, jwks_uri: `${AS_FALSO}/jwks.json`, vxp_proof: confianza },
	// PD5: another provider's Card with the brand's name and its own issuer.
	"https://otro-proveedor.example/.well-known/agent-card.json": card(OTRA_IFACE, { ...bloque, ...confianzaOtra }),
	[metaUrl(OTRA_EMPRESA)]: { issuer: OTRA_EMPRESA, vxp_proof: confianzaOtra },
	[metaUrl(`${OTRA_IFACE}/oauth`)]: { issuer: `${OTRA_IFACE}/oauth`, jwks_uri: `${OTRA_IFACE}/oauth/jwks.json`, vxp_proof: confianzaOtra },
	[confianzaOtra.jwks_uri]: { keys: [kOtro.publicJwk] },
	[confianzaOtra.operator.jwks_uri]: { keys: [kOtro.publicJwk] },
	// PD7: the brand domain's Card with a copy that does not match (different declared custody).
	"https://copia-distinta.ferreteria-demo.example/.well-known/agent-card.json": card(IFACE, { ...bloque, custody: "customer_managed" }),
};
// PD7 needs Demo to list that domain, so the failure is the copy's and not the domain's.
const confianzaPd7 = { ...confianza, domains: [MARCA, "copia-distinta.ferreteria-demo.example"] };

const casos = [
	{ id: "PD1", expect: "valid", anchor: { brand_domain: MARCA }, receipt: recibo, expect_fields: { company: EMPRESA, anchor: "brand_domain", final_state: "succeeded", pact_receipt: "verified" }, note: "Ancla por la marca: Card en el dominio (PACT §2.1) → company → la empresa lista el dominio y la interfaz → AS de PACT; recibo verificado y citado" },
	{ id: "PD2", expect: "valid", anchor: { pact_issuer: AS }, expect_fields: { company: EMPRESA, anchor: "pact_issuer", pact_receipt: "not_presented" }, note: "Ancla por el AS de PACT que el agente conoció al delegar (PACT §5.1); sin recibo presentado" },
	{ id: "PD3", expect: "issuer_not_anchored", anchor: { brand_domain: "demo-falsa.example" }, note: "Una copia fiel de la Card de Demo en un dominio que Demo no lista en `domains`" },
	{ id: "PD4", expect: "issuer_not_anchored", anchor: { pact_issuer: AS_FALSO }, note: "Un AS que se declara de Demo y que Demo no lista en `pact`" },
	{ id: "PD5", expect: "company_mismatch", anchor: { brand_domain: "otro-proveedor.example" }, note: "Ronda 2 M1: la Card de otro proveedor con el nombre de la marca ancla a SU issuer, no al de Demo; el paquete de Demo no valida a nombre de él" },
	{ id: "PD6", expect: "issuer_not_anchored", anchor: { pact_issuer: `${OTRO}/a2a/sin-metadata/oauth` }, note: "Ronda 2 m4: metadata ausente (404) → issuer_not_anchored, sin caerse" },
	{ id: "PD7", expect: "issuer_not_anchored", anchor: { brand_domain: "copia-distinta.ferreteria-demo.example" }, docs_override: { [metaUrl(EMPRESA)]: { issuer: EMPRESA, vxp_proof: confianzaPd7 }, [metaUrl(AS)]: { issuer: AS, jwks_uri: `${AS}/jwks.json`, vxp_proof: confianzaPd7 } }, note: "La copia de la Card no es idéntica a la metadata de la empresa" },
	{ id: "PD8", expect: "issuer_not_anchored", anchor: { brand_domain: MARCA }, docs_override: { [metaUrl(AS)]: { issuer: AS, jwks_uri: `${AS}/jwks.json`, vxp_proof: { ...confianza, jwks_uri: `${AS}/otras-llaves.json` } } }, note: "La copia del bloque en la metadata del AS de PACT no es la de la empresa" },
	{ id: "PD9", expect: "issuer_not_anchored", anchor: { pact_issuer: AS }, docs_override: { [metaUrl(AS)]: { issuer: AS, jwks_uri: "https://cdn.otro.example/jwks.json", vxp_proof: confianza } }, note: "El jwks_uri del AS de PACT (llaves de los recibos) no está bajo su issuer" },
	{ id: "PD10", expect: "issuer_not_anchored", anchor: { brand_domain: MARCA }, docs_override: { [`https://${MARCA}/.well-known/agent-card.json`]: card("https://provider.operator.example/a2a/otra-interfaz", bloque) }, note: "La Card del dominio apunta a una interfaz que la empresa no lista en `pact`" },
	{ id: "R1", expect: "pact_receipt_invalid", seq: 0, anchor: { brand_domain: MARCA }, receipt: reciboDe(kOtro), note: "Recibo firmado con una llave que no está en el jwks_uri del AS de PACT anclado" },
	{ id: "R2", expect: "pact_receipt_invalid", seq: 0, anchor: { brand_domain: MARCA }, receipt: reciboAlterado, note: "Claims del recibo alterados sin volver a firmar" },
	{ id: "R3", expect: "pact_receipt_mismatch", seq: 0, anchor: { brand_domain: MARCA }, receipt: reciboDe(kAs, { grantId: "a2agrant_OTRO" }), note: "Recibo válido de otra delegación" },
	{ id: "R4", expect: "pact_receipt_mismatch", seq: 0, anchor: { brand_domain: MARCA }, receipt: reciboDe(kAs, { actions: [{ tool: "pedido.reprogramar_despacho.preparar", argsHash: dig({ binding: "pact.message", text: "Cambia el despacho del P-1043 al 2026-10-30" }) }] }), note: "Recibo válido de otra petición" },
	{ id: "R5", expect: "pact_receipt_mismatch", seq: 0, anchor: { brand_domain: MARCA }, receipt: reciboDe(kAs, { brand: "https://provider.operator.example/a2a/t_libreria_demo" }), note: "Recibo de otra marca" },
	{ id: "R6", expect: "pact_receipt_mismatch", seq: 0, anchor: { brand_domain: MARCA }, receipt: reciboDe(kAs, { actions: [{ tool: "pedido.reprogramar_despacho.preparar", argsHash: OTRO_HASH }] }), package: cadena({ grantId: GRANT, argsHash: OTRO_HASH }), note: "La request y el recibo coinciden entre sí, pero el argsHash no es la huella de lo pedido (request_digest, SPEC §9.4.1): nadie podría recalcularlo" },
];

const salida = {
	aviso: "VECTORES DE PRUEBA. Llaves derivadas de frases públicas: no usar fuera de pruebas.",
	perfil: "VXP 0.1, perfil PACT: anclaje (SPEC 9.9.1) y cruce con el recibo PACT (SPEC 9.9 paso 4 bis). Corrección ronda 2, 20-oct-2026",
	aud: AGENTE,
	inputs: { solicitud, request_digest: requestDigest, terminos, terms_digest: td },
	keys: { pact_authorization_server: { jwks: { keys: [kAs.publicJwk] }, issuer: AS } },
	package: paquete,
	receipt: recibo,
	docs,
	cases: casos,
};
process.stdout.write(JSON.stringify(salida, null, 2) + "\n");

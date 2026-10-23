// A native-only VXP gateway: no Poppy, no PACT. The whole cycle (discovery, identity, per-request authority,
// proposal, one execution, read-back, proof and relationship) runs on vxp.json and /v1, and the proof
// verifies anchored by the issuer alone.
//
// On purpose, the agent here signs with node:crypto directly: neither the Poppy kit nor the gateway's own
// JOSE helpers. The proof is checked by the independent Python verifier, with material fetched through
// the native discovery only (vxp.json → issuer → RFC 8414 metadata).

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { crearPuerta } from "../src/puerta.ts";

const AUTH = "https://auth.store.example";
const PROVIDER = "https://provider.store.example";
const FERRETERIA = `${AUTH}/e/ferreteria-demo`;
const V1 = `${FERRETERIA}/v1`;
const DOMINIO = "agents.store.example";
const T = "t_ferreteria_demo";
const RAR = "https://vxpprotocol.org/rar/capability";
const RAR_REL = "https://vxpprotocol.org/rar/relationship";
const CAP = "pedido.reprogramar_despacho";
const CLIENTE = "+56900000101";
const VERIFICADOR = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
const tmp = mkdtempSync(join(tmpdir(), "vxp-nativo-solo-"));

// ── Minimal JOSE with node:crypto (ES256, RFC 7515 compact, RFC 9449 DPoP) ─────────────────────

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
type Llave = { privateKey: KeyObject; jwk: { kty: string; crv: string; x: string; y: string } };
function nuevaLlave(): Llave {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const j = publicKey.export({ format: "jwk" }) as { x: string; y: string };
	return { privateKey, jwk: { kty: "EC", crv: "P-256", x: j.x, y: j.y } };
}
function jwt(llave: Llave, header: Record<string, unknown>, payload: Record<string, unknown>): string {
	const h = b64u(JSON.stringify({ alg: "ES256", ...header }));
	const p = b64u(JSON.stringify(payload));
	return `${h}.${p}.${b64u(sign("sha256", Buffer.from(`${h}.${p}`), { key: llave.privateKey, dsaEncoding: "ieee-p1363" }))}`;
}
const ahora = () => Math.floor(Date.now() / 1000);
const jti = () => randomBytes(12).toString("base64url");
function asercion(llave: Llave, iss: string, sub: string, aud: string) {
	return jwt(llave, { typ: "JWT" }, { iss, sub, aud, iat: ahora(), exp: ahora() + 60, jti: jti() });
}
function dpop(llave: Llave, method: string, url: string, token?: string) {
	const u = new URL(url);
	return jwt(llave, { typ: "dpop+jwt", jwk: llave.jwk }, {
		jti: jti(), htm: method, htu: `${u.origin}${u.pathname}`, iat: ahora(),
		...(token ? { ath: b64u(createHash("sha256").update(token).digest()) } : {}),
	});
}

// ── In-process network: the agent's own documents, and the native-only gateway ─────────────────

const AGENTE = "assistant.example";
const clientId = `https://${AGENTE}/agent.json`;
const llaveCliente = nuevaLlave();
const llaveDpop = nuevaLlave();
const buzon: { message: string }[] = [];
// Client ID Metadata Document with VXP extensions only: no Poppy `operations`, no PACT.
const cimd = {
	client_id: clientId,
	client_name: "Native-only assistant",
	jwks_uri: `https://${AGENTE}/jwks.json`,
	redirect_uris: [`https://${AGENTE}/cb`],
	token_endpoint_auth_method: "private_key_jwt",
	extensions: { "vxpprotocol.org/proof": { version: "0.1" }, "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `https://${AGENTE}/vxp/inbox` } },
};
const red = async (input: string, init: RequestInit = {}): Promise<Response> => {
	const url = new URL(input);
	if (url.host === AGENTE) {
		if (url.pathname === "/vxp/inbox" && init.method === "POST") {
			buzon.push(JSON.parse(String(init.body)));
			return new Response(null, { status: 202 });
		}
		return Response.json(url.pathname === "/agent.json" ? cimd : { keys: [{ ...llaveCliente.jwk, alg: "ES256", use: "sig" }] });
	}
	return puerta.handler(new Request(input, init));
};
const puerta = crearPuerta({
	authOrigin: AUTH,
	providerOrigin: PROVIDER,
	empresas: empresasDePrueba({ ferreteria: DOMINIO, libreria: "agents.bookshop.example" }),
	pactDelegada: [T],
	plataformasPact: [],
	fetch: red,
	adaptadores: { poppy: false, pact: false },
});
const interno = async (path: string, body?: unknown) =>
	(await red(`${AUTH}/interno/${path}`, { method: body ? "POST" : "GET", headers: { "x-sovras-prueba": puerta.llaveInterna, "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) })).json();

let token = "";
const base = () => ({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: V1, client_assertion: asercion(llaveCliente, clientId, clientId, FERRETERIA) });
async function tokenRequest(form: Record<string, string>, sub = "usr_native_1") {
	const url = `${FERRETERIA}/oauth/token`;
	const body = new URLSearchParams({ ...form, ...base(), assertion: asercion(llaveCliente, clientId, sub, FERRETERIA) });
	const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: dpop(llaveDpop, "POST", url) }, body: body.toString() });
	return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}
async function pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
	const r = await red(url, { method, headers: { authorization: `DPoP ${token}`, dpop: dpop(llaveDpop, method, url, token), "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
	const t = await r.text();
	return { status: r.status, body: t ? JSON.parse(t) : null };
}
async function autorizar(detalles: unknown[], marcar: string[]) {
	const devR = await red(`${FERRETERIA}/oauth/device`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...base(), authorization_details: JSON.stringify(detalles) }).toString() });
	const dev = await devR.json();
	assert.equal(devR.status, 200, JSON.stringify(dev));
	// The person approves on the company's own page, identified through the company's channel.
	const post = (paso: string, form: Record<string, string | string[]>) => {
		const b = new URLSearchParams();
		for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) b.append(k, x);
		return red(`${FERRETERIA}/vincular/${paso}`, { method: "POST", body: b.toString(), redirect: "manual" });
	};
	await post("telefono", { user_code: dev.user_code, telefono: CLIENTE });
	const otp = ((await interno(`whatsapp/salida?tenant=${T}`)) as { texto: string }[]).at(-1)!.texto.match(/código es (\d{6})/)![1];
	await post("codigo", { user_code: dev.user_code, codigo: otp });
	await post("decision", { user_code: dev.user_code, decision: "allow", scope: marcar });
	const t = await tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
	assert.equal(t.status, 200, JSON.stringify(t.body));
	token = String(t.body.access_token);
	return t.body;
}
const metadataDe = (issuer: string) => `${new URL(issuer).origin}/.well-known/oauth-authorization-server${new URL(issuer).pathname}`;

test("nativo sin adaptadores: no hay poppy.json, ni Agent Card, ni A2A, ni rutas Poppy; la metadata del issuer no trae miembros de Poppy", async () => {
	for (const u of [`https://${DOMINIO}/.well-known/poppy.json`, `https://${DOMINIO}/.well-known/agent-card.json`, `${PROVIDER}/a2a/${T}/.well-known/agent-card.json`, `${FERRETERIA}/poppy/conversaciones`, `${AUTH}/.well-known/oauth-authorization-server/a2a/${T}/oauth`])
		assert.equal((await red(u)).status, 404, u);
	const vxp = await (await red(`https://${DOMINIO}/.well-known/vxp.json`)).json();
	assert.equal(vxp.protocol, "vxp");
	assert.equal(vxp.issuer, FERRETERIA);
	const meta = await (await red(metadataDe(vxp.issuer))).json();
	assert.equal(meta.issuer, FERRETERIA);
	assert.ok(!("poppy_domains" in meta));
	assert.ok(meta.vxp_proof && meta.vxp_relationship);
	assert.deepEqual(meta.vxp_proof.pact, [], "no PACT bindings when that adapter is off");
	// A token request without the native resource has no other profile to fall back to.
	const r = await red(`${FERRETERIA}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", client_id: clientId }).toString() });
	assert.equal(r.status, 400);
	assert.equal((await r.json()).error, "invalid_target");
});

test("nativo sin adaptadores: recorrido completo — autoridad por pedido, propuesta firmada, una ejecución, lectura de vuelta, constancia verificada por el issuer, y relación", async () => {
	const s = await tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
	assert.equal(s.status, 200, JSON.stringify(s.body));
	token = String(s.body.access_token);
	const cuerpo = { operation: CAP, target: { order_ref: "P-1042" }, parameters: { delivery_date: "2026-10-28" } };
	const llave = "native-only-1";
	const r0 = await pedir("POST", `${V1}/requests`, cuerpo, { "idempotency-key": llave });
	assert.equal(r0.status, 202, JSON.stringify(r0.body));
	assert.equal(r0.body.state, "authorization_required");

	const t = await autorizar([{ type: RAR, actions: [CAP], identifier: "P-1042" }, { type: RAR_REL, actions: ["despacho.proponer_cambio"], identifier: "relationship", limits: { max_per_day: 2, duration_seconds: 3600 } }], ["pedidos:modificar", "vxp:relationship"]);
	const rel = (t.relationships as { relationship_id: string; state: string }[] | undefined)?.[0];
	assert.ok(rel, "la relación nace en el mismo consentimiento");

	const r1 = await pedir("POST", `${V1}/requests`, cuerpo, { "idempotency-key": llave });
	assert.ok([200, 201].includes(r1.status), JSON.stringify(r1.body));
	assert.equal(r1.body.state, "proposed");
	const acepta = await pedir("POST", `${V1}/proposals/${r1.body.proposal.id}/accept`, { approved_by: "user" });
	assert.ok([200, 202].includes(acepta.status), JSON.stringify(acepta.body));
	const final = await pedir("GET", `${V1}/requests/${r1.body.request_id}`);
	assert.equal(final.body.state, "succeeded");
	const sistema = (await interno(`sistema?tenant=${T}`)) as { id: string; despacho: string }[];
	assert.equal(sistema.find((p) => p.id === "P-1042")?.despacho, "2026-10-28", "one execution, visible in the company's system");

	// The proof, verified with material reached through the native discovery only.
	const paquete = (await pedir("GET", `${V1}/requests/${r1.body.request_id}/proof`)).body;
	const traer = async (u: string) => (await red(u)).text();
	const issuer = JSON.parse(await traer(`https://${DOMINIO}/.well-known/vxp.json`)).issuer;
	const docs: Record<string, string> = { [metadataDe(issuer)]: await traer(metadataDe(issuer)) };
	const bloque = JSON.parse(docs[metadataDe(issuer)]).vxp_proof;
	for (const u of [bloque.jwks_uri, bloque.operator.jwks_uri, bloque.log.jwks_uri, bloque.log.checkpoint_url]) docs[u] = await traer(u);
	assert.ok(Object.keys(docs).every((u) => !/poppy|agent-card|a2a/.test(u)), JSON.stringify(Object.keys(docs)));
	writeFileSync(join(tmp, "m.json"), JSON.stringify({ anchor: { issuer }, docs }));
	writeFileSync(join(tmp, "p.json"), JSON.stringify(paquete));
	writeFileSync(join(tmp, "o.json"), JSON.stringify(final.body));
	const v = spawnSync("python", [VERIFICADOR, "material", "--material", join(tmp, "m.json"), "--paquete", join(tmp, "p.json")], { encoding: "utf8" });
	const veredicto = JSON.parse(v.stdout.trim().split("\n").at(-1)!);
	assert.equal(veredicto.valid, true, v.stdout + v.stderr);
	assert.equal(veredicto.anchor, "issuer");
	assert.equal(veredicto.final_state, "succeeded");
	assert.equal(veredicto.key_source, "issuer_metadata_saved", "keys read from saved material, and the verdict says so");

	// The company starts a request inside the relationship; it reaches the agent's own HTTP inbox.
	const inicia = await interno("relaciones/iniciar", { tenant: T, relationship_id: rel!.relationship_id, action: "despacho.proponer_cambio", params: { order_ref: "P-1042", delivery_date: "2026-11-02" } });
	assert.ok(!inicia.error, JSON.stringify(inicia));
	assert.equal(buzon.length, 1, "delivered to the inbox the agent declared in its CIMD");
});

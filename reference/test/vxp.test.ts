// VXP tests against the gateway (in process, with the real handler). Each block covers one point:
//   A · Poppy, PACT and native on the same order: a single execution, without breaking their contracts.
//   B · Authorization bound to exact conditions: stale revision, permission for another resource, reuse,
//       revocation and identity change.
//   C · VXP Proof facing pending, contradictory or unverifiable results.
//   D · Traditional channels: detection, in-channel limits and transition to the structured connection.
//   E · VXP Relationship: prior authorization, company-initiated management, limits, expiry and
//       revocation. The receiving agent is local: this tests the components, NOT external interoperability.
//
// Agents sign with the primitives of the official Poppy kit (vendor/poppy-kit). The evidence is
// checked by the independent Python verifier, anchored in the issuer's RFC 8414 metadata.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { decodeJwt, verifyWith } from "../src/jose.ts";
import { crearPuerta } from "../src/puerta.ts";
import { CUPOS, Carriles, TOPE_OTP } from "../src/carriles.ts";
import { dpopProof, generateKey, randomId, type SigningKey, signAssertion, signJwt, nowSeconds } from "../vendor/poppy-kit/validate/jose.ts";

const AUTH = "https://auth.sovras.test";
const PROVIDER = "https://provider.sovras.test";
const FERRETERIA = `${AUTH}/e/ferreteria-demo`;
const V1 = `${FERRETERIA}/v1`;
const DOMINIO = "agentes.ferreteria-demo.test";
const T = "t_ferreteria_demo";
const IFACE = `${PROVIDER}/a2a/${T}`;
const PA_PACT = "https://pa-pact.test";
const RAR = "https://vxpprotocol.org/rar/capability";
const RAR_REL = "https://vxpprotocol.org/rar/relationship";
const CAP = "pedido.reprogramar_despacho";
const ANA = "+56900000101";
const VERIFICADOR = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
const tmp = mkdtempSync(join(tmpdir(), "sovras-vxp-"));

// ── In-process network ──────────────────────────────────────────────────────────────────────────

type Pa = { clientId: string; key: SigningKey; doc: Record<string, unknown>; buzon: { message: string }[] };
const agentes = new Map<string, Pa>();
const paPactKey = await generateKey(true);
async function nuevoAgente(host: string, conBuzon = true): Promise<Pa> {
	const key = await generateKey(true);
	const clientId = `https://${host}/agent.json`;
	const doc = {
		client_id: clientId,
		client_name: `Asistente ${host}`,
		jwks_uri: `https://${host}/jwks.json`,
		redirect_uris: [`https://${host}/cb`],
		token_endpoint_auth_method: "private_key_jwt",
		extensions: { operations: { version: "1" }, "vxpprotocol.org/proof": { version: "0.1" }, ...(conBuzon ? { "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `https://${host}/vxp/inbox` } } : {}) },
	};
	const pa = { clientId, key, doc, buzon: [] };
	agentes.set(host, pa);
	return pa;
}
const red = async (input: string, init: RequestInit = {}): Promise<Response> => {
	const url = new URL(input);
	if (url.origin === PA_PACT) return new Response(JSON.stringify({ keys: [paPactKey.publicJwk] }), { headers: { "content-type": "application/json" } });
	const pa = agentes.get(url.host);
	if (pa && url.pathname === "/vxp/inbox" && init.method === "POST") {
		pa.buzon.push(JSON.parse(String(init.body)));
		return new Response(null, { status: 202 });
	}
	if (pa && url.pathname === "/.well-known/http-message-signatures-directory") return new Response(JSON.stringify(pa.doc), { headers: { "content-type": "application/http-message-signatures-directory+json" } });
	if (pa) return new Response(JSON.stringify(url.pathname === "/agent.json" ? pa.doc : { keys: [pa.key.publicJwk] }), { headers: { "content-type": "application/json" } });
	return puerta.handler(new Request(input, init));
};
function nuevaPuerta(ajustar: (e: ReturnType<typeof empresasDePrueba>) => void = () => {}, extra: { carriles?: Carriles; ttlPase?: number } = {}) {
	const empresas = empresasDePrueba({ ferreteria: DOMINIO, libreria: "agentes.libreria-demo.test" });
	ajustar(empresas);
	return crearPuerta({
		authOrigin: AUTH,
		providerOrigin: PROVIDER,
		empresas,
		pactDelegada: [T],
		plataformasPact: [{ nombre: "pa-pact", issuer: PA_PACT, jwksUri: `${PA_PACT}/jwks.json`, enabled: true }],
		fetch: red,
		...extra,
	});
}
let puerta = nuevaPuerta();
const interno = async (path: string, body?: unknown) =>
	(
		await red(`${AUTH}/interno/${path}`, {
			method: body ? "POST" : "GET",
			headers: { "x-sovras-prueba": puerta.llaveInterna, "content-type": "application/json" },
			...(body ? { body: JSON.stringify(body) } : {}),
		})
	).json();
const pedidos = async () => (await interno(`sistema?tenant=${T}`)) as { id: string; despacho: string }[];
const despacho = async (id: string) => (await pedidos()).find((p) => p.id === id)?.despacho;
const salida = async () => (await interno(`whatsapp/salida?tenant=${T}`)) as { telefono: string; texto: string }[];
const nuevoPedido = (id: string, despachoActual = "2026-10-26", transportista?: string) =>
	interno("pedidos", { tenant: T, pedido: { id, clienteId: "ERP-C-0193", producto: `Producto ${id}`, despacho: despachoActual, direccion: "Calle Ejemplo 100, Santiago", estado: "preparando", ...(transportista ? { transportista } : {}) } });
/** How many times something was executed on an order in the company system (Tool Gateway). */
const ejecuciones = (pedido: string) => [...puerta.nucleo.base(T).operaciones.values()].filter((o) => o.interno.intent.inputs.pedidoId === pedido && o.interno.ejecutada).length;
const declaraciones = (paquete: { statements: string[] }) => paquete.statements.map((s) => JSON.parse(Buffer.from(s.split("~")[0].split(".")[1], "base64url").toString("utf8")));

async function vincularPagina(userCode: string, telefono: string, scope: string[]) {
	const post = (paso: string, form: Record<string, string | string[]>) => {
		const b = new URLSearchParams();
		for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) b.append(k, x);
		return red(`${FERRETERIA}/vincular/${paso}`, { method: "POST", body: b.toString(), redirect: "manual" });
	};
	await post("telefono", { user_code: userCode, telefono });
	const otp = (await salida()).at(-1)!.texto.match(/código es (\d{6})/)![1];
	await post("codigo", { user_code: userCode, codigo: otp });
	await post("decision", { user_code: userCode, decision: "allow", scope });
}

class AgenteNativo {
	readonly sub: string;
	dpopKey!: SigningKey;
	token = "";
	ultimoToken: Record<string, unknown> = {};
	readonly pa: Pa;
	constructor(pa: Pa, sub = `usr_${randomId(9)}`) {
		this.pa = pa;
		this.sub = sub;
	}
	private base() {
		return { client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: V1 };
	}
	private clienteAsercion() {
		return signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: FERRETERIA });
	}
	async tokenRequest(form: Record<string, string>) {
		const url = `${FERRETERIA}/oauth/token`;
		const body = new URLSearchParams({ ...form, ...this.base(), client_assertion: await this.clienteAsercion(), assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: FERRETERIA }) });
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return { status: r.status, body: (await r.json()) as Record<string, unknown> };
	}
	async sesion() {
		this.dpopKey ??= await generateKey(false);
		const r = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
		assert.equal(r.status, 200, JSON.stringify(r.body));
		this.token = String(r.body.access_token);
	}
	/** RFC 8628 + RFC 9396. `detalles` are the authorization_details; `marcar`, the boxes the person leaves checked. */
	async autorizar(detalles: unknown[], marcar: string[], telefono = ANA) {
		this.dpopKey ??= await generateKey(false);
		const devR = await red(`${FERRETERIA}/oauth/device`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ ...this.base(), client_assertion: await this.clienteAsercion(), authorization_details: JSON.stringify(detalles) }).toString(),
		});
		const dev = await devR.json();
		if (devR.status !== 200) return { status: devR.status, body: dev as Record<string, unknown>, pagina: "" };
		const pagina = await red(dev.verification_uri_complete).then((r) => r.text());
		await vincularPagina(dev.user_code, telefono, marcar);
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
		if (t.status === 200) {
			this.token = String(t.body.access_token);
			this.ultimoToken = t.body;
		}
		return { ...t, pagina };
	}
	vincular(pedidosRar: string[]) {
		return this.autorizar(pedidosRar.map((id) => ({ type: RAR, actions: [CAP], identifier: id })), ["pedidos:modificar"]);
	}
	async pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}, llaveDpop = this.dpopKey, token = this.token) {
		const r = await red(url, {
			method,
			headers: { authorization: `DPoP ${token}`, dpop: await dpopProof({ key: llaveDpop, method, url, accessToken: token }), "content-type": "application/json", ...headers },
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		});
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null };
	}
	solicitar(orden: string, fecha: string) {
		return this.pedir("POST", `${V1}/requests`, { operation: CAP, target: { order_ref: orden }, parameters: { delivery_date: fecha } }, { "idempotency-key": randomId(12) });
	}
	aceptar(proposalId: string) {
		return this.pedir("POST", `${V1}/proposals/${proposalId}/accept`, { approved_by: "user" });
	}
	leer(id: string) {
		return this.pedir("GET", `${V1}/requests/${id}`);
	}
	prueba(id: string) {
		return this.pedir("GET", `${V1}/requests/${id}/proof`);
	}
}

class UsuarioPoppy {
	readonly sub: string;
	dpopKey!: SigningKey;
	token = "";
	sessionId = "";
	conv = "";
	readonly pa: Pa;
	constructor(pa: Pa, sub: string) {
		this.pa = pa;
		this.sub = sub;
	}
	async tokenRequest(form: Record<string, string>) {
		const url = `${FERRETERIA}/oauth/token`;
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: FERRETERIA });
		const body = new URLSearchParams({ ...form, client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion });
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return (await r.json()) as Record<string, unknown>;
	}
	async entrar(telefono: string, alcances = ["pedidos:leer", "pedidos:modificar"]) {
		this.dpopKey = await generateKey(false);
		const s = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: FERRETERIA }) });
		this.sessionId = String(s.session_id);
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: FERRETERIA });
		const dev = await red(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ scope: alcances.join(" "), client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion }).toString() }).then((r) => r.json());
		await vincularPagina(dev.user_code, telefono, alcances);
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code, session_id: this.sessionId });
		assert.ok(t.access_token, JSON.stringify(t));
		this.token = String(t.access_token);
	}
	async pedir(method: string, url: string, body?: unknown) {
		const r = await red(url, { method, headers: { authorization: `DPoP ${this.token}`, dpop: await dpopProof({ key: this.dpopKey, method, url, accessToken: this.token }), "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null };
	}
	async proponer(texto: string) {
		const url = this.conv ? `${FERRETERIA}/poppy/conversaciones/${this.conv}/messages?wait=0` : `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await this.pedir("POST", url, { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } });
		this.conv = r.body.conversation_id;
		return [...r.body.events].reverse().find((e: { message?: { operation?: unknown } }) => e.message?.operation)?.message.operation;
	}
	confirmar(op: { operation_id: string; revision: number }) {
		return this.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op.operation_id}/confirm`, { revision: op.revision, approved_by: "user" });
	}
}

class AgentePact {
	readonly sub = `pact_${randomId(6)}`;
	delegacion = "";
	contexto: string | undefined;
	private async jwt() {
		const iat = nowSeconds();
		return signJwt({ alg: "ES256", typ: "JWT", ...(paPactKey.publicJwk.kid ? { kid: paPactKey.publicJwk.kid } : {}) }, { iss: PA_PACT, sub: this.sub, aud: `${PROVIDER}/a2a`, iat, exp: iat + 60 }, paPactKey.privateKey);
	}
	async delegar(telefono: string) {
		const dev = await red(`${IFACE}/oauth/device_authorization`, { method: "POST", headers: { authorization: `Bearer ${await this.jwt()}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: PA_PACT, scope: "pedidos:leer pedidos:modificar" }).toString() }).then((r) => r.json());
		await vincularPagina(dev.user_code, telefono, ["pedidos:leer", "pedidos:modificar"]);
		const t = await red(`${IFACE}/oauth/token`, { method: "POST", headers: { authorization: `Bearer ${await this.jwt()}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: PA_PACT, grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code }).toString() }).then((r) => r.json());
		assert.ok(t.access_token, JSON.stringify(t));
		this.delegacion = t.access_token;
	}
	async enviar(texto: string) {
		const r = await red(`${IFACE}/message:send`, {
			method: "POST",
			headers: { authorization: `Bearer ${await this.jwt()}`, "x-a2a-user-delegation": `Bearer ${this.delegacion}`, "content-type": "application/a2a+json" },
			body: JSON.stringify({ message: { messageId: randomId(8), role: "ROLE_USER", parts: [{ text: texto }], ...(this.contexto ? { contextId: this.contexto } : {}) } }),
		}).then((x) => x.json());
		this.contexto = r.message?.contextId ?? this.contexto;
		return r;
	}
}

const metadataDe = (issuer: string) => {
	const u = new URL(issuer);
	return `${u.origin}/.well-known/oauth-authorization-server${u.pathname}`;
};
/** Independent verifier, with material fetched through the protocol (vxp.json → issuer → metadata). */
async function verificar(paquete: unknown) {
	const docs: Record<string, unknown> = {};
	const traer = async (u: string) => (await red(u)).text();
	const issuer = JSON.parse(await traer(`https://${DOMINIO}/.well-known/vxp.json`)).issuer;
	docs[metadataDe(issuer)] = await traer(metadataDe(issuer));
	const bloque = JSON.parse(String(docs[metadataDe(issuer)])).vxp_proof;
	for (const u of [bloque.jwks_uri, bloque.operator.jwks_uri, bloque.log.jwks_uri]) docs[u] = await traer(u);
	docs[bloque.log.checkpoint_url] = await traer(bloque.log.checkpoint_url);
	const n = randomId(6);
	writeFileSync(join(tmp, `${n}-m.json`), JSON.stringify({ anchor: { issuer }, docs }));
	writeFileSync(join(tmp, `${n}-p.json`), JSON.stringify(paquete));
	const r = spawnSync("python", [VERIFICADOR, "material", "--material", join(tmp, `${n}-m.json`), "--paquete", join(tmp, `${n}-p.json`)], { encoding: "utf8" });
	assert.ok(r.stdout, `el verificador no respondió: ${r.stderr}`);
	return JSON.parse(r.stdout.trim().split("\n").at(-1)!) as Record<string, unknown>;
}

for (const id of ["P-5001", "P-5002", "P-5003", "P-5004", "P-5005", "P-5006", "P-5007", "P-5008", "P-5010", "P-5011", "P-5012", "P-5013", "P-5014"]) await nuevoPedido(id);
await nuevoPedido("P-5009", "2026-10-26", "Transportes Demo (simulado)");
const plataforma = await nuevoAgente("asistente.test");

// ── A · Compatibility ──────────────────────────────────────────────────────────────────────

test("A1 · el mismo pedido pedido por Poppy, PACT y nativo: tres operaciones separadas, UNA ejecución; las otras fallan sin efecto y con su evidencia", async () => {
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar(ANA);
	const pact = new AgentePact();
	await pact.delegar(ANA);
	const nat = new AgenteNativo(plataforma);
	await nat.sesion();
	assert.equal((await nat.vincular(["P-5001"])).status, 200);

	const opPoppy = await poppy.proponer("Cambia el despacho del P-5001 al 2026-10-30");
	const mPact = await pact.enviar("Cambia el despacho del P-5001 al 2026-10-31");
	const opPact = mPact.message.metadata["vxpprotocol.org/operation"];
	const aviso = (await salida()).at(-1)!;
	const rNat = await nat.solicitar("P-5001", "2026-11-01");
	assert.equal(rNat.status, 201, JSON.stringify(rNat.body));
	assert.equal(new Set([opPoppy.operation_id, opPact.operation_id, rNat.body.operation_id]).size, 3);

	// Poppy confirms first: it executes once. Confirming the same revision again does not execute again.
	assert.equal((await poppy.confirmar(opPoppy)).body.state, "succeeded");
	assert.equal((await poppy.confirmar(opPoppy)).body.state, "succeeded");
	assert.equal(await despacho("P-5001"), "2026-10-30");
	// PACT approves over WhatsApp and native accepts: the precondition no longer holds, nothing executes.
	const ap = await interno("whatsapp/entrada", { tenant: T, telefono: aviso.telefono, texto: `APROBAR ${aviso.texto.match(/APROBAR (\d{6})/)![1]}` });
	assert.equal(ap.aceptado, true);
	const aNat = await nat.aceptar(rNat.body.proposal.id);
	assert.equal(aNat.body.state, "failed");
	assert.equal(aNat.body.reason, "precondition_failed");
	assert.equal(await despacho("P-5001"), "2026-10-30", "nadie pisó el cambio ya hecho");
	assert.equal(ejecuciones("P-5001"), 1, "una sola ejecución empresarial");
	const ops = puerta.nucleo.base(T).operaciones;
	assert.equal(ops.get(opPact.operation_id)!.interno.nativo.motivoFinal, "precondition_failed");
	// Each contract keeps its states: Poppy sees its enum, A2A its own.
	assert.equal((await poppy.pedir("GET", `${FERRETERIA}/poppy/operaciones/${opPoppy.operation_id}`)).body.state, "succeeded");
	assert.equal(aNat.body.projections.poppy, "failed");
	assert.equal(aNat.body.projections.a2a, "TASK_STATE_FAILED");
	// The evidence of the failed operation says there was no execution.
	const p = (await nat.prueba(rNat.body.request_id)).body;
	assert.deepEqual(declaraciones(p).map((d) => d.kind), ["request", "terms", "user_approval", "outcome"]);
	const v = await verificar(p);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "failed");
});

// ── B · Authorization bound to exact conditions ─────────────────────────────────────────────

const ana = new AgenteNativo(plataforma, "usr_ana_vxp");
await ana.sesion();

test("B1 · revisión antigua: tras una contrapropuesta, aceptar la revisión 1 da terms_changed y no hay efecto", async () => {
	assert.equal((await ana.vincular(["P-5002", "P-5003", "P-5004", "P-5005"])).status, 200);
	const r = await ana.solicitar("P-5002", "2026-10-28");
	const vieja = r.body.proposal.id;
	const c = await ana.pedir("POST", `${V1}/proposals/${vieja}/counter`, { proposed_terms: { delivery_date: "2026-10-29" } });
	assert.equal(c.body.proposal.revision, 2);
	const a = await ana.aceptar(vieja);
	assert.equal(a.status, 409);
	assert.equal(a.body.error, "terms_changed");
	assert.equal(await despacho("P-5002"), "2026-10-26");
	assert.equal((await ana.aceptar(c.body.proposal.id)).body.state, "succeeded");
	assert.equal(await despacho("P-5002"), "2026-10-29", "se ejecutó la revisión aceptada, con sus términos");
});

test("B2 · permiso de otro recurso: un grant para P-5003 no sirve para pedir ni aceptar sobre P-5006", async () => {
	const r = await ana.solicitar("P-5006", "2026-10-28");
	assert.equal(r.status, 202);
	assert.equal(r.body.state, "authorization_required");
	assert.deepEqual(r.body.authorization.authorization_details, [{ type: RAR, actions: [CAP], identifier: "P-5006" }]);
	assert.equal(ejecuciones("P-5006"), 0);
});

test("B3 · reutilización: aceptar dos veces ejecuta una vez; el código de WhatsApp ya usado no aprueba otra cosa", async () => {
	const r = await ana.solicitar("P-5003", "2026-10-30");
	const a1 = await ana.aceptar(r.body.proposal.id);
	const a2 = await ana.aceptar(r.body.proposal.id);
	assert.equal(a1.body.state, "succeeded");
	assert.equal(a2.status, 200);
	assert.equal(a2.body.state, "succeeded");
	assert.equal(ejecuciones("P-5003"), 1);
	// PACT: the same «APROBAR 123456» a second time approves nothing.
	const pact = new AgentePact();
	await pact.delegar(ANA);
	await pact.enviar("Cambia el despacho del P-5007 al 2026-11-02");
	const aviso = (await salida()).at(-1)!;
	const texto = `APROBAR ${aviso.texto.match(/APROBAR (\d{6})/)![1]}`;
	assert.equal((await interno("whatsapp/entrada", { tenant: T, telefono: aviso.telefono, texto })).aceptado, true);
	assert.equal((await interno("whatsapp/entrada", { tenant: T, telefono: aviso.telefono, texto })).aceptado, false);
	assert.equal(ejecuciones("P-5007"), 1);
});

test("B4 · revocación: la persona revoca entre la propuesta y la aceptación; aceptar ya no ejecuta", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	await x.vincular(["P-5004"]);
	const r = await x.solicitar("P-5004", "2026-10-31");
	assert.equal(r.status, 201);
	for (const g of puerta.del.grants.values()) if (g.sub === x.sub) g.revocado = true; // «Desvincular» (unlink) in the console or over WhatsApp
	const a = await x.aceptar(r.body.proposal.id);
	assert.notEqual(a.body.state, "succeeded");
	assert.ok([403, 404].includes(a.status), JSON.stringify(a.body));
	assert.equal(await despacho("P-5004"), "2026-10-26");
	assert.equal(ejecuciones("P-5004"), 0);
});

test("B5 · cambio de identidad: otra llave DPoP, otro usuario del mismo agente u otro agente no usan la solicitud de Ana", async () => {
	const r = await ana.solicitar("P-5005", "2026-11-01");
	const ajena = await generateKey(false);
	const robada = await ana.pedir("POST", `${V1}/proposals/${r.body.proposal.id}/accept`, { approved_by: "user" }, {}, ajena);
	assert.equal(robada.status, 401, "el token está atado a la llave DPoP de Ana");
	const otroUsuario = new AgenteNativo(plataforma);
	await otroUsuario.sesion();
	assert.equal((await otroUsuario.leer(r.body.request_id)).status, 404);
	assert.equal((await otroUsuario.aceptar(r.body.proposal.id)).status, 404);
	const otro = new AgenteNativo(await nuevoAgente("otro-asistente.test"), ana.sub);
	await otro.sesion();
	assert.equal((await otro.leer(r.body.request_id)).status, 404, "mismo sub, otro client_id: otra identidad");
	assert.equal(ejecuciones("P-5005"), 0);
});

// ── C · VXP Proof ───────────────────────────────────────────────────────────────────────────

test("C1 · pendiente: el transportista no responde → la empresa firma `unknown` (válido); al saberse, corrección a `succeeded`", async () => {
	await ana.vincular(["P-5009"]);
	await interno(`transportista?tenant=${T}`, { respuesta: { "P-5009": "no_responde" } });
	const r = await ana.solicitar("P-5009", "2026-10-29");
	const a = await ana.aceptar(r.body.proposal.id);
	assert.equal(a.body.state, "pending_verification");
	const v1 = await verificar((await ana.prueba(r.body.request_id)).body);
	assert.equal(v1.valid, true, JSON.stringify(v1));
	assert.equal(v1.final_state, "unknown");
	await interno(`transportista?tenant=${T}`, { confirmado: { "P-5009": "accepted" } });
	assert.equal((await ana.leer(r.body.request_id)).body.state, "succeeded");
	const p = (await ana.prueba(r.body.request_id)).body;
	assert.deepEqual(declaraciones(p).map((d) => d.kind).slice(-3), ["outcome", "read_back", "correction"]);
	const v2 = await verificar(p);
	assert.equal(v2.final_state, "succeeded", JSON.stringify(v2));
});

test("C2 · contradictorio: se ejecutó pero el sistema muestra otra fecha → lectura firmada que NO calza, `unknown`, persona; nunca `succeeded`", async () => {
	await ana.vincular(["P-5010"]);
	await interno("sistema", { tenant: T, proximaFalla: "desconocida" });
	const r = await ana.solicitar("P-5010", "2026-10-30");
	assert.equal((await ana.aceptar(r.body.proposal.id)).body.state, "pending_verification");
	// While SOVRAS did not know, someone at the company moved the order to another date.
	puerta.nucleo.empresa(T).sistema.pedidos.find((p) => p.id === "P-5010")!.despacho = "2026-11-09";
	const leida = await ana.leer(r.body.request_id);
	assert.equal(leida.body.state, "waiting_human");
	assert.equal(leida.body.projections.poppy, "in_progress", "Poppy no ve failed ni succeeded");
	assert.match(leida.body.result.summary, /muestra el despacho del pedido P-5010 el 2026-11-09/);
	const p = (await ana.prueba(r.body.request_id)).body;
	const ds = declaraciones(p);
	const rb = ds.filter((d) => d.kind === "read_back").at(-1);
	assert.equal(rb.body.matches_terms, false);
	assert.equal(rb.body.observed.despacho_nuevo, "2026-11-09");
	const v = await verificar(p);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "unknown");
	assert.ok(!(v.derived_assurance as string[]).includes("operator_reported_read_back"), "una lectura que no calza no da el nivel de lectura de vuelta");
	assert.equal((await ana.leer(r.body.request_id)).body.state, "waiting_human", "leer otra vez no reintenta ni inventa");
	assert.equal(ejecuciones("P-5010"), 1);
});

test("C3 · no comprobable: una capacidad sin lectura de vuelta nunca firma `succeeded`; su máximo es `unknown`", async () => {
	const anterior = puerta;
	puerta = nuevaPuerta((empresas) => {
		const cap = empresas[0].release.capacidades.find((c) => c.id === CAP)!;
		empresas[0].release.capacidades = empresas[0].release.capacidades.map((c) => (c === cap ? (({ lecturaDeVuelta: _l, ...resto }) => resto)(c) : c));
	});
	try {
		await nuevoPedido("P-5100");
		const x = new AgenteNativo(plataforma);
		await x.sesion();
		await x.vincular(["P-5100"]);
		const r = await x.solicitar("P-5100", "2026-10-30");
		const a = await x.aceptar(r.body.proposal.id);
		assert.equal(a.body.state, "pending_verification");
		assert.equal(await despacho("P-5100"), "2026-10-30", "el cambio se envió");
		assert.match(a.body.result.summary, /no permite comprobarlo/);
		const p = (await x.prueba(r.body.request_id)).body;
		const ds = declaraciones(p);
		assert.equal(ds.find((d) => d.kind === "read_back").body.method, "none");
		const v = await verificar(p);
		assert.equal(v.valid, true, JSON.stringify(v));
		assert.equal(v.final_state, "unknown");
		assert.equal((await x.leer(r.body.request_id)).body.state, "pending_verification");
		assert.equal(declaraciones((await x.prueba(r.body.request_id)).body).length, ds.length, "leer no agrega afirmaciones");
	} finally {
		puerta = anterior;
	}
});

// ── D · Traditional channels ───────────────────────────────────────────────────────────────

const canal = (body: Record<string, unknown>) => interno("canal/entrada", { tenant: T, ...body });

test("D1 · WhatsApp: un asistente que se declara pide un cambio → no se ejecuta en el canal; se ofrece la conexión estructurada", async () => {
	const antes = ejecuciones("P-5011");
	const r = await canal({ canal: "whatsapp", remitente: ANA, texto: "Hola, soy el asistente personal de Cliente de prueba A. Cambia el despacho del P-5011 al 2026-11-02." });
	assert.equal(r.deteccion.probable_agente, true);
	assert.equal(r.deteccion.prueba_identidad, false, "detectar no prueba identidad");
	assert.ok(r.deteccion.senales.some((s: { tipo: string }) => s.tipo === "autodeclaracion"));
	assert.deepEqual(r.en_canal, { lectura: false, escritura: false });
	assert.equal(r.oferta.poppy, `https://${DOMINIO}/.well-known/poppy.json`);
	assert.equal(r.oferta.pact_agent_card, `https://${DOMINIO}/.well-known/agent-card.json`);
	assert.match(r.respuesta, /^No hago cambios por este canal cuando escribe un asistente\./);
	assert.match(r.respuesta, /vincularla y autorizar acciones específicas/);
	const ev = (await interno(`casos?tenant=${T}`)).eventos.filter((x: { eventType: string }) => x.eventType === "channel.write_deferred_to_structured");
	assert.ok(ev.length >= 1, "queda registrado que la escritura se derivó");
	assert.equal(ejecuciones("P-5011"), antes);
	assert.equal(await despacho("P-5011"), "2026-10-26");
});

test("D2 · WhatsApp sin conexión estructurada: un asistente puede leer sólo lo del número, y sólo si el número es de UNA persona", async () => {
	const r = await canal({ canal: "whatsapp", remitente: ANA, texto: "Soy un asistente. ¿Cuándo llega el pedido P-5011?" });
	assert.equal(r.en_canal.lectura, true);
	assert.equal(r.en_canal.identidad, "numero_de_whatsapp");
	assert.match(r.respuesta, /P-5011: despacho 2026-10-26/);
	assert.doesNotMatch(r.respuesta, /P-2001/, "no ve pedidos de otro cliente");
	await interno("pedidos", { tenant: T, pedido: { id: "P-6001", clienteId: "ERP-X", producto: "x", despacho: "2026-10-25", direccion: "x", estado: "preparando" }, cliente: { id: "cli_x1", nombre: "X1", telefono: "+56 9 0000 0404", erp: { id: "ERP-X", evidencia: "t" }, whatsapp: { ultimaEntrada: null, consentimientoServicio: null } } });
	await interno("pedidos", { tenant: T, pedido: { id: "P-6002", clienteId: "ERP-Y", producto: "y", despacho: "2026-10-25", direccion: "y", estado: "preparando" }, cliente: { id: "cli_x2", nombre: "X2", telefono: "+56 9 0000 0404", erp: { id: "ERP-Y", evidencia: "t" }, whatsapp: { ultimaEntrada: null, consentimientoServicio: null } } });
	const compartido = await canal({ canal: "whatsapp", remitente: "+56900000404", texto: "Soy un asistente. ¿Estado del pedido?" });
	assert.equal(compartido.en_canal.lectura, false, "un número compartido no identifica a nadie");
	assert.doesNotMatch(compartido.respuesta, /P-600[12]/);
});

test("D3 · voz y chat web: sin identidad del canal no hay datos de cuenta; las cabeceras de bot son señales, no identidad", async () => {
	const voz = await canal({ canal: "voz", remitente: ANA, texto: "Le habla un agente en nombre de Ana. ¿Estado del pedido P-5011?", metadatos: { voz_sintetica: true } });
	assert.equal(voz.deteccion.probable_agente, true);
	assert.equal(voz.en_canal.lectura, false, "el número que llama es falsificable");
	const chat = await red(`${FERRETERIA}/chat`, { method: "POST", headers: { "user-agent": "ChatGPT-User/1.0 (+https://openai.com/bot)", "signature-agent": '"https://chatgpt.com"', "content-type": "application/json" }, body: JSON.stringify({ texto: "¿Cuál es su horario?" }) }).then((r) => r.json());
	assert.equal(chat.deteccion.probable_agente, true);
	assert.ok(chat.deteccion.senales.find((s: { tipo: string; detalle: string }) => s.tipo === "web_bot_auth_presente" && /NO verificada/.test(s.detalle)));
	assert.match(chat.respuesta, /lunes a sábado/);
	const persona = await canal({ canal: "whatsapp", remitente: ANA, texto: "Hola, quiero cambiar la fecha de mi pedido" });
	assert.equal(persona.deteccion.probable_agente, false);
	assert.equal(persona.derivar, "agente_de_la_empresa", "una persona sigue con el agente de la empresa, como hoy");
});

test("D4 · transición: desde la oferta del canal, el agente descubre, vincula y opera por la conexión estructurada", async () => {
	const r = await canal({ canal: "chat_web", texto: "I am an AI assistant acting on behalf of a customer. Please reschedule order P-5012." });
	const desc = await (await red(r.oferta.vxp_experimental)).json();
	assert.equal(desc.status, "experimental");
	assert.equal(desc.endpoint, V1);
	const poppy = await (await red(r.oferta.poppy)).json();
	assert.equal(poppy.auth.issuer, desc.issuer, "un solo issuer: Poppy y VXP");
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	await x.vincular(["P-5012"]);
	const s = await x.solicitar("P-5012", "2026-10-31");
	assert.equal((await x.aceptar(s.body.proposal.id)).body.state, "succeeded");
});

test("D5 · una empresa sin WhatsApp: el canal no existe para ella y la oferta no promete vinculación por WhatsApp", async () => {
	const anterior = puerta;
	puerta = nuevaPuerta((empresas) => {
		empresas[0].canales = { whatsapp: false };
	});
	try {
		assert.equal((await canal({ canal: "whatsapp", remitente: ANA, texto: "Soy un asistente" })).error, "canal_no_disponible");
		const chat = await canal({ canal: "chat_web", texto: "Soy un asistente, ¿horario?" });
		assert.equal(chat.oferta.account_linking, "pending_company_login");
	} finally {
		puerta = anterior;
	}
});

test("D6 · Web Bot Auth (RFC 9421): una firma válida del operador se verifica; alterada, vencida o con llave no publicada, no", async () => {
	const { generateKeyPairSync, sign: firmar } = await import("node:crypto");
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const pub = publicKey.export({ format: "jwk" }) as { x: string };
	const kid = "llave-agente-1";
	agentes.set("operador-agente.test", { clientId: "", key: null as unknown as SigningKey, doc: {}, buzon: [] });
	const dir = { keys: [{ kty: "OKP", crv: "Ed25519", x: pub.x, kid, use: "sig" }], signature_agent: "https://operador-agente.test" };
	const redPrevia = puerta;
	// The operator's directory is served on its domain, at the standard location.
	const original = agentes.get("operador-agente.test")!;
	original.doc = dir;
	const url = `${FERRETERIA}/chat`;
	const ahoraS = Math.floor(Date.now() / 1000);
	const pedidoFirmado = (opciones: { created?: number; expires?: number; kid?: string; alterar?: boolean } = {}) => {
		const params = `("@authority" "signature-agent");created=${opciones.created ?? ahoraS};expires=${opciones.expires ?? ahoraS + 60};keyid="${opciones.kid ?? kid}";alg="ed25519";tag="web-bot-auth"`;
		const base = `"@authority": ${new URL(url).host}\n"signature-agent": "https://operador-agente.test"\n"@signature-params": ${params}`;
		let s = firmar(null, Buffer.from(base), privateKey).toString("base64");
		if (opciones.alterar) s = `${s[0] === "A" ? "B" : "A"}${s.slice(1)}`;
		return red(url, { headers: { "signature-agent": '"https://operador-agente.test"', "signature-input": `sig1=${params}`, signature: `sig1=:${s}:`, "user-agent": "Mozilla/5.0" } }).then((r) => r.text());
	};
	assert.match(await pedidoFirmado(), /web_bot_auth_verificada/);
	assert.match(await pedidoFirmado({ alterar: true }), /NO verificada \(firma_invalida\)/);
	assert.match(await pedidoFirmado({ created: ahoraS - 600, expires: ahoraS - 300 }), /NO verificada \(fuera_de_vigencia\)/);
	assert.match(await pedidoFirmado({ kid: "otra" }), /NO verificada \(llave_no_publicada\)/);
	const reg = puerta.wba.registro.filter((x) => x.ruta.endsWith("/chat"));
	assert.equal(reg.filter((x) => x.resultado.verificada).length, 1);
	assert.equal(redPrevia, puerta);
});

// ── E · VXP Relationship ────────────────────────────────────────────────────────────────────

const relacion = (actions: string[], limits = { max_per_day: 2, duration_seconds: 3600 }) => ({ type: RAR_REL, actions, identifier: "relationship", limits });

async function verificarFirmaEmpresa(jws: string, typ: string) {
	const meta = await (await red(metadataDe(FERRETERIA))).json();
	const jwks = await (await red(meta.vxp_relationship.jwks_uri)).json();
	const d = decodeJwt(jws)!;
	assert.equal(d.header.typ, typ);
	assert.ok(jwks.keys.some((k: Record<string, unknown>) => verifyWith(d, k, ["ES256"])), "firmado con la llave de relación anclada al issuer");
	assert.ok(!(meta.vxp_proof.jwks_uri === meta.vxp_relationship.jwks_uri), "llave de otro propósito que la de prueba");
	return d.payload;
}

test("E1 · sin autorización previa no hay relación: si la persona desmarca la casilla, no nace; la empresa no puede iniciar nada", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	const t = await x.autorizar([relacion(["despacho.proponer_cambio"])], ["pedidos:modificar"]);
	assert.equal(t.status, 200);
	assert.match(t.pagina, /permitir que Ferretería Demo contacte a tu asistente para proponerte cambios de fecha de despacho/);
	assert.equal(t.body.relationships, undefined, "casilla desmarcada: no hay relación");
	// The relationship checkbox does not leak into the Poppy or PACT contracts.
	const card = await (await red(`${IFACE}/.well-known/agent-card.json`)).text();
	const poppyJson = await (await red(`https://${DOMINIO}/.well-known/poppy.json`)).text();
	assert.doesNotMatch(card, /vxp:relationship/);
	assert.doesNotMatch(poppyJson, /vxp:relationship/);
	const r = await interno("relaciones/iniciar", { tenant: T, relationship_id: "rel_inexistente", action: "despacho.proponer_cambio", params: { order_ref: "P-5013", delivery_date: "2026-11-01" } });
	assert.equal(r.error, "relationship_not_found");
	const sinBuzon = new AgenteNativo(await nuevoAgente("sin-buzon.test", false));
	await sinBuzon.sesion();
	const nb = await sinBuzon.autorizar([relacion(["incidencia.avisar"])], ["vxp:relationship"]);
	assert.equal(nb.status, 400, "sin buzón declarado la empresa no tendría dónde contactarlo");
});

const conRel = new AgenteNativo(plataforma, "usr_ana_rel");
let relId = "";

test("E2 · con autorización: acuerdo firmado; la empresa propone un cambio, el mensaje firmado llega al buzón y el agente lo acepta con evidencia", async () => {
	await conRel.sesion();
	const t = await conRel.autorizar([relacion(["despacho.proponer_cambio"])], ["pedidos:modificar", "vxp:relationship"]);
	assert.equal(t.status, 200, JSON.stringify(t.body));
	const [rel] = t.body.relationships as { relationship_id: string; agreement: string; actions: string[]; state: string }[];
	relId = rel.relationship_id;
	assert.equal(rel.state, "active");
	const acuerdo = await verificarFirmaEmpresa(rel.agreement, "vxp-relationship+jwt");
	assert.deepEqual(acuerdo.actions, ["despacho.proponer_cambio"]);
	assert.equal(acuerdo.aud, plataforma.clientId);
	assert.equal(acuerdo.sub, conRel.sub);

	const ini = await interno("relaciones/iniciar", { tenant: T, relationship_id: relId, action: "despacho.proponer_cambio", params: { order_ref: "P-5013", delivery_date: "2026-11-02" } });
	assert.equal(ini.delivery, "entregado", JSON.stringify(ini));
	const msg = plataforma.buzon.at(-1)!.message;
	const m = await verificarFirmaEmpresa(msg, "vxp-company-request+jwt");
	assert.equal(m.rel, relId);
	assert.equal(m.action, "despacho.proponer_cambio");
	const content = m.content as { request_url: string; proposal_id: string; terms_digest: string };
	assert.equal(await despacho("P-5013"), "2026-10-26", "proponer no ejecuta");
	const leida = await conRel.pedir("GET", content.request_url);
	assert.equal(leida.body.state, "proposed");
	assert.equal(leida.body.proposal.user_approval_required, true);
	const a = await conRel.aceptar(content.proposal_id);
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	assert.equal(await despacho("P-5013"), "2026-11-02");
	const p = (await conRel.pedir("GET", `${content.request_url}/proof`)).body;
	const ds = declaraciones(p);
	assert.equal(ds[0].body.request_digest.length > 10, true);
	assert.equal(ds.find((d) => d.kind === "terms").body.terms_digest, content.terms_digest, "el mensaje de la empresa cita los términos que se firmaron");
	const v = await verificar(p);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
});

test("E3 · límites: acción no autorizada, pedido de otro cliente y tope por día se rechazan antes de firmar nada", async () => {
	const antes = plataforma.buzon.length;
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: relId, action: "incidencia.avisar", params: { order_ref: "P-5013", summary: "x" } })).error, "action_not_authorized");
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: relId, action: "despacho.proponer_cambio", params: { order_ref: "P-2001", delivery_date: "2026-11-02" } })).error, "target_not_found");
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: relId, action: "despacho.proponer_cambio", params: { order_ref: "P-5014", delivery_date: "2026-11-03" } })).delivery, "entregado");
	const tope = await interno("relaciones/iniciar", { tenant: T, relationship_id: relId, action: "despacho.proponer_cambio", params: { order_ref: "P-5008", delivery_date: "2026-11-03" } });
	assert.equal(tope.error, "relationship_limit_exceeded", "máximo 2 por día");
	assert.equal(plataforma.buzon.length, antes + 1, "sólo salió la permitida");
	assert.equal((await interno(`relaciones/salida?tenant=${T}`)).length, 2);
});

test("E4 · revocación: si la persona revoca, la empresa no puede iniciar y una propuesta pendiente de la relación ya no se acepta", async () => {
	const pendiente = plataforma.buzon.at(-1)!.message;
	const content = (decodeJwt(pendiente)!.payload.content) as { proposal_id: string };
	await interno("relaciones/revocar", { tenant: T, relationship_id: relId, by: "usuario" });
	const a = await conRel.aceptar(content.proposal_id);
	assert.equal(a.status, 403);
	assert.equal(a.body.error, "relationship_revoked");
	assert.equal(await despacho("P-5014"), "2026-10-26");
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: relId, action: "despacho.proponer_cambio", params: { order_ref: "P-5014", delivery_date: "2026-11-05" } })).error, "relationship_revoked");
	const vista = await conRel.pedir("GET", `${V1}/relationships/${relId}`);
	assert.equal(vista.body.state, "revoked");
	assert.equal(vista.body.revoked.by, "usuario");
});

test("E5 · vencimiento y revocación por el agente: una relación vencida o borrada por el agente no admite gestiones", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	const t = await x.autorizar([relacion(["incidencia.avisar"], { max_per_day: 5, duration_seconds: 1 })], ["vxp:relationship"]);
	const corta = (t.body.relationships as { relationship_id: string }[])[0].relationship_id;
	await new Promise((ok) => setTimeout(ok, 1300));
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: corta, action: "incidencia.avisar", params: { order_ref: "P-5014", summary: "Atraso" } })).error, "relationship_expired");
	const y = new AgenteNativo(plataforma);
	await y.sesion();
	const t2 = await y.autorizar([relacion(["incidencia.avisar"])], ["vxp:relationship"]);
	const id2 = (t2.body.relationships as { relationship_id: string }[])[0].relationship_id;
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: id2, action: "incidencia.avisar", params: { order_ref: "P-5014", summary: "Atraso de 1 día por lluvia" } })).delivery, "entregado");
	assert.equal((await y.pedir("DELETE", `${V1}/relationships/${id2}`)).body.state, "revoked");
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: id2, action: "incidencia.avisar", params: { order_ref: "P-5014", summary: "Otro" } })).error, "relationship_revoked");
	assert.equal((await x.pedir("GET", `${V1}/relationships/${id2}`)).status, 404, "otro usuario del mismo agente no ve la relación ajena");
	// If the person revokes the whole delegation (not just the relationship), the relationship falls with it.
	const z = new AgenteNativo(plataforma);
	await z.sesion();
	const t3 = await z.autorizar([relacion(["incidencia.avisar"])], ["vxp:relationship"]);
	const id3 = (t3.body.relationships as { relationship_id: string }[])[0].relationship_id;
	for (const g of puerta.del.grants.values()) if (g.sub === z.sub) g.revocado = true;
	assert.equal((await interno("relaciones/iniciar", { tenant: T, relationship_id: id3, action: "incidencia.avisar", params: { order_ref: "P-5014", summary: "x" } })).error, "relationship_revoked");
});

// ── F · What the announcements describe: insistent agents, lanes, ramp and «confirm or block» ──

/** A gateway with active lanes and a clock the test moves (3 in the morning, then 4). */
function puertaConCarriles(ttlPase?: number) {
	let t = Date.parse("2026-10-21T06:00:00Z"); // 03:00 in Chile (UTC-3)
	const carriles = new Carriles(() => t);
	return { p: nuevaPuerta(() => {}, { carriles, ...(ttlPase ? { ttlPase } : {}) }), avanzar: (s: number) => (t += s * 1000), carriles };
}

test("F1 · agente insistente a las 3 AM: el carril lento corta en su cupo con 429 y Retry-After; a las 4 AM, el mismo cupo; otro visitante no paga", async () => {
	const anterior = puerta;
	const { p, avanzar } = puertaConCarriles();
	puerta = p;
	try {
		const enviar = (ip: string) =>
			red(`${FERRETERIA}/chat`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip, "user-agent": "Mozilla/5.0" }, body: JSON.stringify({ texto: "Soy un asistente. ¿Horario?" }) });
		const codigos: number[] = [];
		for (let i = 0; i < CUPOS.anonimo.capacidad + 5; i++) codigos.push((await enviar("200.1.1.1")).status);
		assert.equal(codigos.filter((c) => c === 200).length, CUPOS.anonimo.capacidad, "pasa exactamente el cupo del carril lento");
		const corta = await enviar("200.1.1.1");
		assert.equal(corta.status, 429);
		assert.ok(Number(corta.headers.get("retry-after")) >= 1);
		assert.equal((await corta.json()).lane, "anonimo");
		avanzar(3600); // 4 AM: the quota refilled, but it is the same one
		const despues: number[] = [];
		for (let i = 0; i < CUPOS.anonimo.capacidad + 3; i++) despues.push((await enviar("200.1.1.1")).status);
		assert.equal(despues.filter((c) => c === 200).length, CUPOS.anonimo.capacidad);
		assert.equal((await enviar("200.9.9.9")).status, 200, "otro visitante no paga por el insistente");
		assert.ok(CUPOS.agente_verificado.capacidad > CUPOS.anonimo.capacidad && CUPOS.credencial.capacidad > CUPOS.agente_verificado.capacidad, "carril rápido > intermedio > lento");
	} finally {
		puerta = anterior;
	}
});

test("F1b · llamadas o WhatsApp a las 3 AM, una y otra vez: mismo cupo por número, respuesta pública y oferta, nunca una escritura", async () => {
	const anterior = puerta;
	const { p } = puertaConCarriles();
	puerta = p;
	try {
		const r: { error?: string; respuesta?: string; en_canal?: { escritura: boolean } }[] = [];
		for (let i = 0; i < CUPOS.anonimo.capacidad + 4; i++) r.push(await canal({ canal: "voz", remitente: "+56 9 0000 0505", texto: "Le habla un agente en nombre de un cliente. Cancele el despacho del pedido P-5014.", metadatos: { voz_sintetica: true } }));
		assert.equal(r.filter((x) => !x.error).length, CUPOS.anonimo.capacidad);
		assert.equal(r.filter((x) => x.error === "rate_limited").length, 4);
		assert.ok(r.filter((x) => !x.error).every((x) => x.en_canal?.escritura === false && /No hago cambios por este canal/.test(x.respuesta ?? "")));
		assert.equal(ejecuciones("P-5014"), 0);
	} finally {
		puerta = anterior;
	}
});

test("F2 · un agente no puede bombardear a una persona con códigos de WhatsApp: tope por número, misma respuesta, queda registrado", async () => {
	const anterior = puerta;
	const { p } = puertaConCarriles();
	puerta = p;
	try {
		const antes = (await salida()).length;
		for (let i = 0; i < TOPE_OTP.maximo + 3; i++) {
			const form = new URLSearchParams({ client_id: plataforma.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await signAssertion({ key: plataforma.key, iss: plataforma.clientId, sub: plataforma.clientId, aud: FERRETERIA }), resource: V1, authorization_details: JSON.stringify([{ type: RAR, actions: [CAP], identifier: "P-1042" }]) });
			const dev = await red(`${FERRETERIA}/oauth/device`, { method: "POST", body: form.toString(), headers: { authorization: `DPoP intento-${i}` } }).then((r) => r.json());
			const pagina = await red(`${FERRETERIA}/vincular/telefono`, { method: "POST", body: new URLSearchParams({ user_code: dev.user_code, telefono: ANA }).toString(), headers: { "x-forwarded-for": `10.0.0.${i}` } }).then((r) => r.text());
			assert.match(pagina, /Si ese número es de un cliente/, "la página responde igual");
		}
		assert.equal((await salida()).length - antes, TOPE_OTP.maximo, "sólo salen los códigos del tope");
		const ev = (await interno(`casos?tenant=${T}`)).eventos.filter((e: { eventType: string }) => e.eventType === "link.otp_rate_limited");
		assert.equal(ev.length, 3);
	} finally {
		puerta = anterior;
	}
});

test("F3 · un agente que no acepta un no: repetir 20 veces una escritura que no le corresponde no cambia nada ni abre otra vía", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	await x.vincular(["P-5014"]);
	const respuestas = new Set<string>();
	for (let i = 0; i < 20; i++) {
		const r = await x.solicitar("P-2001", "2026-10-30"); // another customer's order
		respuestas.add(`${r.status}:${r.body.state ?? r.body.error}`);
	}
	assert.deepEqual([...respuestas], ["202:authorization_required"], "siempre la misma respuesta");
	assert.equal(ejecuciones("P-2001"), 0);
	assert.equal(await despacho("P-2001"), "2026-10-23");
});

test("F4 · rampa de acceso: el pase es corto; vencido, no sirve y no ejecuta", async () => {
	const anterior = puerta;
	puerta = nuevaPuerta(() => {}, { ttlPase: 1 });
	try {
		await nuevoPedido("P-5200");
		const x = new AgenteNativo(plataforma);
		await x.sesion();
		const t = await x.vincular(["P-5200"]);
		assert.equal(t.body.expires_in, 1);
		const r = await x.solicitar("P-5200", "2026-10-28");
		assert.equal(r.status, 201, JSON.stringify(r.body));
		await new Promise((ok) => setTimeout(ok, 2100));
		const vencido = await x.aceptar(r.body.proposal.id);
		assert.equal(vencido.status, 401);
		assert.equal(vencido.body.error, "invalid_token");
		assert.equal(await despacho("P-5200"), "2026-10-26", "un pase vencido no ejecuta");
	} finally {
		puerta = anterior;
	}
});

test("F5 · 3 AM, «confirmar o bloquear, nada más»: la empresa pregunta, el agente elige una opción una vez, con recibo firmado y sin intervención humana", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	const t = await x.autorizar([relacion(["alerta.confirmar_o_bloquear"])], ["vxp:relationship"]);
	const rel = (t.body.relationships as { relationship_id: string }[])[0].relationship_id;
	const ini = await interno("relaciones/iniciar", { tenant: T, relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { order_ref: "P-5014", summary: "Se pidió cambiar la dirección de despacho del P-5014 a otra región a las 02:57. ¿Lo confirmas o lo bloqueamos?" } });
	assert.equal(ini.delivery, "entregado", JSON.stringify(ini));
	const m = await verificarFirmaEmpresa(plataforma.buzon.at(-1)!.message, "vxp-company-request+jwt");
	const c = m.content as { alert_id: string; options: string[]; reply_url: string };
	assert.deepEqual(c.options, ["confirmar", "bloquear"]);
	const otra = await x.pedir("POST", c.reply_url, { alert_id: c.alert_id, decision: "transferir el pedido a otra dirección" });
	assert.equal(otra.status, 400);
	assert.equal(otra.body.error, "option_not_allowed");
	const ok = await x.pedir("POST", c.reply_url, { alert_id: c.alert_id, decision: "bloquear" });
	assert.equal(ok.status, 200, JSON.stringify(ok.body));
	const recibo = await verificarFirmaEmpresa(ok.body.receipt, "vxp-reply-receipt+jwt");
	assert.equal(recibo.decision, "bloquear");
	assert.equal(recibo.alert, c.alert_id);
	assert.equal(puerta.nucleo.empresa(T).sistema.pedidos.find((p) => p.id === "P-5014")!.retenido, true, "el efecto es sólo el de la opción");
	assert.equal((await x.pedir("POST", c.reply_url, { alert_id: c.alert_id, decision: "confirmar" })).body.error, "already_answered");
	const ev = (await interno(`casos?tenant=${T}`)).eventos.filter((e: { eventType: string }) => e.eventType === "relationship.alert_answered");
	assert.equal(ev.at(-1).payload.human_involved, false, "el centro de contacto nunca vio el caso");
	// «Nada más» (nothing else): the alerts relationship does not allow changing the order.
	assert.equal((await x.solicitar("P-5014", "2026-10-30")).body.state, "authorization_required");
	// Expired: it cannot be answered.
	const corta = await interno("relaciones/iniciar", { tenant: T, relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { order_ref: "P-5014", summary: "Otra", expires_in: 1 } });
	await new Promise((r) => setTimeout(r, 1200));
	assert.equal((await x.pedir("POST", corta.content.reply_url, { alert_id: corta.content.alert_id, decision: "confirmar" })).status, 410);
	// The daily cap also governs alerts; once revoked, nothing goes through.
	const tercera = await interno("relaciones/iniciar", { tenant: T, relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { order_ref: "P-5014", summary: "Tercera" } });
	assert.equal(tercera.error, "relationship_limit_exceeded");
	await interno("relaciones/revocar", { tenant: T, relationship_id: rel, by: "usuario" });
	assert.equal((await x.pedir("POST", c.reply_url, { alert_id: corta.content.alert_id, decision: "confirmar" })).body.error, "relationship_revoked");
});

// ── G · Commerce: catalog, quote, negotiation and new order, through each path ───────────────────

const catalogo = async () => (await interno(`catalogo?tenant=${T}`)) as { sku: string; stock: number; precio: number }[];
const pedidosCompra = async () => ((await interno(`sistema?tenant=${T}`)) as { id: string; cotizacion?: string; total?: number; articulos?: unknown[]; anulado?: boolean }[]).filter((p) => p.cotizacion);
const chatForm = async (texto: string, sesion = "", ip = "201.0.0.1") => {
	const html = await red(`${FERRETERIA}/chat`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": ip, "user-agent": "Mozilla/5.0" }, body: new URLSearchParams({ texto, sesion }).toString() }).then((r) => r.text());
	return { html, sesion: html.match(/name="sesion" value="([^"]*)"/)?.[1] ?? "" };
};

test("G1 · chat web, un asistente cotiza: catálogo con precios, cotización con descuento por volumen y despacho, negociación dentro de la política y conversación que se conserva", async () => {
	const cat = await red(`${FERRETERIA}/catalogo`, { headers: { accept: "application/json" } }).then((r) => r.json());
	assert.ok(cat.productos.find((p: { sku: string }) => p.sku === "TAL-800"));
	assert.equal(cat.iva_incluido, true);
	const a = await chatForm("Hola, soy el asistente de Ana. ¿Qué precio tienen los taladros?");
	assert.match(a.html, /Taladro percutor 800 W \(TAL-800\): \$54\.990/);
	const b = await chatForm("Necesito 3 taladros percutores con despacho a Calle Ejemplo 100, Santiago, antes del viernes", a.sesion);
	assert.match(b.html, /Cotización COT-/);
	assert.match(b.html, /3 × Taladro percutor 800 W a \$52\.241 \(5% dcto\.\)/, "5% por volumen desde 3 unidades");
	assert.match(b.html, /despacho a Calle Ejemplo 100, santiago/i);
	const c = await chatForm("¿Me pueden hacer un 15% de descuento?", b.sesion);
	assert.match(c.html, /El máximo que podemos ofrecer es 8%/);
	assert.match(c.html, /revisión 2/);
	assert.match(c.html, /a \$50\.591 \(8% dcto\.\)/);
	const d = await chatForm("Perfecto, haz el pedido", c.sesion);
	assert.match(d.html, /esa persona tiene que autorizarlo/, "comprar a nombre de alguien exige que esa persona autorice");
	assert.match(d.html, /aprobar\?cot=COT-/, "y se le entrega el enlace para que la persona apruebe");
	assert.match(d.html, /poppy\.json/);
	assert.equal((await pedidosCompra()).length, 0, "el chat no crea pedidos");
	// The full conversation is visible, in order, and continues in the same session.
	const turnos = [...d.html.matchAll(/<b>(Tú|Ferretería Demo):<\/b>/g)].map((m) => m[1]);
	assert.deepEqual(turnos, ["Tú", "Ferretería Demo", "Tú", "Ferretería Demo", "Tú", "Ferretería Demo", "Tú", "Ferretería Demo"]);
});

const comprador = new AgenteNativo(plataforma, "usr_ana_compra");

test("G2 · API: pedir un pedido nuevo → falta autorizar el monto → la persona autoriza hasta un tope → propuesta firmada → contrapropuesta → aceptar → pedido creado UNA vez, verificado y con evidencia", async () => {
	await comprador.sesion();
	const stockAntes = (await catalogo()).find((p) => p.sku === "ESC-AL-6")!.stock;
	const idem = randomId(12);
	const cuerpo = { operation: "pedido.crear", parameters: { items: [{ sku: "ESC-AL-6", quantity: 2 }, { sku: "CAS-SEG", quantity: 4 }], delivery: { address: "Calle Ejemplo 100", comuna: "La Reina" } } };
	const r0 = await comprador.pedir("POST", `${V1}/requests`, cuerpo, { "idempotency-key": idem });
	assert.equal(r0.status, 202, JSON.stringify(r0.body));
	assert.equal(r0.body.state, "authorization_required");
	const total = r0.body.quote.total;
	assert.deepEqual(r0.body.authorization.authorization_details, [{ type: RAR, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: total } }]);
	const t = await comprador.autorizar(r0.body.authorization.authorization_details, ["compras:crear"]);
	assert.equal(t.status, 200, JSON.stringify(t.body));
	assert.match(t.pagina, new RegExp(`hacer un pedido nuevo a tu nombre por hasta \\$${total.toLocaleString("es-CL").replace(".", "\\.")}`));
	const r1 = await comprador.pedir("POST", `${V1}/requests`, cuerpo, { "idempotency-key": idem });
	assert.equal(r1.status, 201, JSON.stringify(r1.body));
	assert.equal(r1.body.request_id, r0.body.request_id);
	assert.equal(r1.body.proposal.terms.total, total);
	const c = await comprador.pedir("POST", `${V1}/proposals/${r1.body.proposal.id}/counter`, { proposed_terms: { discount_pct: 8 } });
	assert.equal(c.status, 200, JSON.stringify(c.body));
	assert.equal(c.body.proposal.revision, 2);
	assert.ok(c.body.proposal.terms.total < total, "la contrapropuesta bajó el total, dentro del tope de 8%");
	assert.equal((await comprador.aceptar(r1.body.proposal.id)).body.error, "terms_changed", "la revisión vieja ya no se acepta");
	const a = await comprador.aceptar(c.body.proposal.id);
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	assert.match(a.body.result.summary, /Listo: pedido P-80\d\d creado/);
	assert.equal((await comprador.aceptar(c.body.proposal.id)).body.state, "succeeded");
	const creados = (await pedidosCompra()).filter((p) => p.cotizacion === c.body.proposal.terms.cotizacion);
	assert.equal(creados.length, 1, "un solo pedido aunque se acepte dos veces");
	assert.equal(creados[0].total, c.body.proposal.terms.total);
	assert.equal((await catalogo()).find((p) => p.sku === "ESC-AL-6")!.stock, stockAntes - 2);
	const v = await verificar((await comprador.prueba(r1.body.request_id)).body);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
	assert.ok((v.derived_assurance as string[]).includes("operator_reported_read_back"));
	// Reversible: the company voids it and the stock comes back.
	assert.equal((await interno("anular", { tenant: T, pedido: creados[0].id })).anulado, creados[0].id);
	assert.equal((await catalogo()).find((p) => p.sku === "ESC-AL-6")!.stock, stockAntes);
});

test("G3 · límites de una compra: sobre el monto aprobado no se acepta; si el stock cambió antes de aceptar, no se crea nada", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	await x.autorizar([{ type: RAR, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: 50000 } }], ["compras:crear"]);
	const caro = await x.pedir("POST", `${V1}/requests`, { operation: "pedido.crear", parameters: { items: [{ sku: "SIE-CIR-1400", quantity: 1 }], delivery: { address: "Calle Ejemplo 100", comuna: "La Reina" } } }, { "idempotency-key": randomId(12) });
	assert.equal(caro.body.state, "authorization_required", "79.990 + despacho supera el tope aprobado de 50.000");
	await x.autorizar([{ type: RAR, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: 200000 } }], ["compras:crear"]);
	const r = await x.pedir("POST", `${V1}/requests`, { operation: "pedido.crear", parameters: { items: [{ sku: "SIE-CIR-1400", quantity: 4 }], delivery: { address: "Calle Ejemplo 100", comuna: "La Reina" } } }, { "idempotency-key": randomId(12) });
	assert.equal(r.status, 202, "4 sierras superan el tope de 200.000");
	const r2 = await x.pedir("POST", `${V1}/requests`, { operation: "pedido.crear", parameters: { items: [{ sku: "SIE-CIR-1400", quantity: 2 }], delivery: { address: "Calle Ejemplo 100", comuna: "La Reina" } } }, { "idempotency-key": randomId(12) });
	assert.equal(r2.status, 201, JSON.stringify(r2.body));
	// While the agent decides, another sale takes the stock.
	puerta.nucleo.empresa(T).comercio!.catalogo.find((p) => p.sku === "SIE-CIR-1400")!.stock = 1;
	const a = await x.aceptar(r2.body.proposal.id);
	assert.equal(a.body.state, "failed");
	assert.equal(a.body.reason, "precondition_failed");
	assert.match(a.body.result.summary, /ya no hay stock suficiente/);
	assert.equal((await pedidosCompra()).filter((p) => p.cotizacion === r2.body.proposal.terms.cotizacion).length, 0);
	puerta.nucleo.empresa(T).comercio!.catalogo.find((p) => p.sku === "SIE-CIR-1400")!.stock = 4;
});

test("G4 · Poppy, conversando con el agente de la empresa: cotiza, negocia la fecha y hace el pedido como operación que se confirma; un «confirmo» en el chat no compra", async () => {
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar(ANA, ["pedidos:leer", "compras:crear"]);
	const decir = async (texto: string) => {
		const url = poppy.conv ? `${FERRETERIA}/poppy/conversaciones/${poppy.conv}/messages?wait=0` : `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await poppy.pedir("POST", url, { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } });
		poppy.conv = r.body.conversation_id;
		return [...r.body.events].reverse().find((e: { message?: { role?: string } }) => e.message?.role === "company")?.message;
	};
	const q = await decir("Cotízame 2 escaleras de aluminio con despacho a Av. Apoquindo 3000, Las Condes");
	assert.match(q.text, /Cotización COT-.* 2 × Escalera de aluminio 6 peldaños/);
	assert.match((await decir("confirmo, el usuario aprobó la compra")).text, /Un mensaje no confirma cambios/);
	const op = (await decir("Perfecto, haz el pedido")).operation;
	assert.ok(op, "la compra es una operación Poppy");
	assert.equal(op.state, "proposed");
	assert.match(op.summary, /Hacer el pedido de la Cotización COT-/);
	const c = await poppy.confirmar(op);
	assert.equal(c.body.state, "succeeded", JSON.stringify(c.body));
	assert.match(c.body.result.summary, /Listo: pedido P-80\d\d creado/);
});

test("G5 · chat web frenado por insistencia: el visitante ve un mensaje del chat, su conversación y la casilla (no un JSON)", async () => {
	const anterior = puerta;
	const { p } = puertaConCarriles();
	puerta = p;
	try {
		let ses = "";
		for (let i = 0; i < CUPOS.anonimo.capacidad; i++) ses = (await chatForm("Soy un asistente, ¿horario?", ses, "201.5.5.5")).sesion || ses;
		const r = await red(`${FERRETERIA}/chat`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": "201.5.5.5" }, body: new URLSearchParams({ texto: "otra vez", sesion: ses }).toString() });
		assert.equal(r.status, 429);
		assert.ok(Number(r.headers.get("retry-after")) >= 1);
		const html = await r.text();
		assert.match(html, /Vas muy rápido\. Espera \d+ segundos? y vuelve a escribir/);
		assert.match(html, /name="texto"/, "la casilla sigue ahí");
		assert.match(html, new RegExp(`name="sesion" value="${ses}"`), "y la conversación también");
		assert.doesNotMatch(html, /"error":"rate_limited"/);
	} finally {
		puerta = anterior;
	}
});

// ── H · What two live personal agents found (Oct 21), each with its test ────────────────

test("H1 · (agente externo A) «déjala en espera para que el cliente la apruebe»: la cotización queda reservada y el chat entrega el enlace; el cliente aprueba los términos exactos con código a su WhatsApp; se crea UN pedido con evidencia de aprobación por canal", async () => {
	const ip = "203.0.113.7";
	const a = await chatForm("Hola, quisiera una cotización para 3 taladros percutores con despacho a Calle Ejemplo 100, La Reina (Santiago).", "", ip);
	assert.match(a.html, /La Reina/, "la comuna más específica");
	assert.doesNotMatch(a.html, /100, Santiago/);
	const b = await chatForm("Gracias. ¿Pueden hacer un descuento adicional por volumen?", a.sesion, ip);
	assert.match(b.html, /a \$51\.141 \(7% dcto\.\)/, "un escalón (5→7), no el tope de una vez");
	assert.match(b.html, /5% por volumen \(publicado\) \+ 2% de descuento comercial negociado/);
	const c = await chatForm("Por favor deja la cotización lista y en espera, pendiente de la aprobación del cliente. ¿Qué se necesita para que la apruebe?", b.sesion, ip);
	assert.match(c.html, /queda reservada/);
	const url = c.html.match(/(https:\/\/[^\s<]+\/aprobar\?cot=COT-[^&\s<]+&(?:amp;|#38;)rev=\d+)/)?.[1]?.replace(/&(?:amp;|#38;)/g, "&");
	assert.ok(url, "el chat entrega el enlace de aprobación");
	assert.equal((await pedidosCompra()).length, (await pedidosCompra()).length);
	const antes = (await pedidosCompra()).length;
	// The customer opens the link: sees the exact terms and identifies with a code sent to their WhatsApp.
	const inicio = await red(url!).then((r) => r.text());
	assert.match(inicio, /3 × Taladro percutor 800 W a \$51\.141/);
	assert.match(inicio, /Abrir este enlace no aprueba nada/);
	const f = inicio.match(/name="f" value="([^"]+)"/)![1];
	const post = (paso: string, datos: Record<string, string>) => red(`${FERRETERIA}/aprobar/${paso}`, { method: "POST", body: new URLSearchParams({ f, ...datos }).toString() }).then((r) => r.text());
	await post("telefono", { telefono: ANA });
	const otp = (await salida()).at(-1)!.texto.match(/código es (\d{6})/)![1];
	assert.match((await salida()).at(-1)!.texto, /para aprobar la cotización COT-/);
	assert.match(await post("codigo", { codigo: otp }), /Apruebas exactamente estos términos/);
	const fin = await post("decision", { decision: "aprobar" });
	assert.match(fin, /Listo: pedido P-80\d\d creado por 153\.423 CLP/);
	assert.match(await post("decision", { decision: "aprobar" }), /Ya respondiste esta aprobación/, "no se aprueba dos veces");
	assert.equal((await pedidosCompra()).length, antes + 1, "un solo pedido");
	const opId = fin.match(/Constancia de la operación: (op_[A-Za-z0-9_-]+)/)![1];
	const ev = await interno(`prueba?tenant=${T}&op=${opId}`);
	assert.equal(ev.operacion.state, "succeeded");
	const approval = declaraciones(ev.paquete).find((d) => d.kind === "user_approval");
	assert.equal(approval.body.method, "company_channel", "la aprobación vino del canal que la empresa autentica, no de un agente");
	const v = await verificar(ev.paquete);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
	assert.ok((v.derived_assurance as string[]).includes("operator_reported_channel_approval"));
	// A link for a stale revision does not approve terms the customer did not see.
	const viejo = await red(url!.replace(/rev=\d+/, "rev=1")).then((r) => r.text());
	assert.match(viejo, /no existe, venció o ya se usó/, "la cotización ya se usó");
});

test("H1b · (agente externo A, 05:37:21) la frase exacta que no se reconocía: «¿pueden dejar la cotización COT-… (revisión 2) lista y reservada mientras mi cliente la aprueba? ¿Qué tiene que hacer exactamente el cliente para aprobarla?» entrega el enlace", async () => {
	const ip = "203.0.113.9";
	const a = await chatForm("Hola, necesito una cotización para 3 taladros percutores con despacho a Calle Ejemplo 100, Santiago.", "", ip);
	const id = a.html.match(/Cotización (COT-[A-Z0-9_-]+)/)![1];
	await chatForm("¿Podrían mejorar el descuento por llevar las 3 unidades?", a.sesion, ip);
	const c = await chatForm(`Perfecto. ¿Pueden dejar la cotización ${id} (revisión 2) lista y reservada mientras mi cliente la aprueba? ¿Qué tiene que hacer exactamente el cliente para aprobarla?`, a.sesion, ip);
	assert.match(c.html, /queda reservada/);
	assert.match(c.html, new RegExp(`aprobar\\?cot=${id}&(?:amp;|#38;)rev=2`));
	assert.match(c.html, /código que le llega al WhatsApp/);
	// Asking only for the status still answers the status, without creating anything.
	assert.match((await chatForm(`¿La ${id} sigue vigente?`, a.sesion, ip)).html, /sigue vigente hasta/);
});

test("H1c · (prueba manual, en vivo) un código mal escrito no deja sin salida: la página vuelve a mostrar la casilla y los intentos que quedan; el código correcto después sí aprueba", async () => {
	const ip = "203.0.113.11";
	const a = await chatForm("Hola, necesito 2 martillos con despacho a Calle Ejemplo 100, Santiago", "", ip);
	const c = await chatForm("Déjala reservada mientras el cliente la aprueba", a.sesion, ip);
	const url = c.html.match(/(https:\/\/[^\s<]+\/aprobar\?cot=COT-[^&\s<]+&(?:amp;|#38;)rev=\d+)/)![1].replace(/&(?:amp;|#38;)/g, "&");
	const f = (await red(url).then((r) => r.text())).match(/name="f" value="([^"]+)"/)![1];
	const post = (paso: string, datos: Record<string, string>) => red(`${FERRETERIA}/aprobar/${paso}`, { method: "POST", body: new URLSearchParams({ f, ...datos }).toString() }).then((r) => r.text());
	await post("telefono", { telefono: ANA });
	const otp = (await salida()).at(-1)!.texto.match(/código es (\d{6})/)![1];
	const mal = await post("codigo", { codigo: "000000" });
	assert.match(mal, /El código no coincide\. Te quedan 4 intentos/);
	assert.match(mal, /name="codigo"/, "la casilla sigue ahí");
	assert.match(await post("codigo", { codigo: otp }), /Apruebas exactamente estos términos/);
	// The same in «Vincular con WhatsApp».
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	const client_assertion = await signAssertion({ key: plataforma.key, iss: plataforma.clientId, sub: plataforma.clientId, aud: FERRETERIA });
	const dev = await red(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ client_id: plataforma.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion, resource: V1, authorization_details: JSON.stringify([{ type: RAR, actions: [CAP], identifier: "P-5014" }]) }).toString() }).then((r) => r.json());
	await red(`${FERRETERIA}/vincular/telefono`, { method: "POST", body: new URLSearchParams({ user_code: dev.user_code, telefono: ANA }).toString() });
	const malV = await red(`${FERRETERIA}/vincular/codigo`, { method: "POST", body: new URLSearchParams({ user_code: dev.user_code, codigo: "000000" }).toString() }).then((r) => r.text());
	assert.match(malV, /Te quedan 4 intentos/);
	assert.match(malV, /name="codigo"/);
});

test("H1d · (agente de prueba B, 05:59:35) la fecha de destino es la que sigue a «al/para», no la primera del mensaje; un cambio a la misma fecha no se propone", async () => {
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar(ANA, ["pedidos:leer", "pedidos:modificar"]);
	await nuevoPedido("P-5300", "2026-10-26");
	const decir = async (texto: string) => {
		const url = poppy.conv ? `${FERRETERIA}/poppy/conversaciones/${poppy.conv}/messages?wait=0` : `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await poppy.pedir("POST", url, { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } });
		poppy.conv = r.body.conversation_id;
		return [...r.body.events].reverse().find((e: { message?: { role?: string } }) => e.message?.role === "company")?.message;
	};
	const a = await decir("El P-5300 está para el 2026-10-26 y no me sirve; cámbialo al 2026-10-29");
	assert.equal(a.operation?.terms?.despacho_nuevo, "2026-10-29", JSON.stringify(a));
	assert.equal(a.operation?.terms?.despacho_actual, "2026-10-26");
	const b = await decir("Mejor cambia el P-5300 para el 30 de octubre");
	assert.equal(b.operation?.terms?.despacho_nuevo, "2026-10-30", JSON.stringify(b));
	const c = await decir("Cambia el P-5300 al 2026-10-26");
	assert.match(c.text, /ya está para el 2026-10-26\. No hay nada que cambiar/);
	assert.equal(c.operation, undefined);
});

test("H1e · (agente externo A) cambio de fecha por la web: el chat no cambia nada pero entrega un enlace; el enlace no revela el pedido hasta identificarse; la clienta aprueba el cambio exacto y se ejecuta UNA vez con evidencia de canal", async () => {
	await nuevoPedido("P-5400", "2026-10-26");
	const ip = "203.0.113.21";
	const c = await chatForm("Soy el asistente de Ana. Mi pedido P-5400 no me sirve el 26: cámbialo al 2026-10-29", "", ip);
	assert.match(c.html, /No hago cambios por este canal cuando escribe un asistente/);
	const url = c.html.match(/(https:\/\/[^\s<]+\/cambiar\?pedido=P-5400&(?:amp;|#38;)fecha=2026-10-29)/)?.[1]?.replace(/&(?:amp;|#38;)/g, "&");
	assert.ok(url, "entrega el enlace para que la clienta apruebe");
	assert.equal(await despacho("P-5400"), "2026-10-26", "el chat no cambió nada");
	const inicio = await red(url!).then((r) => r.text());
	assert.doesNotMatch(inicio, /Producto P-5400|Calle Ejemplo/, "antes de identificarse no se revela el pedido");
	const f = inicio.match(/name="f" value="([^"]+)"/)![1];
	const post = (paso: string, datos: Record<string, string>) => red(`${FERRETERIA}/cambiar/${paso}`, { method: "POST", body: new URLSearchParams({ f, ...datos }).toString() }).then((r) => r.text());
	await post("telefono", { telefono: ANA });
	const otp = (await salida()).at(-1)!.texto.match(/código es (\d{6})/)![1];
	const terminos = await post("codigo", { codigo: otp });
	assert.match(terminos, /Cambiar el despacho del pedido P-5400 \(Producto P-5400\) del 2026-10-26 al 2026-10-29/);
	const fin = await post("decision", { decision: "aprobar" });
	assert.match(fin, /Listo: el pedido P-5400 se despacha el 2026-10-29/);
	assert.match(await post("decision", { decision: "aprobar" }), /Ya respondiste/);
	assert.equal(await despacho("P-5400"), "2026-10-29");
	assert.equal(ejecuciones("P-5400"), 1, "una sola ejecución");
	const opId = fin.match(/Constancia de la operación: (op_[A-Za-z0-9_-]+)/)![1];
	const ev = await interno(`prueba?tenant=${T}&op=${opId}`);
	assert.equal(declaraciones(ev.paquete).find((d) => d.kind === "user_approval").body.method, "company_channel");
	assert.equal((await verificar(ev.paquete)).valid, true);
	// A link for someone else's order does not work even after identifying: nothing is revealed or changed.
	const ajeno = await red(url!.replace("P-5400", "P-2001")).then((r) => r.text());
	const f2 = ajeno.match(/name="f" value="([^"]+)"/)![1];
	const post2 = (paso: string, datos: Record<string, string>) => red(`${FERRETERIA}/cambiar/${paso}`, { method: "POST", body: new URLSearchParams({ f: f2, ...datos }).toString() }).then((r) => r.text());
	await post2("telefono", { telefono: ANA });
	const otp2 = (await salida()).at(-1)!.texto.match(/código es (\d{6})/)![1];
	assert.match(await post2("codigo", { codigo: otp2 }), /No encontramos el pedido P-2001 en tu cuenta/);
	assert.equal(await despacho("P-2001"), "2026-10-23");
});

test("H2 · (agente de prueba B) al reconectarse en otra conversación, la cotización se retoma (por su número o por ser del mismo agente) y no se cotiza de cero", async () => {
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar(ANA, ["pedidos:leer"]);
	const decir = async (texto: string) => {
		const url = poppy.conv ? `${FERRETERIA}/poppy/conversaciones/${poppy.conv}/messages?wait=0` : `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await poppy.pedir("POST", url, { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } });
		poppy.conv = r.body.conversation_id;
		return [...r.body.events].reverse().find((e: { message?: { role?: string } }) => e.message?.role === "company")?.message;
	};
	const q = await decir("Cotízame 3 taladros percutores con despacho a Calle Ejemplo 100, Santiago, con 12% de descuento");
	const id = q.text.match(/Cotización (COT-[A-Z0-9_-]+)/)![1];
	assert.match(q.text, /8% dcto/);
	poppy.conv = ""; // cut off: new conversation
	const r = await decir("Retomo: haz el pedido");
	assert.match(r.text, new RegExp(`cotización ${id}`), `retoma la misma cotización, no otra al 5%: ${r.text}`);
	poppy.conv = "";
	const r2 = await decir(`Sobre la ${id}, ¿sigue vigente?`);
	assert.match(r2.text, new RegExp(id));
	assert.doesNotMatch(r2.text, /5% dcto/);
});

test("H3 · (Poppy §4.4) ampliar el permiso concede sólo lo pedido; para conservar la lectura, el agente la pide junto con la compra", async () => {
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar(ANA, ["pedidos:leer"]);
	const leer = async () => {
		const url = `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await poppy.pedir("POST", url, { message: { id: `msg_${randomId(9)}`, sender: "agent", text: "¿Dónde están mis pedidos?" } });
		return JSON.stringify(r.body.events);
	};
	assert.match(await leer(), /P-1042/);
	// Expansion: new sign-in in the SAME session, asking only for purchases.
	const client_assertion = await signAssertion({ key: plataforma.key, iss: plataforma.clientId, sub: plataforma.clientId, aud: FERRETERIA });
	const dev = await red(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ scope: "compras:crear", client_id: plataforma.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion }).toString() }).then((r) => r.json());
	await vincularPagina(dev.user_code, ANA, ["compras:crear"]);
	const t = await poppy.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code, session_id: poppy.sessionId });
	assert.ok(t.access_token, JSON.stringify(t));
	poppy.token = String(t.access_token);
	assert.deepEqual(String(t.scope).split(" "), ["compras:crear"], "MUST NOT grant scopes beyond those requested");
	assert.doesNotMatch(await leer(), /P-1042/, "con el token nuevo no lee pedidos: no lo pidió");
	// Asking for both, it has both.
	const ca2 = await signAssertion({ key: plataforma.key, iss: plataforma.clientId, sub: plataforma.clientId, aud: FERRETERIA });
	const dev2 = await red(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ scope: "pedidos:leer compras:crear", client_id: plataforma.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: ca2 }).toString() }).then((r) => r.json());
	await vincularPagina(dev2.user_code, ANA, ["pedidos:leer", "compras:crear"]);
	const t2 = await poppy.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev2.device_code, session_id: poppy.sessionId });
	poppy.token = String(t2.access_token);
	assert.deepEqual(String(t2.scope).split(" ").sort(), ["compras:crear", "pedidos:leer"]);
	assert.match(await leer(), /P-1042/, "pidiendo la lectura, lee");
});

test("H4 · permiso permanente: el cliente aprueba UNA vez con tope; dentro del tope el agente cierra solo (standing_permission) con evidencia; sobre el tope, igual tiene que preguntar", async () => {
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar(ANA, ["pedidos:leer", "compras:sin_confirmar"]);
	const decir = async (texto: string) => {
		const url = poppy.conv ? `${FERRETERIA}/poppy/conversaciones/${poppy.conv}/messages?wait=0` : `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await poppy.pedir("POST", url, { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } });
		poppy.conv = r.body.conversation_id;
		return [...r.body.events].reverse().find((e: { message?: { role?: string } }) => e.message?.role === "company")?.message;
	};
	await decir("Cotízame 3 taladros percutores con despacho a Calle Ejemplo 100, Santiago");
	const m1 = await decir("Haz el pedido");
	const op = m1?.operation;
	assert.ok(op, JSON.stringify(m1));
	assert.equal(op.user_approval_required, false, "dentro del tope de $200.000 no exige la aprobación de esta revisión");
	assert.match(op.summary, /Dentro de tu permiso permanente/);
	const c = await poppy.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op.operation_id}/confirm`, { revision: op.revision, approved_by: "standing_permission" });
	assert.equal(c.body.state, "succeeded", JSON.stringify(c.body));
	const ev = await interno(`prueba?tenant=${T}&op=${op.operation_id}`);
	const ap = declaraciones(ev.paquete).find((d) => d.kind === "user_approval");
	assert.equal(ap.body.basis, "standing_permission", "la evidencia dice que se confirmó por permiso permanente, no por una aprobación de esta revisión");
	assert.equal((await verificar(ev.paquete)).valid, true);
	// Over the cap: 3 circular saws (≈ $220.000) require the customer's approval.
	poppy.conv = "";
	await decir("Cotízame 3 sierras circulares con despacho a Calle Ejemplo 100, Santiago");
	const op2 = (await decir("Haz el pedido")).operation;
	assert.equal(op2.user_approval_required, true);
	const c2 = await poppy.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op2.operation_id}/confirm`, { revision: op2.revision, approved_by: "standing_permission" });
	assert.equal(c2.status, 403);
	assert.equal(c2.body.error, "user_approval_required");
	puerta.nucleo.empresa(T).comercio!.catalogo.find((p) => p.sku === "SIE-CIR-1400")!.stock = 4;
});

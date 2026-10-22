// Tests for the native profile (technical design 0.1), integrated with the VXP specification.
//
// The native agent uses the primitives of the official Poppy kit (vendor/poppy-kit/validate/jose.ts)
// to sign its assertions and its DPoP proofs, not the gateway's. The PACT agent signs its JWT with
// the same kit. The outcome proof is checked by the independent Python verifier.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { ESTADOS_NATIVOS, FINALES, TRANSICIONES, proyectarA2A, proyectarPoppy, transicionLegal } from "../src/estados.ts";
import { crearPuerta } from "../src/puerta.ts";
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
const CAP = "pedido.reprogramar_despacho";
const VERIFICADOR = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
const tmp = mkdtempSync(join(tmpdir(), "sovras-nativo-"));

const POPPY_ENUM = new Set(["proposed", "in_progress", "succeeded", "failed", "cancelled", "expired"]);
const A2A_ENUM = new Set(["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_REJECTED", "TASK_STATE_AUTH_REQUIRED"]);

// ── In-process network ──────────────────────────────────────────────────────────────────────────

type Pa = { clientId: string; key: SigningKey; doc: Record<string, unknown> };
const agentes = new Map<string, Pa>();
const paPactKey = await generateKey(true);
async function nuevoAgente(host: string): Promise<Pa> {
	const key = await generateKey(true);
	const clientId = `https://${host}/agent.json`;
	const doc = {
		client_id: clientId,
		client_name: `Asistente ${host}`,
		jwks_uri: `https://${host}/jwks.json`,
		redirect_uris: [`https://${host}/cb`],
		token_endpoint_auth_method: "private_key_jwt",
		extensions: { operations: { version: "1" }, "vxpprotocol.org/proof": { version: "0.1" } },
	};
	const pa = { clientId, key, doc };
	agentes.set(host, pa);
	return pa;
}
const red = async (input: string, init: RequestInit = {}): Promise<Response> => {
	const url = new URL(input);
	if (url.origin === PA_PACT) return new Response(JSON.stringify({ keys: [paPactKey.publicJwk] }), { headers: { "content-type": "application/json" } });
	const pa = agentes.get(url.host);
	if (pa) return new Response(JSON.stringify(url.pathname === "/agent.json" ? pa.doc : { keys: [pa.key.publicJwk] }), { headers: { "content-type": "application/json" } });
	return puerta.handler(new Request(input, init));
};
const puerta = crearPuerta({
	authOrigin: AUTH,
	providerOrigin: PROVIDER,
	empresas: empresasDePrueba({ ferreteria: DOMINIO, libreria: "agentes.libreria-demo.test" }),
	pactDelegada: [T],
	plataformasPact: [{ nombre: "pa-pact", issuer: PA_PACT, jwksUri: `${PA_PACT}/jwks.json`, enabled: true }],
	fetch: red,
});
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
const transportista = async (body?: unknown) => interno(`transportista?tenant=${T}`, body ?? undefined);
const salida = async () => (await interno(`whatsapp/salida?tenant=${T}`)) as { telefono: string; texto: string }[];
const totalOps = () => puerta.nucleo.base(T).operaciones.size;

// Ana's test orders with an external carrier (condition `carrier_acceptance`) and without one.
const nuevoPedido = (id: string, despachoActual: string, transportista?: string) =>
	interno("pedidos", { tenant: T, pedido: { id, clienteId: "ERP-C-0193", producto: `Producto ${id}`, despacho: despachoActual, direccion: "Calle Ejemplo 100, Santiago", estado: "preparando", ...(transportista ? { transportista } : {}) } });
for (const id of ["P-1044", "P-1045", "P-1046", "P-1050", "P-1051"]) await nuevoPedido(id, "2026-10-26", "Transportes Demo (simulado)");
for (const id of ["P-1047", "P-1048", "P-1049", "P-1052", "P-1053"]) await nuevoPedido(id, "2026-10-26");
// Two different customers sharing the same WhatsApp (a family phone).
await interno("pedidos", { tenant: T, pedido: { id: "P-3001", clienteId: "cli_carla", producto: "Martillo", despacho: "2026-10-25", direccion: "Calle 1", estado: "preparando" }, cliente: { id: "cli_carla", nombre: "Carla Soto", telefono: "+56 9 0000 0303" } });
await interno("pedidos", { tenant: T, pedido: { id: "P-3002", clienteId: "cli_diego", producto: "Serrucho", despacho: "2026-10-25", direccion: "Calle 1", estado: "preparando" }, cliente: { id: "cli_diego", nombre: "Diego Soto", telefono: "+56 9 0000 0303" } });

// ── Native agent ───────────────────────────────────────────────────────────────────────────

class AgenteNativo {
	readonly sub: string;
	dpopKey!: SigningKey;
	token = "";
	readonly pa: Pa;
	constructor(pa: Pa, sub = `usr_${randomId(9)}`) {
		this.pa = pa;
		this.sub = sub;
	}
	private base() {
		return { client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: V1 };
	}
	private async clienteAsercion() {
		return signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: FERRETERIA });
	}
	async tokenRequest(form: Record<string, string>) {
		const url = `${FERRETERIA}/oauth/token`;
		const body = new URLSearchParams({
			...form,
			...this.base(),
			client_assertion: await this.clienteAsercion(),
			assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: FERRETERIA }),
		});
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return { status: r.status, body: (await r.json()) as Record<string, unknown> };
	}
	async sesion() {
		this.dpopKey ??= await generateKey(false);
		const r = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
		assert.equal(r.status, 200, JSON.stringify(r.body));
		this.token = String(r.body.access_token);
	}
	/** RFC 8628 + RFC 9396: requests `authorization_details` for specific orders and links over WhatsApp. */
	async vincular(pedidosRar: string[], telefono: string): Promise<{ status: number; body: Record<string, unknown>; enviado: boolean }> {
		this.dpopKey ??= await generateKey(false);
		const rar = pedidosRar.map((id) => ({ type: RAR, actions: [CAP], identifier: id }));
		const dev = await red(`${FERRETERIA}/oauth/device`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ ...this.base(), client_assertion: await this.clienteAsercion(), authorization_details: JSON.stringify(rar) }).toString(),
		}).then((r) => r.json());
		assert.ok(dev.user_code, JSON.stringify(dev));
		const pagina = await red(dev.verification_uri_complete).then((r) => r.text());
		for (const id of pedidosRar) assert.match(pagina, new RegExp(`pedido ${id}`), "la persona ve el pedido exacto que autoriza");
		const post = (paso: string, form: Record<string, string | string[]>) => {
			const b = new URLSearchParams();
			for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) b.append(k, x);
			return red(`${FERRETERIA}/vincular/${paso}`, { method: "POST", body: b.toString(), redirect: "manual" });
		};
		const antes = (await salida()).length;
		await post("telefono", { user_code: dev.user_code, telefono });
		const msgs = await salida();
		if (msgs.length === antes) return { ...(await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code })), enviado: false };
		const otp = msgs.at(-1)!.texto.match(/código es (\d{6})/)![1];
		await post("codigo", { user_code: dev.user_code, codigo: otp });
		await post("decision", { user_code: dev.user_code, decision: "allow", scope: "pedidos:modificar" });
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
		if (t.status === 200) this.token = String(t.body.access_token);
		return { ...t, enviado: true };
	}
	async pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
		const r = await red(url, {
			method,
			headers: { authorization: `DPoP ${this.token}`, dpop: await dpopProof({ key: this.dpopKey, method, url, accessToken: this.token }), "content-type": "application/json", ...headers },
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		});
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null };
	}
	solicitar(orden: string, fecha: string, llave: string | null = randomId(12)) {
		return this.pedir("POST", `${V1}/requests`, { operation: CAP, target: { order_ref: orden }, parameters: { delivery_date: fecha } }, llave ? { "idempotency-key": llave } : {});
	}
	aceptar(v: { proposal: { id: string } }, body: Record<string, unknown> = { approved_by: "user" }) {
		return this.pedir("POST", `${V1}/proposals/${v.proposal.id}/accept`, body);
	}
	leer(id: string) {
		return this.pedir("GET", `${V1}/requests/${id}`);
	}
}

// ── Poppy agent (same CIMD as the native one) and PACT agent ───────────────────────────────────

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
	async entrar(telefono: string) {
		this.dpopKey = await generateKey(false);
		const s = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: FERRETERIA }) });
		this.sessionId = String(s.session_id);
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: FERRETERIA });
		const dev = await red(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ scope: "pedidos:leer pedidos:modificar", client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion }).toString() }).then((r) => r.json());
		await vincularPagina(dev.user_code, telefono, ["pedidos:leer", "pedidos:modificar"]);
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
}

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

// ── Independent verifier, anchored by the issuer discovered in vxp.json ────────────────

const metadataDe = (issuer: string) => {
	const u = new URL(issuer);
	return `${u.origin}/.well-known/oauth-authorization-server${u.pathname}`;
};
async function verificar(paquete: unknown, operacion?: unknown) {
	const docs: Record<string, unknown> = {};
	const traer = async (u: string) => (await red(u)).text();
	const desc = JSON.parse(await traer(`https://${DOMINIO}/.well-known/vxp.json`));
	assert.equal(desc.organization.domain, DOMINIO);
	const issuer = desc.issuer;
	docs[metadataDe(issuer)] = await traer(metadataDe(issuer));
	const bloque = JSON.parse(String(docs[metadataDe(issuer)])).vxp_proof;
	assert.ok(bloque.domains.includes(DOMINIO), "la metadata del issuer reconoce el dominio que sirvió vxp.json");
	for (const u of [bloque.jwks_uri, bloque.operator.jwks_uri, bloque.log.jwks_uri]) docs[u] = await traer(u);
	docs[bloque.log.checkpoint_url] = await traer(bloque.log.checkpoint_url);
	const n = randomId(6);
	writeFileSync(join(tmp, `${n}-m.json`), JSON.stringify({ anchor: { issuer }, docs }));
	writeFileSync(join(tmp, `${n}-p.json`), JSON.stringify(paquete));
	const args = [VERIFICADOR, "material", "--material", join(tmp, `${n}-m.json`), "--paquete", join(tmp, `${n}-p.json`)];
	if (operacion) {
		writeFileSync(join(tmp, `${n}-o.json`), JSON.stringify(operacion));
		args.push("--operacion", join(tmp, `${n}-o.json`));
	}
	const r = spawnSync("python", args, { encoding: "utf8" });
	assert.ok(r.stdout, `el verificador no respondió: ${r.stderr}`);
	return JSON.parse(r.stdout.trim().split("\n").at(-1)!) as Record<string, unknown>;
}
/** The native view, shaped as a Poppy operation (its projection), for the verifier cross-check. */
const comoPoppy = (v: Record<string, any>) => ({
	operation_id: v.operation_id,
	revision: v.proposal.revision,
	summary: v.proposal.summary,
	terms: v.proposal.terms,
	expires_at: v.proposal.expires_at,
	user_approval_required: v.proposal.user_approval_required,
	state: v.projections.poppy,
	result: v.result,
});
const declaraciones = (paquete: { statements: string[] }) => paquete.statements.map((s) => JSON.parse(Buffer.from(s.split("~")[0].split(".")[1], "base64url").toString("utf8")));

// ── Scenario ───────────────────────────────────────────────────────────────────────────────

const plataforma = await nuevoAgente("asistente.test");
const ana = new AgenteNativo(plataforma, "usr_ana_en_asistente");
await ana.sesion();
const todas: string[] = [];

test("0 · descubrimiento: vxp.json en el dominio, sin llaves; la confianza sale de la metadata RFC 8414 del mismo issuer", async () => {
	const s = await (await red(`https://${DOMINIO}/.well-known/vxp.json`)).json();
	const p = await (await red(`https://${DOMINIO}/.well-known/poppy.json`)).json();
	assert.equal(s.protocol, "vxp");
	assert.equal(s.organization.domain, DOMINIO);
	assert.equal(s.issuer, p.auth.issuer, "un solo issuer para Poppy y nativo");
	for (const k of ["jwks_uri", "custody", "operator", "log"]) assert.ok(!(k in s) && !(k in (s.outcome_proof ?? {})), `vxp.json no trae ${k}`);
	const meta = await (await red(metadataDe(s.issuer))).json();
	assert.equal(meta.issuer, s.issuer);
	assert.ok(meta.vxp_proof.jwks_uri);
	assert.ok(meta.authorization_details_types_supported.includes(RAR));
	assert.equal(s.endpoint, V1);
});

test("7 · idempotencia: sin clave 400; misma clave y cuerpo, la misma solicitud; otro cuerpo, 409; tras vincular, la misma solicitud se reevalúa", async () => {
	const sinClave = await ana.solicitar("P-1052", "2026-10-28", null);
	assert.equal(sinClave.status, 400);
	assert.equal(sinClave.body.error, "idempotency_key_required");
	const llave = randomId(12);
	const a = await ana.solicitar("P-1052", "2026-10-28", llave);
	assert.equal(a.status, 202, JSON.stringify(a.body));
	assert.equal(a.body.state, "authorization_required", "sin cuenta vinculada no hay propuesta");
	assert.deepEqual(a.body.authorization.authorization_details, [{ type: RAR, actions: [CAP], identifier: "P-1052" }]);
	assert.equal(a.body.projections.poppy, null, "Poppy no tiene operación antes de la propuesta");
	assert.equal(a.body.projections.a2a, "TASK_STATE_AUTH_REQUIRED");
	const b = await ana.solicitar("P-1052", "2026-10-28", llave);
	assert.equal(b.body.request_id, a.body.request_id, "misma clave y cuerpo = misma solicitud");
	const c = await ana.solicitar("P-1052", "2026-10-29", llave);
	assert.equal(c.status, 409);
	assert.equal(c.body.error, "idempotency_key_reused");
	const v = await ana.vincular(["P-1042", "P-1044", "P-1045", "P-1046", "P-1047", "P-1048", "P-1049", "P-1050", "P-1052", "P-1053"], "+56900000101");
	assert.equal(v.status, 200, JSON.stringify(v.body));
	assert.equal((v.body.authorization_details as unknown[]).length, 10, "RFC 9396 §7: el token devuelve los detalles concedidos");
	const ops = totalOps();
	const d = await ana.solicitar("P-1052", "2026-10-28", llave);
	assert.equal(d.status, 201, JSON.stringify(d.body));
	assert.equal(d.body.request_id, a.body.request_id, "la misma solicitud, ahora con permisos");
	assert.equal(d.body.state, "proposed");
	const e = await ana.solicitar("P-1052", "2026-10-28", llave);
	assert.equal(e.body.proposal.id, d.body.proposal.id);
	assert.equal(totalOps(), ops + 1, "un reintento no crea otra operación");
	const ev = await ana.pedir("GET", `${V1}/requests/${a.body.request_id}/events`);
	assert.deepEqual(ev.body.events.map((x: { to: string }) => x.to), ["received", "authorization_required", "proposed"]);
	todas.push(a.body.request_id);
});

test("1a · propuesta condicional: no llega a succeeded hasta carrier_acceptance; con la aceptación, la lectura cierra y el verificador lo acepta", async () => {
	await transportista({ respuesta: { "P-1044": "no_responde" } });
	const r = await ana.solicitar("P-1044", "2026-10-29");
	assert.equal(r.status, 201, JSON.stringify(r.body));
	assert.deepEqual(r.body.proposal.commitment, { mode: "conditional", requires: ["carrier_acceptance"] });
	assert.equal(r.body.proposal.terms.carrier_acceptance, "accepted");
	assert.match(r.body.proposal.summary, /sujeto a que Transportes Demo/);
	const a = await ana.aceptar(r.body);
	assert.equal(a.status, 202, JSON.stringify(a.body));
	assert.equal(a.body.state, "pending_verification", "el ERP cambió, pero falta la condición");
	assert.equal(a.body.projections.poppy, "in_progress");
	assert.equal(a.body.projections.a2a, "TASK_STATE_WORKING");
	assert.equal(await despacho("P-1044"), "2026-10-29");
	const sigue = await ana.leer(r.body.request_id);
	assert.equal(sigue.body.state, "pending_verification", "leer no inventa la condición");
	await transportista({ confirmado: { "P-1044": "accepted" } });
	const fin = await ana.leer(r.body.request_id);
	assert.equal(fin.body.state, "succeeded");
	assert.equal(fin.body.effects.find((x: { system: string }) => x.system === "carrier").status, "accepted");
	const paq = (await ana.pedir("GET", `${V1}/requests/${r.body.request_id}/proof`)).body;
	const ds = declaraciones(paq);
	assert.equal(ds[0].body.channel, "vxp");
	const terms = ds.find((d: { kind: string }) => d.kind === "terms");
	assert.deepEqual(terms.body.commitment, { mode: "conditional", requires: ["carrier_acceptance"] });
	assert.ok(terms.body.read_back_terms.includes("carrier_acceptance"), "la condición es un término que la lectura debe observar");
	const lectura = ds.find((d: { kind: string }) => d.kind === "read_back");
	assert.equal(lectura.body.observed.carrier_acceptance, "accepted");
	const ver = await verificar(paq, comoPoppy(fin.body));
	assert.equal(ver.valid, true, JSON.stringify(ver));
	assert.equal(ver.final_state, "succeeded");
	assert.equal(ver.operation, "matches");
	todas.push(r.body.request_id);
});

test("1b · el transportista rechaza: failed con efectos parciales declarados (ERP aplicado y revertido), y el verificador lo acepta como failed", async () => {
	await transportista({ respuesta: { "P-1045": "rechaza" } });
	const r = await ana.solicitar("P-1045", "2026-10-30");
	const a = await ana.aceptar(r.body);
	assert.equal(a.status, 200, JSON.stringify(a.body));
	assert.equal(a.body.state, "failed");
	assert.equal(a.body.reason, "carrier_rejected");
	const erp = a.body.effects.find((x: { system: string }) => x.system === "erp");
	const carrier = a.body.effects.find((x: { system: string }) => x.system === "carrier");
	assert.deepEqual([erp.applied, erp.reverted], [true, true], "lo que se hizo y lo que se deshizo");
	assert.deepEqual([carrier.applied, carrier.status], [false, "rejected"]);
	assert.match(a.body.result.summary, /rechazó.*se revirtió/);
	assert.equal(await despacho("P-1045"), "2026-10-26", "el ERP vuelve a su fecha");
	const paq = (await ana.pedir("GET", `${V1}/requests/${r.body.request_id}/proof`)).body;
	const ver = await verificar(paq, comoPoppy(a.body));
	assert.equal(ver.valid, true, JSON.stringify(ver));
	assert.equal(ver.final_state, "failed");
	todas.push(r.body.request_id);
});

test("6 · el transportista no responde: sin reintento ni failed; leer sólo consulta; la lectura posterior cierra", async () => {
	await transportista({ respuesta: { "P-1046": "no_responde" } });
	const r = await ana.solicitar("P-1046", "2026-10-31");
	const a = await ana.aceptar(r.body);
	assert.equal(a.body.state, "pending_verification");
	const antes = await transportista();
	const pedidas = antes.solicitudes.filter((s: { pedidoId: string }) => s.pedidoId === "P-1046").length;
	assert.equal(pedidas, 1);
	for (let i = 0; i < 3; i++) {
		const l = await ana.leer(r.body.request_id);
		assert.equal(l.body.state, "pending_verification", "ni failed ni succeeded sin saber");
	}
	const despues = await transportista();
	assert.equal(despues.solicitudes.filter((s: { pedidoId: string }) => s.pedidoId === "P-1046").length, 1, "nunca se repite la acción");
	assert.ok(despues.consultas > antes.consultas, "leer consulta al transportista");
	const sinFin = (await ana.pedir("GET", `${V1}/requests/${r.body.request_id}/proof`)).body;
	const ver = await verificar(sinFin);
	assert.equal(ver.final_state, "unknown", "sin outcome, la prueba dice «no sé»");
	await transportista({ confirmado: { "P-1046": "rejected" } });
	const fin = await ana.leer(r.body.request_id);
	assert.equal(fin.body.state, "failed");
	assert.equal(fin.body.reason, "carrier_rejected");
	assert.equal(await despacho("P-1046"), "2026-10-26");
	todas.push(r.body.request_id);
});

test("3 · cancelar durante la ejecución pide detener: no promete revertir y el estado lo dice", async () => {
	await transportista({ respuesta: { "P-1050": "no_responde" } });
	const r = await ana.solicitar("P-1050", "2026-11-02");
	const a = await ana.aceptar(r.body);
	assert.equal(a.body.state, "pending_verification");
	const c = await ana.pedir("POST", `${V1}/requests/${r.body.request_id}/cancel`);
	assert.equal(c.status, 202);
	assert.equal(c.body.state, "pending_verification", "pedir detener no es estar cancelada");
	assert.deepEqual([c.body.cancellation.status, c.body.cancellation.reversal_promised], ["requested", false]);
	const erp = c.body.effects.find((x: { system: string }) => x.system === "erp");
	assert.equal(erp.applied, true);
	assert.ok(!erp.reverted, "no se finge que se deshizo");
	assert.equal(await despacho("P-1050"), "2026-11-02");
	await transportista({ confirmado: { "P-1050": "accepted" } });
	const fin = await ana.leer(r.body.request_id);
	assert.equal(fin.body.state, "succeeded", "la detención llegó tarde y se informa así");
	assert.equal(fin.body.cancellation.status, "not_stopped");
	// Before the proposal or before executing, cancelling does cancel.
	const p = await ana.solicitar("P-1053", "2026-11-03");
	const cp = await ana.pedir("POST", `${V1}/requests/${p.body.request_id}/cancel`);
	assert.equal(cp.body.state, "cancelled");
	assert.equal(await despacho("P-1053"), "2026-10-26");
	todas.push(r.body.request_id, p.body.request_id);
});

test("2 · límites: superado el máximo de revisiones o la vigencia, o los intentos, accept da error y no hay efecto", async () => {
	await interno("limites", { tenant: T, limites: { max_revisions: 2 } });
	const r = await ana.solicitar("P-1047", "2026-10-28");
	assert.equal(r.body.proposal.limits.max_revisions, 2);
	const c1 = await ana.pedir("POST", `${V1}/proposals/${r.body.proposal.id}/counter`, { proposed_terms: { delivery_date: "2026-10-29" } });
	assert.equal(c1.status, 200, JSON.stringify(c1.body));
	assert.equal(c1.body.proposal.revision, 2);
	assert.equal(c1.body.proposal.limits.revisions_left, 0);
	const c2 = await ana.pedir("POST", `${V1}/proposals/${c1.body.proposal.id}/counter`, { proposed_terms: { delivery_date: "2026-10-30" } });
	assert.equal(c2.status, 409);
	assert.equal(c2.body.error, "negotiation_limit_exceeded");
	assert.equal(c2.body.state, "failed");
	const ac = await ana.aceptar(c1.body);
	assert.equal(ac.status, 409, JSON.stringify(ac.body));
	assert.equal(ac.body.error, "proposal_not_acceptable");
	assert.equal(await despacho("P-1047"), "2026-10-26");

	await interno("limites", { tenant: T, limites: { max_revisions: 3, proposal_ttl_seconds: 1 } });
	const v = await ana.solicitar("P-1048", "2026-10-28");
	await new Promise((x) => setTimeout(x, 1300));
	const av = await ana.aceptar(v.body);
	assert.equal(av.status, 409, JSON.stringify(av.body));
	assert.equal(av.body.error, "proposal_expired");
	assert.equal(av.body.state, "expired");
	assert.equal(av.body.projections.poppy, "expired");
	assert.equal(await despacho("P-1048"), "2026-10-26");

	await interno("limites", { tenant: T, limites: { proposal_ttl_seconds: 900, max_accept_attempts: 3 } });
	const i = await ana.solicitar("P-1049", "2026-10-28");
	const malo = { proposal: { id: i.body.proposal.id.replace(/_r1$/, "_r9") } };
	const e1 = await ana.aceptar(malo);
	const e2 = await ana.aceptar(malo);
	assert.deepEqual([e1.body.error, e2.body.error], ["terms_changed", "terms_changed"]);
	const e3 = await ana.aceptar(malo);
	assert.equal(e3.body.error, "attempt_limit_exceeded");
	assert.equal(e3.body.state, "failed");
	const tarde = await ana.aceptar(i.body);
	assert.equal(tarde.status, 409);
	assert.equal(await despacho("P-1049"), "2026-10-26");
	todas.push(r.body.request_id, v.body.request_id, i.body.request_id);
});

test("5 · RFC 9396: un grant para P-1042 no sirve para P-1043, ni para aceptar con otro token; un pedido ajeno no se concede", async () => {
	const otra = new AgenteNativo(plataforma);
	await otra.sesion();
	const g = await otra.vincular(["P-1042"], "+56900000101");
	assert.equal(g.status, 200, JSON.stringify(g.body));
	const ops = totalOps();
	const r = await otra.solicitar("P-1043", "2026-10-30");
	assert.equal(r.status, 202);
	assert.equal(r.body.state, "authorization_required");
	assert.deepEqual(r.body.authorization.authorization_details, [{ type: RAR, actions: [CAP], identifier: "P-1043" }]);
	assert.equal(totalOps(), ops, "sin grant del pedido no hay propuesta");
	const ok = await otra.solicitar("P-1042", "2026-11-04");
	assert.equal(ok.status, 201, JSON.stringify(ok.body));
	// Accepting re-verifies: a new token that only covers P-1043 does not accept the one for P-1042.
	const tokenP1042 = otra.token;
	const g2 = await otra.vincular(["P-1043"], "+56900000101");
	assert.equal(g2.status, 200);
	const ac = await otra.aceptar(ok.body);
	assert.equal(ac.status, 403, JSON.stringify(ac.body));
	assert.equal(ac.body.error, "authorization_required");
	otra.token = tokenP1042;
	assert.notEqual(await despacho("P-1042"), "2026-11-04");
	const ajeno = await otra.vincular(["P-2001"], "+56900000101");
	assert.equal(ajeno.status, 400);
	assert.equal(ajeno.body.error, "invalid_authorization_details", "el servidor no confía en el identifier del agente");
	await otra.pedir("POST", `${V1}/requests/${ok.body.request_id}/cancel`);
	todas.push(r.body.request_id, ok.body.request_id);
});

test("4 · la misma operación por nativo, Poppy y PACT: tres registros con identidades separadas; ninguno ve ni reescribe el del otro", async () => {
	// Native (the `asistente.test` platform, User ID `usr_ana_en_asistente`).
	const n = await ana.solicitar("P-1042", "2026-10-28");
	assert.equal(n.status, 201, JSON.stringify(n.body));
	const na = await ana.aceptar(n.body);
	assert.equal(na.body.state, "succeeded", JSON.stringify(na.body));
	// Poppy: SAME client_id and SAME User ID as the native agent.
	const poppy = new UsuarioPoppy(plataforma, ana.sub);
	await poppy.entrar("+56900000101");
	const op = await poppy.proponer("Cambia el despacho del P-1042 al 2026-10-29");
	assert.ok(op, "Poppy propone");
	const pc = await poppy.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op.operation_id}/confirm`, { revision: op.revision, approved_by: "user" });
	assert.equal(pc.body.state, "succeeded", JSON.stringify(pc.body));
	// PACT.
	const pact = new AgentePact();
	await pact.delegar("+56900000101");
	const m = await pact.enviar("Cambia el despacho del P-1042 al 2026-10-30");
	const opPact = m.message.metadata["vxpprotocol.org/operation"];
	const anot = m.message.metadata["https://vxpprotocol.org/ext/native/v0.1"];
	assert.deepEqual(anot, { state: "proposed", a2a_state: "TASK_STATE_INPUT_REQUIRED" }, "bajo A2A el estado nativo va en metadata, con un valor A2A existente");
	const aviso = (await salida()).at(-1)!;
	const codigo = aviso.texto.match(/APROBAR (\d{6})/)![1];
	const ap = await interno("whatsapp/entrada", { tenant: T, telefono: aviso.telefono, texto: `APROBAR ${codigo}` });
	assert.equal(ap.aceptado, true);
	assert.equal(await despacho("P-1042"), "2026-10-30");

	const ids = [n.body.operation_id, op.operation_id, opPact.operation_id];
	assert.equal(new Set(ids).size, 3, "tres operaciones, una por entrada");
	const base = puerta.nucleo.base(T).operaciones;
	assert.deepEqual(ids.map((i) => base.get(i)!.interno.dueno.protocolo), ["vxp", "poppy", "pact"]);
	const canales = ids.map((i) => (puerta.pruebas.declaraciones(T, i)[0].payload.body as { channel: string }).channel);
	assert.deepEqual(canales, ["vxp", "poppy", "pact"]);
	const grants = [...puerta.del.grants.values()].filter((g) => g.clienteId === "cli_a_ferreteria");
	assert.deepEqual(new Set(grants.map((g) => g.protocolo)), new Set(["vxp", "poppy", "pact"]), "permisos separados por protocolo");
	// The same client_id and the same User ID over Poppy do not see the native operation, nor the reverse.
	assert.equal((await poppy.pedir("GET", `${FERRETERIA}/poppy/operaciones/${n.body.operation_id}`)).status, 404);
	assert.equal((await ana.leer(op.operation_id)).status, 404);
	// An open Poppy proposal is not rewritten from native mode even if agent and User ID match.
	const abierta = await poppy.proponer("Cambia el despacho del P-1043 al 2026-11-05");
	assert.equal(abierta.revision, 1);
	const g = await ana.vincular(["P-1043"], "+56900000101");
	assert.equal(g.status, 200);
	const nat = await ana.solicitar("P-1043", "2026-11-06");
	assert.equal(nat.status, 201, JSON.stringify(nat.body));
	assert.notEqual(nat.body.operation_id, abierta.operation_id, "otra operación, no la de Poppy");
	assert.equal(base.get(abierta.operation_id)!.revision, 1, "la operación Poppy no cambió");
	todas.push(n.body.request_id, nat.body.request_id);
});

test("4b · el mismo teléfono no fusiona usuarios: un número compartido por dos clientes no vincula a ninguno", async () => {
	const x = new AgenteNativo(plataforma);
	await x.sesion();
	const r = await x.vincular(["P-3001"], "+56900000303");
	assert.equal(r.enviado, false, "no sale un código a un número que no identifica a una sola persona");
	assert.equal(r.status, 400);
	assert.equal(r.body.error, "authorization_pending");
	const ev = (await interno(`casos?tenant=${T}`)).eventos.filter((e: { eventType: string }) => e.eventType === "link.ambiguous_identifier");
	assert.ok(ev.length >= 1);
	const s = await x.solicitar("P-3001", "2026-10-28");
	assert.equal(s.body.state, "authorization_required");
});

test("8 · transiciones: la tabla es la del diseño; lo ilegal se rechaza; todo lo que pasó en este archivo fue legal", async () => {
	for (const f of FINALES) for (const h of ESTADOS_NATIVOS) assert.equal(transicionLegal(f, h), false, `${f} es final`);
	assert.equal(transicionLegal("received", "succeeded"), false);
	assert.equal(transicionLegal("proposed", "executing"), false, "no se ejecuta sin aceptar");
	assert.equal(transicionLegal("accepted", "succeeded"), false, "no hay éxito sin ejecutar y verificar");
	assert.equal(transicionLegal("executing", "cancelled"), false, "cancelar durante la ejecución no cancela");
	assert.equal(transicionLegal(null, "proposed"), false);
	const terminada = [...puerta.nucleo.base(T).operaciones.values()].find((o) => o.interno.nativo.estado === "succeeded")!;
	assert.throws(() => puerta.nucleo.transicion(terminada, "executing", "prueba"), /transicion_ilegal/);
	let revisadas = 0;
	for (const id of todas) {
		const ev = await ana.pedir("GET", `${V1}/requests/${id}/events`);
		if (ev.status !== 200) continue;
		for (const e of ev.body.events) {
			if (e.from === null) assert.equal(e.to, "received");
			else assert.ok(TRANSICIONES[e.from as keyof typeof TRANSICIONES].includes(e.to), `${e.from} → ${e.to}`);
			revisadas++;
		}
	}
	assert.ok(revisadas > 20, `transiciones revisadas: ${revisadas}`);
});

test("9 · proyección: cada estado nativo cae en un valor existente de Poppy y de A2A; Poppy nunca ve un valor nativo", async () => {
	for (const e of ESTADOS_NATIVOS) {
		const p = proyectarPoppy(e);
		assert.ok(p === null || POPPY_ENUM.has(p), `${e} → ${p}`);
		assert.ok(A2A_ENUM.has(proyectarA2A(e)), `${e} → ${proyectarA2A(e)}`);
	}
	// Over Poppy, a conditional operation waiting for the carrier shows as `in_progress`.
	await transportista({ respuesta: { "P-1051": "no_responde" } });
	const poppy = new UsuarioPoppy(plataforma, `usr_${randomId(6)}`);
	await poppy.entrar("+56900000101");
	const op = await poppy.proponer("Cambia el despacho del P-1051 al 2026-10-30");
	const c = await poppy.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op.operation_id}/confirm`, { revision: op.revision, approved_by: "user" });
	assert.equal(c.body.state, "in_progress");
	const g = await poppy.pedir("GET", `${FERRETERIA}/poppy/operaciones/${op.operation_id}`);
	assert.equal(g.body.state, "in_progress");
	assert.ok(POPPY_ENUM.has(g.body.state));
	assert.equal(puerta.nucleo.base(T).operaciones.get(op.operation_id)!.interno.nativo.estado, "pending_verification");
	assert.doesNotMatch(JSON.stringify({ state: g.body.state }), /pending_verification|waiting_human|executing|accepted/);
});

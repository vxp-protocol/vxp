// Stress sandbox: dedicated tests for the three journeys (commerce with returns, hospitality and
// bilateral relationship) in their normal, changing-conditions and adversarial variants, plus the
// end-to-end access of an external agent (B: arrival without credentials → recognition → linking →
// temporary permission → EXPANSION mid-operation → subsequent bilateral relationship).
//
// It does not repeat what is already tested (test/vxp.test.ts A–G and the rest): everything here runs
// on the new pieces — the (fictional) Hotel Demo, the hardware store's return, the simulated payment
// provider, the simulated channel manager, the conditions simulator (/interno/condiciones,
// /interno/reset) and the access log. Every claim is checked against the systems (PMS, ERP, payment
// ledger, VXP Proof chain with the independent Python verifier), never against the agent's text.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { hotelDePrueba, prepararDevoluciones } from "../src/datos-hotel.ts";
import { isoDia, masDias } from "../src/hotel.ts";
import { decodeJwt, verifyWith } from "../src/jose.ts";
import { crearPuerta } from "../src/puerta.ts";
import { dpopProof, generateKey, nowSeconds, randomId, type SigningKey, signAssertion, signJwt } from "../vendor/poppy-kit/validate/jose.ts";

const AUTH = "https://auth.sovras.test";
const PROVIDER = "https://provider.sovras.test";
const FERRETERIA = `${AUTH}/e/ferreteria-demo`;
const HOTEL = `${AUTH}/e/hotel-demo`;
const T = "t_ferreteria_demo";
const TH = "t_hotel_demo";
const DOM_FERRETERIA = "agentes.ferreteria-demo.test";
const DOM_HOTEL = "reservas.hotel-demo.test";
const PA_PACT = "https://pa-pact.test";
const RAR = "https://vxpprotocol.org/rar/capability";
const RAR_REL = "https://vxpprotocol.org/rar/relationship";
const ANA = "+56900000101";
const BRUNO = "+56900000202";
const TODOS_H = ["reservas:leer", "reservas:crear", "reservas:modificar", "reservas:cancelar"];
const VERIFICADOR = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
const tmp = mkdtempSync(join(tmpdir(), "sovras-exigencia-"));
const hoy = isoDia(new Date());
const f = (n: number) => masDias(hoy, n);

// ── In-process network ──────────────────────────────────────────────────────────────────────────

type Pa = { clientId: string; key: SigningKey; doc: Record<string, unknown>; buzon: { message: string }[] };
const agentes = new Map<string, Pa>();
const paPactKey = await generateKey(true);
async function nuevoAgente(host: string): Promise<Pa> {
	const key = await generateKey(true);
	const clientId = `https://${host}/agent.json`;
	const doc = {
		client_id: clientId,
		client_name: `Asistente ${host}`,
		jwks_uri: `https://${host}/jwks.json`,
		token_endpoint_auth_method: "private_key_jwt",
		extensions: { operations: { version: "1" }, "vxpprotocol.org/proof": { version: "0.1" }, "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `https://${host}/vxp/inbox` } },
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
	if (pa) return new Response(JSON.stringify(url.pathname === "/agent.json" ? pa.doc : { keys: [pa.key.publicJwk] }), { headers: { "content-type": "application/json" } });
	return puerta.handler(new Request(input, init));
};
function nuevaPuerta() {
	const empresas = empresasDePrueba({ ferreteria: DOM_FERRETERIA, libreria: "agentes.libreria-demo.test" });
	prepararDevoluciones(empresas[0]);
	empresas.push(hotelDePrueba(DOM_HOTEL));
	return crearPuerta({ authOrigin: AUTH, providerOrigin: PROVIDER, empresas, pactDelegada: [T, TH], plataformasPact: [{ nombre: "pa-pact", issuer: PA_PACT, jwksUri: `${PA_PACT}/jwks.json`, enabled: true }], fetch: red });
}
const puerta = nuevaPuerta();
const interno = async (path: string, body?: unknown, llave = puerta.llaveInterna) => {
	const r = await red(`${AUTH}/interno/${path}`, { method: body ? "POST" : "GET", headers: { "x-sovras-prueba": llave, "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) });
	return r.status === 404 && !r.headers.get("content-type") ? { status: 404 } : r.json();
};
const condicion = (tenant: string, c: Record<string, unknown>) => interno("condiciones", { tenant, ...c });
type Estado = { reservas: { id: string; estadia?: string; estado: string; llegada: string; salida: string; total: number; servicios: { codigo: string; cantidad: number }[] }[]; pedidos: { id: string; estado: string; anulado?: boolean; total?: number; cotizacion?: string }[]; pagos: { movimientos: { ref: string; tipo: string; monto: number; estado: string }[]; conciliacion: Record<string, { garantia: number; capturado: number; reembolsado: number }>; consultas: number }; stock: { sku: string; stock: number; precio: number }[] | null; operaciones: { operation_id: string; capability: string; nativo: string; dueno: { clientId: string; sub: string } }[]; devoluciones: { pedido: string; reembolso: number }[] | null };
const estado = async (tenant: string) => (await interno(`estado?tenant=${tenant}`)) as Estado;
const movimientos = async (tenant: string, ref: string, tipo?: string) => (await estado(tenant)).pagos.movimientos.filter((m) => m.ref === ref && (!tipo || m.tipo === tipo));
const salida = async (tenant: string) => (await interno(`whatsapp/salida?tenant=${tenant}`)) as { telefono: string; texto: string }[];
const declaraciones = (paquete: { statements: string[] }) => paquete.statements.map((s) => JSON.parse(Buffer.from(s.split("~")[0].split(".")[1], "base64url").toString("utf8")));

async function vincularPagina(iss: string, tenant: string, userCode: string, telefono: string, scope: string[]) {
	const post = (paso: string, form: Record<string, string | string[]>) => {
		const b = new URLSearchParams();
		for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) b.append(k, x);
		return red(`${iss}/vincular/${paso}`, { method: "POST", body: b.toString(), redirect: "manual" });
	};
	await post("telefono", { user_code: userCode, telefono });
	const otp = (await salida(tenant)).at(-1)!.texto.match(/código es (\d{6})/)![1];
	await post("codigo", { user_code: userCode, codigo: otp });
	await post("decision", { user_code: userCode, decision: "allow", scope });
}

const metadataDe = (issuer: string) => {
	const u = new URL(issuer);
	return `${u.origin}/.well-known/oauth-authorization-server${u.pathname}`;
};
/** Independent verifier (Python), with the material fetched through the protocol from the company's domain. */
async function verificar(paquete: unknown, dominio: string) {
	const docs: Record<string, unknown> = {};
	const traer = async (u: string) => (await red(u)).text();
	const issuer = JSON.parse(await traer(`https://${dominio}/.well-known/vxp.json`)).issuer;
	docs[metadataDe(issuer)] = await traer(metadataDe(issuer));
	const bloque = JSON.parse(String(docs[metadataDe(issuer)])).vxp_proof;
	for (const u of [bloque.jwks_uri, bloque.operator.jwks_uri, bloque.log.jwks_uri]) docs[u] = await traer(u);
	docs[bloque.log.checkpoint_url] = await traer(bloque.log.checkpoint_url);
	const n = randomId(6);
	writeFileSync(join(tmp, `${n}-m.json`), JSON.stringify({ anchor: { issuer }, docs }));
	writeFileSync(join(tmp, `${n}-p.json`), JSON.stringify(paquete));
	const r = spawnSync("python", [VERIFICADOR, "material", "--material", join(tmp, `${n}-m.json`), "--paquete", join(tmp, `${n}-p.json`)], { encoding: "utf8" });
	assert.ok(r.stdout, `el verificador no respondió: ${r.stderr}`);
	return JSON.parse(r.stdout.trim().split("\n").at(-1)!) as { valid: boolean; final_state: string; derived_assurance: string[]; error?: string };
}

// ── Test agents (they sign with the primitives of the official Poppy kit) ────────────────────

class AgenteNativo {
	readonly sub: string;
	dpopKey!: SigningKey;
	token = "";
	ultimoToken: Record<string, unknown> = {};
	readonly pa: Pa;
	readonly iss: string;
	readonly tenant: string;
	constructor(pa: Pa, iss: string, tenant: string, sub = `usr_${randomId(9)}`) {
		this.pa = pa;
		this.iss = iss;
		this.tenant = tenant;
		this.sub = sub;
	}
	get v1() {
		return `${this.iss}/v1`;
	}
	private base() {
		return { client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: this.v1 };
	}
	async tokenRequest(form: Record<string, string>) {
		const url = `${this.iss}/oauth/token`;
		const body = new URLSearchParams({ ...form, ...this.base(), client_assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: this.iss }), assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: this.iss }) });
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return { status: r.status, body: (await r.json()) as Record<string, unknown> };
	}
	async sesion() {
		this.dpopKey ??= await generateKey(false);
		const r = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
		assert.equal(r.status, 200, JSON.stringify(r.body));
		this.token = String(r.body.access_token);
	}
	async autorizar(detalles: unknown[], marcar: string[], telefono = ANA) {
		this.dpopKey ??= await generateKey(false);
		const devR = await red(`${this.iss}/oauth/device`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...this.base(), client_assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: this.iss }), authorization_details: JSON.stringify(detalles) }).toString() });
		const dev = await devR.json();
		if (devR.status !== 200) return { status: devR.status, body: dev as Record<string, unknown>, pagina: "" };
		const pagina = await red(dev.verification_uri_complete).then((r) => r.text());
		await vincularPagina(this.iss, this.tenant, dev.user_code, telefono, marcar);
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
		if (t.status === 200) {
			this.token = String(t.body.access_token);
			this.ultimoToken = t.body;
		}
		return { ...t, pagina };
	}
	async pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
		const r = await red(url, { method, headers: { authorization: `DPoP ${this.token}`, dpop: await dpopProof({ key: this.dpopKey, method, url, accessToken: this.token }), "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null, corte: r.headers.get("x-sovras-corte") === "1" };
	}
	solicitar(cuerpo: unknown, llave = randomId(12)) {
		return this.pedir("POST", `${this.v1}/requests`, cuerpo, { "idempotency-key": llave });
	}
	aceptar(proposalId: string) {
		return this.pedir("POST", `${this.v1}/proposals/${proposalId}/accept`, { approved_by: "user" });
	}
	contraproponer(proposalId: string, propuesta: Record<string, unknown>) {
		return this.pedir("POST", `${this.v1}/proposals/${proposalId}/counter`, { proposed_terms: propuesta });
	}
	prueba(id: string) {
		return this.pedir("GET", `${this.v1}/requests/${id}/proof`);
	}
}

class UsuarioPoppy {
	readonly sub: string;
	dpopKey!: SigningKey;
	token = "";
	sessionId = "";
	conv = "";
	readonly pa: Pa;
	readonly iss: string;
	readonly tenant: string;
	constructor(pa: Pa, iss: string, tenant: string, sub = `usr_${randomId(6)}`) {
		this.pa = pa;
		this.iss = iss;
		this.tenant = tenant;
		this.sub = sub;
	}
	private async tokenRequest(form: Record<string, string>) {
		const url = `${this.iss}/oauth/token`;
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: this.iss });
		const body = new URLSearchParams({ ...form, client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion });
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return (await r.json()) as Record<string, unknown>;
	}
	async sesion() {
		this.dpopKey ??= await generateKey(false);
		const s = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: this.iss }) });
		this.sessionId = String(s.session_id);
		this.token = String(s.access_token);
	}
	/** Device Sign-In (Poppy 4.6) with «Vincular con WhatsApp»; reusing the session if there already was one. */
	async entrar(telefono: string, alcances: string[]) {
		if (!this.sessionId) await this.sesion();
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: this.iss });
		const dev = await red(`${this.iss}/oauth/device`, { method: "POST", body: new URLSearchParams({ scope: alcances.join(" "), client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion }).toString() }).then((r) => r.json());
		await vincularPagina(this.iss, this.tenant, dev.user_code, telefono, alcances);
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code, session_id: this.sessionId });
		assert.ok(t.access_token, JSON.stringify(t));
		this.token = String(t.access_token);
		return t;
	}
	async pedir(method: string, url: string, body?: unknown) {
		const r = await red(url, { method, headers: { authorization: `DPoP ${this.token}`, dpop: await dpopProof({ key: this.dpopKey, method, url, accessToken: this.token }), "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null };
	}
	/** One conversation turn. Returns the company's message and the turn's `authorization` events. */
	async decir(texto: string, id = `msg_${randomId(9)}`) {
		const url = this.conv ? `${this.iss}/poppy/conversaciones/${this.conv}/messages?wait=0` : `${this.iss}/poppy/conversaciones?wait=0`;
		const r = await this.pedir("POST", url, { message: { id, sender: "agent", text: texto } });
		assert.ok(r.body?.conversation_id, JSON.stringify(r.body));
		this.conv = r.body.conversation_id;
		const evs = r.body.events as { type: string; message?: { role?: string; text: string; operation?: Record<string, any>; data?: Record<string, any> }; error?: string; scope?: string }[];
		const ultimo = evs.map((e, i) => ({ e, i })).filter((x) => x.e.message?.role === "user").at(-1)!.i;
		const turno = evs.slice(ultimo);
		return { ...turno.filter((e) => e.message?.role === "company").at(-1)!.message!, autorizacion: turno.find((e) => e.type === "authorization") };
	}
	confirmar(op: { operation_id: string; revision: number }) {
		return this.pedir("POST", `${this.iss}/poppy/operaciones/${op.operation_id}/confirm`, { revision: op.revision, approved_by: "user" });
	}
	operacion(id: string) {
		return this.pedir("GET", `${this.iss}/poppy/operaciones/${id}`);
	}
	paquete(id: string) {
		return this.pedir("GET", `${this.iss}/sovras/proof/operations/${id}`);
	}
}

class AgentePact {
	readonly sub = `pact_${randomId(6)}`;
	delegacion = "";
	contexto: string | undefined;
	readonly tenant: string;
	readonly iss: string;
	constructor(tenant: string, iss: string) {
		this.tenant = tenant;
		this.iss = iss;
	}
	get iface() {
		return `${PROVIDER}/a2a/${this.tenant}`;
	}
	private async jwt() {
		const iat = nowSeconds();
		return signJwt({ alg: "ES256", typ: "JWT", ...(paPactKey.publicJwk.kid ? { kid: paPactKey.publicJwk.kid } : {}) }, { iss: PA_PACT, sub: this.sub, aud: `${PROVIDER}/a2a`, iat, exp: iat + 60 }, paPactKey.privateKey);
	}
	async delegar(telefono: string, scope: string[]) {
		const dev = await red(`${this.iface}/oauth/device_authorization`, { method: "POST", headers: { authorization: `Bearer ${await this.jwt()}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: PA_PACT, scope: scope.join(" ") }).toString() }).then((r) => r.json());
		await vincularPagina(this.iss, this.tenant, dev.user_code, telefono, scope);
		const t = await red(`${this.iface}/oauth/token`, { method: "POST", headers: { authorization: `Bearer ${await this.jwt()}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: PA_PACT, grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code }).toString() }).then((r) => r.json());
		assert.ok(t.access_token, JSON.stringify(t));
		this.delegacion = t.access_token;
		return t;
	}
	async enviar(texto: string) {
		const r = await red(`${this.iface}/message:send`, {
			method: "POST",
			headers: { authorization: `Bearer ${await this.jwt()}`, ...(this.delegacion ? { "x-a2a-user-delegation": `Bearer ${this.delegacion}` } : {}), "content-type": "application/a2a+json" },
			body: JSON.stringify({ message: { messageId: randomId(8), role: "ROLE_USER", parts: [{ text: texto }], ...(this.contexto ? { contextId: this.contexto } : {}) } }),
		}).then((x) => x.json());
		this.contexto = r.message?.contextId ?? r.task?.contextId ?? this.contexto;
		return r;
	}
}

const chat = async (iss: string, texto: string, sesion = "", ua = "Mozilla/5.0") =>
	(await red(`${iss}/chat`, { method: "POST", headers: { "content-type": "application/json", "user-agent": ua, "x-forwarded-for": "190.0.0.9" }, body: JSON.stringify({ texto, sesion }) })).json();

/** Approves, through the company's (simulated) WhatsApp line, the last approval that was sent. */
async function aprobarPorWhatsapp(tenant: string) {
	const aviso = (await salida(tenant)).at(-1)!;
	return interno("whatsapp/entrada", { tenant, telefono: aviso.telefono, texto: `APROBAR ${aviso.texto.match(/APROBAR (\d{6})/)![1]}` });
}

const plataforma = await nuevoAgente("asistente-exigencia.test");
const otraPlataforma = await nuevoAgente("otro-asistente.test");
// Ana at the hotel over Poppy, with all permissions: used by several tests.
const anaH = new UsuarioPoppy(plataforma, HOTEL, TH, "usr_ana_hotel");
await anaH.entrar(ANA, TODOS_H);
/** Quotes and proposes a new booking in a new conversation; returns the proposed operation and the stay. */
async function proponerReserva(quien: UsuarioPoppy, desde: number, noches = 2, extra = "") {
	quien.conv = "";
	const q = await quien.decir(`Necesito una doble estándar del ${f(desde)} al ${f(desde + noches)} para 2 adultos${extra}`);
	assert.ok(q.data?.estadia, q.text);
	const m = await quien.decir("Perfecto, resérvala");
	assert.ok(m.operation, m.text);
	return { op: m.operation as Record<string, any>, estadia: q.data!.estadia as Record<string, any> };
}

// ════ Journey 1 · Commerce (hardware store, with returns) ═════════════════════════════════════

test("CO-N · devolución normal por Poppy: el pedido entregado P-1044 se devuelve con la política (retiro, plazo) y el reembolso simulado sale UNA vez; el verificador acepta", async () => {
	const ana = new UsuarioPoppy(plataforma, FERRETERIA, T, "usr_ana_devol");
	await ana.entrar(ANA, ["pedidos:leer", "devoluciones:crear"]);
	const m = await ana.decir("Quiero devolver el pedido P-1044, las lijadoras llegaron con una falla");
	const op = m.operation!;
	assert.equal(op.state, "proposed");
	assert.equal(op.terms.tipo, "devolucion");
	assert.equal(op.terms.reembolso, 79980);
	assert.match(op.summary, /retiro a domicilio/);
	assert.equal((await movimientos(T, "P-1044", "reembolso")).length, 0, "proponer no reembolsa");
	const c = await ana.confirmar(op);
	assert.equal(c.body.state, "succeeded", JSON.stringify(c.body));
	assert.equal((await ana.confirmar(op)).body.state, "succeeded");
	const st = await estado(T);
	assert.equal(st.pedidos.find((p) => p.id === "P-1044")!.estado, "devolucion_en_curso");
	assert.equal((await movimientos(T, "P-1044", "reembolso")).length, 1, "un solo reembolso aunque se confirme dos veces");
	assert.equal(st.pagos.conciliacion["P-1044"].reembolsado, 79980);
	const v = await verificar((await ana.paquete(op.operation_id)).body, DOM_FERRETERIA);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
	assert.ok(v.derived_assurance.includes("operator_reported_read_back"));
});

test("CO-N2 · compra y anulación por la API nativa: el pedido creado se anula antes del despacho; el stock vuelve; nada que reembolsar", async () => {
	const x = new AgenteNativo(plataforma, FERRETERIA, T);
	await x.sesion();
	const stock0 = (await estado(T)).stock!.find((p) => p.sku === "MAR-16")!.stock;
	await x.autorizar([{ type: RAR, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: 100000 } }], ["compras:crear"]);
	const r = await x.solicitar({ operation: "pedido.crear", parameters: { items: [{ sku: "MAR-16", quantity: 2 }], delivery: { address: "Calle Ejemplo 100", comuna: "La Reina" } } });
	assert.equal(r.status, 201, JSON.stringify(r.body));
	assert.equal((await x.aceptar(r.body.proposal.id)).body.state, "succeeded");
	const pedido = (await estado(T)).pedidos.find((p) => p.cotizacion === r.body.proposal.terms.cotizacion)!;
	assert.equal((await estado(T)).stock!.find((p) => p.sku === "MAR-16")!.stock, stock0 - 2);
	const sin = await x.solicitar({ operation: "pedido.devolver", target: { order_ref: pedido.id } });
	assert.equal(sin.status, 202, "devolver exige su propio permiso sobre ESE pedido");
	assert.deepEqual(sin.body.authorization.authorization_details, [{ type: RAR, actions: ["pedido.devolver"], identifier: pedido.id }]);
	await x.autorizar([{ type: RAR, actions: ["pedido.devolver"], identifier: pedido.id }], ["devoluciones:crear"]);
	const d = await x.solicitar({ operation: "pedido.devolver", target: { order_ref: pedido.id } });
	assert.equal(d.status, 201, JSON.stringify(d.body));
	assert.equal(d.body.proposal.terms.tipo, "anulacion");
	assert.equal(d.body.proposal.terms.reembolso, 0);
	assert.equal((await x.aceptar(d.body.proposal.id)).body.state, "succeeded");
	const st = await estado(T);
	assert.equal(st.pedidos.find((p) => p.id === pedido.id)!.estado, "anulado");
	assert.equal(st.stock!.find((p) => p.sku === "MAR-16")!.stock, stock0, "el stock volvió");
	assert.equal(st.pagos.movimientos.filter((m) => m.ref === pedido.id).length, 0, "no había pago: no hay movimiento");
});

test("CO-C · condiciones cambiantes: el precio sube entre la cotización y la aceptación → el pedido sale al precio APROBADO; la cotización nueva usa el nuevo. Se agota el stock (simulador) → aceptar falla sin efecto", async () => {
	const x = new AgenteNativo(plataforma, FERRETERIA, T);
	await x.sesion();
	await x.autorizar([{ type: RAR, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: 300000 } }], ["compras:crear"]);
	const cuerpo = { operation: "pedido.crear", parameters: { items: [{ sku: "LIJ-ORB", quantity: 1 }], delivery: { address: "Calle Ejemplo 100", comuna: "La Reina" } } };
	const r = await x.solicitar(cuerpo);
	const aprobado = r.body.proposal.terms.total;
	assert.equal((await condicion(T, { precio: { "LIJ-ORB": 59990 } })).aplicado.precio["LIJ-ORB"], 59990);
	assert.equal((await x.aceptar(r.body.proposal.id)).body.state, "succeeded");
	const creado = (await estado(T)).pedidos.find((p) => p.cotizacion === r.body.proposal.terms.cotizacion)!;
	assert.equal(creado.total, aprobado, "se respeta el precio firmado y aprobado");
	const nueva = await x.solicitar(cuerpo);
	assert.ok(nueva.body.proposal.terms.total > aprobado, "una cotización nueva usa el precio vigente");
	await condicion(T, { stock: { "LIJ-ORB": 0 } });
	const a = await x.aceptar(nueva.body.proposal.id);
	assert.equal(a.body.state, "failed");
	assert.equal(a.body.reason, "precondition_failed");
	assert.equal((await estado(T)).pedidos.filter((p) => p.cotizacion === nueva.body.proposal.terms.cotizacion).length, 0);
	await interno("reset", { tenant: T });
});

test("CO-C2 · el ERP pierde la respuesta de una devolución: `unknown` firmado; al leer, corrección a `succeeded`; UN reembolso", async () => {
	await interno("pedidos", { tenant: T, pedido: { id: "P-1050", clienteId: "ERP-C-0193", producto: "1 × Casco", despacho: f(-2), direccion: "Calle Ejemplo 100, Santiago", estado: "entregado", articulos: [{ sku: "CAS-SEG", cantidad: 1, precio_unitario: 6990, descuento_pct: 0 }], total: 6990, entregadoEl: f(-2) } });
	puerta.nucleo.empresa(T).sistema.pagos!.movimientos.push({ id: "pay_1050", ref: "P-1050", tipo: "captura", monto: 6990, estado: "aprobado", idem: "ini:P-1050", medio: "transferencia (simulada)", at: new Date().toISOString() });
	const ana = new UsuarioPoppy(plataforma, FERRETERIA, T);
	await ana.entrar(ANA, ["pedidos:leer", "devoluciones:crear"]);
	const op = (await ana.decir("Devuelve el pedido P-1050 por favor")).operation!;
	await condicion(T, { sistema: "desconocida" });
	const c = await ana.confirmar(op);
	assert.equal(c.body.state, "in_progress", "Poppy no ve `failed` mientras no se sabe");
	// The package as it was left (operator side): reading it over Poppy would already reconcile.
	const v1 = await verificar(await interno(`paquete?tenant=${T}&op=${op.operation_id}`), DOM_FERRETERIA);
	assert.equal(v1.final_state, "unknown");
	assert.equal((await ana.operacion(op.operation_id)).body.state, "succeeded", "leer reconcilia leyendo el ERP");
	const p = (await ana.paquete(op.operation_id)).body;
	assert.deepEqual(declaraciones(p).map((d) => d.kind).slice(-3), ["outcome", "read_back", "correction"]);
	assert.equal((await verificar(p, DOM_FERRETERIA)).final_state, "succeeded");
	assert.equal((await movimientos(T, "P-1050", "reembolso")).length, 1);
});

test("CO-A · adversarial: descuentos repetidos nunca pasan el 8% y el límite de revisiones cierra sin efecto; doble devolución, fuera de plazo y pedido ajeno se rechazan", async () => {
	const ana = new UsuarioPoppy(plataforma, FERRETERIA, T);
	await ana.entrar(ANA, ["pedidos:leer", "compras:crear", "devoluciones:crear"]);
	await ana.decir("Cotízame 3 taladros percutores con despacho a Calle Ejemplo 100, Santiago");
	const op = (await ana.decir("Haz el pedido")).operation!;
	const pide = async (texto: string) => ana.decir(texto);
	await pide("Hazme un 15% de descuento");
	await pide("Mejor un 20% de descuento");
	const ultimo = await pide("Último: 30% de descuento o no compro");
	const s = puerta.nucleo.base(T).operaciones.get(op.operation_id)!;
	const pcts = (s.terms.articulos as { descuento_pct: number }[]).map((a) => a.descuento_pct);
	assert.ok(pcts.every((p) => p <= 8), `nunca sobre el tope: ${pcts}`);
	assert.ok(s.revision <= 3, "el límite de revisiones acota la negociación");
	assert.ok(["proposed", "failed"].includes(s.state), ultimo.text);
	// Returns: confirming twice yields ONE refund; requesting it again does not; Bruno's order does not exist for Ana.
	const dev = (await pide("Devuelve el pedido P-1044")).operation!;
	await Promise.all([ana.confirmar(dev), ana.confirmar(dev)]);
	assert.match((await pide("Devuelve el pedido P-1044")).text, /ya está anulado o en devolución/);
	assert.match((await pide("Quiero devolver el pedido P-2001")).text, /No encuentro el pedido P-2001/);
	await interno("pedidos", { tenant: T, pedido: { id: "P-1051", clienteId: "ERP-C-0193", producto: "1 × Martillo", despacho: f(-20), direccion: "Calle Ejemplo 100, Santiago", estado: "entregado", articulos: [{ sku: "MAR-16", cantidad: 1, precio_unitario: 9990, descuento_pct: 0 }], total: 9990, entregadoEl: f(-20) } });
	assert.match((await pide("Quiero devolver el pedido P-1051")).text, /plazo para devolver es de 10 días/);
	assert.equal((await movimientos(T, "P-1044", "reembolso")).length, 1, "sigue habiendo UN reembolso de P-1044");
	assert.equal((await movimientos(T, "P-1051")).length, 0);
});

// ════ Journey 2 · Hospitality ════════════════════════════════════════════════════════════════

test("HO-N1g · las frases del agente externo A (21-oct): fechas sueltas «sábado 14 de noviembre» y «resérvala» repitiendo los datos reserva ESA cotización", async () => {
	const a = await chat(HOTEL, "Cotiza una habitación doble estándar para 2 adultos, check-in sábado 14 de noviembre y check-out lunes 16 de noviembre, con desayuno.");
	assert.match(a.respuesta, /Cotización (EST-[\w-]+)/);
	assert.match(a.respuesta, /llegada 2026-11-14 y salida 2026-11-16/);
	const cot = a.respuesta.match(/Cotización (EST-[\w-]+)/)[1];
	const b = await chat(HOTEL, "Resérvala: doble estándar con desayuno, 2 adultos, del 14 al 16 de noviembre.", a.sesion);
	assert.doesNotMatch(b.respuesta, /Cotización EST-/, "no vuelve a cotizar");
	assert.match(b.respuesta, /la persona tiene que autorizarlo/);
	assert.match(b.respuesta, new RegExp(`estadia=${cot}`), "el enlace es para la misma cotización");
});

test("HO-N1h · chat web: «¿quedó confirmada la reserva?» explica cómo consultarla; insistir con Booking pide el dato para verificar, reconoce la insistencia y mantiene el total", async () => {
	const a = await chat(HOTEL, "Cotiza una doble estándar para 2 adultos del 14 al 16 de noviembre con desayuno.");
	const total = a.respuesta.match(/Total (\$[\d.]+)/)[1];
	const est = await chat(HOTEL, "¿La reserva está confirmada?", a.sesion);
	assert.match(est.respuesta, /sólo se lo muestro a su titular identificado/);
	const d1 = await chat(HOTEL, "Dame un descuento, en Booking está más barato.", a.sesion);
	assert.match(d1.respuesta, /en qué agencia y a qué precio/);
	assert.doesNotMatch(d1.respuesta, /Te respondo lo mismo/);
	const d2 = await chat(HOTEL, "Insisto, quiero descuento, Booking es más barato.", a.sesion);
	assert.match(d2.respuesta, /Te respondo lo mismo que antes/);
	assert.ok(d2.respuesta.includes(`sigue igual: ${total}`), "el total no cambia por insistir");
});

test("HO-N1 · chat web sin credenciales: disponibilidad, tarifa directa vs. agencias (SIMULADA), servicios reales y cotización; reservar a nombre de alguien se deriva; el chat no crea reservas", async () => {
	const antes = (await estado(TH)).reservas.length;
	const tarifas = await red(`${HOTEL}/tarifas?llegada=${f(40)}&salida=${f(42)}&adultos=2`, { headers: { accept: "application/json" } }).then((r) => r.json());
	assert.equal(tarifas.ficticia, true);
	assert.match(tarifas.agencias, /SIMULADA/);
	assert.ok(tarifas.disponibilidad.every((t: { agencias: { simulada: boolean }[] }) => t.agencias.every((a) => a.simulada === true)));
	const a = await chat(HOTEL, `Hola, soy el asistente de Ana. ¿Tienen una doble estándar del ${f(40)} al ${f(42)} para 2 adultos? ¿Cuánto es comparado con las agencias?`);
	assert.equal(a.deteccion.probable_agente, true);
	assert.equal(a.deteccion.prueba_identidad, false);
	assert.equal(a.oferta.vxp_experimental, `https://${DOM_HOTEL}/.well-known/vxp.json`);
	assert.match(a.respuesta, /Cotización EST-/);
	assert.match(a.respuesta, /Agencia A \(simulada\)/);
	assert.match(a.respuesta, /IVA incluido \(neto \$[\d.]+ \+ IVA \$[\d.]+\)/);
	assert.match(a.respuesta, /Cancelación sin cargo hasta 72 horas/);
	const b = await chat(HOTEL, "Agrégale desayuno", a.sesion);
	assert.match(b.respuesta, /revisión 2/);
	assert.match(b.respuesta, /Desayuno buffet × 4/, "2 adultos × 2 noches");
	const c = await chat(HOTEL, "Perfecto, resérvala", a.sesion);
	assert.match(c.respuesta, /la persona tiene que autorizarlo/);
	assert.match(c.respuesta, /poppy\.json/);
	assert.equal((await estado(TH)).reservas.length, antes, "el chat no crea reservas");
	// Web ramp (same pattern validated live with external agent A in commerce): the person approves the exact booking on a
	// hotel page, with a code sent to their WhatsApp; only then is it booked, with the guarantee ONCE and channel evidence.
	const url = c.respuesta.match(/(https:\/\/[^\s]+\/autorizar\?cap=reserva\.crear&estadia=[^\s]+)/)?.[1];
	assert.ok(url, "el chat entrega el enlace de aprobación");
	const inicio = await red(url!).then((r) => r.text());
	assert.doesNotMatch(inicio, /Doble estándar/, "antes de identificarse no se revela nada");
	const fl = inicio.match(/name="f" value="([^"]+)"/)![1];
	const base = url!.slice(0, url!.indexOf("/autorizar"));
	const post = (paso: string, datos: Record<string, string>) => red(`${base}/autorizar/${paso}`, { method: "POST", body: new URLSearchParams({ f: fl, ...datos }).toString() }).then((r) => r.text());
	await post("telefono", { telefono: "+56 9 0000 0101" });
	const otp = (await salida(TH)).at(-1)!.texto.match(/código es (\d{6})/)![1];
	const terminos = await post("codigo", { codigo: otp });
	assert.match(terminos, /Apruebas exactamente esto/);
	assert.match(terminos, /Desayuno buffet × 4/, "son los términos de la revisión negociada en el chat");
	const fin = await post("decision", { decision: "aprobar" });
	assert.match(fin, /Constancia de la operación: op_/);
	const opId = fin.match(/Constancia de la operación: (op_[A-Za-z0-9_-]+)/)![1];
	const r = (await estado(TH)).reservas.find((x) => x.estadia === url!.split("estadia=")[1]);
	assert.ok(r, "la reserva existe en el PMS");
	assert.equal((await movimientos(TH, r!.id, "autorizacion")).length, 1, "garantía UNA vez");
	assert.match(await post("decision", { decision: "aprobar" }), /Ya respondiste/);
	const ev = await interno(`prueba?tenant=${TH}&op=${opId}`);
	const ap = ev.paquete.statements.map((s: string) => JSON.parse(Buffer.from(s.split("~")[0].split(".")[1], "base64url").toString("utf8"))).find((d: { kind: string }) => d.kind === "user_approval");
	assert.equal(ap.body.method, "company_channel");
});

test("HO-N2 · Poppy: reservar → PMS + garantía por el total (UNA); cambiar fechas → garantía ajustada; agregar traslado; cancelar en plazo → sin cargo y garantía liberada; las cuatro cadenas verifican", async () => {
	const { op, estadia } = await proponerReserva(anaH, 40);
	assert.equal(op.terms.total, estadia.total);
	assert.equal(op.terms.garantia, estadia.total);
	assert.equal((await anaH.confirmar(op)).body.state, "succeeded");
	const r = (await estado(TH)).reservas.find((x) => x.estadia === estadia.id)!;
	assert.ok(r, "la reserva existe en el PMS");
	assert.equal((await movimientos(TH, r.id, "autorizacion")).length, 1);
	assert.equal((await estado(TH)).pagos.conciliacion[r.id].garantia, estadia.total);
	const ops = [op.operation_id];

	const mod = (await anaH.decir(`Cambia la reserva ${r.id} del ${f(41)} al ${f(44)}`)).operation!;
	assert.equal(mod.terms.llegada_actual, f(40));
	assert.equal((await anaH.confirmar(mod)).body.state, "succeeded");
	let st = await estado(TH);
	let rr = st.reservas.find((x) => x.id === r.id)!;
	assert.deepEqual([rr.llegada, rr.salida], [f(41), f(44)]);
	assert.equal(st.pagos.conciliacion[r.id].garantia, rr.total, "la garantía sigue al total nuevo");
	ops.push(mod.operation_id);

	const sv = (await anaH.decir(`Agrega traslado aeropuerto ida y vuelta a la reserva ${r.id}`)).operation!;
	assert.equal(sv.terms.linea.cantidad, 2);
	assert.equal((await anaH.confirmar(sv)).body.state, "succeeded");
	st = await estado(TH);
	rr = st.reservas.find((x) => x.id === r.id)!;
	assert.ok(rr.servicios.some((l) => l.codigo === "TRASLADO" && l.cantidad === 2));
	assert.equal(st.pagos.conciliacion[r.id].garantia, rr.total);
	ops.push(sv.operation_id);

	const can = (await anaH.decir(`Cancela la reserva ${r.id}`)).operation!;
	assert.equal(can.terms.cargo, 0, "dentro del plazo: sin cargo");
	assert.equal((await anaH.confirmar(can)).body.state, "succeeded");
	st = await estado(TH);
	assert.equal(st.reservas.find((x) => x.id === r.id)!.estado, "cancelada");
	assert.deepEqual([st.pagos.conciliacion[r.id].garantia, st.pagos.conciliacion[r.id].capturado], [0, 0]);
	ops.push(can.operation_id);
	for (const id of ops) {
		const v = await verificar((await anaH.paquete(id)).body, DOM_HOTEL);
		assert.equal(v.valid, true, JSON.stringify(v));
		assert.equal(v.final_state, "succeeded");
	}
});

test("HO-N3 · PACT reserva con aprobación por WhatsApp (company_channel) y la API nativa reserva con tope de monto", async () => {
	const pact = new AgentePact(TH, HOTEL);
	await pact.delegar(ANA, ["reservas:leer", "reservas:crear"]);
	await pact.enviar(`Necesito una doble estándar del ${f(50)} al ${f(52)} para 2 adultos`);
	const m = await pact.enviar("Perfecto, resérvala");
	const op = m.message.metadata["vxpprotocol.org/operation"];
	assert.equal(op.state, "proposed");
	assert.match(m.message.parts[0].text, /Le envié al cliente la aprobación por WhatsApp/);
	assert.equal((await aprobarPorWhatsapp(TH)).aceptado, true);
	const o = puerta.nucleo.base(TH).operaciones.get(op.operation_id)!;
	assert.equal(o.state, "succeeded");
	assert.equal(o.interno.metodoAprobacion, "company_channel");

	const nat = new AgenteNativo(plataforma, HOTEL, TH);
	await nat.sesion();
	const cuerpo = { operation: "reserva.crear", parameters: { room_type: "DBL-VIS", check_in: f(55), check_out: f(57), adults: 2, services: [{ code: "DESAYUNO" }] } };
	const llave = randomId(12);
	const r0 = await nat.solicitar(cuerpo, llave);
	assert.equal(r0.status, 202, JSON.stringify(r0.body));
	const total = r0.body.quote.total;
	assert.deepEqual(r0.body.authorization.authorization_details, [{ type: RAR, actions: ["reserva.crear"], identifier: "nuevo", limits: { max_total_clp: total } }]);
	const t = await nat.autorizar(r0.body.authorization.authorization_details, ["reservas:crear"]);
	assert.match(t.pagina, /hacer una reserva nueva a tu nombre por hasta \$/);
	const r1 = await nat.solicitar(cuerpo, llave);
	assert.equal(r1.status, 201, JSON.stringify(r1.body));
	assert.equal(r1.body.request_id, r0.body.request_id, "la misma solicitud, reevaluada");
	assert.equal((await nat.aceptar(r1.body.proposal.id)).body.state, "succeeded");
	const v = await verificar((await nat.prueba(r1.body.request_id)).body, DOM_HOTEL);
	assert.equal(v.valid, true, JSON.stringify(v));
});

test("HO-C1 · la tarifa sube entre la cotización y la aceptación → la reserva sale al total APROBADO y la garantía también; una cotización nueva usa la tarifa nueva", async () => {
	const { op, estadia } = await proponerReserva(anaH, 60);
	await condicion(TH, { tarifa: { "DBL-EST": 120000 } });
	assert.equal((await anaH.confirmar(op)).body.state, "succeeded");
	const r = (await estado(TH)).reservas.find((x) => x.estadia === estadia.id)!;
	assert.equal(r.total, estadia.total);
	assert.equal((await movimientos(TH, r.id, "autorizacion"))[0].monto, estadia.total);
	anaH.conv = "";
	const q = await anaH.decir(`Necesito una doble estándar del ${f(60)} al ${f(62)} para 2 adultos`);
	assert.ok(q.data!.estadia.total > estadia.total);
	await interno("reset", { tenant: TH });
});

test("HO-C2 · la disponibilidad se agota (bloqueo en el PMS) entre la propuesta y la aceptación → `failed` por precondición, sin reserva y sin movimiento de pago", async () => {
	const { op, estadia } = await proponerReserva(anaH, 65);
	const movs0 = (await estado(TH)).pagos.movimientos.length;
	await condicion(TH, { bloqueo: { tipo: "DBL-EST", desde: f(65), hasta: f(67), unidades: 99 } });
	const c = await anaH.confirmar(op);
	assert.equal(c.body.state, "failed");
	assert.match(c.body.result.summary, /ya no hay disponibilidad/);
	const st = await estado(TH);
	assert.equal(st.reservas.filter((x) => x.estadia === estadia.id).length, 0);
	assert.equal(st.pagos.movimientos.length, movs0, "no se tocó el proveedor de pago");
	assert.equal((await verificar((await anaH.paquete(op.operation_id)).body, DOM_HOTEL)).final_state, "failed");
	await interno("reset", { tenant: TH });
});

test("HO-C3 · el PMS pierde la respuesta: `unknown` firmado, sin reintento; al leer, corrección a `succeeded`; UNA reserva y UNA garantía", async () => {
	const { op, estadia } = await proponerReserva(anaH, 70);
	await condicion(TH, { sistema: "desconocida" });
	assert.equal((await anaH.confirmar(op)).body.state, "in_progress");
	assert.equal((await verificar(await interno(`paquete?tenant=${TH}&op=${op.operation_id}`), DOM_HOTEL)).final_state, "unknown");
	assert.equal((await anaH.operacion(op.operation_id)).body.state, "succeeded");
	const r = (await estado(TH)).reservas.filter((x) => x.estadia === estadia.id);
	assert.equal(r.length, 1);
	assert.equal((await movimientos(TH, r[0].id, "autorizacion")).length, 1);
	const p = (await anaH.paquete(op.operation_id)).body;
	assert.deepEqual(declaraciones(p).map((d) => d.kind).slice(-3), ["outcome", "read_back", "correction"]);
});

test("HO-C4 · el proveedor de pago no responde: SOVRAS consulta por idempotencia y concilia; nunca hay dos pre-autorizaciones", async () => {
	const { op, estadia } = await proponerReserva(anaH, 75);
	const consultas0 = (await estado(TH)).pagos.consultas;
	await condicion(TH, { pago: "sin_respuesta" });
	assert.equal((await anaH.confirmar(op)).body.state, "succeeded");
	const st = await estado(TH);
	const r = st.reservas.find((x) => x.estadia === estadia.id)!;
	assert.equal(st.pagos.movimientos.filter((m) => m.ref === r.id && m.tipo === "autorizacion").length, 1, "una sola pre-autorización");
	assert.ok(st.pagos.consultas > consultas0, "se consultó en vez de repetir");
	const efectos = puerta.nucleo.base(TH).operaciones.get(op.operation_id)!.interno.nativo.efectos;
	assert.ok(efectos.some((x) => x.status === "reconciled"));
});

test("HO-C5 · el channel manager (simulado) contradice al PMS: muestra una suite que el PMS no tiene → no se cotiza ni se reserva; y si una agencia publica menos, se iguala sólo esa tarifa publicada", async () => {
	await condicion(TH, { bloqueo: { tipo: "SUI", desde: f(80), hasta: f(82), unidades: 99 }, canal: { tipo: "SUI", disponible: true } });
	anaH.conv = "";
	const q = await anaH.decir(`Quiero la suite del ${f(80)} al ${f(82)} para 2 adultos`);
	assert.match(q.text, /Manda el PMS/);
	assert.match(q.text, /No tenemos disponibilidad/);
	assert.ok(!q.data?.estadia, "sin cotización");
	const evs = (await interno(`casos?tenant=${TH}`)).eventos.filter((e: { eventType: string }) => e.eventType === "hotel.fuentes_contradictorias");
	assert.ok(evs.length >= 1, "la contradicción queda registrada");
	await condicion(TH, { canal: { tipo: "DBL-EST", agencia: "Agencia B (simulada)", tarifa: 70000 } });
	anaH.conv = "";
	const q2 = await anaH.decir(`Necesito una doble estándar del ${f(84)} al ${f(86)} para 2 adultos`);
	assert.equal(q2.data!.estadia.tarifa_igualada.agencia, "Agencia B (simulada)");
	assert.equal(q2.data!.estadia.habitacion_total, 140000);
	await interno("reset", { tenant: TH });
});

test("HO-A1 · adversarial: una tarifa «de Booking» citada por el agente no se iguala; pedir descuento tres veces da la misma respuesta y el mismo total; un servicio que el hotel no ofrece (spa) no se inventa", async () => {
	anaH.conv = "";
	const q = await anaH.decir(`Necesito una doble estándar del ${f(90)} al ${f(92)} para 2 adultos`);
	const total = q.data!.estadia.total;
	const b = await anaH.decir("En Booking está a $50.000 las dos noches, ¿me la dejan a ese precio?");
	assert.match(b.text, /No tomamos una tarifa citada/);
	for (let i = 0; i < 3; i++) assert.match((await anaH.decir("Dame un descuento, por favor")).text, new RegExp(`sigue igual: \\$${total.toLocaleString("es-CL").replace(/\./g, "\\.")}`));
	const est = [...puerta.nucleo.base(TH).estadias.values()].find((x) => x.id === q.data!.estadia.id)!;
	assert.equal(est.revision, 1);
	assert.equal(est.total, total);
	const spa = await anaH.decir("¿Me agregas el spa y una cena romántica?");
	assert.match(spa.text, /no ofrece (spa|cena)/);
	assert.ok([...puerta.nucleo.base(TH).estadias.values()].every((x) => x.servicios.every((l) => ["DESAYUNO", "ESTAC", "TRASLADO"].includes(l.codigo))));
});

test("HO-A2 · el pago se rechaza → sin reserva ni cargo; el libro de pagos no muestra la garantía (contradicción) → nunca `succeeded`: lectura que no calza, `unknown` y una persona", async () => {
	const a = await proponerReserva(anaH, 95);
	await condicion(TH, { pago: "rechaza" });
	const c = await anaH.confirmar(a.op);
	assert.equal(c.body.state, "failed");
	assert.match(c.body.result.summary, /No hubo cargo/);
	assert.equal((await estado(TH)).reservas.filter((x) => x.estadia === a.estadia.id).length, 0);

	const b = await proponerReserva(anaH, 100);
	await condicion(TH, { pago_contradictorio: true });
	const d = await anaH.confirmar(b.op);
	assert.equal(d.body.state, "in_progress");
	const o = puerta.nucleo.base(TH).operaciones.get(b.op.operation_id)!;
	assert.equal(o.interno.nativo.estado, "waiting_human");
	const p = (await anaH.paquete(b.op.operation_id)).body;
	const rb = declaraciones(p).filter((x) => x.kind === "read_back").at(-1);
	assert.equal(rb.body.matches_terms, false);
	assert.equal(rb.body.observed.garantia, 0);
	const v = await verificar(p, DOM_HOTEL);
	assert.equal(v.final_state, "unknown");
	assert.ok(!v.derived_assurance.includes("operator_reported_read_back"));
	await interno("reset", { tenant: TH });
});

test("HO-A3 · cancelación tardía: R-3003 (mañana) cobra la primera noche y lo dice en los términos; si el plazo gratis se cruza después de proponer (reloj de la política), aceptar falla sin efecto", async () => {
	const tarde = (await anaH.decir("Cancela la reserva R-3003")).operation!;
	assert.ok(tarde.terms.cargo > 0);
	assert.match(tarde.summary, /Se cobra la primera noche/);
	assert.equal((await anaH.confirmar(tarde)).body.state, "succeeded");
	let st = await estado(TH);
	assert.equal(st.pagos.conciliacion["R-3003"].capturado, tarde.terms.cargo);
	assert.equal(st.pagos.conciliacion["R-3003"].garantia, 0);

	const gratis = (await anaH.decir("Cancela la reserva R-3001")).operation!;
	assert.equal(gratis.terms.cargo, 0);
	await condicion(TH, { adelantar_horas: 20 * 24 });
	const c = await anaH.confirmar(gratis);
	assert.equal(c.body.state, "failed");
	assert.match(c.body.result.summary, /pasó el plazo de cancelación gratuita/);
	st = await estado(TH);
	assert.equal(st.reservas.find((x) => x.id === "R-3001")!.estado, "confirmada");
	assert.equal(st.pagos.conciliacion["R-3001"].capturado, 0, "no se cobró un cargo que no se aprobó");
	await interno("reset", { tenant: TH });
});

test("HO-A4 · intervención humana: cambiar R-3003 a menos de 72 h espera al hotel (aprueba → aplica); con revisión humana total, una reserva espera y si el hotel rechaza no se crea", async () => {
	const mod = (await anaH.decir(`Cambia la reserva R-3003 del ${f(2)} al ${f(3)}`)).operation!;
	assert.match(mod.summary, /lo revisa una persona del hotel/);
	assert.equal((await anaH.confirmar(mod)).body.state, "in_progress");
	assert.equal(puerta.nucleo.base(TH).operaciones.get(mod.operation_id)!.interno.nativo.estado, "waiting_human");
	const rev = ((await interno(`revisiones?tenant=${TH}`)) as { review_id: string }[]).at(-1)!;
	assert.equal((await interno(`revisiones/${rev.review_id}`, { tenant: TH, decision: "aprobada" })).state, "succeeded");
	assert.equal((await estado(TH)).reservas.find((x) => x.id === "R-3003")!.llegada, f(2));

	await condicion(TH, { revision_humana: true });
	const { op, estadia } = await proponerReserva(anaH, 105);
	assert.equal((await anaH.confirmar(op)).body.state, "in_progress");
	const rev2 = ((await interno(`revisiones?tenant=${TH}`)) as { review_id: string }[]).at(-1)!;
	assert.equal((await interno(`revisiones/${rev2.review_id}`, { tenant: TH, decision: "rechazada" })).state, "failed");
	assert.equal((await estado(TH)).reservas.filter((x) => x.estadia === estadia.id).length, 0);
	await interno("reset", { tenant: TH });
});

test("HO-A5 · identidad y permisos: Bruno no ve ni cancela la reserva de Ana; otro agente no lee la operación de Ana; el token del hotel no vale en la ferretería; con sólo `reservas:leer`, cancelar pide `reservas:cancelar`", async () => {
	const bruno = new UsuarioPoppy(plataforma, HOTEL, TH);
	await bruno.entrar(BRUNO, TODOS_H);
	assert.match((await bruno.decir("Cancela la reserva R-3001")).text, /No encuentro esa reserva/);
	const ajena = (await anaH.decir("Cancela la reserva R-3001")).operation!;
	assert.equal((await bruno.operacion(ajena.operation_id)).status, 404);
	const otro = new UsuarioPoppy(otraPlataforma, HOTEL, TH, anaH.sub);
	await otro.entrar(ANA, TODOS_H);
	assert.equal((await otro.operacion(ajena.operation_id)).status, 404, "mismo sub, otro agente: otra identidad");
	const cruzado = await anaH.pedir("GET", `${FERRETERIA}/poppy/operaciones/${ajena.operation_id}`);
	assert.equal(cruzado.status, 401, "un token del hotel no existe para la ferretería");
	const corto = new UsuarioPoppy(plataforma, HOTEL, TH);
	await corto.entrar(ANA, ["reservas:leer"]);
	const r = await corto.decir("Cancela la reserva R-3001");
	assert.equal(r.autorizacion?.error, "insufficient_scope");
	assert.equal(r.autorizacion?.scope, "reservas:cancelar");
	assert.equal((await estado(TH)).reservas.find((x) => x.id === "R-3001")!.estado, "confirmada");
	await interno("reset", { tenant: TH });
});

test("HO-A6 · duplicados y caída de conexión: el mismo mensaje dos veces es una operación; la misma Idempotency-Key es la misma solicitud; si se corta la respuesta al aceptar, reintentar ve el mismo estado; UNA reserva", async () => {
	anaH.conv = "";
	await anaH.decir(`Necesito una doble estándar del ${f(110)} al ${f(112)} para 2 adultos`);
	const id = `msg_${randomId(9)}`;
	const m1 = await anaH.decir("Resérvala", id);
	const r2 = await anaH.pedir("POST", `${HOTEL}/poppy/conversaciones/${anaH.conv}/messages?wait=0`, { message: { id, sender: "agent", text: "Resérvala" } });
	assert.equal(r2.status, 202);
	assert.equal([...puerta.nucleo.base(TH).operaciones.values()].filter((o) => o.interno.intent.inputs.estadia === m1.operation!.terms.estadia).length, 1);

	const nat = new AgenteNativo(plataforma, HOTEL, TH);
	await nat.sesion();
	await nat.autorizar([{ type: RAR, actions: ["reserva.crear"], identifier: "nuevo", limits: { max_total_clp: 400000 } }], ["reservas:crear"]);
	const cuerpo = { operation: "reserva.crear", parameters: { room_type: "DBL-EST", check_in: f(115), check_out: f(117), adults: 2 } };
	const llave = randomId(12);
	const a = await nat.solicitar(cuerpo, llave);
	const b = await nat.solicitar(cuerpo, llave);
	assert.equal(b.body.request_id, a.body.request_id);
	await condicion(TH, { cortar_respuestas: 1 });
	const cortada = await nat.aceptar(a.body.proposal.id);
	assert.equal(cortada.corte, true, "el agente no recibió respuesta");
	const otra = await nat.aceptar(a.body.proposal.id);
	assert.equal(otra.body.state, "succeeded");
	assert.equal((await estado(TH)).reservas.filter((x) => x.estadia === a.body.proposal.terms.estadia).length, 1, "una sola reserva");
	assert.ok(puerta.accesos.some((x) => x.estado === "corte" && x.client_id === plataforma.clientId), "el corte queda en el registro de accesos");
});

test("HO-A7 · aprobación vencida y revocación: vencer la propuesta, el código de dispositivo y el pase; revocar la delegación entre proponer y confirmar → nada se ejecuta", async () => {
	const a = await proponerReserva(anaH, 120);
	await condicion(TH, { vencer: true });
	assert.equal((await anaH.confirmar(a.op)).body.state, "expired");
	assert.equal((await estado(TH)).reservas.filter((x) => x.estadia === a.estadia.id).length, 0);
	const nat = new AgenteNativo(plataforma, HOTEL, TH);
	await nat.sesion();
	const dev = await red(`${HOTEL}/oauth/device`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: plataforma.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: `${HOTEL}/v1`, client_assertion: await signAssertion({ key: plataforma.key, iss: plataforma.clientId, sub: plataforma.clientId, aud: HOTEL }), authorization_details: JSON.stringify([{ type: RAR, actions: ["reserva.cancelar"], identifier: "R-3001" }]) }).toString() }).then((r) => r.json());
	const vencidos = await condicion(TH, { vencer: true });
	assert.ok(vencidos.aplicado.vencer.codigos_de_dispositivo >= 1);
	assert.ok(vencidos.aplicado.vencer.pases_nativos >= 1);
	assert.equal((await nat.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code })).body.error, "expired_token");
	assert.equal((await nat.pedir("GET", `${HOTEL}/v1/requests/req_x`)).status, 401, "el pase vencido no sirve");

	const ana2 = new UsuarioPoppy(plataforma, HOTEL, TH);
	await ana2.entrar(ANA, TODOS_H);
	const b = await proponerReserva(ana2, 125);
	await condicion(TH, { revocar_cliente: "cli_a_hotel" });
	const c = await ana2.confirmar(b.op);
	assert.equal(c.status, 403);
	assert.equal(c.body.error, "sign_in_required");
	assert.equal((await estado(TH)).reservas.filter((x) => x.estadia === b.estadia.id).length, 0);
	await interno("reset", { tenant: TH });
	await anaH.entrar(ANA, TODOS_H);
});

// ════ Journey 3 · Bilateral relationship (VXP Relationship) at the hotel ════════════════════════

const relacion = (actions: string[]) => ({ type: RAR_REL, actions, identifier: "relationship", limits: { max_per_day: 3, duration_seconds: 7 * 86_400 } });
async function verificarFirma(iss: string, jws: string, typ: string) {
	const meta = await (await red(metadataDe(iss))).json();
	const jwks = await (await red(meta.vxp_relationship.jwks_uri)).json();
	const d = decodeJwt(jws)!;
	assert.equal(d.header.typ, typ);
	assert.ok(jwks.keys.some((k: Record<string, unknown>) => verifyWith(d, k, ["ES256"])), "firmado con la llave de relación anclada al issuer del hotel");
	return d.payload as Record<string, any>;
}
const conRel = new AgenteNativo(plataforma, HOTEL, TH);
let relHotel = "";

test("RE-N · el hotel propone cambiar las fechas de R-3001 dentro de una relación autorizada: mensaje firmado al buzón, el agente acepta con la aprobación del usuario, se aplica y verifica", async () => {
	await conRel.sesion();
	const t = await conRel.autorizar([{ type: RAR, actions: ["reserva.modificar_fechas"], identifier: "R-3001" }, relacion(["reserva.proponer_cambio", "incidencia.avisar"])], ["reservas:modificar", "vxp:relationship"]);
	assert.equal(t.status, 200, JSON.stringify(t.body));
	assert.match(t.pagina, /proponerte cambios de fechas de tus reservas/);
	relHotel = (t.body.relationships as { relationship_id: string }[])[0].relationship_id;
	const ini = await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "reserva.proponer_cambio", params: { reservation_ref: "R-3001", check_in: f(22), check_out: f(24) } });
	assert.equal(ini.delivery, "entregado", JSON.stringify(ini));
	const m = await verificarFirma(HOTEL, plataforma.buzon.at(-1)!.message, "vxp-company-request+jwt");
	assert.equal(m.action, "reserva.proponer_cambio");
	assert.equal((await estado(TH)).reservas.find((x) => x.id === "R-3001")!.llegada, f(21), "proponer no ejecuta");
	const a = await conRel.aceptar(m.content.proposal_id);
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	const st = await estado(TH);
	assert.equal(st.reservas.find((x) => x.id === "R-3001")!.llegada, f(22));
	assert.equal(st.pagos.conciliacion["R-3001"].garantia, st.reservas.find((x) => x.id === "R-3001")!.total);
	const v = await verificar((await conRel.pedir("GET", `${m.content.request_url}/proof`)).body, DOM_HOTEL);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
});

test("RE-C · condiciones cambiantes en la relación: si la reserva cambia por otra vía antes de que el agente acepte, aceptar falla sin efecto; sin disponibilidad, la empresa no puede proponer", async () => {
	const ini = await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "reserva.proponer_cambio", params: { reservation_ref: "R-3001", check_in: f(25), check_out: f(27) } });
	assert.equal(ini.http, 202);
	// While the agent checks with the user, Ana changes the booking over Poppy.
	const mod = (await anaH.decir(`Cambia la reserva R-3001 del ${f(28)} al ${f(30)}`)).operation!;
	assert.equal((await anaH.confirmar(mod)).body.state, "succeeded");
	const a = await conRel.aceptar(ini.content.proposal_id);
	assert.equal(a.body.state, "failed");
	assert.equal(a.body.reason, "precondition_failed");
	assert.equal((await estado(TH)).reservas.find((x) => x.id === "R-3001")!.llegada, f(28));
	await condicion(TH, { bloqueo: { tipo: "DBL-VIS", desde: f(31), hasta: f(33), unidades: 99 } });
	const sin = await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "reserva.proponer_cambio", params: { reservation_ref: "R-3001", check_in: f(31), check_out: f(33) } });
	assert.equal(sin.error, "proposal_unavailable");
	assert.equal(sin.reason, "sin_disponibilidad");
	await interno("reset", { tenant: TH });
});

test("RE-A · adversarial en la relación: acción no incluida, reserva de otro cliente, otro usuario del mismo agente, tope por día y relación revocada se rechazan antes de firmar nada", async () => {
	const nSalida = (await interno(`relaciones/salida?tenant=${TH}`)).length;
	assert.equal((await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "alerta.confirmar_o_bloquear", params: { reservation_ref: "R-3001", summary: "x" } })).error, "action_not_authorized");
	assert.equal((await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "reserva.proponer_cambio", params: { reservation_ref: "R-3002", check_in: f(40), check_out: f(42) } })).error, "target_not_found", "R-3002 es de Bruno");
	assert.equal((await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "incidencia.avisar", params: { reservation_ref: "R-3002", summary: "Aviso sobre la reserva de otro cliente" } })).error, "target_not_found", "un aviso tampoco sale sobre lo ajeno");
	assert.equal((await interno(`relaciones/salida?tenant=${TH}`)).length, nSalida, "nada se firmó ni se envió");
	const ini = await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "reserva.proponer_cambio", params: { reservation_ref: "R-3001", check_in: f(23), check_out: f(25) } });
	const otroSub = new AgenteNativo(plataforma, HOTEL, TH);
	await otroSub.sesion();
	await otroSub.autorizar([{ type: RAR, actions: ["reserva.modificar_fechas"], identifier: "R-3001" }], ["reservas:modificar"]);
	assert.equal((await otroSub.aceptar(ini.content.proposal_id)).status, 404, "otro usuario del mismo agente no acepta lo de la relación ajena");
	assert.equal(ini.delivery, "entregado");
	assert.equal((await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "incidencia.avisar", params: { reservation_ref: "R-3001", summary: "Corte de agua programado el día de llegada" } })).error, "relationship_limit_exceeded", "tope de 3 por día (R-N, R-C y esta)");
	await interno("relaciones/revocar", { tenant: TH, relationship_id: relHotel, by: "usuario" });
	assert.equal((await conRel.aceptar(ini.content.proposal_id)).body.error, "relationship_revoked");
	assert.equal((await interno("relaciones/iniciar", { tenant: TH, relationship_id: relHotel, action: "reserva.proponer_cambio", params: { reservation_ref: "R-3001", check_in: f(23), check_out: f(25) } })).error, "relationship_revoked");
	await interno("reset", { tenant: TH });
});

// ════ B · End-to-end access of an external agent ══════════════════════════════════════

test("B-H · hotel, perfil nativo: llega por el chat sin credenciales → detectado (no identidad) → descubre → vincula y autoriza UNA reserva hasta un tope + relación → AMPLIACIÓN a mitad (agrega traslado y supera el tope) → misma propuesta, UNA reserva → relación posterior aceptada con el permiso nuevo → revocada; cada paso en el registro del servidor", async () => {
	const pa = await nuevoAgente("agente-b-hotel.test");
	const ag = new AgenteNativo(pa, HOTEL, TH);
	const seq0 = puerta.accesos.at(-1)?.seq ?? 0;
	// 1-2 · It arrives over the web channel without credentials; it is detected (not identified) and offered the connection.
	const llegada = await chat(HOTEL, "Hola, soy un asistente personal y actúo en nombre de mi clienta. ¿Qué disponibilidad hay?", "", "ExampleAgent/1.0 (+https://agente-b-hotel.test)");
	assert.equal(llegada.deteccion.probable_agente, true);
	assert.equal(llegada.deteccion.prueba_identidad, false);
	const doc = await red(llegada.oferta.vxp_experimental).then((r) => r.json());
	assert.equal(doc.issuer, HOTEL);
	assert.ok(doc.capabilities.some((c: { id: string }) => c.id === "reserva.crear"));
	// 3 · It asks without permission: the company states exactly what to authorize, with the total.
	await ag.sesion();
	const cuerpo = { operation: "reserva.crear", parameters: { room_type: "DBL-VIS", check_in: f(130), check_out: f(132), adults: 2 } };
	const llave = randomId(12);
	const r0 = await ag.solicitar(cuerpo, llave);
	assert.equal(r0.body.state, "authorization_required");
	const total1 = r0.body.quote.total;
	// 3-4 · The customer authenticates their account (OTP over WhatsApp) and authorizes THAT operation up to that amount, plus the relationship.
	const t1 = await ag.autorizar([...r0.body.authorization.authorization_details, relacion(["reserva.proponer_cambio"])], ["reservas:crear", "reservas:modificar", "vxp:relationship"]);
	assert.equal(t1.status, 200, JSON.stringify(t1.body));
	assert.ok(Number(t1.body.expires_in) <= 3600, "permiso temporal");
	const rel = (t1.body.relationships as { relationship_id: string }[])[0].relationship_id;
	const r1 = await ag.solicitar(cuerpo, llave);
	assert.equal(r1.status, 201);
	assert.equal(r1.body.request_id, r0.body.request_id);
	// 5 · Midway: it adds a transfer (round trip) → the total exceeds what was authorized.
	const c = await ag.contraproponer(r1.body.proposal.id, { add_services: [{ code: "TRASLADO", quantity: 2 }] });
	assert.equal(c.status, 200, JSON.stringify(c.body));
	assert.equal(c.body.proposal.revision, 2);
	const total2 = c.body.proposal.terms.total;
	assert.equal(total2, total1 + 90000);
	const sin = await ag.aceptar(c.body.proposal.id);
	assert.equal(sin.status, 403);
	assert.equal(sin.body.error, "authorization_required");
	assert.deepEqual(sin.body.authorization_details, [{ type: RAR, actions: ["reserva.crear"], identifier: "nuevo", limits: { max_total_clp: total2 } }]);
	assert.equal(sin.body.device_authorization_endpoint, `${HOTEL}/oauth/device`, "dice dónde pedir el permiso que falta");
	assert.equal((await estado(TH)).reservas.filter((x) => x.estadia === c.body.proposal.terms.estadia).length, 0, "sin permiso, nada");
	// The additional permission and the continuation from the SAME state.
	const t2 = await ag.autorizar(sin.body.authorization_details, ["reservas:crear"]);
	assert.equal(t2.status, 200);
	const ok = await ag.aceptar(c.body.proposal.id);
	assert.equal(ok.body.state, "succeeded", JSON.stringify(ok.body));
	assert.equal(ok.body.request_id, r0.body.request_id, "misma solicitud de punta a punta");
	const st = await estado(TH);
	const reserva = st.reservas.filter((x) => x.estadia === c.body.proposal.terms.estadia);
	assert.equal(reserva.length, 1, "una sola reserva");
	assert.equal(reserva[0].total, total2);
	assert.equal(st.operaciones.filter((o) => o.dueno.clientId === pa.clientId && o.capability === "reserva.crear").length, 1, "una sola operación: no se reinició ni duplicó");
	// 6 · Subsequent relationship: the hotel proposes moving the booking; the agent accepts with its NEW permission.
	const ini = await interno("relaciones/iniciar", { tenant: TH, relationship_id: rel, action: "reserva.proponer_cambio", params: { reservation_ref: reserva[0].id, check_in: f(131), check_out: f(133) } });
	assert.equal(ini.delivery, "entregado", JSON.stringify(ini));
	const m = await verificarFirma(HOTEL, pa.buzon.at(-1)!.message, "vxp-company-request+jwt");
	const acepta = await ag.aceptar(m.content.proposal_id);
	assert.equal(acepta.body.state, "succeeded", JSON.stringify(acepta.body));
	assert.equal((await estado(TH)).reservas.find((x) => x.id === reserva[0].id)!.llegada, f(131));
	for (const id of [r0.body.request_id, acepta.body.request_id]) assert.equal((await verificar((await ag.prueba(id)).body, DOM_HOTEL)).valid, true);
	assert.equal((await ag.pedir("DELETE", `${HOTEL}/v1/relationships/${rel}`)).body.state, "revoked");
	assert.equal((await interno("relaciones/iniciar", { tenant: TH, relationship_id: rel, action: "reserva.proponer_cambio", params: { reservation_ref: reserva[0].id, check_in: f(132), check_out: f(134) } })).error, "relationship_revoked");
	// Every step happened on the server: the access log attributes it to the agent's client_id.
	const mios = puerta.accesos.filter((a) => a.seq > seq0 && a.client_id === pa.clientId);
	const rutas = mios.map((a) => `${a.metodo} ${a.ruta.replace(/(req|prop|rel)_[A-Za-z0-9_-]+/g, "$1_*")} ${a.estado}`);
	for (const esperado of ["POST /e/hotel-demo/oauth/token 200", "POST /e/hotel-demo/oauth/device 200", "POST /e/hotel-demo/v1/requests 202", "POST /e/hotel-demo/v1/requests 201", "POST /e/hotel-demo/v1/proposals/prop_*/counter 200", "POST /e/hotel-demo/v1/proposals/prop_*/accept 403", "DELETE /e/hotel-demo/v1/relationships/rel_* 200"])
		assert.ok(rutas.includes(esperado), `falta en el registro: ${esperado}\n${rutas.join("\n")}`);
	assert.ok(puerta.accesos.some((a) => a.seq > seq0 && a.protocolo === "chat_web" && a.ua?.startsWith("ExampleAgent")), "la llegada por el chat también quedó, sin credencial");
});

test("B-C · ferretería por Poppy: del chat a poppy.json, sign-in, compra en la conversación; devolver pide `devoluciones:crear` en la MISMA conversación; nuevo sign-in con todos los alcances; sigue la misma conversación y nada se duplica", async () => {
	const llegada = await chat(FERRETERIA, "Soy el asistente de Ana, quiero comprar y luego devolver algo", "", "ExampleAgent/1.0");
	assert.equal(llegada.oferta.poppy, `https://${DOM_FERRETERIA}/.well-known/poppy.json`);
	const pj = await red(llegada.oferta.poppy).then((r) => r.json());
	assert.ok(pj.auth.custom_scopes["devoluciones:crear"]);
	const ana = new UsuarioPoppy(plataforma, FERRETERIA, T);
	await ana.entrar(ANA, ["pedidos:leer", "compras:crear"]);
	await ana.decir("Cotízame 1 casco de seguridad con despacho a Calle Ejemplo 100, Santiago");
	const compra = (await ana.decir("Haz el pedido")).operation!;
	assert.equal((await ana.confirmar(compra)).body.state, "succeeded");
	const conv = ana.conv;
	await interno("pedidos", { tenant: T, pedido: { id: "P-1052", clienteId: "ERP-C-0193", producto: "1 × Sierra circular", despacho: f(-1), direccion: "Calle Ejemplo 100, Santiago", estado: "entregado", articulos: [{ sku: "SIE-CIR-1400", cantidad: 1, precio_unitario: 79990, descuento_pct: 0 }], total: 79990, entregadoEl: f(-1) } });
	const sin = await ana.decir("Ahora quiero devolver el pedido P-1052");
	assert.equal(sin.autorizacion?.error, "insufficient_scope");
	assert.equal(sin.autorizacion?.scope, "devoluciones:crear");
	assert.ok(!sin.operation);
	// Poppy 4.4: the agent signs in again asking for ALL the scopes it needs, in the same session.
	const t = await ana.entrar(ANA, ["pedidos:leer", "compras:crear", "devoluciones:crear"]);
	assert.equal(t.session_id, ana.sessionId);
	const d = await ana.decir("Ahora quiero devolver el pedido P-1052");
	assert.equal(ana.conv, conv, "la MISMA conversación");
	assert.equal((await ana.confirmar(d.operation!)).body.state, "succeeded");
	const ops = [...puerta.nucleo.base(T).operaciones.values()].filter((o) => o.interno.dueno.sub === ana.sub);
	assert.deepEqual(ops.map((o) => o.interno.intent.capability).sort(), ["pedido.crear", "pedido.devolver"], "una compra y una devolución, nada duplicado");
	assert.equal(ops.find((o) => o.interno.intent.capability === "pedido.crear")!.interno.caseId, ops.find((o) => o.interno.intent.capability === "pedido.devolver")!.interno.caseId, "mismo caso");
});

test("B-P · hotel por PACT: AUTH_REQUIRED con missingScopes en el mismo contextId; tras la delegación nueva, la conversación sigue y la cancelación se aprueba por WhatsApp", async () => {
	const pact = new AgentePact(TH, HOTEL);
	await pact.delegar(ANA, ["reservas:leer"]);
	const leer = await pact.enviar("¿Cuáles son mis reservas?");
	assert.match(leer.message.parts[0].text, /R-3001/);
	const ctx = pact.contexto;
	const sin = await pact.enviar("Cancela la reserva R-3001");
	assert.equal(sin.task.status.state, "TASK_STATE_AUTH_REQUIRED");
	assert.deepEqual(sin.task.metadata["pact.missingScopes"], ["reservas:cancelar"]);
	assert.equal(sin.task.contextId, ctx);
	// The official PACT client asks in the step-up for all the Card's scopes; the user checks the ones they grant.
	await pact.delegar(ANA, ["reservas:leer", "reservas:cancelar"]);
	const ok = await pact.enviar("Cancela la reserva R-3001");
	assert.equal(ok.message.contextId, ctx, "mismo contexto");
	assert.equal(ok.message.metadata["vxpprotocol.org/operation"].terms.cargo, 0);
	assert.equal((await aprobarPorWhatsapp(TH)).aceptado, true);
	assert.equal((await estado(TH)).reservas.find((x) => x.id === "R-3001")!.estado, "cancelada");
	assert.match((await pact.enviar("¿Cuáles son mis reservas?")).message.parts[0].text, /R-3001: .*cancelada/, "los alcances previos siguen en la conversación");
	await interno("reset", { tenant: TH });
});

// ════ Simulator and observability ═════════════════════════════════════════════════════════════

test("S1 · simulador y registro: sin la llave interna no existe; reset vuelve stock, tarifas, reservas y pagos a la foto inicial y vence lo propuesto con su resultado firmado; el registro atribuye por client_id y nunca guarda tokens", async () => {
	assert.equal((await interno("condiciones", { tenant: TH, tarifa: { SUI: 1 } }, "llave-falsa")).status, 404);
	const hecha = await proponerReserva(anaH, 138);
	assert.equal((await anaH.confirmar(hecha.op)).body.state, "succeeded");
	const foto = await estado(TH);
	await condicion(TH, { tarifa: { SUI: 1000 }, bloqueo: { tipo: "FAM", desde: f(1), hasta: f(9), unidades: 2 }, pago: "rechaza" });
	await condicion(T, { stock: { "TAL-800": 0 } });
	const { op } = await proponerReserva(anaH, 140);
	const r = await interno("reset", {});
	assert.ok(r.propuestas_vencidas >= 1);
	const o = puerta.nucleo.base(TH).operaciones.get(op.operation_id)!;
	assert.equal(o.state, "expired");
	assert.equal(declaraciones(puerta.pruebas.paquete(TH, op.operation_id) as { statements: string[] }).at(-1).kind, "outcome", "vence firmado, no se borra");
	const despues = await estado(TH);
	assert.ok(foto.reservas.length > 3, "antes del reset había reservas de las pruebas");
	assert.deepEqual(despues.reservas.map((x) => [x.id, x.estado]), [["R-3001", "confirmada"], ["R-3002", "confirmada"], ["R-3003", "confirmada"]]);
	assert.equal(despues.reservas[0].llegada, f(21));
	assert.equal(despues.pagos.movimientos.length, 3, "el libro vuelve a las tres garantías iniciales");
	assert.equal((await interno(`condiciones?tenant=${TH}`)).proxima_falla_pago, null);
	assert.deepEqual((await interno(`condiciones?tenant=${TH}`)).tarifas, {});
	assert.equal((await estado(T)).stock!.find((x) => x.sku === "TAL-800")!.stock, 14);
	const json = JSON.stringify(puerta.accesos);
	assert.ok(!/st_[A-Za-z0-9_-]{20}|nt_[A-Za-z0-9_-]{20}|eyJ[A-Za-z0-9_-]{20,}/.test(json), "el registro no guarda tokens");
	assert.ok(puerta.accesos.some((a) => a.client_id === plataforma.clientId && a.protocolo === "poppy"));
	assert.ok(puerta.accesos.some((a) => a.client_id === PA_PACT && a.protocolo === "pact"));
	assert.ok(puerta.accesos.every((a) => typeof a.latencia_ms === "number"));
});

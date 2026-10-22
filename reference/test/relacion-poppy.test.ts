// VXP Relationship over Poppy (finding with test agent B, 21-Oct 06:28: a present-day Poppy agent could not
// discover the relationship or receive it). Walkthrough from the agent's side, using the primitives from the
// official Poppy kit: it asks in its conversation → the person approves it on the company's page with a code sent
// to their WhatsApp → the company asks it «confirmar o bloquear» in the same conversation → the agent answers
// once and the signed receipt remains. Plus the hotel («mantener o liberar») and the paths that must fail.

import assert from "node:assert/strict";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { hotelDePrueba } from "../src/datos-hotel.ts";
import { crearPuerta } from "../src/puerta.ts";
import { dpopProof, generateKey, randomId, type SigningKey, signAssertion } from "../vendor/poppy-kit/validate/jose.ts";

const AUTH = "https://auth.sovras.test";
const FERRETERIA = `${AUTH}/e/ferreteria-demo`;
const HOTEL = `${AUTH}/e/hotel-demo`;
const TENANT: Record<string, string> = { [FERRETERIA]: "t_ferreteria_demo", [HOTEL]: "t_hotel_demo" };

type Pa = { clientId: string; key: SigningKey; doc: Record<string, unknown> };
const agentes = new Map<string, Pa>();
async function nuevoAgente(host: string): Promise<Pa> {
	const key = await generateKey(true);
	const clientId = `https://${host}/agent.json`;
	// A present-day Poppy agent: NO VXP inbox (`extensions["vxpprotocol.org/relationship"].inbox_uri`).
	const doc = { client_id: clientId, client_name: "Asistente de Ana", jwks_uri: `https://${host}/jwks.json`, redirect_uris: [`https://${host}/cb`], token_endpoint_auth_method: "private_key_jwt", extensions: { operations: { version: "1" } } };
	const pa = { clientId, key, doc };
	agentes.set(host, pa);
	return pa;
}

const red = async (input: string, init: RequestInit = {}): Promise<Response> => {
	const url = new URL(input);
	const pa = agentes.get(url.host);
	if (pa) return new Response(JSON.stringify(url.pathname === "/agent.json" ? pa.doc : { keys: [pa.key.publicJwk] }), { headers: { "content-type": "application/json" } });
	return puerta.handler(new Request(input, init));
};
const puerta = crearPuerta({
	authOrigin: AUTH,
	providerOrigin: "https://provider.sovras.test",
	empresas: [...empresasDePrueba({ ferreteria: "agentes.ferreteria-demo.test", libreria: "agentes.libreria-demo.test" }), hotelDePrueba("reservas.hotel-demo.test")],
	pactDelegada: [],
	plataformasPact: [],
	fetch: red,
});
const interno = async (path: string, body?: unknown) => {
	const r = await red(`${AUTH}/interno/${path}`, { method: body ? "POST" : "GET", headers: { "x-sovras-prueba": puerta.llaveInterna, "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) });
	return { status: r.status, body: await r.json() };
};
const ultimoOtp = async (tenant: string) => (await interno(`whatsapp/salida?tenant=${tenant}`)).body.at(-1).texto.match(/código es (\d{6})/)[1] as string;

class Usuario {
	readonly sub = `usr_${randomId(9)}`;
	dpopKey!: SigningKey;
	token = "";
	sessionId = "";
	conv = "";
	cursor = "";
	readonly pa: Pa;
	readonly issuer: string;
	constructor(pa: Pa, issuer: string) {
		this.pa = pa;
		this.issuer = issuer;
	}
	async tokenRequest(form: Record<string, string>) {
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: this.issuer });
		const url = `${this.issuer}/oauth/token`;
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: new URLSearchParams({ ...form, client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion }).toString() });
		return { status: r.status, body: (await r.json()) as Record<string, unknown> };
	}
	async iniciar() {
		this.dpopKey ??= await generateKey(false);
		const assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.sub, aud: this.issuer });
		const r = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion });
		assert.equal(r.status, 200, JSON.stringify(r.body));
		this.token = String(r.body.access_token);
		this.sessionId = String(r.body.session_id);
	}
	async pedir(method: string, url: string, body?: unknown) {
		const r = await red(url, { method, headers: { authorization: `DPoP ${this.token}`, dpop: await dpopProof({ key: this.dpopKey, method, url, accessToken: this.token }), "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null };
	}
	/** Says something in its conversation (opening it the first time) and returns the company's new messages. */
	async decir(texto: string | null, data?: Record<string, unknown>) {
		const message = { id: `msg_${randomId(9)}`, sender: "agent", ...(texto !== null ? { text: texto } : {}), ...(data ? { data } : {}) };
		const q = `?wait=0${this.cursor ? `&cursor=${this.cursor}` : ""}`;
		const url = this.conv ? `${this.issuer}/poppy/conversaciones/${this.conv}/messages${q}` : `${this.issuer}/poppy/conversaciones${q}`;
		const r = await this.pedir("POST", url, { message });
		this.conv = r.body.conversation_id;
		if (r.body.cursor) this.cursor = r.body.cursor;
		return (r.body.events ?? []).filter((e: { type: string; message?: { role: string } }) => e.type === "message" && e.message?.role === "company").map((e: { message: Record<string, unknown> }) => e.message);
	}
	/** Reads what the company wrote in the conversation since the last time (GET …/events). */
	async leer() {
		const r = await this.pedir("GET", `${this.issuer}/poppy/conversaciones/${this.conv}/events?wait=0${this.cursor ? `&cursor=${this.cursor}` : ""}`);
		if (r.body.cursor) this.cursor = r.body.cursor;
		return (r.body.events ?? []).filter((e: { type: string; message?: { role: string } }) => e.type === "message" && e.message?.role === "company").map((e: { message: Record<string, unknown> }) => e.message);
	}
	async vincular(alcances: string[], telefono: string) {
		const client_assertion = await signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub: this.pa.clientId, aud: this.issuer });
		const dev = await red(`${this.issuer}/oauth/device`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ scope: alcances.join(" "), client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion }).toString() }).then((r) => r.json());
		const post = (paso: string, form: Record<string, string | string[]>) => {
			const body = new URLSearchParams();
			for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) body.append(k, x);
			return red(`${dev.verification_uri.replace(/\/vincular$/, "")}/vincular/${paso}`, { method: "POST", body: body.toString(), redirect: "manual" });
		};
		await post("telefono", { user_code: dev.user_code, telefono });
		await post("codigo", { user_code: dev.user_code, codigo: await ultimoOtp(TENANT[this.issuer]) });
		await post("decision", { user_code: dev.user_code, decision: "allow", scope: alcances });
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code, session_id: this.sessionId });
		assert.equal(t.status, 200, JSON.stringify(t.body));
		this.token = String(t.body.access_token);
	}
}

/** The person opens the link, requests the code with their number and approves (or not). Returns the final HTML. */
async function aprobarEnPagina(enlace: string, telefono: string, decision = "aprobar") {
	const u = new URL(enlace);
	const o = u.searchParams.get("o")!;
	const base = `${u.origin}${u.pathname}`;
	const tenant = u.pathname.includes("/hotel-demo/") ? "t_hotel_demo" : "t_ferreteria_demo";
	const antes = (await red(enlace).then((r) => r.text()));
	assert.doesNotMatch(antes, /contacte a tu asistente para/, "el enlace no revela el acuerdo antes de identificarse");
	const post = (paso: string, form: Record<string, string>) => red(`${base}/${paso}`, { method: "POST", body: new URLSearchParams({ o, ...form }).toString() }).then(async (r) => ({ status: r.status, html: await r.text() }));
	const n = (await interno(`whatsapp/salida?tenant=${tenant}`)).body.length;
	await post("telefono", { telefono });
	if ((await interno(`whatsapp/salida?tenant=${tenant}`)).body.length === n) return { sinCodigo: true, html: "" };
	const cod = await post("codigo", { codigo: await ultimoOtp(tenant) });
	assert.match(cod.html, /contacte a tu asistente para/);
	return { sinCodigo: false, ...(await post("decision", { decision })) };
}

const agentePrueba = await nuevoAgente("agente-terceros.test");

test("RP1 · comercio: el agente pide el acuerdo en su conversación, la persona lo aprueba y la empresa le pregunta «confirmar o bloquear» ahí mismo", async () => {
	const ana = new Usuario(agentePrueba, FERRETERIA);
	await ana.iniciar();
	// Without a linked account, asking for it leads to linking first.
	const sin = await ana.decir("Quiero que me avisen si hay una compra rara, para confirmar o bloquear.");
	assert.match(String(sin[0].text), /primero vincula tu cuenta/);
	await ana.vincular(["pedidos:leer"], "+56900000101");
	const oferta = await ana.decir("Quiero que me avisen si hay una compra rara, para confirmar o bloquear.");
	const vxp = (oferta[0].data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"];
	assert.equal(vxp.type, "relationship_offer");
	// Only what was asked for, and the link on the company's own domain.
	assert.deepEqual(vxp.actions, ["alerta.confirmar_o_bloquear"]);
	assert.equal(new URL(String(vxp.approval_url)).host, "agentes.ferreteria-demo.test");
	// Another number (another customer's) gets no code: only the owner of the linked account approves.
	assert.equal((await aprobarEnPagina(String(vxp.approval_url), "+56900000202")).sinCodigo, true);
	const fin = await aprobarEnPagina(String(vxp.approval_url), "+56900000101");
	assert.match(fin.html, /Acuerdo aprobado/);
	const aviso = await ana.leer();
	const acuerdo = (aviso.at(-1)!.data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"];
	assert.equal(acuerdo.type, "relationship_agreement");
	const rel = String(acuerdo.relationship_id);

	// 3 a.m.: the company flags an unusual purchase and asks. The agent reads it in its conversation.
	const ini = await interno("relaciones/iniciar?tenant=t_ferreteria_demo", { relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { order_ref: "P-1042", summary: "Compra de P-1042 con despacho a una comuna nueva, ingresada a las 03:12." } });
	assert.equal(ini.status, 201, JSON.stringify(ini.body));
	assert.equal(ini.body.delivery, "entregado");
	const pregunta = await ana.leer();
	assert.match(String(pregunta.at(-1)!.text), /Confirmar o Bloquear\?/);
	const req = (pregunta.at(-1)!.data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"];
	assert.equal(req.type, "company_request");
	assert.match(String(req.message), /^ey/, "lleva el mensaje firmado");

	// An ambiguous answer does not count; «confirmo» does, only once, with a receipt.
	assert.match(String((await ana.decir("confirmo o bloqueo, no sé"))[0].text), /Responde sólo una opción/);
	const resp = await ana.decir("Confirmo, ella se cambió de casa la semana pasada.");
	const recibo = (resp[0].data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"];
	assert.equal(recibo.type, "reply_receipt");
	assert.equal(recibo.decision, "confirmar");
	assert.match(String(recibo.receipt), /^ey/);
	const pedido = (await interno("sistema?tenant=t_ferreteria_demo")).body.find((p: { id: string }) => p.id === "P-1042");
	assert.equal(pedido.retenido, false);
	// Already answered: a later «bloquear» changes nothing and the conversation continues normally.
	await ana.decir("Mejor bloquéalo");
	assert.equal((await interno("sistema?tenant=t_ferreteria_demo")).body.find((p: { id: string }) => p.id === "P-1042").retenido, false);
	// Asking again returns the current agreement; it does not create another.
	const otra = await ana.decir("Avísame si hay algo raro");
	assert.equal(((otra[0].data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"]).type, "relationship");
});

test("RP2 · hotel: el huésped no llega y el hotel pregunta «mantener o liberar»; «liberar» suelta la reserva", async () => {
	const ana = new Usuario(agentePrueba, HOTEL);
	await ana.iniciar();
	await ana.vincular(["reservas:leer"], "+56900000101");
	const oferta = await ana.decir("Acepto que el hotel me contacte si no llego, para mantener o liberar la reserva.");
	const vxp = (oferta[0].data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"];
	assert.deepEqual(vxp.actions, ["alerta.mantener_o_liberar"]);
	assert.equal(new URL(String(vxp.approval_url)).host, "reservas.hotel-demo.test");
	assert.doesNotMatch(String(oferta[0].text), /pedidos/, "con palabras de hotel");
	assert.match((await aprobarEnPagina(String(vxp.approval_url), "+56900000101")).html, /Acuerdo aprobado/);
	const rel = String(((await ana.leer()).at(-1)!.data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"].relationship_id);
	// A commerce action is not in the hotel's agreement.
	assert.equal((await interno("relaciones/iniciar?tenant=t_hotel_demo", { relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { reservation_ref: "R-3003", summary: "x" } })).body.error, "action_not_authorized");
	const ini = await interno("relaciones/iniciar?tenant=t_hotel_demo", { relationship_id: rel, action: "alerta.mantener_o_liberar", params: { reservation_ref: "R-3003", summary: "Son las 23:00 y no has hecho check-in en R-3003." } });
	assert.equal(ini.body.delivery, "entregado", JSON.stringify(ini.body));
	assert.match(String((await ana.leer()).at(-1)!.text), /Mantener o Liberar\?/);
	const resp = await ana.decir(null, { "vxpprotocol.org/relationship": { decision: "liberar" } });
	assert.equal(((resp[0].data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"]).decision, "liberar");
	const estado = (await interno("estado?tenant=t_hotel_demo")).body;
	const r3003 = (estado.reservas ?? estado.sistema?.hotel?.reservas ?? []).find((x: { id: string }) => x.id === "R-3003");
	assert.equal(r3003?.estado, "cancelada", JSON.stringify(Object.keys(estado)));
});

test("RP3 · revocada la cuenta, la empresa ya no puede preguntar y una respuesta tardía no cuenta", async () => {
	const ana = new Usuario(agentePrueba, FERRETERIA);
	await ana.iniciar();
	await ana.vincular(["pedidos:leer"], "+56900000101");
	const vxp = ((await ana.decir("Que me avisen si hay una compra rara"))[0].data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"];
	await aprobarEnPagina(String(vxp.approval_url), "+56900000101");
	const rel = String(((await ana.leer()).at(-1)!.data as Record<string, Record<string, unknown>>)["vxpprotocol.org/relationship"].relationship_id);
	await interno("relaciones/iniciar?tenant=t_ferreteria_demo", { relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { order_ref: "P-1043", summary: "Compra rara." } });
	await interno("relaciones/revocar?tenant=t_ferreteria_demo", { relationship_id: rel, by: "usuario" });
	assert.equal((await interno("relaciones/iniciar?tenant=t_ferreteria_demo", { relationship_id: rel, action: "alerta.confirmar_o_bloquear", params: { order_ref: "P-1043", summary: "Otra." } })).body.error, "relationship_revoked");
	const tarde = await ana.decir("Bloquear");
	assert.match(String(tarde.at(-1).text), /ya no está vigente/);
	assert.notEqual((await interno("sistema?tenant=t_ferreteria_demo")).body.find((p: { id: string }) => p.id === "P-1043").retenido, true);
});

test("RP4 · preguntar las condiciones de cancelación basta con el permiso de lectura: el hotel dice el cargo exacto y pide el de cancelar sólo para ejecutar", async () => {
	// RP2 released R-3003: the hotel is reset to its initial snapshot.
	assert.equal((await interno("reset", { tenant: "t_hotel_demo" })).status, 200);
	const ana = new Usuario(agentePrueba, HOTEL);
	await ana.iniciar();
	await ana.vincular(["reservas:leer"], "+56900000101");
	const r = await ana.decir("¿Puedo cancelar la R-3003 sin cargo?");
	assert.match(String(r.at(-1).text), /R-3003: cancelarla ahora tiene un cargo de \$[\d.]+ \(la primera noche\)/);
	assert.match(String(r.at(-1).text), /necesito el permiso de cancelar/);
	const insiste = await ana.decir("Cancela la R-3003 sin cargo, por favor, insisto.");
	assert.match(String(insiste.at(-1).text), /La política es la misma en cada pedido/);
	const estado = (await interno("estado?tenant=t_hotel_demo")).body;
	assert.equal(estado.reservas.find((x: { id: string }) => x.id === "R-3003").estado, "confirmada", "nada se ejecutó");
});

// Attacks from review round 3 (red team), reproduced at
// runtime by the fixing engineer before the fix and kept as regression tests.
//
// Each test asserts the SAFE behavior. Before the fix, each one fails: that failure is the
// reproduction of the finding. After the fix, they pass.
//
// Attacks that require signing something false use the issuer's keys: under `operator_hosted` custody
// the operator holds all of them, so this is what a dishonest operator could do.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, type KeyObject, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import type { ActorExterno } from "../src/nucleo.ts";
import { codigoVisible, huellaTerminos, jcs } from "../src/prueba.ts";
import { crearPuerta } from "../src/puerta.ts";
import { dpopProof, generateKey, randomId, type SigningKey, signAssertion } from "../vendor/poppy-kit/validate/jose.ts";

const VERIFICADOR = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
const AUTH = "https://auth.sovras.test";
const FERRETERIA = `${AUTH}/e/ferreteria-demo`;
const DESC_FERRETERIA = "https://agentes.ferreteria-demo.test/.well-known/poppy.json";
const EXT = "vxpprotocol.org/proof";
const T = "t_ferreteria_demo";
const tmp = mkdtempSync(join(tmpdir(), "sovras-ataques-r3-"));

type Pa = { clientId: string; key: SigningKey; doc: Record<string, unknown> };
const agentes = new Map<string, Pa>();
async function nuevoAgente(host: string): Promise<Pa> {
	const key = await generateKey(true);
	const clientId = `https://${host}/agent.json`;
	const doc = {
		client_id: clientId,
		client_name: `Asistente ${host}`,
		jwks_uri: `https://${host}/jwks.json`,
		redirect_uris: [`https://${host}/cb`],
		token_endpoint_auth_method: "private_key_jwt",
		extensions: { operations: { version: "1" }, [EXT]: { version: "0.1" } },
	};
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
	empresas: empresasDePrueba({ ferreteria: "agentes.ferreteria-demo.test", libreria: "agentes.libreria-demo.test" }),
	pactDelegada: [T],
	plataformasPact: [],
	fetch: red,
});
// One order per attack, so each reproduction is independent of the others.
const ferreteria = puerta.nucleo.empresa(T);
for (const [id, despacho] of [["P-9001", "2026-10-24"], ["P-9002", "2026-10-24"], ["P-9003", "2026-10-24"], ["P-9004", "2026-10-24"], ["P-9005", "2026-10-24"], ["P-9006", "2026-10-24"], ["P-9007", "2026-10-24"]])
	ferreteria.sistema.pedidos.push({ id, clienteId: "ERP-C-0193", producto: "Caja de tornillos", despacho, direccion: "Calle Ejemplo 100, Santiago", estado: "preparando" });
const despachoDe = (id: string) => ferreteria.sistema.pedidos.find((p) => p.id === id)!.despacho;

const interno = async (path: string, body?: unknown) =>
	(
		await red(`${AUTH}/interno/${path}`, {
			method: body ? "POST" : "GET",
			headers: { "x-sovras-prueba": puerta.llaveInterna, "content-type": "application/json" },
			...(body ? { body: JSON.stringify(body) } : {}),
		})
	).json();

class Usuario {
	readonly sub = `usr_${randomId(9)}`;
	dpopKey!: SigningKey;
	token = "";
	sessionId = "";
	conv = "";
	readonly pa: Pa;
	constructor(pa: Pa) {
		this.pa = pa;
	}
	private aserto(sub = this.pa.clientId) {
		return signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub, aud: FERRETERIA });
	}
	async tokenRequest(form: Record<string, string>) {
		const url = `${FERRETERIA}/oauth/token`;
		const body = new URLSearchParams({ ...form, client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await this.aserto() });
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return (await r.json()) as Record<string, unknown>;
	}
	async entrar(telefono: string, alcances = ["pedidos:leer", "pedidos:modificar"]) {
		this.dpopKey = await generateKey(false);
		const s = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: await this.aserto(this.sub) });
		this.token = String(s.access_token);
		this.sessionId = String(s.session_id);
		const dev = await red(`${FERRETERIA}/oauth/device`, {
			method: "POST",
			body: new URLSearchParams({ scope: alcances.join(" "), client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await this.aserto() }).toString(),
		}).then((r) => r.json());
		const post = (paso: string, form: Record<string, string | string[]>) => {
			const b = new URLSearchParams();
			for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) b.append(k, x);
			return red(`${FERRETERIA}/vincular/${paso}`, { method: "POST", body: b.toString(), redirect: "manual" });
		};
		await post("telefono", { user_code: dev.user_code, telefono });
		const otp = (await interno(`whatsapp/salida?tenant=${T}`)).at(-1).texto.match(/código es (\d{6})/)[1];
		await post("codigo", { user_code: dev.user_code, codigo: otp });
		await post("decision", { user_code: dev.user_code, decision: "allow", scope: alcances });
		const t = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code, session_id: this.sessionId });
		assert.ok(t.access_token, JSON.stringify(t));
		this.token = String(t.access_token);
	}
	async pedir(method: string, url: string, body?: unknown) {
		const r = await red(url, {
			method,
			headers: { authorization: `DPoP ${this.token}`, dpop: await dpopProof({ key: this.dpopKey, method, url, accessToken: this.token }), "content-type": "application/json" },
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		});
		const text = await r.text();
		return { status: r.status, body: text ? JSON.parse(text) : null };
	}
	/** Asks for something through the conversation; returns the operation (or null) and the company's text. */
	async mensaje(texto: string): Promise<{ op: Record<string, unknown> | null; texto: string }> {
		const msg = { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } };
		const url = this.conv ? `${FERRETERIA}/poppy/conversaciones/${this.conv}/messages?wait=0` : `${FERRETERIA}/poppy/conversaciones?wait=0`;
		const r = await this.pedir("POST", url, msg);
		this.conv = r.body.conversation_id;
		const ultimo = [...r.body.events].reverse().find((e: { message?: { role?: string } }) => e.message?.role === "company")?.message;
		return { op: ultimo?.operation ?? null, texto: String(ultimo?.text ?? "") };
	}
	async proponer(texto: string): Promise<Record<string, unknown>> {
		const { op, texto: t } = await this.mensaje(texto);
		assert.ok(op, t);
		return op;
	}
	confirmar(op: Record<string, unknown>, revision = Number(op.revision)) {
		return this.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op.operation_id}/confirm`, { revision, approved_by: "user" });
	}
	async operacion(id: unknown) {
		return (await this.pedir("GET", `${FERRETERIA}/poppy/operaciones/${id}`)).body;
	}
	async paquete(id: unknown) {
		return (await this.pedir("GET", `${FERRETERIA}/sovras/proof/operations/${id}`)).body;
	}
}

// ── Independent verifier, with the public material ───────────────────────────────────────────

const decodificar = (sdjwt: string) => JSON.parse(Buffer.from(sdjwt.split("~")[0].split(".")[1], "base64url").toString("utf8"));
const metadataDe = (issuer: string) => {
	const u = new URL(issuer);
	return `${u.origin}/.well-known/oauth-authorization-server${u.pathname}`;
};
async function material() {
	const docs: Record<string, unknown> = {};
	const traer = async (u: string) => (await red(u)).text();
	docs[DESC_FERRETERIA] = await traer(DESC_FERRETERIA);
	const issuer = JSON.parse(String(docs[DESC_FERRETERIA])).auth.issuer;
	docs[metadataDe(issuer)] = await traer(metadataDe(issuer));
	const bloque = JSON.parse(String(docs[metadataDe(issuer)])).vxp_proof;
	for (const u of [bloque.jwks_uri, bloque.operator.jwks_uri, bloque.log.jwks_uri]) docs[u] = await traer(u);
	docs[bloque.log.checkpoint_url] = await traer(bloque.log.checkpoint_url);
	return { anchor: { domain: new URL(DESC_FERRETERIA).host }, docs };
}
let n = 0;
async function verificar(paquete: unknown, operacion?: unknown) {
	const dir = join(tmp, `v${++n}`);
	writeFileSync(`${dir}-material.json`, JSON.stringify(await material()));
	writeFileSync(`${dir}-paquete.json`, JSON.stringify(paquete));
	const args = [VERIFICADOR, "material", "--material", `${dir}-material.json`, "--paquete", `${dir}-paquete.json`];
	if (operacion) {
		writeFileSync(`${dir}-op.json`, JSON.stringify(operacion));
		args.push("--operacion", `${dir}-op.json`);
	}
	const r = spawnSync("python", args, { encoding: "utf8" });
	assert.ok(r.stdout, `el verificador no respondió: ${r.stderr}`);
	return JSON.parse(r.stdout.trim().split("\n").at(-1)!) as Record<string, unknown>;
}

type LlaveInterna = { privateKey: KeyObject; publica: { kid: string } };
const llaveOperador = () => Reflect.get(puerta.pruebas, "operador") as LlaveInterna;
const llaveEmpresa = () => (Reflect.get(puerta.pruebas, "empresas") as Map<string, { llave: LlaveInterna }>).get(T)!.llave;
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
function firmar(llave: LlaveInterna, payload: Record<string, unknown>): string {
	const h = b64u(jcs({ alg: "ES256", kid: llave.publica.kid, typ: "vxp-stmt+sd-jwt" }));
	const p = b64u(jcs(payload));
	return `${h}.${p}.${b64u(sign("sha256", Buffer.from(`${h}.${p}`, "ascii"), { key: llave.privateKey, dsaEncoding: "ieee-p1363" }))}`;
}
const huella = (jwt: string) => `sha-256:${createHash("sha256").update(jwt.slice(0, jwt.lastIndexOf(".")), "ascii").digest("base64url")}`;
const llaveDe = (kind: string) => (["terms", "company_review", "outcome", "correction", "revocation"].includes(kind) ? llaveEmpresa() : llaveOperador());

/**
 * What a dishonest operator would do: rewrite links and re-sign everything that follows, with
 * `seq` and `prev` kept up to date. Keeps each link's disclosures. No log (`log` absent).
 */
function reencadenar(statements: string[], cambiar: (payloads: Record<string, unknown>[]) => Record<string, unknown>[]): string[] {
	const discl = new Map<number, string>();
	const payloads = statements.map((s, i) => {
		const p = decodificar(s);
		p.__i = i;
		discl.set(i, s.split("~").slice(1).join("~"));
		return p;
	});
	const nuevos = cambiar(payloads);
	const salida: string[] = [];
	let prev: string | null = null;
	nuevos.forEach((p, seq) => {
		const original = p.__i as number | undefined;
		const { __i: _x, ...limpio } = p;
		Object.assign(limpio, { seq, prev });
		const jwt = firmar(llaveDe(String(limpio.kind)), limpio);
		salida.push(`${jwt}~${original === undefined ? "" : discl.get(original)}`);
		prev = huella(jwt);
	});
	return salida;
}

// ── Scenario ───────────────────────────────────────────────────────────────────────────────────

const agenteA = await nuevoAgente("asistente-a.test");
const agenteB = await nuevoAgente("asistente-b.test");
const ana = new Usuario(agenteA);
await ana.entrar("+56900000101");
// The same customer with another `sub` of the same agent, and with another agent (M2).
const anaOtroSub = new Usuario(agenteA);
await anaOtroSub.entrar("+56900000101");
const anaOtroAgente = new Usuario(agenteB);
await anaOtroAgente.entrar("+56900000101");

test("m1: la aprobación que afirma el agente se nombra por su raíz real, el operador", async () => {
	const op = await ana.proponer("Cambia el despacho del P-9001 al 2026-10-26");
	const r = await ana.confirmar(op);
	assert.equal(r.body.state, "succeeded");
	const p = await ana.paquete(op.operation_id);
	const v = await verificar(p, r.body);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.ok(!(v.derived_assurance as string[]).includes("agent_asserted_approval"), JSON.stringify(v.derived_assurance));
	// What the company asserts in the `outcome` also uses the name from the real root.
	const afirmado = decodificar(p.statements.at(-1)).body.claimed_assurance as string[];
	assert.ok(afirmado.includes("operator_reported_agent_approval") && !afirmado.includes("agent_asserted_approval"), JSON.stringify(afirmado));
	assert.ok((v.derived_assurance as string[]).includes("operator_reported_agent_approval"), JSON.stringify(v.derived_assurance));
	const doc = await (await red(DESC_FERRETERIA)).json();
	assert.ok(!JSON.stringify(doc.extensions[EXT]).includes("agent_asserted_approval"), "poppy.json no promete un nivel con el nombre retirado");
});

test("M1: una lectura de vuelta firmada que contradice la fecha aprobada no pasa con la operación en la mano", async () => {
	const op = await ana.proponer("Cambia el despacho del P-9002 al 2026-10-26");
	const r = await ana.confirmar(op);
	assert.equal(r.body.state, "succeeded");
	const p = await ana.paquete(op.operation_id);
	// The operator signs `matches_terms: true` with the OLD date in every observed member other than the order.
	const falsa = reencadenar(p.statements, (ps) =>
		ps.map((x) => {
			if (x.kind !== "read_back") return x;
			const b = structuredClone(x.body) as { observed: Record<string, unknown> };
			for (const k of Object.keys(b.observed)) if (k !== "pedido" && k !== "_sd") b.observed[k] = "2026-10-24";
			return { ...x, body: b };
		}),
	);
	const v = await verificar({ ...p, statements: falsa, log: undefined }, r.body);
	assert.equal(v.valid, false, `aceptó una lectura que contradice los términos: ${JSON.stringify(v)}`);
	assert.equal(v.error, "read_back_terms_mismatch");
});

test("M1: una lectura de vuelta que no observa el efecto aprobado no respalda `succeeded` (sin la operación)", async () => {
	const op = await ana.proponer("Cambia el despacho del P-9003 al 2026-10-26");
	const r = await ana.confirmar(op);
	assert.equal(r.body.state, "succeeded");
	const p = await ana.paquete(op.operation_id);
	const sinEfecto = reencadenar(p.statements, (ps) =>
		ps.map((x) => {
			if (x.kind !== "read_back") return x;
			const b = structuredClone(x.body) as { observed: Record<string, unknown> };
			for (const k of Object.keys(b.observed)) if (k !== "pedido" && k !== "_sd") delete b.observed[k];
			return { ...x, body: b };
		}),
	);
	const v = await verificar({ ...p, statements: sinEfecto, log: undefined });
	assert.equal(v.valid, false, `aceptó un succeeded cuya lectura no observa el efecto: ${JSON.stringify(v)}`);
	assert.equal(v.error, "read_back_incomplete");
});

test("M2: otro sub u otro agente del mismo cliente no reescribe la operación propuesta de otro", async () => {
	const opA = await ana.proponer("Cambia el despacho del P-9004 al 2026-10-26");
	const opB = await anaOtroSub.proponer("Cambia el despacho del P-9004 al 2026-10-27");
	const opC = await anaOtroAgente.proponer("Cambia el despacho del P-9004 al 2026-10-28");
	assert.notEqual(opB.operation_id, opA.operation_id, "otro sub recibió la operación de A");
	assert.notEqual(opC.operation_id, opA.operation_id, "otro agente recibió la operación de A");
	assert.equal(opB.revision, 1);
	// A confirms what A asked for: the terms were not swapped underneath it.
	const r = await ana.confirmar(opA);
	assert.equal(r.status, 200, JSON.stringify(r.body));
	assert.equal(r.body.state, "succeeded");
	assert.equal(despachoDe("P-9004"), "2026-10-26");
	await anaOtroAgente.pedir("POST", `${FERRETERIA}/poppy/operaciones/${opC.operation_id}/cancel`);
	// M3 (precondition): B confirms on a delivery that already changed → `failed` with no effect, not a second `succeeded`.
	const rb = await anaOtroSub.confirmar(opB);
	assert.equal(rb.body.state, "failed", JSON.stringify(rb.body));
	assert.equal(despachoDe("P-9004"), "2026-10-26", "B no sobrescribió el cambio de A");
	const v = await verificar(await anaOtroSub.paquete(opB.operation_id), rb.body);
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "failed");
});

test("M2: una revisión nueva pedida por el agente queda registrada en la cadena (counter + answers)", async () => {
	const op1 = await ana.proponer("Cambia el despacho del P-9005 al 2026-10-26");
	const op2 = await ana.proponer("Mejor cambia el P-9005 al 2026-10-27");
	assert.equal(op2.operation_id, op1.operation_id, "el mismo dueño sí reutiliza su operación");
	assert.equal(op2.revision, 2);
	const s: string[] = (await ana.paquete(op1.operation_id)).statements;
	const kinds = s.map((x) => decodificar(x).kind);
	assert.deepEqual(kinds, ["request", "terms", "counter", "terms"]);
	assert.equal(decodificar(s[3]).body.answers, huella(s[2].split("~")[0]), "la revisión 2 responde a la petición registrada");
	assert.equal((await ana.confirmar(op2)).body.state, "succeeded");
});

test("M3: dos operaciones sobre el mismo pedido no terminan las dos en `succeeded`", async () => {
	const op1 = await ana.proponer("Cambia el despacho del P-9006 al 2026-12-15");
	assert.equal((await ana.confirmar(op1)).body.state, "in_progress", "espera la revisión de la empresa");
	const intento = await ana.mensaje("Cambia el despacho del P-9006 al 2026-10-26");
	if (intento.op) await ana.confirmar(intento.op);
	const pend = (await interno(`revisiones?tenant=${T}`)) as { review_id: string; summary: string }[];
	const rev = pend.find((x) => x.summary.includes("P-9006"))!;
	await interno(`revisiones/${rev.review_id}`, { tenant: T, decision: "aprobada" });
	const finales = [await ana.operacion(op1.operation_id), ...(intento.op ? [await ana.operacion(intento.op.operation_id)] : [])];
	const ok = finales.filter((o) => o.state === "succeeded");
	// What the independent verifier would say about each `succeeded`, with its operation in hand.
	const veredictos: string[] = [];
	for (const o of ok) veredictos.push(`${o.operation_id}: ${JSON.stringify((({ valid, final_state, operation }) => ({ valid, final_state, operation }))(await verificar(await ana.paquete(o.operation_id), o)))}`);
	assert.ok(ok.length <= 1, `dos succeeded contradictorios: ${finales.map((o) => `${o.operation_id}=${o.state} (${(o.terms as { despacho_nuevo: string }).despacho_nuevo})`).join(", ")}; sistema: ${despachoDe("P-9006")}; verificador: ${veredictos.join(" | ")}`);
	for (const o of ok) assert.equal((o.terms as { despacho_nuevo: string }).despacho_nuevo, despachoDe("P-9006"));
	// Only one operation in progress per order: the second proposal does not open another, and says so.
	assert.equal(intento.op, null, "se abrió una segunda operación sobre un pedido con otra en curso");
	assert.match(intento.texto, /en curso/, "la segunda propuesta se rechaza diciendo por qué");
});

test("m3: si la empresa exige revisión, un operador que la omite no produce una cadena válida", async () => {
	const op = await ana.proponer("Cambia el despacho del P-9007 al 2026-12-20");
	await ana.confirmar(op);
	const pend = (await interno(`revisiones?tenant=${T}`)) as { review_id: string; summary: string }[];
	await interno(`revisiones/${pend.find((x) => x.summary.includes("P-9007"))!.review_id}`, { tenant: T, decision: "aprobada" });
	const final = await ana.operacion(op.operation_id);
	assert.equal(final.state, "succeeded");
	const p = await ana.paquete(op.operation_id);
	assert.ok(p.statements.some((s: string) => decodificar(s).kind === "company_review"));
	const sinRevision = reencadenar(p.statements, (ps) => ps.filter((x) => x.kind !== "company_review"));
	const v = await verificar({ ...p, statements: sinRevision, log: undefined }, final);
	assert.equal(v.valid, false, `aceptó una ejecución sin la revisión que la empresa exigía: ${JSON.stringify(v)}`);
	assert.equal(v.error, "order_violation");
});

test("m2: la huella de términos no permite confirmar una dirección candidata", async () => {
	const op = await ana.proponer("Cambia el despacho del P-1043 al 2026-10-29");
	const s: string[] = (await ana.paquete(op.operation_id)).statements;
	const terms = decodificar(s.find((x) => decodificar(x).kind === "terms")!).body;
	// The attacker knows everything but the address (worst case): order, product, dates, `expires_at` (in clear in `terms`).
	const candidatas = ["Calle Ejemplo 200, Concepción", "Calle Ejemplo 100, Santiago", "Calle Ejemplo 300, Santiago"];
	const acierta = candidatas.filter((direccion) => {
		const t = { pedido: "P-1043", producto: "Escalera de aluminio 6 peldaños", despacho_actual: "2026-10-27", despacho_nuevo: "2026-10-29", direccion, costo: { amount: "0", currency: "CLP" } };
		const summary = `Cambiar el despacho del pedido P-1043 (Escalera de aluminio 6 peldaños) del 2026-10-27 al 2026-10-29, a ${direccion}, sin costo.`;
		return huellaTerminos({ company: FERRETERIA, operation_id: String(op.operation_id), revision: 1, summary, terms: t, expires_at: terms.expires_at, user_approval_required: true }) === terms.terms_digest;
	});
	assert.deepEqual(acierta, [], `la huella confirmó la dirección: ${acierta}`);
	// With the salt (which the AP does have in the operation) the digest recomputes the same.
	const sal = (op.terms as { vxp_salt?: string }).vxp_salt;
	assert.ok(typeof sal === "string" && Buffer.from(sal, "base64url").length >= 16, "sal de 128 bits o más en los términos");
	await ana.pedir("POST", `${FERRETERIA}/poppy/operaciones/${op.operation_id}/cancel`);
});

test("m4: una respuesta por WhatsApp a una operación vencida no se informa como aceptada", async () => {
	// A PACT actor with its delegation, built in-process: what matters is the channel's response.
	const grantId = "grant_ataque_m4";
	puerta.del.grants.set(grantId, {
		id: grantId,
		tenantId: T,
		protocolo: "pact",
		clientId: "https://pa-pact.test",
		sub: "pact-user-1",
		clienteId: "cli_a_ferreteria",
		alcances: ["pedidos:leer", "pedidos:modificar"],
		expira: Math.floor(Date.now() / 1000) + 3600,
		revocado: false,
		refreshVigente: "x",
		refreshUsados: new Set(),
	});
	const actor: ActorExterno = { tenantId: T, via: "agente_personal", protocolo: "pact", clientId: "https://pa-pact.test", sub: "pact-user-1", clienteId: "cli_a_ferreteria", alcances: ["pedidos:leer", "pedidos:modificar"], grantId };
	const caso = puerta.nucleo.abrirCaso(T, actor);
	const r = puerta.nucleo.proponerReprogramacion(actor, caso.id, "P-1042", "2026-10-25", null, { binding: "pact.message", text: "P-1042 al 2026-10-25" });
	assert.ok(r.ok);
	const op = r.operacion;
	(Reflect.get(puerta.pact, "pedirAprobacion") as (...a: unknown[]) => string).call(puerta.pact, ferreteria, actor, op);
	op.expires_at = new Date(Date.now() - 1000).toISOString();
	const aceptado = await puerta.pact.whatsappEntrante(T, "+56 9 0000 0101", `APROBAR ${codigoVisible(op.interno.termsDigest)}`);
	assert.equal(op.state, "expired");
	assert.equal(aceptado, false, "informó «aceptado» sobre una operación que no aprobó");
});

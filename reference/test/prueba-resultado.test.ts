// Outcome proof (VXP specification, Proof) issued by the gateway and checked by the independent
// verifier (verifier/verificar_paquete.py: Python + `cryptography`, no code shared
// with src/). The agent uses the primitives from the official Poppy kit, not the gateway's.
//
// The verifier receives only public material: poppy.json, the JWKS it names, the log's signed
// checkpoint and its consistency proof. Here they are fetched in-process and passed as a file; against
// the live server the verifier fetches them itself over HTTP (scripts/verificar-vivo.sh).
//
// Negative cases that require signing something false use the issuer's keys: under
// `operator_hosted` custody the operator holds all of them, so that is exactly what a dishonest
// operator could do. The verifier must catch it through the chain, the log or the operation.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, type KeyObject, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { jcs } from "../src/prueba.ts";
import { crearPuerta } from "../src/puerta.ts";
import { dpopProof, generateKey, randomId, type SigningKey, signAssertion } from "../vendor/poppy-kit/validate/jose.ts";

const VERIFICADOR = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
const AUTH = "https://auth.sovras.test";
const FERRETERIA = `${AUTH}/e/ferreteria-demo`;
const LIBRERIA = `${AUTH}/e/libreria-demo`;
const DESC_FERRETERIA = "https://agentes.ferreteria-demo.test/.well-known/poppy.json";
const DESC_LIBRERIA = "https://agentes.libreria-demo.test/.well-known/poppy.json";
const EXT = "vxpprotocol.org/proof";
const tmp = mkdtempSync(join(tmpdir(), "sovras-prueba-"));

type Pa = { clientId: string; key: SigningKey; doc: Record<string, unknown> };
const agentes = new Map<string, Pa>();
async function nuevoAgente(host: string, conPrueba: boolean | string): Promise<Pa> {
	const key = await generateKey(true);
	const clientId = `https://${host}/agent.json`;
	const doc = {
		client_id: clientId,
		client_name: `Asistente ${host}`,
		jwks_uri: `https://${host}/jwks.json`,
		redirect_uris: [`https://${host}/cb`],
		token_endpoint_auth_method: "private_key_jwt",
		extensions: { operations: { version: "1" }, ...(conPrueba ? { [EXT]: { version: typeof conPrueba === "string" ? conPrueba : "0.1" } } : {}) },
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
	// Demo offers PACT delegation: its metadata declares the interface and the PACT AS (round 2, M1).
	pactDelegada: ["t_ferreteria_demo"],
	plataformasPact: [],
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

class Usuario {
	readonly sub = `usr_${randomId(9)}`;
	dpopKey!: SigningKey;
	token = "";
	sessionId = "";
	conv = "";
	readonly pa: Pa;
	readonly issuer: string;
	constructor(pa: Pa, issuer: string) {
		this.pa = pa;
		this.issuer = issuer;
	}
	private async aserto(sub = this.pa.clientId) {
		return signAssertion({ key: this.pa.key, iss: this.pa.clientId, sub, aud: this.issuer });
	}
	async tokenRequest(form: Record<string, string>) {
		const url = `${this.issuer}/oauth/token`;
		const body = new URLSearchParams({ ...form, client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await this.aserto() });
		const r = await red(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: this.dpopKey, method: "POST", url }) }, body: body.toString() });
		return (await r.json()) as Record<string, unknown>;
	}
	async entrar(telefono: string, alcances = ["pedidos:leer", "pedidos:modificar"]) {
		this.dpopKey = await generateKey(false);
		const s = await this.tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: await this.aserto(this.sub) });
		this.token = String(s.access_token);
		this.sessionId = String(s.session_id);
		const dev = await red(`${this.issuer}/oauth/device`, {
			method: "POST",
			body: new URLSearchParams({ scope: alcances.join(" "), client_id: this.pa.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await this.aserto() }).toString(),
		}).then((r) => r.json());
		const tenant = this.issuer === FERRETERIA ? "t_ferreteria_demo" : "t_libreria_demo";
		const post = (paso: string, form: Record<string, string | string[]>) => {
			const b = new URLSearchParams();
			for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) b.append(k, x);
			return red(`${this.issuer}/vincular/${paso}`, { method: "POST", body: b.toString(), redirect: "manual" });
		};
		await post("telefono", { user_code: dev.user_code, telefono });
		const otp = (await interno(`whatsapp/salida?tenant=${tenant}`)).at(-1).texto.match(/código es (\d{6})/)[1];
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
	/** Asks for something through the conversation and returns the operation carried by the company's message. */
	async proponer(texto: string): Promise<Record<string, unknown>> {
		const msg = { message: { id: `msg_${randomId(9)}`, sender: "agent", text: texto } };
		const url = this.conv ? `${this.issuer}/poppy/conversaciones/${this.conv}/messages?wait=0` : `${this.issuer}/poppy/conversaciones?wait=0`;
		const r = await this.pedir("POST", url, msg);
		this.conv = r.body.conversation_id;
		const op = [...r.body.events].reverse().find((e: { message?: { operation?: unknown } }) => e.message?.operation)?.message.operation;
		assert.ok(op, JSON.stringify(r.body.events));
		return op;
	}
	confirmar(op: Record<string, unknown>, revision = Number(op.revision)) {
		return this.pedir("POST", `${this.issuer}/poppy/operaciones/${op.operation_id}/confirm`, { revision, approved_by: "user" });
	}
	async paquete(opId: string) {
		const r = await this.pedir("GET", `${this.issuer}/sovras/proof/operations/${opId}`);
		return r;
	}
}

// ── The independent verifier ─────────────────────────────────────────────────────────────────────

const decodificar = (sdjwt: string) => JSON.parse(Buffer.from(sdjwt.split("~")[0].split(".")[1], "base64url").toString("utf8"));
const tamano = (jws: string) => Number(JSON.parse(Buffer.from(jws.split(".")[1], "base64url").toString("utf8")).tree_size);

const metadataDe = (issuer: string) => {
	const u = new URL(issuer);
	return `${u.origin}/.well-known/oauth-authorization-server${u.pathname}`;
};

/**
 * Fetches the public material, as a third party starting from the company's domain would (SPEC §9.9.1):
 * poppy.json, the RFC 8414 metadata of the issuer it names, and whatever that metadata names.
 */
async function material(descubrir: string, paquete: { log?: { checkpoint: string } }, checkpointVivo?: string) {
	const docs: Record<string, unknown> = {};
	const traer = async (u: string) => (await red(u)).text();
	docs[descubrir] = await traer(descubrir);
	const issuer = JSON.parse(String(docs[descubrir])).auth.issuer;
	docs[metadataDe(issuer)] = await traer(metadataDe(issuer));
	const bloque = JSON.parse(String(docs[metadataDe(issuer)])).vxp_proof;
	for (const u of [bloque.jwks_uri, bloque.operator.jwks_uri, bloque.log.jwks_uri]) docs[u] = await traer(u);
	const vivo = checkpointVivo ?? (await traer(bloque.log.checkpoint_url));
	docs[bloque.log.checkpoint_url] = vivo;
	if (paquete.log) {
		const a = tamano(paquete.log.checkpoint);
		const b = tamano(vivo);
		if (b > a) {
			const u = `${bloque.log.consistency_url}?first=${a}&second=${b}`;
			docs[u] = await traer(u);
		}
	}
	return { anchor: { domain: new URL(descubrir).host }, docs };
}

let n = 0;
async function verificar(
	paquete: unknown,
	o: { descubrir?: string; aud?: string; operacion?: unknown; checkpointVivo?: string; ajustar?: (m: { anchor: Record<string, string>; docs: Record<string, unknown> }) => void } = {},
) {
	const p = paquete as { log?: { checkpoint: string } };
	const dir = join(tmp, `v${++n}`);
	const m: { anchor: Record<string, string>; docs: Record<string, unknown> } = await material(o.descubrir ?? DESC_FERRETERIA, p, o.checkpointVivo);
	o.ajustar?.(m);
	writeFileSync(`${dir}-material.json`, JSON.stringify(m));
	writeFileSync(`${dir}-paquete.json`, JSON.stringify(paquete));
	const args = [VERIFICADOR, "material", "--material", `${dir}-material.json`, "--paquete", `${dir}-paquete.json`];
	if (o.aud) args.push("--aud", o.aud);
	if (o.operacion) {
		writeFileSync(`${dir}-op.json`, JSON.stringify(o.operacion));
		args.push("--operacion", `${dir}-op.json`);
	}
	const r = spawnSync("python", args, { encoding: "utf8" });
	assert.ok(r.stdout, `el verificador no respondió: ${r.stderr}`);
	return JSON.parse(r.stdout.trim().split("\n").at(-1)!) as Record<string, unknown>;
}

// ── What a dishonest operator could sign (it holds every key under `operator_hosted`) ──────────

type LlaveInterna = { privateKey: KeyObject; publica: { kid: string } };
const llaveOperador = () => Reflect.get(puerta.pruebas, "operador") as LlaveInterna;
const llaveEmpresa = (tenant: string) => (Reflect.get(puerta.pruebas, "empresas") as Map<string, { llave: LlaveInterna }>).get(tenant)!.llave;
const llaveRegistro = () => Reflect.get(puerta.pruebas, "registro") as LlaveInterna;
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
function firmar(llave: LlaveInterna, payload: Record<string, unknown>, typ = "vxp-stmt+sd-jwt"): string {
	const h = b64u(jcs({ alg: "ES256", kid: llave.publica.kid, typ }));
	const p = b64u(jcs(payload));
	return `${h}.${p}.${b64u(sign("sha256", Buffer.from(`${h}.${p}`, "ascii"), { key: llave.privateKey, dsaEncoding: "ieee-p1363" }))}`;
}
/** Digest of a statement (SPEC §9.2): over `header.payload`, without the signature. */
const huella = (jwt: string) => `sha-256:${createHash("sha256").update(jwt.slice(0, jwt.lastIndexOf(".")), "ascii").digest("base64url")}`;

// ── Scenario ───────────────────────────────────────────────────────────────────────────────────

const conPrueba = await nuevoAgente("asistente.test", true);
const sinPrueba = await nuevoAgente("otro.test", false);
// Round 2 (m5): an agent that lists another version of the extension counts as not listing it.
const versionVieja = await nuevoAgente("version-vieja.test", "0");
const ana = new Usuario(conPrueba, FERRETERIA);
await ana.entrar("+56900000101");

let paqueteFeliz: Record<string, unknown> & { statements: string[]; log: Record<string, unknown> };
let opFinal: Record<string, unknown>;

test("poppy.json declara la extensión con custodia, registro sin testigos y sólo la capacidad de escritura", async () => {
	const doc = await (await red(DESC_FERRETERIA)).json();
	const b = doc.extensions[EXT];
	assert.equal(b.version, "0.1");
	assert.equal(b.company, doc.auth.issuer);
	assert.equal(b.custody, "operator_hosted");
	assert.deepEqual(b.log.witnesses, []);
	assert.deepEqual(b.capabilities.map((c: { name: string }) => c.name), ["pedido.reprogramar_despacho", "pedido.crear"], "las escrituras de la empresa: reprogramar y, desde que vende, crear pedidos");
	assert.ok(!b.capabilities[0].max_assurance.includes("operator_reported_channel_approval"), "bajo Poppy no se promete aprobación por canal");
	// The anchor (SPEC §9.9.1): the issuer's RFC 8414 metadata publishes the trust members, and the copy in poppy.json is identical.
	const meta = await (await red(metadataDe(doc.auth.issuer))).json();
	assert.equal(meta.issuer, doc.auth.issuer);
	assert.ok(meta.poppy_domains.includes(doc.organization.domain));
	for (const m of ["company", "jwks_uri", "operator", "custody", "log"]) assert.deepEqual(b[m], meta.vxp_proof[m], m);
	assert.ok(b.jwks_uri.startsWith(`${doc.auth.issuer}/`), "las llaves de la empresa están bajo su issuer");
	const jwksEmpresa = await (await red(b.jwks_uri)).json();
	const jwksOperador = await (await red(b.operator.jwks_uri)).json();
	assert.notEqual(jwksEmpresa.keys[0].kid, jwksOperador.keys[0].kid);
	assert.ok(!("d" in jwksEmpresa.keys[0]));
});

test("feliz: propuesta → contrapropuesta → revisión 2 → confirmar → lectura de vuelta → resultado, y el verificador independiente lo acepta", async () => {
	const op1 = await ana.proponer("Cambia el despacho del P-1042 al 2026-10-27");
	assert.equal(op1.revision, 1);
	const m1 = op1[EXT] as { latest: string; bundle_url: string };
	assert.equal(decodificar(m1.latest).kind, "terms", "la operación propuesta ya trae los términos firmados por la empresa");
	assert.equal(m1.bundle_url, `${FERRETERIA}/sovras/proof/operations/${op1.operation_id}`);

	const c = await ana.pedir("POST", `${FERRETERIA}/sovras/proof/operations/${op1.operation_id}/counter`, {
		base_revision: 1,
		proposed_terms: { despacho_nuevo: "2026-10-28" },
		note: "Puede ser un día después.",
	});
	assert.equal(c.status, 200, JSON.stringify(c.body));
	assert.equal(c.body.revision, 2);
	assert.match(String(c.body.summary), /2026-10-28/);
	const vieja = await ana.pedir("POST", `${FERRETERIA}/sovras/proof/operations/${op1.operation_id}/counter`, { base_revision: 1, proposed_terms: { despacho_nuevo: "2026-10-26" } });
	assert.equal(vieja.status, 409);
	assert.equal(vieja.body.error, "counter_rejected");
	assert.equal((await interno("sistema?tenant=t_ferreteria_demo")).find((p: { id: string }) => p.id === "P-1042").despacho, "2026-10-24", "una contrapropuesta no ejecuta nada");

	const r = await ana.confirmar(c.body, 2);
	assert.equal(r.body.state, "succeeded");
	opFinal = r.body;
	assert.equal(decodificar((r.body[EXT] as { latest: string }).latest).kind, "outcome");

	const p = await ana.paquete(String(op1.operation_id));
	assert.equal(p.status, 200);
	paqueteFeliz = p.body;
	const kinds = paqueteFeliz.statements.map((s) => decodificar(s).kind);
	assert.deepEqual(kinds, ["request", "terms", "counter", "terms", "user_approval", "execution", "read_back", "outcome"]);
	assert.equal(decodificar(paqueteFeliz.statements[3]).body.answers, huella(paqueteFeliz.statements[2].split("~")[0]), "la revisión 2 responde a la contrapropuesta");

	const v = await verificar(paqueteFeliz, { aud: conPrueba.clientId, operacion: opFinal });
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
	assert.equal(v.revision, 2);
	assert.equal(v.approval, "agent_asserted", "bajo Poppy la aprobación es la que afirma el agente, y se dice así");
	assert.deepEqual(v.derived_assurance, ["issuer_key_attested", "operator_observed", "operator_reported_read_back", "operator_reported_agent_approval"]);
	assert.equal(v.single_root, "operator");
	assert.equal(v.company, FERRETERIA);
	assert.equal(v.anchor, "poppy_domain");
	assert.equal(v.logged, false, "sin testigos no hay `logged`");
	assert.equal(v.log_inclusion, "ok");
	assert.equal(v.operation, "matches");
});

test("privacidad: la dirección y el teléfono no viajan en claro; la dirección sólo como divulgación", async () => {
	const texto = JSON.stringify(paqueteFeliz);
	assert.doesNotMatch(texto, /Calle Ejemplo/);
	assert.doesNotMatch(texto, /\+56/);
	const rb = decodificar(paqueteFeliz.statements[6]);
	assert.equal(rb.body.observed.direccion, undefined);
	assert.equal(rb.body.observed._sd.length, 1);
	const disc = JSON.parse(Buffer.from(paqueteFeliz.statements[6].split("~")[1], "base64url").toString("utf8"));
	assert.equal(disc[1], "direccion");
	assert.match(disc[2], /Calle Ejemplo/);
});

test("B1 (ronda 1): las llaves salen del issuer, no del documento que entrega quien presenta el paquete", async () => {
	// A third party publishes, on its own domain, an Agent Card that claims to be Ferretería Demo, with its own keys.
	const atacante = "https://atacante.test/.well-known/agent-card.json";
	const card = await (await red("https://provider.sovras.test/a2a/t_ferreteria_demo/.well-known/agent-card.json")).json();
	const ext = card.capabilities.extensions.find((x: { uri: string }) => x.uri === "https://vxpprotocol.org/ext/proof/v0.1");
	const falsa = { ...card, capabilities: { ...card.capabilities, extensions: [{ ...ext, params: { ...ext.params, jwks_uri: "https://atacante.test/e.json", custody: "customer_managed" } }] } };
	const conCard = (url: string, doc: unknown) => (m: { anchor: Record<string, string>; docs: Record<string, unknown> }) => {
		m.anchor = { issuer: FERRETERIA, card: url };
		m.docs[url] = JSON.stringify(doc);
	};
	assert.equal((await verificar(paqueteFeliz, { ajustar: conCard(atacante, falsa) })).error, "issuer_not_anchored");
	// The provider's real Agent Card is a faithful copy of the issuer's metadata: with it, the same package validates under the A2A profile.
	const real = "https://provider.sovras.test/a2a/t_ferreteria_demo/.well-known/agent-card.json";
	const v = await verificar(paqueteFeliz, { ajustar: conCard(real, card) });
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.profile, "a2a");
	// A poppy.json copied to another domain does not speak for the company (Poppy §3, rule 1).
	const copia = await verificar(paqueteFeliz, {
		ajustar: (m) => {
			m.anchor = { domain: "copia.test" };
			m.docs["https://copia.test/.well-known/poppy.json"] = m.docs[DESC_FERRETERIA];
		},
	});
	assert.equal(copia.error, "issuer_not_anchored");
	// Even if the company declares `customer_managed`, without verifiable evidence the root is still the operator (SPEC §9.6).
	assert.equal(v.single_root, "operator");
});

test("ronda 2 (M1): un cliente sólo-PACT ancla la prueba con lo que PACT le da (dominio de la marca o AS de PACT)", async () => {
	const marca = "agentes.ferreteria-demo.test";
	const cardProveedor = "https://provider.sovras.test/a2a/t_ferreteria_demo/.well-known/agent-card.json";
	// PACT §2.1: the Card on the brand's domain redirects to the provider's.
	const r = await red(`https://${marca}/.well-known/agent-card.json`, { redirect: "manual" });
	assert.equal(r.status, 302);
	assert.equal(r.headers.get("location"), cardProveedor);
	const as = "https://provider.sovras.test/a2a/t_ferreteria_demo/oauth";
	const metaAs = metadataDe(as);
	const docsPact: Record<string, string> = {
		[`https://${marca}/.well-known/agent-card.json`]: await (await red(cardProveedor)).text(),
		[metaAs]: await (await red(metaAs)).text(),
	};
	const ajustar = (anchor: Record<string, string>, cambiar?: (d: Record<string, unknown>) => void) => (m: { anchor: Record<string, string>; docs: Record<string, unknown> }) => {
		m.anchor = anchor;
		Object.assign(m.docs, docsPact);
		cambiar?.(m.docs);
	};
	const porMarca = await verificar(paqueteFeliz, { ajustar: ajustar({ brand_domain: marca }) });
	assert.equal(porMarca.valid, true, JSON.stringify(porMarca));
	assert.equal(porMarca.anchor, "brand_domain");
	assert.equal(porMarca.company, FERRETERIA);
	assert.equal(porMarca.pact_interface, "https://provider.sovras.test/a2a/t_ferreteria_demo");
	const porAs = await verificar(paqueteFeliz, { ajustar: ajustar({ pact_issuer: as }) });
	assert.equal(porAs.valid, true, JSON.stringify(porAs));
	assert.equal(porAs.anchor, "pact_issuer");
	// If the company does not list that domain, the Card alone anchors nothing.
	const sinDominio = await verificar(paqueteFeliz, {
		ajustar: ajustar({ brand_domain: marca }, (d) => {
			const u = metadataDe(FERRETERIA);
			const meta = JSON.parse(String(d[u]));
			meta.vxp_proof.domains = [];
			d[u] = JSON.stringify(meta);
		}),
	});
	assert.equal(sinDominio.error, "issuer_not_anchored");
	// Nor does a PACT AS other than the one the company lists.
	const otroAs = await verificar(paqueteFeliz, { ajustar: ajustar({ pact_issuer: "https://provider.sovras.test/a2a/t_libreria_demo/oauth" }) });
	assert.equal(otroAs.error, "issuer_not_anchored");
});

test("negativo: una prueba alterada sin volver a firmar → signature_invalid", async () => {
	const s = [...paqueteFeliz.statements];
	const [h, pl, sig] = s[7].split("~")[0].split(".");
	const p = JSON.parse(Buffer.from(pl, "base64url").toString("utf8"));
	p.body.state = "failed";
	s[7] = `${h}.${b64u(jcs(p))}.${sig}~`;
	const v = await verificar({ ...paqueteFeliz, statements: s });
	assert.equal(v.error, "signature_invalid");
});

test("negativo: términos cambiados — el agente vio otro resumen que el que firmó la empresa → operation_terms_mismatch", async () => {
	const v = await verificar(paqueteFeliz, { operacion: { ...opFinal, summary: String(opFinal.summary).replace("sin costo", "con cargo de $3.990") } });
	assert.equal(v.error, "operation_terms_mismatch");
	const v2 = await verificar(paqueteFeliz, { operacion: { ...opFinal, terms: { ...(opFinal.terms as object), despacho_nuevo: "2026-11-30" } } });
	assert.equal(v2.error, "operation_terms_mismatch");
});

test("negativo: el operador re-firma la ejecución sobre la revisión 1 → execution_terms_mismatch", async () => {
	const s = [...paqueteFeliz.statements];
	const t1 = decodificar(s[1]).body.terms_digest;
	const p5 = decodificar(s[5]);
	p5.body.terms_digest = t1;
	s[5] = `${firmar(llaveOperador(), p5)}~`;
	const v = await verificar({ ...paqueteFeliz, statements: s });
	assert.equal(v.error, "execution_terms_mismatch");
});

test("negativo: resultado `succeeded` sin lectura de vuelta (se saca la lectura y se re-firma) → succeeded_without_matching_read_back", async () => {
	const s = paqueteFeliz.statements.slice(0, 6);
	const out = decodificar(paqueteFeliz.statements[7]);
	out.seq = 6;
	out.prev = huella(s[5].split("~")[0]);
	s.push(`${firmar(llaveEmpresa("t_ferreteria_demo"), out)}~`);
	const v = await verificar({ ...paqueteFeliz, statements: s, log: undefined });
	assert.equal(v.error, "succeeded_without_matching_read_back");
	// And with a read-back that does not match:
	const s2 = paqueteFeliz.statements.slice(0, 6);
	const rb = decodificar(paqueteFeliz.statements[6]);
	rb.body.matches_terms = false;
	const rbJwt = firmar(llaveOperador(), rb);
	s2.push(`${rbJwt}~${paqueteFeliz.statements[6].split("~").slice(1).join("~")}`);
	const out2 = decodificar(paqueteFeliz.statements[7]);
	out2.prev = huella(rbJwt);
	s2.push(`${firmar(llaveEmpresa("t_ferreteria_demo"), out2)}~`);
	const v2 = await verificar({ ...paqueteFeliz, statements: s2, log: undefined });
	assert.equal(v2.error, "succeeded_without_matching_read_back");
});

test("negativo: otra empresa — un paquete de Librería Demo no valida con el material de Ferretería Demo, ni un eslabón suyo dentro de una cadena de Demo", async () => {
	const anaLibreria = new Usuario(conPrueba, LIBRERIA);
	await anaLibreria.entrar("+56900000101");
	const op = await anaLibreria.proponer("Cambia el despacho del P-7001 al 2026-10-26");
	const r = await anaLibreria.confirmar(op);
	assert.equal(r.body.state, "succeeded");
	const pa = (await anaLibreria.paquete(String(op.operation_id))).body;
	assert.equal((await verificar(pa, { descubrir: DESC_LIBRERIA, aud: conPrueba.clientId })).valid, true, "con su propio material sí valida");
	assert.equal((await verificar(pa)).error, "company_mismatch");
	// Its outcome, re-chained into Demo's chain:
	const s = paqueteFeliz.statements.slice(0, 7);
	const out = decodificar(pa.statements.at(-1));
	Object.assign(out, { company: decodificar(s[0]).company, op: decodificar(s[0]).op, seq: 7, prev: huella(s[6].split("~")[0]) });
	s.push(`${firmar(llaveEmpresa("t_libreria_demo"), out)}~`);
	assert.equal((await verificar({ ...paqueteFeliz, statements: s, log: undefined })).error, "unknown_issuer");
	// And the Demo account does not see Demo's package:
	assert.equal((await ana.paquete(String(op.operation_id))).status, 404);
});

test("negativo: replay — un resultado de otra operación insertado, o el paquete presentado por otro agente", async () => {
	const op = await ana.proponer("Cambia el despacho del P-1043 al 2026-10-29");
	await ana.confirmar(op);
	const otro = (await ana.paquete(String(op.operation_id))).body;
	const s = [...paqueteFeliz.statements.slice(0, 7), otro.statements.at(-1)];
	assert.equal((await verificar({ ...paqueteFeliz, statements: s })).error, "op_mismatch");
	assert.equal((await verificar(paqueteFeliz, { aud: sinPrueba.clientId })).error, "aud_mismatch");
});

test("negativo: equivocación — una cadena alternativa bien firmada no está en el registro, y un checkpoint distinto del mismo tamaño se detecta", async () => {
	// The operator re-signs the outcome as `failed` and shows it with the real inclusion proofs.
	const s = [...paqueteFeliz.statements];
	const out = decodificar(s[7]);
	out.body.state = "failed";
	s[7] = `${firmar(llaveEmpresa("t_ferreteria_demo"), out)}~`;
	assert.equal((await verificar({ ...paqueteFeliz, statements: s })).error, "log_inclusion_failed");
	// The verifier sees another checkpoint of the same size signed by the log: split view.
	const cp = JSON.parse(Buffer.from(String(paqueteFeliz.log.checkpoint).split(".")[1], "base64url").toString("utf8"));
	const falso = firmar(llaveRegistro(), { ...cp, root_hash: b64u(createHash("sha256").update("otra vista").digest()) }, "vxp-checkpoint+jwt");
	assert.equal((await verificar(paqueteFeliz, { checkpointVivo: falso })).error, "equivocation_detected");
	// With the real live checkpoint (larger), RFC 9162 consistency does match.
	const ok = await verificar(paqueteFeliz);
	assert.equal(ok.consistency, "ok");
	assert.ok(Number(ok.live_tree_size) > Number(ok.tree_size));
});

test("negativo: el paquete de una operación no se le entrega a otra persona del mismo agente", async () => {
	const bruno = new Usuario(conPrueba, FERRETERIA);
	await bruno.entrar("+56900000202");
	const r = await bruno.paquete(String(opFinal.operation_id));
	assert.equal(r.status, 404);
	assert.equal(r.body.error, "operation_not_found");
});

test("un agente que no lista la extensión no recibe el miembro en la operación", async () => {
	const u = new Usuario(sinPrueba, FERRETERIA);
	await u.entrar("+56900000202");
	const op = await u.proponer("Cambia el despacho del P-2001 al 2026-10-24");
	assert.equal(op[EXT], undefined);
	assert.equal(op.state, "proposed");
});

test("un agente que lista otra versión de la extensión (Poppy §3.3: la mayor) no recibe el miembro", async () => {
	const u = new Usuario(versionVieja, FERRETERIA);
	await u.entrar("+56900000202");
	const op = await u.proponer("Cambia el despacho del P-2001 al 2026-10-25");
	assert.equal(op[EXT], undefined);
	assert.equal(op.state, "proposed");
});

test("timeout (VXP Proof): mientras no se sabe, la empresa firma `unknown`; al leer de vuelta, una corrección a `succeeded` que cita esa lectura", async () => {
	await interno("sistema", { tenant: "t_ferreteria_demo", proximaFalla: "desconocida" });
	const op = await ana.proponer("Cambia el despacho del P-1042 al 2026-10-30");
	const c = await ana.confirmar(op);
	assert.equal(c.body.state, "in_progress", "Poppy sigue viendo in_progress: nunca failed sin saber");
	const enCurso = Reflect.get(puerta.pruebas, "cadenas").get(`t_ferreteria_demo|${op.operation_id}`).declaraciones.map((d: { sdjwt: string }) => d.sdjwt);
	assert.deepEqual(enCurso.map((s: string) => decodificar(s).kind), ["request", "terms", "user_approval", "execution", "outcome"]);
	const v = await verificar({ v: "0.1", company: FERRETERIA, op: op.operation_id, statements: enCurso });
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "unknown", "lo pendiente es evidencia firmada de que no se sabe, no la falta de evidencia");
	const p = (await ana.paquete(String(op.operation_id))).body; // reading the package attempts verification
	assert.deepEqual(p.statements.map((s: string) => decodificar(s).kind), ["request", "terms", "user_approval", "execution", "outcome", "read_back", "correction"]);
	const corr = decodificar(p.statements.at(-1));
	assert.equal(corr.body.read_back, decodificar(p.statements.at(-2)) && corr.body.read_back, "la corrección cita una lectura");
	const v2 = await verificar(p, { operacion: (await ana.pedir("GET", `${FERRETERIA}/poppy/operaciones/${op.operation_id}`)).body });
	assert.equal(v2.final_state, "succeeded", JSON.stringify(v2));
});

test("falla definitiva: hay ejecución y resultado `failed`, sin lectura de vuelta", async () => {
	await interno("sistema", { tenant: "t_ferreteria_demo", proximaFalla: "definitiva" });
	const op = await ana.proponer("Cambia el despacho del P-1042 al 2026-10-31");
	const c = await ana.confirmar(op);
	assert.equal(c.body.state, "failed");
	const v = await verificar((await ana.paquete(String(op.operation_id))).body, { operacion: c.body });
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "failed");
	assert.deepEqual(v.derived_assurance, ["issuer_key_attested", "operator_observed", "operator_reported_agent_approval"]);
});

test("revisión de la empresa: va después de la aprobación del cliente sobre la misma huella; aprobar y rechazar", async () => {
	const op = await ana.proponer("Cambia el despacho del P-1043 al 2026-11-25");
	assert.equal((await ana.confirmar(op)).body.state, "in_progress");
	const [rev] = await interno("revisiones?tenant=t_ferreteria_demo");
	await interno(`revisiones/${rev.review_id}`, { tenant: "t_ferreteria_demo", decision: "aprobada" });
	const p = (await ana.paquete(String(op.operation_id))).body;
	assert.deepEqual(p.statements.map((s: string) => decodificar(s).kind), ["request", "terms", "user_approval", "company_review", "execution", "read_back", "outcome"]);
	assert.equal((await verificar(p)).final_state, "succeeded");

	const op2 = await ana.proponer("Cambia el despacho del P-1043 al 2026-12-20");
	await ana.confirmar(op2);
	const [rev2] = await interno("revisiones?tenant=t_ferreteria_demo");
	await interno(`revisiones/${rev2.review_id}`, { tenant: "t_ferreteria_demo", decision: "rechazada" });
	const final = (await ana.pedir("GET", `${FERRETERIA}/poppy/operaciones/${op2.operation_id}`)).body;
	assert.equal(final.state, "failed");
	const v = await verificar((await ana.paquete(String(op2.operation_id))).body, { operacion: final });
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "failed");
	assert.equal(v.approval, null, "la empresa denegó: no queda una aprobación vigente");
});

test("el emisor no deja que un rol firme lo que es del otro (SPEC §9.5 regla 3), ni números fuera del perfil JCS", () => {
	const op = decodificar(paqueteFeliz.statements[0]).op;
	assert.throws(() => puerta.pruebas.emitir("t_ferreteria_demo", op, "operador", "outcome", { state: "succeeded" }), /no firma/);
	assert.throws(() => puerta.pruebas.emitir("t_ferreteria_demo", op, "empresa", "read_back", {}), /no firma/);
	assert.throws(() => jcs({ monto: 1.5 }), /enteros/);
	assert.equal(jcs({ b: 1, a: [true, null, "ñ"] }), '{"a":[true,null,"ñ"],"b":1}');
});

test("una revisión nueva que cruza el umbral exige revisión de la empresa aunque la revisión 1 no la exigía", async () => {
	const op = await ana.proponer("Cambia el despacho del P-1042 al 2026-11-01");
	assert.doesNotMatch(String(op.summary), /lo revisa una persona/);
	const op2 = await ana.proponer("Mejor cambia el P-1042 al 2026-12-24");
	assert.equal(op2.revision, 2);
	assert.match(String(op2.summary), /lo revisa una persona/);
	const c = await ana.confirmar(op2);
	assert.equal(c.body.state, "in_progress");
	const pend = await interno("revisiones?tenant=t_ferreteria_demo");
	assert.ok(pend.some((x: { huella: string }) => x.huella), "quedó en la bandeja de la empresa");
	for (const x of pend) await interno(`revisiones/${x.review_id}`, { tenant: "t_ferreteria_demo", decision: "rechazada" });
});

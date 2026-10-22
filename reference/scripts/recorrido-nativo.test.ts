// A reproducible run of the native profile over the network, for publication.
//
// The gateway runs in its own process with no adapter (VXP_ADAPTERS=none) and persistent proof keys
// (VXP_KEYS_DIR). The personal agent is another HTTP server that publishes its Client ID Metadata Document,
// its JWKS and its inbox, and signs with node:crypto directly. Everything goes over TCP: discovery, OAuth with
// DPoP, account linking through the company's page, request, acceptance, result, proof, and a request the
// company starts inside the relationship. Each proof is checked by the independent verifier fetching public
// material over HTTP (`vivo` mode), and the material is saved so anyone can verify it offline.
//
// Usage, from reference/:
//   VXP_RECORRIDO_DIR=<out> VXP_KEYS_DIR=<private keys dir> node --test scripts/recorrido-nativo.test.ts
// Writes to <out>: recorrido.json (every HTTP exchange of the agent), and paquete-, operacion- and
// material-<op>.json per operation. The keys directory holds private keys: keep it out of <out>.
// Uses ports 3730 (gateway) and 3734 (agent).

import assert from "node:assert/strict";
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

const SALIDA = process.env.VXP_RECORRIDO_DIR;
const LLAVES = process.env.VXP_KEYS_DIR;
assert.ok(SALIDA && LLAVES, "set VXP_RECORRIDO_DIR and VXP_KEYS_DIR");
assert.ok(!resolve(LLAVES).startsWith(resolve(SALIDA)), "the keys directory must not be inside the output directory");
mkdirSync(SALIDA, { recursive: true });
const RAIZ = join(import.meta.dirname, "..");
const VERIFICADOR = join(RAIZ, "..", "verifier", "verificar_paquete.py");
const MATERIAL = join(RAIZ, "scripts", "capturar-material.py");

// ── Every HTTP exchange of the agent is recorded ─────────────────────────────────────────────────
const registro: unknown[] = [];
const fetchOriginal = globalThis.fetch;
globalThis.fetch = async (input: RequestInfo | URL, init: RequestInit = {}) => {
	const url = String(input instanceof Request ? input.url : input);
	const r = await fetchOriginal(input, init);
	const txt = await r.clone().text();
	let body: unknown = txt;
	try { body = JSON.parse(txt); } catch {}
	let req: unknown = init.body ? String(init.body) : null;
	try { req = JSON.parse(String(init.body)); } catch {}
	// The test-only key of the gateway's internal routes is never written down.
	const headers = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).filter(([k]) => k.toLowerCase() !== "x-sovras-prueba"));
	registro.push({ at: new Date().toISOString(), method: init.method ?? "GET", url, headers, request: req, status: r.status, response: body });
	return r;
};
after(() => writeFileSync(join(SALIDA, "recorrido.json"), JSON.stringify(registro, null, 1)));

const P = "http://localhost:3730";
const AG = "http://localhost:3734";
const ISSUER = `${P}/e/ferreteria-demo`;
const V1 = `${ISSUER}/v1`;
const CAP = "pedido.reprogramar_despacho";
const RAR_REL = "https://vxpprotocol.org/rar/relationship";
const tmp = mkdtempSync(join(tmpdir(), "vxp-recorrido-"));

// ── Minimal JOSE with node:crypto (ES256, RFC 9449 DPoP) ───────────────────────────────────────
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
const asercion = (llave: Llave, iss: string, sub: string, aud: string) => jwt(llave, { typ: "JWT" }, { iss, sub, aud, iat: ahora(), exp: ahora() + 60, jti: jti() });
function dpop(llave: Llave, method: string, url: string, token?: string) {
	const u = new URL(url);
	return jwt(llave, { typ: "dpop+jwt", jwk: llave.jwk }, { jti: jti(), htm: method, htu: `${u.origin}${u.pathname}`, iat: ahora(), ...(token ? { ath: b64u(createHash("sha256").update(token).digest()) } : {}) });
}

let servidor: ChildProcess;
let interna = "";
const buzon: { message: string }[] = [];
let agente: ReturnType<typeof createServer>;
const clave = nuevaLlave();
const llaveDpop = nuevaLlave();
const clientId = `${AG}/agent.json`;
const SUB = `usr_${randomBytes(4).toString("hex")}`;

before(async () => {
	agente = createServer((req, res) => {
		if (req.method === "POST" && req.url === "/vxp/inbox") {
			let b = "";
			req.on("data", (c) => (b += c));
			req.on("end", () => {
				buzon.push(JSON.parse(b));
				res.writeHead(202).end();
			});
			return;
		}
		// VXP extensions only: no Poppy `operations`, no PACT.
		const doc =
			req.url === "/agent.json"
				? { client_id: clientId, client_name: "Test assistant (native profile)", jwks_uri: `${AG}/jwks.json`, token_endpoint_auth_method: "private_key_jwt", extensions: { "vxpprotocol.org/proof": { version: "0.1" }, "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `${AG}/vxp/inbox` } } }
				: req.url === "/jwks.json"
					? { keys: [{ ...clave.jwk, alg: "ES256", use: "sig" }] }
					: null;
		res.writeHead(doc ? 200 : 404, { "content-type": "application/json" }).end(JSON.stringify(doc ?? {}));
	});
	await new Promise<void>((ok) => agente.listen(3734, ok));
	servidor = spawn(process.execPath, ["src/main.ts"], { cwd: RAIZ, env: { ...process.env, PORT: "3730", PA_PORT: "3732", ORIGENES_LOCALES: AG, SOVRAS_MUTAR: "", VXP_DATOS_NEUTROS: "1", VXP_ADAPTERS: "none", VXP_KEYS_DIR: LLAVES } });
	interna = await new Promise<string>((ok, mal) => {
		const t = setTimeout(() => mal(new Error("the gateway did not start")), 15_000);
		servidor.stdout!.on("data", (d) => {
			const m = String(d).match(/llave interna: (\S+)/);
			if (m) {
				clearTimeout(t);
				ok(m[1]);
			}
		});
	});
});
after(() => {
	servidor?.kill();
	agente?.close();
});

// The company's own console (simulated): starting a request inside the relationship is recorded; reading the
// simulated WhatsApp line is not.
const interno = async (path: string, body?: unknown) =>
	(await (path.startsWith("relaciones/") ? fetch : fetchOriginal)(`${P}/interno/${path}`, { method: body ? "POST" : "GET", headers: { "x-sovras-prueba": interna, "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) })).json();
let token = "";
const base = () => ({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: V1 });
async function tokenReq(form: Record<string, string>) {
	const url = `${ISSUER}/oauth/token`;
	const body = new URLSearchParams({ ...form, ...base(), client_assertion: asercion(clave, clientId, clientId, ISSUER), assertion: asercion(clave, clientId, SUB, ISSUER) });
	const r = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: dpop(llaveDpop, "POST", url) }, body });
	return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}
async function pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
	const r = await fetch(url, { method, headers: { authorization: `DPoP ${token}`, dpop: dpop(llaveDpop, method, url, token), "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
	const t = await r.text();
	return { status: r.status, body: t ? JSON.parse(t) : null };
}
const comoOperacion = (v: Record<string, any>) => ({ operation_id: v.operation_id, revision: v.proposal.revision, summary: v.proposal.summary, terms: v.proposal.terms, expires_at: v.proposal.expires_at, user_approval_required: v.proposal.user_approval_required, state: v.projections.poppy, result: v.result });

function verificar(paquete: unknown, operacion: unknown) {
	const op = (paquete as { op: string }).op;
	const p = join(SALIDA!, `paquete-${op}.json`);
	const o = join(SALIDA!, `operacion-${op}.json`);
	writeFileSync(p, JSON.stringify(paquete, null, 1));
	writeFileSync(o, JSON.stringify(operacion, null, 1));
	const r = spawnSync("python", [VERIFICADOR, "vivo", "--http-local", "--issuer", ISSUER, "--paquete", p, "--aud", clientId, "--operacion", o], { encoding: "utf8" });
	assert.ok(r.stdout, r.stderr);
	const veredicto = JSON.parse(r.stdout.trim().split("\n").at(-1)!);
	const m = spawnSync("python", [MATERIAL, VERIFICADOR, P, ISSUER, p, join(SALIDA!, `material-${op}.json`), o], { encoding: "utf8" });
	registro.push({ at: new Date().toISOString(), verifier: "verifier/verificar_paquete.py vivo", op, verdict: veredicto, material_capture: (m.stdout + m.stderr).trim().split("\n").slice(-2) });
	return veredicto;
}

let relacion = "";

test("R1 · native only: discover → ask (authority missing) → the person approves on the company's page → ask → accept → one execution → proof verified by the independent verifier", async () => {
	for (const u of ["/.well-known/poppy.json", "/.well-known/agent-card.json"]) assert.equal((await fetch(`${P}${u}`)).status, 404, u);
	const desc = await (await fetch(`${P}/.well-known/vxp.json`)).json();
	assert.equal(desc.endpoint, V1);
	const meta = await (await fetch(`${P}/.well-known/oauth-authorization-server/e/ferreteria-demo`)).json();
	assert.equal(meta.issuer, desc.issuer);
	assert.ok(!("poppy_domains" in meta));

	const s = await tokenReq({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
	assert.equal(s.status, 200, JSON.stringify(s.body));
	token = String(s.body.access_token);
	const idem = randomBytes(9).toString("base64url");
	const pedido = { operation: CAP, target: { order_ref: "P-1042" }, parameters: { delivery_date: "2026-10-28" } };
	const r0 = await pedir("POST", `${V1}/requests`, pedido, { "idempotency-key": idem });
	assert.equal(r0.status, 202);
	assert.equal(r0.body.state, "authorization_required");

	const det = [...r0.body.authorization.authorization_details, { type: RAR_REL, actions: ["despacho.proponer_cambio"], identifier: "relationship", limits: { max_per_day: 2, duration_seconds: 3600 } }];
	const dev = await (await fetch(`${ISSUER}/oauth/device`, { method: "POST", body: new URLSearchParams({ ...base(), client_assertion: asercion(clave, clientId, clientId, ISSUER), authorization_details: JSON.stringify(det) }) })).json();
	await fetch(dev.verification_uri_complete);
	const form = (o: Record<string, string | string[]>) => {
		const b = new URLSearchParams();
		for (const [k, v] of Object.entries(o)) for (const x of [v].flat()) b.append(k, x);
		return b;
	};
	await fetch(`${ISSUER}/vincular/telefono`, { method: "POST", body: form({ user_code: dev.user_code, telefono: "+56 9 0000 0101" }), redirect: "manual" });
	const otp = (await interno("whatsapp/salida?tenant=t_ferreteria_demo")).at(-1).texto.match(/código es (\d{6})/)[1];
	await fetch(`${ISSUER}/vincular/codigo`, { method: "POST", body: form({ user_code: dev.user_code, codigo: otp }), redirect: "manual" });
	const dec = await fetch(`${ISSUER}/vincular/decision`, { method: "POST", body: form({ user_code: dev.user_code, decision: "allow", scope: ["pedidos:modificar", "vxp:relationship"] }), redirect: "manual" });
	assert.equal(dec.status, 303);
	const t = await tokenReq({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
	assert.equal(t.status, 200, JSON.stringify(t.body));
	token = String(t.body.access_token);
	relacion = (t.body.relationships as { relationship_id: string }[])[0].relationship_id;

	const r1 = await pedir("POST", `${V1}/requests`, pedido, { "idempotency-key": idem });
	assert.equal(r1.status, 201, JSON.stringify(r1.body));
	assert.equal(r1.body.request_id, r0.body.request_id, "the same request, re-evaluated");
	const a = await pedir("POST", `${V1}/proposals/${r1.body.proposal.id}/accept`, { approved_by: "user" });
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	const v = verificar((await pedir("GET", `${V1}/requests/${r1.body.request_id}/proof`)).body, comoOperacion(a.body));
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.anchor, "issuer");
	assert.equal(v.final_state, "succeeded");
});

test("R2 · native only: the company starts a change inside the relationship; the signed message reaches the agent's inbox; the agent accepts", async () => {
	const ini = await interno("relaciones/iniciar", { tenant: "t_ferreteria_demo", relationship_id: relacion, action: "despacho.proponer_cambio", params: { order_ref: "P-1043", delivery_date: "2026-10-30" } });
	assert.equal(ini.http, 202, JSON.stringify(ini));
	const c = JSON.parse(Buffer.from(buzon.at(-1)!.message.split(".")[1], "base64url").toString()).content as { request_url: string; proposal_id: string };
	const a = await pedir("POST", `${V1}/proposals/${c.proposal_id}/accept`, { approved_by: "user" });
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	const v = verificar((await pedir("GET", `${c.request_url}/proof`)).body, comoOperacion(a.body));
	assert.equal(v.valid, true, JSON.stringify(v));
});

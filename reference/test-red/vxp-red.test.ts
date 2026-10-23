// VXP over the network: the gateway runs in its own process (src/main.ts, node:http) and the personal agent is
// another HTTP server that publishes its Client ID Metadata Document, its JWKS and its inbox. Everything goes over
// TCP: discovery, OAuth with DPoP, «Vincular con WhatsApp» (forms), request, acceptance,
// outcome, evidence and a company-initiated action. The evidence is checked by the
// Python verifier, which fetches the material over HTTP itself (`vivo` mode).
//
// Usage: node --test test-red/vxp-red.test.ts   (uses ports 3630, 3632 and 3634)

import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { decodeJwt, verifyWith } from "../src/jose.ts";
import { dpopProof, generateKey, randomId, type SigningKey, signAssertion } from "../vendor/poppy-kit/validate/jose.ts";

const RAIZ = join(import.meta.dirname, "..");
const P = "http://localhost:3630";
const AG = "http://localhost:3634";
const FERRETERIA = `${P}/e/ferreteria-demo`;
const V1 = `${FERRETERIA}/v1`;
const CAP = "pedido.reprogramar_despacho";
const RAR = "https://vxpprotocol.org/rar/capability";
const RAR_REL = "https://vxpprotocol.org/rar/relationship";
const tmp = mkdtempSync(join(tmpdir(), "vxp-red-"));

let servidor: ChildProcess;
let llave = "";
const buzon: { message: string }[] = [];
let agente: ReturnType<typeof createServer>;
let clave: SigningKey;
const clientId = `${AG}/agent.json`;

before(async () => {
	clave = await generateKey(true);
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
		const doc =
			req.url === "/agent.json"
				? { client_id: clientId, client_name: "Asistente de prueba (red)", jwks_uri: `${AG}/jwks.json`, token_endpoint_auth_method: "private_key_jwt", extensions: { operations: { version: "1" }, "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `${AG}/vxp/inbox` } } }
				: req.url === "/jwks.json"
					? { keys: [clave.publicJwk] }
					: null;
		res.writeHead(doc ? 200 : 404, { "content-type": "application/json" }).end(JSON.stringify(doc ?? {}));
	});
	await new Promise<void>((ok) => agente.listen(3634, ok));
	servidor = spawn(process.execPath, ["src/main.ts"], { cwd: RAIZ, env: { ...process.env, PORT: "3630", PA_PORT: "3632", ORIGENES_LOCALES: AG, SOVRAS_MUTAR: "" } });
	llave = await new Promise<string>((ok, mal) => {
		const t = setTimeout(() => mal(new Error("el servidor no partió")), 15_000);
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

const interno = async (path: string, body?: unknown) =>
	(await fetch(`${P}/interno/${path}`, { method: body ? "POST" : "GET", headers: { "x-sovras-prueba": llave, "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) })).json();

let dpopKey: SigningKey;
let token = "";
const SUB = `usr_red_${randomId(6)}`;
const base = () => ({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: V1 });
async function tokenReq(form: Record<string, string>) {
	const url = `${FERRETERIA}/oauth/token`;
	const body = new URLSearchParams({ ...form, ...base(), client_assertion: await signAssertion({ key: clave, iss: clientId, sub: clientId, aud: FERRETERIA }), assertion: await signAssertion({ key: clave, iss: clientId, sub: SUB, aud: FERRETERIA }) });
	const r = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: dpopKey, method: "POST", url }) }, body });
	return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}
async function pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
	const r = await fetch(url, { method, headers: { authorization: `DPoP ${token}`, dpop: await dpopProof({ key: dpopKey, method, url, accessToken: token }), "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
	const t = await r.text();
	return { status: r.status, body: t ? JSON.parse(t) : null };
}
// Child processes run asynchronously: a blocking spawnSync freezes this process's event loop, the server then
// closes the idle keep-alive socket, and the next fetch reuses the dead socket and fails with ECONNRESET.
const ejecutar = (cmd: string, args: string[]) =>
	new Promise<{ status: number | null; stdout: string; stderr: string }>((ok) => {
		const h = spawn(cmd, args);
		let stdout = "";
		let stderr = "";
		h.stdout.on("data", (d) => (stdout += d));
		h.stderr.on("data", (d) => (stderr += d));
		h.on("close", (status) => ok({ status, stdout, stderr }));
	});
async function verificador(paquete: unknown, operacion?: unknown) {
	const n = randomId(6);
	writeFileSync(join(tmp, `${n}-p.json`), JSON.stringify(paquete));
	const args = [join(RAIZ, "..", "verifier", "verificar_paquete.py"), "vivo", "--http-local", "--issuer", FERRETERIA, "--paquete", join(tmp, `${n}-p.json`), "--aud", clientId];
	if (operacion) {
		writeFileSync(join(tmp, `${n}-o.json`), JSON.stringify(operacion));
		args.push("--operacion", join(tmp, `${n}-o.json`));
	}
	const r = await ejecutar("python", args);
	assert.ok(r.stdout, r.stderr);
	return JSON.parse(r.stdout.trim().split("\n").at(-1)!);
}
const comoPoppy = (v: Record<string, any>) => ({ operation_id: v.operation_id, revision: v.proposal.revision, summary: v.proposal.summary, terms: v.proposal.terms, expires_at: v.proposal.expires_at, user_approval_required: v.proposal.user_approval_required, state: v.projections.poppy, result: v.result });

let relacion = "";

test("R1 · por red: descubrir → pedir (faltan permisos) → vincular por WhatsApp → pedir → aceptar → resultado verificado → evidencia verificada por un tercero", async () => {
	const desc = await (await fetch(`${P}/.well-known/vxp.json`)).json();
	assert.equal(desc.endpoint, V1);
	assert.equal(desc.status, "experimental");
	const meta = await (await fetch(`${P}/.well-known/oauth-authorization-server/e/ferreteria-demo`)).json();
	assert.equal(meta.issuer, desc.issuer);
	assert.ok(meta.authorization_details_types_supported.includes(RAR_REL));

	dpopKey = await generateKey(false);
	const s = await tokenReq({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
	assert.equal(s.status, 200, JSON.stringify(s.body));
	token = String(s.body.access_token);
	const idem = randomId(12);
	const pedido = { operation: CAP, target: { order_ref: "P-1042" }, parameters: { delivery_date: "2026-10-28" } };
	const r0 = await pedir("POST", `${V1}/requests`, pedido, { "idempotency-key": idem });
	assert.equal(r0.status, 202);
	assert.equal(r0.body.state, "authorization_required");

	// Device Authorization with what is missing + the bilateral relationship; the person uses the page over HTTP.
	const det = [...r0.body.authorization.authorization_details, { type: RAR_REL, actions: ["despacho.proponer_cambio"], identifier: "relationship", limits: { max_per_day: 2, duration_seconds: 3600 } }];
	const dev = await (await fetch(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ ...base(), client_assertion: await signAssertion({ key: clave, iss: clientId, sub: clientId, aud: FERRETERIA }), authorization_details: JSON.stringify(det) }) })).json();
	const pagina = await (await fetch(dev.verification_uri_complete)).text();
	assert.match(pagina, /del pedido P-1042/);
	assert.match(pagina, /contacte a tu asistente/);
	const form = (o: Record<string, string | string[]>) => {
		const b = new URLSearchParams();
		for (const [k, v] of Object.entries(o)) for (const x of [v].flat()) b.append(k, x);
		return b;
	};
	await fetch(`${FERRETERIA}/vincular/telefono`, { method: "POST", body: form({ user_code: dev.user_code, telefono: "+56 9 0000 0101" }), redirect: "manual" });
	const otp = (await interno("whatsapp/salida?tenant=t_ferreteria_demo")).at(-1).texto.match(/código es (\d{6})/)[1];
	await fetch(`${FERRETERIA}/vincular/codigo`, { method: "POST", body: form({ user_code: dev.user_code, codigo: otp }), redirect: "manual" });
	const dec = await fetch(`${FERRETERIA}/vincular/decision`, { method: "POST", body: form({ user_code: dev.user_code, decision: "allow", scope: ["pedidos:modificar", "vxp:relationship"] }), redirect: "manual" });
	assert.equal(dec.status, 303);
	const t = await tokenReq({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
	assert.equal(t.status, 200, JSON.stringify(t.body));
	token = String(t.body.access_token);
	relacion = (t.body.relationships as { relationship_id: string }[])[0].relationship_id;

	const r1 = await pedir("POST", `${V1}/requests`, pedido, { "idempotency-key": idem });
	assert.equal(r1.status, 201, JSON.stringify(r1.body));
	assert.equal(r1.body.request_id, r0.body.request_id, "la misma solicitud, reevaluada");
	const a = await pedir("POST", `${V1}/proposals/${r1.body.proposal.id}/accept`, { approved_by: "user" });
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	assert.equal((await interno("sistema?tenant=t_ferreteria_demo")).find((p: { id: string }) => p.id === "P-1042").despacho, "2026-10-28", "el sistema de la empresa cambió");
	const paq = (await pedir("GET", `${V1}/requests/${r1.body.request_id}/proof`)).body;
	const v = await verificador(paq, comoPoppy(a.body));
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
	assert.ok(v.derived_assurance.includes("operator_reported_read_back"));
});

test("R2 · por red: la empresa inicia un cambio dentro de la relación; el mensaje firmado llega al buzón del agente por HTTP; el agente lo verifica y lo acepta", async () => {
	const ini = await interno("relaciones/iniciar", { tenant: "t_ferreteria_demo", relationship_id: relacion, action: "despacho.proponer_cambio", params: { order_ref: "P-1043", delivery_date: "2026-10-30" } });
	assert.equal(ini.delivery, "entregado", JSON.stringify(ini));
	assert.equal(ini.http, 202);
	const msg = buzon.at(-1)!.message;
	const meta = await (await fetch(`${P}/.well-known/oauth-authorization-server/e/ferreteria-demo`)).json();
	const jwks = await (await fetch(meta.vxp_relationship.jwks_uri)).json();
	const d = decodeJwt(msg)!;
	assert.ok(jwks.keys.some((k: Record<string, unknown>) => verifyWith(d, k, ["ES256"])), "el agente verifica la firma con la llave anclada al issuer");
	assert.equal(d.payload.aud, clientId);
	assert.equal(d.payload.sub, SUB);
	const c = d.payload.content as { request_url: string; proposal_id: string };
	const a = await pedir("POST", `${V1}/proposals/${c.proposal_id}/accept`, { approved_by: "user" });
	assert.equal(a.body.state, "succeeded", JSON.stringify(a.body));
	const v = await verificador((await pedir("GET", `${c.request_url}/proof`)).body, comoPoppy(a.body));
	assert.equal(v.valid, true, JSON.stringify(v));
	assert.equal(v.final_state, "succeeded");
});

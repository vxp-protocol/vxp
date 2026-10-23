// Stress sandbox over the network: the gateway in its own process (src/main.ts, node:http) serves the
// hardware store at http://localhost:3610 and the hotel at http://127.0.0.1:3610 (another host, same port:
// the gateway routes by the Host header, as with two tunnels). The agent is another HTTP server (3614).
// All over TCP: discovery on the hotel's domain, OAuth with DPoP, «Vincular con WhatsApp» via
// forms, request, permission EXPANSION midway, acceptance with the connection CUT (the socket
// closes with no response) and retry, evidence checked by the Python verifier fetching the
// material over HTTP, and the evidence collector exporting the run with its attribution.
//
// Usage: node --test test-red/exigencia-red.test.ts   (uses ports 3610 and 3614)

import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { dpopProof, generateKey, randomId, type SigningKey, signAssertion } from "../vendor/poppy-kit/validate/jose.ts";

const RAIZ = join(import.meta.dirname, "..");
const PUERTO = 3610;
const P = `http://localhost:${PUERTO}`;
const DOM_HOTEL = `http://127.0.0.1:${PUERTO}`;
const AG = "http://localhost:3614";
const RAR = "https://vxpprotocol.org/rar/capability";
const tmp = mkdtempSync(join(tmpdir(), "vxp-exigencia-red-"));

let servidor: ChildProcess;
let llave = "";
let agente: ReturnType<typeof createServer>;
let clave: SigningKey;
let dpopKey: SigningKey;
let token = "";
const clientId = `${AG}/agent.json`;
const SUB = `usr_red_${randomId(6)}`;
let HOTEL = "";

before(async () => {
	clave = await generateKey(true);
	dpopKey = await generateKey(false);
	agente = createServer((req, res) => {
		const doc =
			req.url === "/agent.json"
				? { client_id: clientId, client_name: "Asistente de prueba (red, exigencia)", jwks_uri: `${AG}/jwks.json`, token_endpoint_auth_method: "private_key_jwt", extensions: { operations: { version: "1" } } }
				: req.url === "/jwks.json"
					? { keys: [clave.publicJwk] }
					: null;
		res.writeHead(doc ? 200 : 404, { "content-type": "application/json" }).end(JSON.stringify(doc ?? {}));
	});
	await new Promise<void>((ok) => agente.listen(3614, ok));
	servidor = spawn(process.execPath, ["src/main.ts"], { cwd: RAIZ, env: { ...process.env, PORT: String(PUERTO), PA_PORT: "3612", HOTEL_ORIGIN: DOM_HOTEL, ORIGENES_LOCALES: AG, SOVRAS_MUTAR: "" } });
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
const base = () => ({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: `${HOTEL}/v1` });
async function tokenReq(form: Record<string, string>) {
	const url = `${HOTEL}/oauth/token`;
	const body = new URLSearchParams({ ...form, ...base(), client_assertion: await signAssertion({ key: clave, iss: clientId, sub: clientId, aud: HOTEL }), assertion: await signAssertion({ key: clave, iss: clientId, sub: SUB, aud: HOTEL }) });
	const r = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof({ key: dpopKey, method: "POST", url }) }, body });
	return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}
async function pedir(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
	const r = await fetch(url, { method, headers: { authorization: `DPoP ${token}`, dpop: await dpopProof({ key: dpopKey, method, url, accessToken: token }), "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
	const t = await r.text();
	return { status: r.status, body: t ? JSON.parse(t) : null };
}
/** RFC 8628 + RFC 9396 via forms, like a person with a browser; the OTP is read by the operator of the simulated line. */
async function autorizar(detalles: unknown[], marcar: string[]) {
	const dev = await fetch(`${HOTEL}/oauth/device`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...base(), client_assertion: await signAssertion({ key: clave, iss: clientId, sub: clientId, aud: HOTEL }), authorization_details: JSON.stringify(detalles) }) }).then((r) => r.json());
	const post = (paso: string, f: Record<string, string | string[]>) => {
		const b = new URLSearchParams();
		for (const [k, v] of Object.entries(f)) for (const x of [v].flat()) b.append(k, x);
		return fetch(`${HOTEL}/vincular/${paso}`, { method: "POST", body: b, redirect: "manual" });
	};
	await post("telefono", { user_code: dev.user_code, telefono: "+56 9 0000 0101" });
	const otp = ((await interno("whatsapp/salida?tenant=t_hotel_demo")) as { texto: string }[]).at(-1)!.texto.match(/código es (\d{6})/)![1];
	await post("codigo", { user_code: dev.user_code, codigo: otp });
	await post("decision", { user_code: dev.user_code, decision: "allow", scope: marcar });
	const t = await tokenReq({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code });
	assert.equal(t.status, 200, JSON.stringify(t.body));
	token = String(t.body.access_token);
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

test("RX1 · por red, hotel: descubre en SU dominio → pide → vincula → amplía el permiso a mitad → acepta con la conexión cortada → reintenta → UNA reserva; el verificador en Python y el recolector lo confirman desde fuera", async () => {
	const doc = await fetch(`${DOM_HOTEL}/.well-known/vxp.json`).then((r) => r.json());
	assert.equal(doc.organization.name, "Hotel Demo");
	HOTEL = doc.issuer;
	assert.equal(HOTEL, `${P}/e/hotel-demo`, "el issuer vive en el origen de SOVRAS, el descubrimiento en el dominio del hotel");
	const t0 = await tokenReq({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
	token = String(t0.body.access_token);
	const hoy = new Date();
	const dia = (n: number) => new Date(hoy.getTime() + n * 86_400_000).toISOString().slice(0, 10);
	const cuerpo = { operation: "reserva.crear", parameters: { room_type: "DBL-EST", check_in: dia(45), check_out: dia(47), adults: 2 } };
	const llaveIdem = randomId(12);
	const r0 = await pedir("POST", `${HOTEL}/v1/requests`, cuerpo, { "idempotency-key": llaveIdem });
	assert.equal(r0.status, 202, JSON.stringify(r0.body));
	await autorizar(r0.body.authorization.authorization_details, ["reservas:crear"]);
	const r1 = await pedir("POST", `${HOTEL}/v1/requests`, cuerpo, { "idempotency-key": llaveIdem });
	assert.equal(r1.status, 201);
	assert.equal(r1.body.request_id, r0.body.request_id);
	const c = await pedir("POST", `${HOTEL}/v1/proposals/${r1.body.proposal.id}/counter`, { proposed_terms: { add_services: [{ code: "DESAYUNO" }] } });
	assert.equal(c.status, 200, JSON.stringify(c.body));
	const sin = await pedir("POST", `${HOTEL}/v1/proposals/${c.body.proposal.id}/accept`, { approved_by: "user" });
	assert.equal(sin.status, 403);
	await autorizar(sin.body.authorization_details, ["reservas:crear"]);
	await interno("condiciones", { tenant: "t_hotel_demo", cortar_respuestas: 1 });
	await assert.rejects(pedir("POST", `${HOTEL}/v1/proposals/${c.body.proposal.id}/accept`, { approved_by: "user" }), "la conexión se corta sin respuesta");
	const otra = await pedir("POST", `${HOTEL}/v1/proposals/${c.body.proposal.id}/accept`, { approved_by: "user" });
	assert.equal(otra.body.state, "succeeded", JSON.stringify(otra.body));
	const estado = await interno("estado?tenant=t_hotel_demo");
	assert.equal(estado.reservas.filter((x: { estadia?: string }) => x.estadia === c.body.proposal.terms.estadia).length, 1, "una sola reserva pese al corte y al reintento");

	const paquete = (await pedir("GET", `${HOTEL}/v1/requests/${r0.body.request_id}/proof`)).body;
	writeFileSync(join(tmp, "p.json"), JSON.stringify(paquete));
	const v = await ejecutar("python", [join(RAIZ, "..", "verifier", "verificar_paquete.py"), "vivo", "--http-local", "--issuer", HOTEL, "--paquete", join(tmp, "p.json"), "--aud", clientId]);
	const veredicto = JSON.parse(v.stdout.trim().split("\n").at(-1)!);
	assert.equal(veredicto.valid, true, v.stdout + v.stderr);
	assert.equal(veredicto.final_state, "succeeded");
	assert.equal(veredicto.key_source, "issuer_metadata_live", "keys fetched for this check");

	const rec = await ejecutar(process.execPath, [join(RAIZ, "scripts", "recolectar-evidencia.mjs"), "--base", P, "--llave", llave, "--salida", tmp, "--etiqueta", "rx1"]);
	assert.equal(rec.status, 0, rec.stdout + rec.stderr);
	const dir = join(tmp, readdirSync(tmp).find((n) => n.endsWith("-rx1"))!);
	const verif = JSON.parse(readFileSync(join(dir, "verificacion-paquetes.json"), "utf8")) as { client_id: string; veredicto: { valid: boolean } }[];
	assert.ok(verif.length >= 1);
	assert.ok(verif.every((x) => x.veredicto.valid), JSON.stringify(verif.filter((x) => !x.veredicto.valid)).slice(0, 800));
	const atrib = JSON.parse(readFileSync(join(dir, "atribucion.json"), "utf8")) as { actor: string; operaciones: string[]; estados: Record<string, number> }[];
	const yo = atrib.find((a) => a.actor === `client_id:${clientId}#${SUB}`);
	assert.ok(yo, `el agente aparece por su client_id: ${atrib.map((a) => a.actor).join(" | ")}`);
	assert.ok(yo!.operaciones.some((o) => o.includes("reserva.crear") && o.includes("válido")));
	assert.equal(yo!.estados.corte, 1, "el corte quedó atribuido");
	assert.match(readFileSync(join(dir, "RESUMEN.md"), "utf8"), /Hotel|hotel-demo/);
});

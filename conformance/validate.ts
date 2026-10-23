// VXP conformance validator: acts as a personal agent against a company that implements the VXP native
// profile, and reports each check against the rule of the specification it tests.
//
// Statuses: pass · fail · optional (an optional capability the company does not offer) · manual (cannot be
// checked automatically; see CHECKLIST.md) · skipped (a step it depends on could not run).
//
// It shares no code with the reference implementation: JOSE with node:crypto, and the proof checked with the
// independent browser verifier (../verifier/vxp-verify.js). Node 22.18+, no dependencies.
//
// Usage: node conformance/validate.ts <config.json> [--report <out.json>]
// See conformance/README.md for the config and for running it against the reference implementation.

import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

type Status = "pass" | "fail" | "optional" | "manual" | "skipped";
type Check = { id: string; rules: string[]; title: string; status: Status; detail: string };
type Config = {
	/** Host (and port) that serves /.well-known/vxp.json. */
	domain: string;
	/** "https" by default; "http" only for local testing. */
	scheme?: "https" | "http";
	/** Where this validator's agent documents are reachable by the company (it serves them on agentPort). */
	agentOrigin?: string;
	agentPort?: number;
	/** A write operation the company offers, with a resource the test account owns. */
	operation: { operation: string; target: Record<string, unknown>; parameters: Record<string, unknown> };
	/** Optional: a counter-proposal the company should accept for that operation. */
	counter?: { proposed_terms: Record<string, unknown>; note?: string } | null;
	/** Optional: a relationship to ask for in the same consent. */
	relationship?: { actions: string[]; limits: Record<string, number> } | null;
	/**
	 * How the person approves the device authorization. "manual" prints the URL and waits; a command runs with
	 * VXP_VERIFICATION_URI, VXP_USER_CODE and VXP_SCOPE in its environment and must return once approved.
	 */
	approve: "manual" | { command: string };
	/**
	 * Optional: how to make the company start a request inside the relationship (a company action, outside the
	 * agent's reach). Runs with VXP_RELATIONSHIP_ID, VXP_ACTION and VXP_KIND ("proposal" or "question").
	 */
	companyRequest?: { command: string; proposalAction?: string; questionAction?: string } | null;
};

const C: Check[] = [];
function check(id: string, rules: string[], title: string, status: Status, detail = "") {
	C.push({ id, rules, title, status, detail });
	const mark = { pass: "PASS", fail: "FAIL", optional: "OPT ", manual: "MAN ", skipped: "SKIP" }[status];
	console.log(`${mark}  ${id.padEnd(5)} ${title}${detail ? ` — ${detail}` : ""}  [${rules.join(", ")}]`);
}
const ok = (cond: boolean, id: string, rules: string[], title: string, detail = "") => (check(id, rules, title, cond ? "pass" : "fail", detail), cond);

// ── JOSE with node:crypto ───────────────────────────────────────────────────────────────────────
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
type Llave = { privateKey: KeyObject; jwk: { kty: string; crv: string; x: string; y: string } };
function nuevaLlave(): Llave {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const j = publicKey.export({ format: "jwk" }) as { x: string; y: string };
	return { privateKey, jwk: { kty: "EC", crv: "P-256", x: j.x, y: j.y } };
}
function jwt(llave: Llave, header: Record<string, unknown>, payload: Record<string, unknown>) {
	const h = b64u(JSON.stringify({ alg: "ES256", ...header }));
	const p = b64u(JSON.stringify(payload));
	return `${h}.${p}.${b64u(sign("sha256", Buffer.from(`${h}.${p}`), { key: llave.privateKey, dsaEncoding: "ieee-p1363" }))}`;
}
const ahora = () => Math.floor(Date.now() / 1000);
const jti = () => randomBytes(12).toString("base64url");
const asercion = (k: Llave, iss: string, sub: string, aud: string) => jwt(k, { typ: "JWT" }, { iss, sub, aud, iat: ahora(), exp: ahora() + 60, jti: jti() });
function dpop(k: Llave, method: string, url: string, token?: string) {
	const u = new URL(url);
	return jwt(k, { typ: "dpop+jwt", jwk: k.jwk }, { jti: jti(), htm: method, htu: `${u.origin}${u.pathname}`, iat: ahora(), ...(token ? { ath: b64u(createHash("sha256").update(token).digest()) } : {}) });
}
const decode = (t: string) => JSON.parse(Buffer.from(t.split("~")[0].split(".")[1], "base64url").toString("utf8"));

// ── The test agent ──────────────────────────────────────────────────────────────────────────────
class Agente {
	readonly clave = nuevaLlave();
	readonly dpopKey = nuevaLlave();
	readonly sub = `usr_vxp_validator_${randomBytes(4).toString("hex")}`;
	readonly buzon: { message: string }[] = [];
	token = "";
	server!: Server;
	readonly origin: string;
	readonly port: number;
	constructor(origin: string, port: number) {
		this.origin = origin;
		this.port = port;
	}
	get clientId() {
		return `${this.origin}/agent.json`;
	}
	cimd() {
		return {
			client_id: this.clientId,
			client_name: "VXP conformance validator",
			jwks_uri: `${this.origin}/jwks.json`,
			token_endpoint_auth_method: "private_key_jwt",
			extensions: { "vxpprotocol.org/proof": { version: "0.1" }, "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `${this.origin}/vxp/inbox` } },
		};
	}
	escuchar() {
		this.server = createServer((req, res) => {
			if (req.method === "POST" && req.url === "/vxp/inbox") {
				let b = "";
				req.on("data", (c) => (b += c));
				req.on("end", () => {
					try { this.buzon.push(JSON.parse(b)); } catch {}
					res.writeHead(202).end();
				});
				return;
			}
			const doc = req.url === "/agent.json" ? this.cimd() : req.url === "/jwks.json" ? { keys: [{ ...this.clave.jwk, alg: "ES256", use: "sig" }] } : null;
			res.writeHead(doc ? 200 : 404, { "content-type": "application/json" }).end(JSON.stringify(doc ?? {}));
		});
		return new Promise<void>((ok) => this.server.listen(this.port, ok));
	}
}

async function http(method: string, url: string, init: { body?: unknown; form?: Record<string, string>; headers?: Record<string, string> } = {}) {
	const headers: Record<string, string> = { ...(init.headers ?? {}) };
	let body: string | undefined;
	if (init.form) {
		headers["content-type"] = "application/x-www-form-urlencoded";
		body = new URLSearchParams(init.form).toString();
	} else if (init.body !== undefined) {
		headers["content-type"] = "application/json";
		body = JSON.stringify(init.body);
	}
	const r = await fetch(url, { method, headers, body, redirect: "manual" });
	const text = await r.text();
	let json: any = null;
	try { json = text ? JSON.parse(text) : null; } catch {}
	return { status: r.status, json, text, headers: r.headers };
}

function correr(cmd: string, env: Record<string, string>) {
	return new Promise<number>((ok) => {
		const p = spawn(cmd, { shell: true, stdio: "inherit", env: { ...process.env, ...env } });
		p.on("exit", (c) => ok(c ?? 1));
	});
}

async function main() {
	const args = process.argv.slice(2);
	const cfgPath = args.find((a) => !a.startsWith("--"));
	if (!cfgPath) {
		console.error("usage: node conformance/validate.ts <config.json> [--report <out.json>]");
		process.exit(2);
	}
	const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as Config;
	const reportPath = args.includes("--report") ? args[args.indexOf("--report") + 1] : null;
	const scheme = cfg.scheme ?? "https";
	const port = cfg.agentPort ?? 3890;
	const agente = new Agente(cfg.agentOrigin ?? `http://localhost:${port}`, port);
	await agente.escuchar();
	console.log(`VXP conformance validator · company ${scheme}://${cfg.domain} · agent ${agente.clientId}\n`);
	try {
		await validar(cfg, scheme, agente);
	} catch (e) {
		check("X0", [], "validator stopped on an unexpected response", "fail", String((e as Error).message ?? e));
	} finally {
		agente.server.close();
	}
	const resumen = Object.fromEntries((["pass", "fail", "optional", "manual", "skipped"] as Status[]).map((s) => [s, C.filter((c) => c.status === s).length]));
	console.log(`\n${JSON.stringify(resumen)}`);
	const report = { validator: "vxp-conformance 0.1", spec: "VXP draft 0.1", company: `${scheme}://${cfg.domain}`, at: new Date().toISOString(), summary: resumen, checks: C };
	if (reportPath) {
		writeFileSync(reportPath, JSON.stringify(report, null, 2));
		writeFileSync(reportPath.replace(/\.json$/, "") + ".md", markdown(report));
		console.log(`report: ${reportPath} and ${reportPath.replace(/\.json$/, "")}.md`);
	}
	process.exit(resumen.fail ? 1 : 0);
}

function markdown(r: { company: string; at: string; summary: Record<string, number>; checks: Check[] }) {
	const ancla = (rule: string) => `https://vxpprotocol.org/spec/#${rule.toLowerCase()}`;
	const filas = r.checks.map((c) => `| ${c.id} | ${c.status} | ${c.title} | ${c.rules.map((x) => `[${x}](${ancla(x)})`).join(", ")} | ${c.detail.replace(/\|/g, "\\|")} |`);
	return [
		`# VXP conformance report`,
		``,
		`Company: ${r.company} · ${r.at} · validator vxp-conformance 0.1 against VXP draft 0.1`,
		``,
		`Summary: ${Object.entries(r.summary).map(([k, v]) => `${k} ${v}`).join(" · ")}`,
		``,
		`| Check | Status | What | Rules | Detail |`,
		`|---|---|---|---|---|`,
		...filas,
		``,
		`Checks marked **manual** are in [CHECKLIST.md](CHECKLIST.md). This report is produced by the implementer's own run; it is not a certification.`,
		``,
	].join("\n");
}

async function validar(cfg: Config, scheme: string, ag: Agente) {
	const base = `${scheme}://${cfg.domain}`;

	// ── Discovery (§8) ──
	const d = await http("GET", `${base}/.well-known/vxp.json`);
	if (!ok(d.status === 200 && d.json?.protocol === "vxp", "D1", ["native-discovery"], "vxp.json is served on the company domain with protocol vxp", `HTTP ${d.status}`)) return;
	const vxp = d.json;
	ok(vxp.version === "0.1", "D2", ["versioning"], "vxp.json declares version 0.1", String(vxp.version));
	ok(vxp.organization?.domain === new URL(base).host || vxp.organization?.domain === new URL(base).hostname, "D3", ["native-discovery"], "organization.domain is the host that served the document", String(vxp.organization?.domain));
	ok(typeof vxp.issuer === "string" && typeof vxp.endpoint === "string" && vxp.endpoint.startsWith(vxp.issuer), "D4", ["native-discovery"], "issuer and endpoint are declared, endpoint under the issuer", `${vxp.issuer} · ${vxp.endpoint}`);
	ok(!("jwks_uri" in vxp) && !("operator" in vxp) && !("custody" in vxp), "D5", ["native-discovery"], "vxp.json carries no proof trust members");
	const caps = Array.isArray(vxp.capabilities) ? vxp.capabilities : [];
	const cap = caps.find((c: any) => c.id === cfg.operation.operation);
	ok(!!cap && ["public", "delegated"].includes(cap.access) && ["static", "dynamic"].includes(cap.admission), "D6", ["native-discovery"], "the operation under test is published with access and admission", cfg.operation.operation);
	const metaUrl = `${new URL(vxp.issuer).origin}/.well-known/oauth-authorization-server${new URL(vxp.issuer).pathname}`;
	const m = await http("GET", metaUrl);
	if (!ok(m.status === 200 && m.json?.issuer === vxp.issuer, "D7", ["issuer-anchoring"], "RFC 8414 metadata answers at the issuer's well-known path with an identical issuer", `HTTP ${m.status}`)) return;
	const meta = m.json;
	const vp = meta.vxp_proof;
	ok(!!vp && vp.company === vxp.issuer && String(vp.jwks_uri ?? "").startsWith(vxp.issuer), "D8", ["issuer-anchoring", "P7"], "vxp_proof names the company issuer and keeps its keys under it");
	ok(Array.isArray(vp?.domains) && vp.domains.some((x: string) => x.toLowerCase() === new URL(base).host.toLowerCase() || x.toLowerCase() === new URL(base).hostname.toLowerCase()), "D9", ["native-discovery"], "the discovery domain is listed in vxp_proof.domains");
	ok((meta.authorization_details_types_supported ?? []).includes("https://vxpprotocol.org/rar/capability"), "D10", ["native-authorization"], "the authorization server accepts the capability RAR type");
	ok((meta.dpop_signing_alg_values_supported ?? []).includes("ES256") && (meta.token_endpoint_auth_methods_supported ?? []).includes("private_key_jwt"), "D11", ["native-authorization"], "DPoP ES256 and private_key_jwt are supported");
	const relMeta = meta.vxp_relationship;
	if (!relMeta) check("D12", ["R1", "R5"], "VXP Relationship advertised in the issuer metadata", "optional", "not offered");
	else ok(String(relMeta.jwks_uri ?? "").startsWith(vxp.issuer) && relMeta.jwks_uri !== vp?.jwks_uri, "D12", ["R1", "R5"], "VXP Relationship advertised, with its own key set under the issuer");

	// ── Session (§8 authorization) ──
	const tokenUrl = String(meta.token_endpoint);
	const formBase = { client_id: ag.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", resource: vxp.endpoint };
	const pedirToken = (form: Record<string, string>) =>
		http("POST", tokenUrl, { form: { ...form, ...formBase, client_assertion: asercion(ag.clave, ag.clientId, ag.clientId, vxp.issuer), assertion: asercion(ag.clave, ag.clientId, ag.sub, vxp.issuer) }, headers: { dpop: dpop(ag.dpopKey, "POST", tokenUrl) } });
	const s = await pedirToken({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
	if (!ok(s.status === 200 && typeof s.json?.access_token === "string" && /dpop/i.test(String(s.json.token_type)), "A1", ["native-authorization", "ID3"], "a session token is issued to a private_key_jwt client, bound with DPoP", `HTTP ${s.status} ${s.json?.error ?? ""}`)) return;
	ag.token = s.json.access_token;
	const sinDpop = await http("POST", `${vxp.endpoint}/requests`, { body: cfg.operation, headers: { authorization: `Bearer ${ag.token}`, "idempotency-key": jti() } });
	ok(sinDpop.status === 401 || sinDpop.status === 400 || sinDpop.status === 403, "A2", ["native-endpoints", "native-authorization"], "a request without a DPoP proof is refused", `HTTP ${sinDpop.status}`);
	const pedir = (method: string, url: string, body?: unknown, headers: Record<string, string> = {}) =>
		http(method, url, { body, headers: { authorization: `DPoP ${ag.token}`, dpop: dpop(ag.dpopKey, method, url, ag.token), ...headers } });

	// ── Requests and authority (§8, O2) ──
	const sinLlave = await pedir("POST", `${vxp.endpoint}/requests`, cfg.operation);
	ok(sinLlave.status === 400 && sinLlave.json?.error === "idempotency_key_required", "Q1", ["native-endpoints", "native-idempotency"], "a request without Idempotency-Key gets 400 idempotency_key_required", `HTTP ${sinLlave.status} ${sinLlave.json?.error ?? ""}`);
	const idem = jti();
	const r0 = await pedir("POST", `${vxp.endpoint}/requests`, cfg.operation, { "idempotency-key": idem });
	const faltan = r0.json?.authorization?.authorization_details ?? r0.json?.authorization_details;
	if (!ok(r0.status === 202 && r0.json?.state === "authorization_required" && Array.isArray(faltan), "Q2", ["O2", "native-authorization"], "without authority, the request is held as authorization_required with exactly what is missing", `HTTP ${r0.status} ${r0.json?.state ?? r0.json?.error ?? ""}`)) return;
	// Another body under the same key: one parameter value changed (a date or number moves by one).
	const variante = JSON.parse(JSON.stringify(cfg.operation));
	const k0 = Object.keys(variante.parameters).find((k) => typeof variante.parameters[k] === "string" && /\d$/.test(variante.parameters[k]) || typeof variante.parameters[k] === "number");
	if (k0) variante.parameters[k0] = typeof variante.parameters[k0] === "number" ? variante.parameters[k0] + 1 : variante.parameters[k0].replace(/\d$/, (d: string) => String((Number(d) + 1) % 10 || 1));
	const otro = await pedir("POST", `${vxp.endpoint}/requests`, variante, { "idempotency-key": idem });
	ok(otro.status === 409 && otro.json?.error === "idempotency_key_reused", "Q3", ["native-idempotency"], "the same Idempotency-Key with another body gets 409 idempotency_key_reused", `HTTP ${otro.status} ${otro.json?.error ?? ""}`);

	// ── The person approves (RFC 8628 + RFC 9396) ──
	const detalles = [...faltan, ...(cfg.relationship && relMeta ? [{ type: "https://vxpprotocol.org/rar/relationship", actions: cfg.relationship.actions, identifier: "relationship", limits: cfg.relationship.limits }] : [])];
	const dev = await http("POST", String(meta.device_authorization_endpoint), { form: { ...formBase, client_assertion: asercion(ag.clave, ag.clientId, ag.clientId, vxp.issuer), authorization_details: JSON.stringify(detalles) } });
	if (!ok(dev.status === 200 && typeof dev.json?.device_code === "string" && typeof dev.json?.verification_uri === "string", "A3", ["native-authorization", "R3"], "device authorization (RFC 8628) accepts the authorization_details", `HTTP ${dev.status} ${dev.json?.error ?? ""}`)) return;
	check("A4", ["R3", "ID1"], "the consent screen shows each item in business language, with its own relationship checkbox, and links the account through an authentication the company controls", "manual", "see CHECKLIST.md");
	const scope = Array.from(new Set(faltan.flatMap((x: any) => x.scope ?? []).concat(cfg.relationship && relMeta ? ["vxp:relationship"] : []))) as string[];
	if (cfg.approve === "manual") {
		console.log(`\n  Approve as the person: ${dev.json.verification_uri_complete ?? dev.json.verification_uri} (code ${dev.json.user_code}). Waiting…\n`);
	} else {
		const code = await correr(cfg.approve.command, { VXP_VERIFICATION_URI: String(dev.json.verification_uri_complete ?? dev.json.verification_uri), VXP_USER_CODE: String(dev.json.user_code), VXP_SCOPE: scope.join(" ") });
		if (code !== 0) return check("A5", ["native-authorization"], "approval helper", "fail", `exit ${code}`);
	}
	let t: Awaited<ReturnType<typeof pedirToken>> | null = null;
	for (let i = 0; i < 120; i++) {
		t = await pedirToken({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.json.device_code });
		if (t.status === 200) break;
		if (t.json?.error !== "authorization_pending" && t.json?.error !== "slow_down") break;
		await new Promise((r) => setTimeout(r, Math.max(1, Number(dev.json.interval ?? 2)) * 1000));
	}
	if (!ok(t!.status === 200 && typeof t!.json?.access_token === "string", "A5", ["native-authorization"], "after the person approves, the token carries the granted authority", `HTTP ${t!.status} ${t!.json?.error ?? ""}`)) return;
	ag.token = t!.json.access_token;
	ok(Array.isArray(t!.json.authorization_details), "A6", ["native-authorization"], "the token response returns the authorization_details granted");

	// ── The operation (§6 P1, O4, O6, O7) ──
	const r1 = await pedir("POST", `${vxp.endpoint}/requests`, cfg.operation, { "idempotency-key": idem });
	if (!ok((r1.status === 200 || r1.status === 201) && r1.json?.state === "proposed" && r1.json?.request_id === r0.json?.request_id, "Q4", ["native-idempotency", "O2"], "the same request, re-evaluated with the new authority, becomes proposed", `HTTP ${r1.status} ${r1.json?.state ?? ""} ${r1.json?.error ?? r1.json?.reason ?? ""}`)) return;
	const reqId = r1.json.request_id;
	let prop = r1.json.proposal;
	ok(!!prop?.id && Number.isInteger(prop?.revision) && typeof prop?.summary === "string" && prop?.terms && typeof prop.terms.vxp_salt === "string", "P1", ["P1", "O4"], "the proposal carries a revision, a summary and exact terms with a fresh vxp_salt");
	ok(["firm", "conditional"].includes(prop?.commitment?.mode) && Array.isArray(prop?.commitment?.requires) && (prop.commitment.mode === "firm") === (prop.commitment.requires.length === 0), "P2", ["commitment", "O4"], "the revision declares its commitment: firm with no conditions, or conditional with them", JSON.stringify(prop?.commitment));
	ok(r1.json?.projections?.poppy === "proposed" && r1.json?.projections?.a2a === "TASK_STATE_INPUT_REQUIRED", "E1", ["E1", "E2", "state-projection"], "the request projects its state onto the Poppy and A2A enums", JSON.stringify(r1.json?.projections));
	const ajeno = new Agente(ag.origin, ag.port);
	const sAjena = await http("POST", tokenUrl, { form: { ...formBase, grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", client_assertion: asercion(ag.clave, ag.clientId, ag.clientId, vxp.issuer), assertion: asercion(ag.clave, ag.clientId, ajeno.sub, vxp.issuer) }, headers: { dpop: dpop(ajeno.dpopKey, "POST", tokenUrl) } });
	if (sAjena.status === 200) {
		const u = `${vxp.endpoint}/requests/${reqId}`;
		const v = await http("GET", u, { headers: { authorization: `DPoP ${sAjena.json.access_token}`, dpop: dpop(ajeno.dpopKey, "GET", u, sAjena.json.access_token) } });
		ok(v.status === 404, "O3", ["ID3", "O1"], "another user of the same agent cannot see the request", `HTTP ${v.status}`);
	} else check("O3", ["ID3", "O1"], "another user of the same agent cannot see the request", "skipped", "second session refused");

	if (cfg.counter) {
		const c = await pedir("POST", `${vxp.endpoint}/proposals/${prop.id}/counter`, cfg.counter);
		if (ok(c.status === 200 && c.json?.proposal?.revision > prop.revision, "N1", ["native-endpoints", "P1"], "a counter-proposal produces a new revision", `HTTP ${c.status} ${c.json?.error ?? ""}`)) {
			const vieja = await pedir("POST", `${vxp.endpoint}/proposals/${prop.id}/accept`, { approved_by: "user" });
			ok(vieja.status === 409 && vieja.json?.error === "terms_changed", "N2", ["O4", "P1"], "accepting the superseded revision gets 409 terms_changed and runs nothing", `HTTP ${vieja.status} ${vieja.json?.error ?? ""}`);
			prop = c.json.proposal;
		}
	} else check("N1", ["native-endpoints"], "counter-proposal", "optional", "no counter configured for this operation");

	const a = await pedir("POST", `${vxp.endpoint}/proposals/${prop.id}/accept`, { approved_by: "user" });
	if (!ok((a.status === 200 || a.status === 202) && !a.json?.error, "X1", ["O6", "native-endpoints"], "accepting the current revision runs the operation", `HTTP ${a.status} ${a.json?.state ?? a.json?.error ?? ""}`)) return;
	let fin = a.json;
	for (let i = 0; i < 30 && !["succeeded", "failed", "cancelled", "expired"].includes(fin?.state); i++) {
		await new Promise((r) => setTimeout(r, 1000));
		fin = (await pedir("GET", `${vxp.endpoint}/requests/${reqId}`)).json;
	}
	ok(fin?.state === "succeeded", "X2", ["O7", "P6"], "the operation reaches succeeded only after the company reads its system", String(fin?.state));
	const otra = await pedir("POST", `${vxp.endpoint}/proposals/${prop.id}/accept`, { approved_by: "user" });
	ok(otra.status === 200 && otra.json?.state === fin?.state, "X3", ["O6", "native-idempotency"], "accepting again returns the same result and runs nothing more", `HTTP ${otra.status}`);
	const ev = await pedir("GET", `${vxp.endpoint}/requests/${reqId}/events`);
	ok(ev.status === 200 && Array.isArray(ev.json?.events) && ev.json.events.length > 1, "X4", ["E1", "state-transitions"], "the request's transitions can be read", `${ev.json?.events?.length ?? 0} events`);

	// ── The proof (§6, §10), checked with the independent browser verifier ──
	const pq = await pedir("GET", `${vxp.endpoint}/requests/${reqId}/proof`);
	if (!ok(pq.status === 200 && Array.isArray(pq.json?.statements), "V1", ["proof", "native-endpoints"], "the proof package can be fetched", `HTTP ${pq.status}`)) return;
	const kinds = pq.json.statements.map((x: string) => decode(x).kind);
	ok(kinds.includes("execution") && kinds.filter((k: string) => k === "execution").length === 1, "V2", ["O6", "P1"], "the chain records exactly one execution", kinds.join(","));
	const iRb = kinds.lastIndexOf("read_back");
	const iOut = kinds.lastIndexOf("outcome");
	ok(iRb >= 0 && iOut >= 0, "V3", ["O7", "P5", "P6"], "a read_back of the company's system is in the chain with the outcome", kinds.join(","));
	const docs: Record<string, string> = {};
	const traer = async (u: string) => (docs[u] = (await http("GET", u)).text);
	await traer(metaUrl);
	for (const u of [vp.jwks_uri, vp.operator?.jwks_uri, vp.log?.jwks_uri, vp.log?.checkpoint_url].filter(Boolean)) await traer(u);
	const ver = await import(pathToFileURL(join(import.meta.dirname, "..", "verifier", "vxp-verify.js")).href);
	const operacion = { operation_id: fin.operation_id ?? r1.json.operation_id, revision: prop.revision, summary: prop.summary, terms: prop.terms, expires_at: prop.expires_at, user_approval_required: prop.user_approval_required, state: fin?.projections?.poppy, result: fin?.result };
	const verdict = await ver.verifyPackage({ package: JSON.stringify(pq.json), material: JSON.stringify({ anchor: { issuer: vxp.issuer }, docs }), operation: JSON.stringify(operacion) });
	ok(verdict.valid === true, "V4", ["proof-chain-rules", "issuer-anchoring", "P8"], "the independent verifier accepts the proof, anchored by the issuer, and it matches the operation the agent saw", verdict.valid ? `final_state ${verdict.final_state}` : `${verdict.error} seq ${verdict.seq}`);
	ok(verdict.final_state === fin?.state, "V5", ["P8"], "the proof's final state is the operation's state", `${verdict.final_state} / ${fin?.state}`);
	check("V6", ["P7"], "level of evidence (derived by the verifier)", verdict.valid ? "pass" : "skipped", verdict.valid ? `derived ${(verdict.derived_assurance ?? []).join(",")} · single_root ${verdict.single_root} · logged ${verdict.logged}` : "");
	const alterado = JSON.parse(JSON.stringify(pq.json));
	const ult = alterado.statements.length - 1;
	const [h, p, sg] = alterado.statements[ult].split("~")[0].split(".");
	const pl = JSON.parse(Buffer.from(p, "base64url").toString());
	pl.body.state = pl.body.state === "succeeded" ? "failed" : "succeeded";
	alterado.statements[ult] = `${h}.${b64u(JSON.stringify(pl))}.${sg}~` + alterado.statements[ult].split("~").slice(1).join("~");
	const vAlt = await ver.verifyPackage({ package: JSON.stringify(alterado), material: JSON.stringify({ anchor: { issuer: vxp.issuer }, docs }) });
	ok(vAlt.valid === false, "V7", ["proof-chain-rules"], "a tampered outcome is rejected", String(vAlt.error));

	// ── VXP Relationship (§7) ──
	const rels = t!.json.relationships as any[] | undefined;
	if (!cfg.relationship || !relMeta) return check("R0", ["R1"], "VXP Relationship", "optional", relMeta ? "no relationship configured" : "not offered by the company");
	const rel = rels?.[0];
	if (!ok(!!rel?.relationship_id && typeof rel?.agreement === "string", "R1", ["R4"], "the token returns the relationship with its signed agreement")) return;
	const ag1 = decode(rel.agreement);
	const hAg = JSON.parse(Buffer.from(rel.agreement.split(".")[0], "base64url").toString());
	ok(hAg.typ === "vxp-relationship+jwt" && ag1.iss === vxp.issuer && ag1.aud === ag.clientId && ag1.sub === ag.sub, "R2", ["R4"], "the agreement is a vxp-relationship+jwt from the issuer to this agent and user", `${hAg.typ} iss ${ag1.iss}`);
	const g = await pedir("GET", `${vxp.endpoint}/relationships/${rel.relationship_id}`);
	ok(g.status === 200, "R3", ["R11"], "the agent can read its relationship", `HTTP ${g.status}`);
	if (!cfg.companyRequest) {
		check("R4", ["R6", "R7", "R8"], "a company-initiated request reaches the agent's inbox, signed", "skipped", "no companyRequest command configured: starting one is a company action");
	} else {
		const action = cfg.companyRequest.proposalAction ?? cfg.relationship.actions[0];
		const code = await correr(cfg.companyRequest.command, { VXP_RELATIONSHIP_ID: rel.relationship_id, VXP_ACTION: action, VXP_KIND: "proposal" });
		await new Promise((r) => setTimeout(r, 500));
		const msg = ag.buzon.at(-1)?.message;
		if (ok(code === 0 && !!msg, "R4", ["R7"], "a company-initiated request reaches the agent's inbox", `exit ${code}, ${ag.buzon.length} message(s)`)) {
			const hm = JSON.parse(Buffer.from(msg!.split(".")[0], "base64url").toString());
			const pm = decode(msg!);
			const jw = JSON.parse((await http("GET", relMeta.jwks_uri)).text);
			const { createPublicKey, verify } = await import("node:crypto");
			const k = jw.keys.find((x: any) => x.kid === hm.kid);
			const firmaOk = !!k && verify("sha256", Buffer.from(msg!.split(".").slice(0, 2).join(".")), { key: createPublicKey({ key: k, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(msg!.split(".")[2], "base64url"));
			ok(hm.typ === "vxp-company-request+jwt" && firmaOk && pm.aud === ag.clientId && pm.rel === rel.relationship_id, "R5", ["R7", "R5"], "the message is a vxp-company-request+jwt signed with the relationship key anchored to the issuer", `typ ${hm.typ}, signature ${firmaOk}`);
			const c = pm.content ?? {};
			if (c.proposal_id) {
				const acc = await pedir("POST", `${vxp.endpoint}/proposals/${c.proposal_id}/accept`, { approved_by: "user" });
				ok((acc.status === 200 || acc.status === 202) && !acc.json?.error, "R6", ["R8", "R9"], "the company's proposal is a normal operation the agent accepts with the person's approval", `HTTP ${acc.status} ${acc.json?.state ?? acc.json?.error ?? ""}`);
			} else check("R6", ["R8"], "the company's proposal is a normal operation", "skipped", "the message carries no proposal_id");
		}
		if (cfg.companyRequest.questionAction) {
			const n0 = ag.buzon.length;
			await correr(cfg.companyRequest.command, { VXP_RELATIONSHIP_ID: rel.relationship_id, VXP_ACTION: cfg.companyRequest.questionAction, VXP_KIND: "question" });
			await new Promise((r) => setTimeout(r, 500));
			const q = ag.buzon.length > n0 ? decode(ag.buzon.at(-1)!.message).content : null;
			if (ok(!!q?.alert_id && Array.isArray(q?.options), "R7", ["R17"], "a closed question arrives with alert_id and options")) {
				const r1x = await pedir("POST", `${vxp.endpoint}/relationships/${rel.relationship_id}/replies`, { alert_id: q.alert_id, decision: "__not_an_option__" });
				ok(r1x.status === 400 && r1x.json?.error === "option_not_allowed", "R8", ["R17"], "an answer outside the options gets 400 option_not_allowed", `HTTP ${r1x.status} ${r1x.json?.error ?? ""}`);
				const r2x = await pedir("POST", `${vxp.endpoint}/relationships/${rel.relationship_id}/replies`, { alert_id: q.alert_id, decision: q.options[0] });
				ok(r2x.status === 200 && typeof r2x.json?.receipt === "string", "R9", ["R17"], "a valid answer gets a signed receipt", `HTTP ${r2x.status}`);
				const r3x = await pedir("POST", `${vxp.endpoint}/relationships/${rel.relationship_id}/replies`, { alert_id: q.alert_id, decision: q.options[0] });
				ok(r3x.status === 409 && r3x.json?.error === "already_answered", "R10", ["R17"], "answering twice gets 409 already_answered", `HTTP ${r3x.status} ${r3x.json?.error ?? ""}`);
			}
		} else check("R7", ["R17"], "closed questions answered over HTTP", "optional", "no question action configured");
	}
	const del = await pedir("DELETE", `${vxp.endpoint}/relationships/${rel.relationship_id}`);
	ok(del.status === 200, "R11", ["R10"], "the agent can revoke the relationship", `HTTP ${del.status}`);
	if (cfg.companyRequest) {
		const n0 = ag.buzon.length;
		const code = await correr(cfg.companyRequest.command, { VXP_RELATIONSHIP_ID: rel.relationship_id, VXP_ACTION: cfg.companyRequest.proposalAction ?? cfg.relationship.actions[0], VXP_KIND: "proposal", VXP_EXPECT_REFUSAL: "1" });
		ok(ag.buzon.length === n0, "R12", ["R6", "R10"], "after revocation the company cannot start anything inside the relationship", `exit ${code}, inbox +${ag.buzon.length - n0}`);
	} else check("R12", ["R6", "R10"], "after revocation the company cannot start anything", "skipped", "no companyRequest command configured");
	check("M1", ["ID1", "ID2"], "account linking evidence and ambiguous identifiers", "manual", "see CHECKLIST.md");
	check("M2", ["privacy"], "no personal data in clear in the proof; per-company pseudonyms", "manual", "see CHECKLIST.md");
}

main();

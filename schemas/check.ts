// Checks the VXP 0.1 JSON Schemas: each one is well formed and every $ref resolves; real objects produced by the
// reference implementation, the verifiers' vectors and the personal agent validate against them; and objects that
// break a rule of the specification are rejected.
//
// Usage: node schemas/check.ts [--run <dir>]   (<dir>: output of reference/scripts/recorrido-nativo.test.ts)
// Node 22.18+, no dependencies. The validator is the JSON Schema 2020-12 subset validator of the vendored Poppy
// kit (Apache 2.0), which has no relation to the reference implementation's code.

import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateSchema } from "../reference/vendor/poppy-kit/validate/schema.ts";

const ROOT = join(import.meta.dirname, "..");
const DIR = join(import.meta.dirname, "0.1");
const read = (p: string) => JSON.parse(readFileSync(p, "utf8"));

// ── The schemas ────────────────────────────────────────────────────────────────────────────────
const files = readdirSync(DIR).filter((f) => f.endsWith(".schema.json")).sort();
const refs: Record<string, object> = {};
for (const f of files) {
	const s = read(join(DIR, f));
	assert.equal(s.$schema, "https://json-schema.org/draft/2020-12/schema", `${f}: $schema`);
	assert.equal(s.$id, `https://vxpprotocol.org/schemas/0.1/${f}`, `${f}: $id names its published URL`);
	assert.ok(typeof s.title === "string" && typeof s.description === "string", `${f}: title and description`);
	refs[f] = s;
}
const index = read(join(DIR, "index.json"));
assert.deepEqual(index.schemas.map((x: { file: string }) => x.file).sort(), files.filter((f) => f !== "common.schema.json"), "index.json lists every schema");

// Every $ref resolves (the validator reports an unresolved one as an error on any value that reaches it).
for (const f of files) {
	const walk = (node: unknown, at: string) => {
		if (Array.isArray(node)) return node.forEach((x, i) => walk(x, `${at}/${i}`));
		if (!node || typeof node !== "object") return;
		for (const [k, v] of Object.entries(node)) {
			if (k === "$ref" && typeof v === "string") {
				const [file, frag = ""] = v.split("#");
				const root = file ? refs[file] : refs[f];
				assert.ok(root, `${f}${at}: $ref ${v} names a schema that does not exist`);
				let n: any = root;
				for (const seg of frag.replace(/^\//, "").split("/").filter(Boolean)) n = n?.[seg];
				assert.ok(n && typeof n === "object", `${f}${at}: $ref ${v} does not resolve`);
			} else walk(v, `${at}/${k}`);
		}
	};
	walk(refs[f], "");
}

// ── Validation helpers ─────────────────────────────────────────────────────────────────────────
let checked = 0;
const failures: string[] = [];
const counts: Record<string, number> = {};
function expectValid(schema: string, value: unknown, where: string) {
	const errors = validateSchema(refs[schema], value, refs);
	checked++;
	counts[schema] = (counts[schema] ?? 0) + 1;
	if (errors.length) failures.push(`${where} → ${schema}: ${errors.slice(0, 3).map((e) => `${e.path || "/"} ${e.message}`).join("; ")}`);
}
function expectValidAt(schema: object, label: string, value: unknown, where: string) {
	const errors = validateSchema(schema, value, refs);
	checked++;
	counts[label] = (counts[label] ?? 0) + 1;
	if (errors.length) failures.push(`${where} → ${label}: ${errors.slice(0, 3).map((e) => `${e.path || "/"} ${e.message}`).join("; ")}`);
}
const b64json = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
const header = (jws: string) => b64json(jws.split("~")[0].split(".")[0]);
const payload = (jws: string) => b64json(jws.split("~")[0].split(".")[1]);

/** A proof package, each statement's header and payload, and the log checkpoint. */
function proofPackage(p: any, where: string) {
	expectValid("proof-package.schema.json", p, where);
	(p.statements ?? []).forEach((s: string, i: number) => {
		expectValid("statement-header.schema.json", header(s), `${where} statement ${i} header`);
		expectValid("statement.schema.json", payload(s), `${where} statement ${i}`);
	});
	if (p.log?.checkpoint) expectValid("checkpoint.schema.json", payload(p.log.checkpoint), `${where} checkpoint`);
}

/** One HTTP exchange of a native run, routed to its schema by method, path and status. */
function exchange(x: any, where: string) {
	if (!x?.method || !x.url) return;
	const path = new URL(x.url).pathname;
	const body = x.response;
	const json = body && typeof body === "object";
	if (x.request && typeof x.request === "object") {
		if (x.method === "POST" && /\/v1\/requests$/.test(path)) expectValid("request-body.schema.json", x.request, `${where} request body`);
		if (/\/v1\/proposals\/[^/]+\/accept$/.test(path)) expectValid("accept-body.schema.json", x.request, `${where} accept body`);
		if (/\/v1\/proposals\/[^/]+\/counter$/.test(path)) expectValid("counter-body.schema.json", x.request, `${where} counter body`);
		if (/\/v1\/relationships\/[^/]+\/replies$/.test(path)) expectValid("reply-body.schema.json", x.request, `${where} reply body`);
	}
	if (!json) return;
	if (x.status >= 400) return expectValid("error.schema.json", body, `${where} ${x.status}`);
	if (path === "/.well-known/vxp.json") return expectValid("vxp.schema.json", body, `${where} vxp.json`);
	if (path.startsWith("/.well-known/oauth-authorization-server")) return expectValid("issuer-metadata.schema.json", body, `${where} metadata`);
	if (/\/oauth\/token$/.test(path) && body.access_token) {
		expectValid("token-response.schema.json", body, `${where} token`);
		for (const r of body.relationships ?? []) expectValid("relationship-agreement.schema.json", payload(r.agreement), `${where} agreement`);
		return;
	}
	if (/\/v1\/requests$/.test(path)) return expectValid(body.effect === "read" ? "read-response.schema.json" : "request.schema.json", body, `${where} request`);
	if (/\/v1\/requests\/[^/]+$/.test(path) || /\/v1\/proposals\/[^/]+\/(accept|counter)$/.test(path) || /\/v1\/requests\/[^/]+\/cancel$/.test(path)) return expectValid("request.schema.json", body, `${where} request`);
	if (/\/v1\/requests\/[^/]+\/events$/.test(path)) return expectValid("events.schema.json", body, `${where} events`);
	if (/\/v1\/requests\/[^/]+\/proof$/.test(path)) return proofPackage(body, `${where} proof`);
	if (/\/v1\/relationships\/[^/]+\/replies$/.test(path)) {
		expectValid("reply-response.schema.json", body, `${where} reply`);
		return expectValid("reply-receipt.schema.json", payload(body.receipt), `${where} receipt`);
	}
	if (/\/v1\/relationships\/[^/]+$/.test(path)) return expectValid("relationship.schema.json", body, `${where} relationship`);
	if (/\/interno\/relaciones\/iniciar$/.test(path) && body.content) {
		// The reference's test console returns the content the company signed; the whole message is checked live
		// by the conformance validator, which receives it in its inbox.
		return expectValidAt({ $ref: "company-request.schema.json#/$defs/content" }, "company-request content", body.content, `${where} company request content`);
	}
}

// ── Real objects ───────────────────────────────────────────────────────────────────────────────
// Native runs: the published one and, with --run, a fresh one from the current code.
const runs = [join(ROOT, "site", "downloads", "native-run-2026-10-22-evening", "http-log.json")];
const i = process.argv.indexOf("--run");
if (i > 0) runs.push(join(process.argv[i + 1], "recorrido.json"));
for (const r of runs) {
	assert.ok(existsSync(r), `missing ${r}`);
	read(r).forEach((x: unknown, n: number) => exchange(x, `${r.slice(ROOT.length + 1)}#${n}`));
}
// Proof packages kept with the runs, the personal agent's run, and every chain in the vectors.
for (const d of ["native-run-2026-10-22-evening", "native-run-2026-10-22"]) {
	const base = join(ROOT, "site", "downloads", d);
	for (const f of readdirSync(base).filter((f) => f.startsWith("paquete-"))) proofPackage(read(join(base, f)), `${d}/${f}`);
}
proofPackage(read(join(ROOT, "agent", "runs", "2026-10-23", "proof-package.json")), "agent/runs/2026-10-23/proof-package.json");
for (const v of ["vectores-0.1.json", "vectores-pact-0.1.json"]) {
	const walk = (o: unknown, at: string) => {
		if (typeof o === "string" && /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~/.test(o)) {
			const p = payload(o);
			if (p.kind && header(o).typ === "vxp-stmt+sd-jwt") {
				expectValid("statement-header.schema.json", header(o), `${v}${at} header`);
				expectValid("statement.schema.json", p, `${v}${at}`);
			}
		} else if (Array.isArray(o)) o.forEach((x, n) => walk(x, `${at}/${n}`));
		else if (o && typeof o === "object") for (const [k, x] of Object.entries(o)) if (k !== "negative" && k !== "malleated_outcome") walk(x, `${at}/${k}`);
	};
	walk(read(join(ROOT, "vectors", v)), "");
}

// ── Objects that break a rule must be rejected ─────────────────────────────────────────────────
const invalid = read(join(import.meta.dirname, "invalid.json")) as { why: string; schema: string; value: unknown }[];
for (const c of invalid) {
	checked++;
	if (validateSchema(refs[c.schema], c.value, refs).length === 0) failures.push(`accepted an invalid object: ${c.why} (${c.schema})`);
}

console.log(`schemas: ${files.length} · objects checked: ${checked} (${invalid.length} invalid ones rejected) · by schema: ${JSON.stringify(counts)}`);
if (failures.length) {
	console.error(failures.join("\n"));
	process.exit(1);
}

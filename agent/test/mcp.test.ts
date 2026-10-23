// The MCP server, driven over stdio the way an MCP host does it (JSON-RPC 2.0, one message per line):
// legacy handshake (initialize) and modern per-request _meta (2026-07-28) on the same process; the whole
// hotel task through tools; and actions with effect that run only after the person confirms through the
// host (elicitation), never on the model's word.

import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import { approveOnCompanyPage } from "./helpers/person.ts";
import { run } from "./helpers/run.ts";
import { HOTEL_TENANT, PHONE, nextFriday, plusDays, type Reference, startReference } from "./helpers/setup.ts";

const CLI = join(import.meta.dirname, "..", "bin", "vxp-agent.ts");
const AG = "http://localhost:3851";
let ref: Reference;
let proc: ChildProcess;
const state = mkdtempSync(join(tmpdir(), "vxp-agent-mcp-"));
const stdoutLines: string[] = [];
const waiting = new Map<number | string, (m: any) => void>();
/** The host's UI: how the person answers each elicitation the server asks for. */
let personAnswers: { action: string; content?: unknown }[] = [];
const elicitations: any[] = [];
let nextId = 1;

const META = (caps: object = {}) => ({ "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "test-host", version: "1" }, "io.modelcontextprotocol/clientCapabilities": caps });

function rpc(method: string, params: object = {}): Promise<any> {
	const id = nextId++;
	const p = new Promise((ok) => waiting.set(id, ok));
	proc.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
	return p;
}
async function tool(name: string, args: object, meta?: object): Promise<any> {
	const r = await rpc("tools/call", { name, arguments: args, ...(meta ? { _meta: meta } : {}) });
	assert.ok(r.result, JSON.stringify(r));
	return r.result;
}
const sc = (r: any) => r.structuredContent;

before(async () => {
	ref = await startReference({ port: 3850, agentOrigins: [AG] });
	proc = spawn(process.execPath, [CLI, "mcp", "--port", "3851", "--state", state, "--origin", AG, "--allow-http", [ref.origin, `http://${ref.hotelDomain}`, AG].join(",")], { stdio: ["pipe", "pipe", "pipe"] });
	proc.stderr!.on("data", () => {});
	createInterface({ input: proc.stdout! }).on("line", (line) => {
		stdoutLines.push(line);
		const m = JSON.parse(line);
		if (m.method === "elicitation/create") {
			elicitations.push(m.params);
			const answer = personAnswers.shift() ?? { action: "cancel" };
			proc.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id: m.id, result: answer })}\n`);
			return;
		}
		waiting.get(m.id)?.(m);
	});
	await new Promise((ok) => setTimeout(ok, 1500));
});
after(async () => {
	proc?.stdin?.end();
	proc?.kill();
	await ref?.stop();
});

test("protocol: legacy initialize and modern _meta on one process; discover; version errors", async () => {
	const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "test-host", version: "1" } });
	assert.equal(init.result.protocolVersion, "2025-06-18");
	assert.deepEqual(init.result.capabilities, { tools: { listChanged: false } });
	proc.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
	const list = await rpc("tools/list");
	const names = list.result.tools.map((t: { name: string }) => t.name);
	for (const n of ["vxp_discover", "vxp_read", "vxp_request", "vxp_authorize", "vxp_accept", "vxp_proof", "vxp_inbox", "vxp_reply"]) assert.ok(names.includes(n), n);
	assert.equal(list.result.tools.find((t: { name: string }) => t.name === "vxp_accept").annotations.destructiveHint, true);
	assert.ok(!names.some((n: string) => /mandate|rule_set|approve/.test(n)), "no tool lets the model set rules or decide approvals");

	const disc = await rpc("server/discover", { _meta: META() });
	assert.equal(disc.result.resultType, "complete");
	assert.ok(disc.result.supportedVersions.includes("2026-07-28"));
	assert.equal(disc.result._meta["io.modelcontextprotocol/serverInfo"].name, "vxp-agent");
	const bad = await rpc("tools/list", { _meta: { ...META(), "io.modelcontextprotocol/protocolVersion": "1900-01-01" } });
	assert.equal(bad.error.code, -32022);
	assert.equal(bad.error.data.requested, "1900-01-01");
	const noCaps = await rpc("tools/list", { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } });
	assert.equal(noCaps.error.code, -32602);
	const modernList = await rpc("tools/list", { _meta: META() });
	assert.equal(modernList.result.resultType, "complete");
	assert.equal((await rpc("no/such")).error.code, -32601);
});

test("the hotel task through MCP tools; accept and reply run only after the person confirms", async () => {
	const d = sc(await tool("vxp_discover", { domains: [ref.storeDomain, ref.hotelDomain], operation: "reserva.crear" }));
	const hotel = d.results.find((r: { offers_operation?: boolean }) => r.offers_operation);
	assert.equal(hotel.name, "Hotel Demo");
	const ci = nextFriday(28);
	const co = plusDays(ci, 2);
	const av = sc(await tool("vxp_read", { company: hotel.issuer, operation: "hotel.disponibilidad", parameters: { check_in: ci, check_out: co, adults: 2 } }));
	assert.equal(av.http, 200);
	const req = sc(await tool("vxp_request", { company: hotel.issuer, operation: "reserva.crear", parameters: { room_type: "DBL-EST", check_in: ci, check_out: co, adults: 2, services: [{ code: "DESAYUNO" }] } }));
	assert.equal(req.state, "authorization_required");
	const since = ref.lines.length;
	const auth = sc(await tool("vxp_authorize", { company: hotel.issuer, request_id: req.request_id, cap_clp: 250_000, relationship_actions: ["alerta.mantener_o_liberar"] }));
	assert.match(auth.tell_the_person, /Hotel Demo's own page/);
	await approveOnCompanyPage(auth.verification_uri_complete, PHONE, () => ref.waitForCode(since));
	assert.equal(sc(await tool("vxp_check_authorization", { company: hotel.issuer, wait_seconds: 20 })).status, "granted");
	assert.equal(sc(await tool("vxp_resubmit", { request_id: req.request_id })).state, "proposed");

	// The person has set no cap for the agent: accepting needs their confirmation. They decline first.
	personAnswers = [{ action: "decline" }];
	const no = sc(await tool("vxp_accept", { request_id: req.request_id }));
	assert.equal(no.status, "denied_by_person");
	assert.match(elicitations.at(-1).message, /Total \$\d/);
	assert.equal(sc(await tool("vxp_status", { request_id: req.request_id })).state, "proposed", "nothing ran");
	// Then they confirm the exact terms in the host's form.
	personAnswers = [{ action: "accept", content: { approve: true } }];
	const yes = sc(await tool("vxp_accept", { request_id: req.request_id }));
	assert.equal(yes.status, "accepted");
	assert.equal(yes.approved_by, "user");
	assert.equal(yes.state, "succeeded");
	assert.equal(sc(await tool("vxp_proof", { request_id: req.request_id })).verdict.valid, true);

	// The hotel's late-arrival rule (simulated clock: reference test aid) writes to the agent's inbox.
	await ref.internal("relaciones/revisar-llegadas", { tenant: HOTEL_TENANT, at: `${ci}T23:35:00.000Z` });
	const inbox = sc(await tool("vxp_inbox", {}));
	assert.equal(inbox.messages.length, 1);
	const alert = inbox.messages[0].content.alert_id;

	// Modern client without elicitation: the model only gets an approval URL to show; nothing is sent.
	const pending = sc(await tool("vxp_reply", { message_id: alert, decision: "mantener" }, META({})));
	assert.equal(pending.status, "needs_user_approval");
	assert.ok(pending.approval_url.startsWith(`${AG}/approve/`));
	assert.equal(sc(await tool("vxp_inbox", {})).messages[0].status, "new");

	// With only what the model received, the approval cannot be decided.
	const stored = JSON.parse(readFileSync(join(state, "approvals.json"), "utf8"))[pending.approval_id];
	const seen = JSON.stringify(pending);
	assert.ok(!seen.includes(stored.secret) && !seen.includes(stored.person_code) && !/[?&]k=/.test(seen), "no secret or person code reaches the model");
	assert.equal(new URL(pending.approval_url).search, "");
	const pageHtml = await (await fetch(pending.approval_url)).text();
	assert.ok(!pageHtml.includes(stored.person_code), "opening the page does not reveal the code");
	const tryPost = (body: Record<string, string>) => fetch(pending.approval_url, { method: "POST", body: new URLSearchParams(body) });
	assert.equal((await tryPost({ decision: "approve" })).status, 403);
	assert.equal((await tryPost({ decision: "approve", k: stored.secret })).status, 403, "the old ?k= secret is not a proof");
	for (const guess of ["00000000", "12345678", "99999999"]) assert.equal((await tryPost({ decision: "approve", code: guess })).status, 403);
	const locked = JSON.parse(readFileSync(join(state, "approvals.json"), "utf8"))[pending.approval_id];
	assert.equal(locked.status, "denied", "five wrong attempts deny the approval");
	await tryPost({ decision: "approve", code: stored.person_code });
	assert.equal(JSON.parse(readFileSync(join(state, "approvals.json"), "utf8"))[pending.approval_id].status, "denied", "a denied approval never becomes a yes");
	assert.equal(sc(await tool("vxp_inbox", {})).messages[0].status, "new", "nothing was sent to the hotel");
	// The person, in their own terminal, can still approve a new request with the CLI.
	const again = sc(await tool("vxp_reply", { message_id: alert, decision: "mantener" }, META({})));
	assert.notEqual(again.approval_id, pending.approval_id);
	const cliApprove = await run(process.execPath, [CLI, "approvals", "--state", state]);
	assert.equal(JSON.parse(cliApprove.stdout).find((x: { id: string }) => x.id === again.approval_id).code_for_the_page.length, 8, "the code is printed in the person's terminal");

	// Modern client with elicitation: input_required (MRTR), then the retry carries the person's answer.
	const ir = await tool("vxp_reply", { message_id: alert, decision: "mantener" }, META({ elicitation: {} }));
	assert.equal(ir.resultType, "input_required");
	assert.equal(ir.inputRequests.confirm.method, "elicitation/create");
	// A «yes» that does not carry the server's requestState (e.g. made up by the model) is not taken.
	const forged = await rpc("tools/call", { name: "vxp_reply", arguments: { message_id: alert, decision: "mantener" }, inputResponses: { confirm: { action: "accept", content: { approve: true } } }, requestState: `${ir.requestState.split(".")[0]}.forged`, _meta: META({ elicitation: {} }) });
	assert.equal(forged.result.resultType, "input_required");
	assert.equal(sc(await tool("vxp_inbox", {})).messages[0].status, "new");
	const r = await rpc("tools/call", { name: "vxp_reply", arguments: { message_id: alert, decision: "mantener" }, inputResponses: { confirm: { action: "accept", content: { approve: true } } }, requestState: ir.requestState, _meta: META({ elicitation: {} }) });
	assert.equal(r.result.structuredContent.status, "replied");
	assert.equal(r.result.structuredContent.http, 200);
	assert.equal(r.result.structuredContent.receipt_verified, true);

	// stdout carried MCP messages only.
	for (const l of stdoutLines) assert.equal(JSON.parse(l).jsonrpc, "2.0");
});

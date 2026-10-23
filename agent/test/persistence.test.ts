// Persistence: the whole task through the CLI, each step in its own process, and the agent's server
// (CIMD, JWKS, inbox, approvals) stopped and started again in the middle. Everything continues from the
// state directory: keys, the pending device authorization, the token, the request and its
// Idempotency-Key, the approval, the relationship and the inbox's seen jti.

import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { approveOnCompanyPage } from "./helpers/person.ts";
import { run } from "./helpers/run.ts";
import { HOTEL_TENANT, PHONE, nextFriday, plusDays, type Reference, startReference } from "./helpers/setup.ts";

const CLI = join(import.meta.dirname, "..", "bin", "vxp-agent.ts");
const AG = "http://localhost:3841";
const state = mkdtempSync(join(tmpdir(), "vxp-agent-persist-"));
let ref: Reference;
let server: ChildProcess | null = null;

const base = () => ["--state", state, "--origin", AG, "--allow-http", [ref.origin, `http://${ref.hotelDomain}`, AG].join(",")];
async function cli(...args: string[]): Promise<any> {
	const r = await run(process.execPath, [CLI, ...args, ...base()]);
	assert.equal(r.status, 0, `vxp-agent ${args.join(" ")}\n${r.stdout}\n${r.stderr}`);
	return JSON.parse(r.stdout);
}
async function serve(): Promise<ChildProcess> {
	const p = spawn(process.execPath, [CLI, "serve", "--port", "3841", ...base()], { stdio: ["ignore", "ignore", "pipe"] });
	await new Promise<void>((ok, fail) => {
		const t = setTimeout(() => fail(new Error("agent server did not start")), 10_000);
		p.stderr!.on("data", (d) => String(d).includes("listening") && (clearTimeout(t), ok()));
	});
	return p;
}
const stop = (p: ChildProcess | null) => new Promise<void>((ok) => (!p || p.exitCode !== null ? ok() : (p.once("exit", () => ok()), p.kill())));

before(async () => {
	ref = await startReference({ port: 3840, agentOrigins: [AG] });
});
after(async () => {
	await stop(server);
	await ref?.stop();
});

test("each step in a new process, with the agent's server restarted mid-task: the task continues from the state directory", async () => {
	server = await serve();
	const id1 = await cli("init");
	const found = await cli("discover", ref.hotelDomain, "--offers", "reserva.crear");
	assert.equal(found[0].offers, true);
	const H = found[0].issuer;
	// No cap rule for the agent this time: the person approves the exact terms in a terminal, later.
	await cli("mandate", "reply", H, "alerta.mantener_o_liberar", "mantener");
	const ci = nextFriday(21);
	const req = await cli("request", H, "reserva.crear", "--params", JSON.stringify({ room_type: "DBL-EST", check_in: ci, check_out: plusDays(ci, 2), adults: 2, services: [{ code: "DESAYUNO" }] }));
	assert.equal(req.http, 202);
	const since = ref.lines.length;
	const auth = await cli("authorize", H, "--request", req.request_id, "--cap-clp", "250000", "--relationship", "alerta.mantener_o_liberar");
	assert.ok(auth.verification_uri_complete.startsWith(ref.origin));

	// The agent's server goes down; the person approves meanwhile; a NEW server process comes up.
	await stop(server);
	await approveOnCompanyPage(auth.verification_uri_complete, PHONE, () => ref.waitForCode(since));
	server = await serve();
	assert.equal((await cli("whoami")).client_id, id1.client_id, "same identity after restart");
	assert.equal((await cli("approve-url", H)).user_code, auth.user_code, "the pending authorization survived");

	const grant = await cli("wait-authorization", H, "--timeout", "20");
	assert.equal(grant.status, "granted");
	const proposed = await cli("resubmit", req.request_id);
	assert.equal(proposed.http, 201);
	assert.equal(proposed.request_id, req.request_id);
	const ask = await cli("accept", req.request_id);
	assert.equal(ask.status, "needs_user_approval");
	assert.equal((await cli("approvals"))[0].id, ask.approval_id);
	assert.equal((await cli("approve", ask.approval_id, "--yes")).approval_status, "approved");
	const done = await cli("accept", req.request_id);
	assert.equal(done.status, "accepted");
	assert.equal(done.approved_by, "user");
	assert.equal(done.view.state, "succeeded");
	assert.equal((await cli("proof", req.request_id)).verdict.valid, true);
	assert.equal((await cli("verify", req.request_id)).valid, true);

	// The hotel writes while the second server runs; then that server restarts and the replay is refused.
	const rel = (await cli("relationships"))[0];
	const sent = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", { reservation_ref: done.view.result.data.reserva, summary: "¿Mantenemos o liberamos?" });
	assert.equal(sent.body.http, 202);
	const inbox = await cli("inbox");
	assert.equal(inbox.length, 1);
	assert.equal(inbox[0].reply.decision, "mantener");
	await stop(server);
	server = await serve();
	const genuine = ((await ref.internal(`relaciones/salida?tenant=${HOTEL_TENANT}`)).body as { mensaje: string }[]).at(-1)!.mensaje;
	const replay = await fetch(`${AG}/vxp/inbox`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: genuine }) });
	assert.equal(replay.status, 409, "the seen jti survived the restart");
	assert.equal((await cli("inbox")).length, 1);
});

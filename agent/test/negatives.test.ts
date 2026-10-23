// What must NOT happen: an amount above the person's cap does not execute; a revoked or expired
// relationship is not used; a company message with a forged signature or a repeated jti is rejected;
// an altered proof does not verify.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { RAR_CAPABILITY } from "../src/agent.ts";
import { generatePrivateJwk, signJwt, signingKey } from "../src/jose.ts";
import { decideOnAgentPage } from "./helpers/person.ts";
import { type AgentUnderTest, HOTEL_TENANT, linkAccount, nextFriday, plusDays, type Reference, startAgent, startReference } from "./helpers/setup.ts";

let ref: Reference;
const agents: AgentUnderTest[] = [];
let port = 3861;
const fresh = async () => {
	const t = await startAgent(ref, port++);
	agents.push(t);
	await t.agent.discover([ref.hotelDomain]);
	return t;
};
const ORIGINS = Array.from({ length: 8 }, (_, i) => `http://localhost:${3861 + i}`);

before(async () => {
	ref = await startReference({ port: 3860, agentOrigins: ORIGINS });
});
after(async () => {
	for (const t of agents) t.close();
	await ref?.stop();
});

async function hotelBookings(): Promise<number> {
	return ((await ref.internal(`estado?tenant=${HOTEL_TENANT}`)).body as { reservas: unknown[] }).reservas.length;
}

const stay = (room: string, weeks = 2) => {
	const ci = nextFriday(7 * weeks);
	return { room_type: room, check_in: ci, check_out: plusDays(ci, 2), adults: 2, services: [{ code: "DESAYUNO" }] };
};

test("cap exceeded: the agent does not ask for more authority, the company does not propose above the grant, and the agent does not accept above the person's cap", async () => {
	const { agent: a } = await fresh();
	const H = a.company(ref.hotelDomain).issuer;
	const before = await hotelBookings();

	// (a) The agent refuses to ask the company for authority above the person's cap.
	const vis = await a.createRequest(H, "reserva.crear", {}, stay("DBL-VIS"));
	assert.ok(vis.body.quote.total > 250_000);
	await assert.rejects(a.authorize(H, { forRequest: vis.record!.request_id, capClp: 250_000 }), /above the cap of 250000/);

	// (b) With a grant of $250.000, the company itself does not propose the $273.400 stay.
	await linkAccount(ref, a, H, { details: [{ type: RAR_CAPABILITY, actions: ["reserva.crear"], identifier: "nuevo", limits: { max_total_clp: 250_000 } }] });
	const r = await a.resubmit(vis.record!.request_id);
	assert.equal(r.http, 202);
	assert.equal(r.body.state, "authorization_required");
	assert.equal(r.body.authorization.authorization_details[0].limits.max_total_clp, vis.body.quote.total);

	// (c) The person authorized $300.000 at the hotel, but their own rule for the agent is $250.000:
	// the agent does not accept, and does not even ask the person to approve.
	const vis2 = await a.createRequest(H, "reserva.crear", {}, stay("DBL-VIS", 3));
	await linkAccount(ref, a, H, { forRequest: vis2.record!.request_id, capClp: 300_000 });
	const p = await a.resubmit(vis2.record!.request_id);
	assert.equal(p.body.state, "proposed");
	a.setMandate(H, "reserva.crear", 250_000);
	const acc = await a.accept(vis2.record!.request_id);
	assert.equal(acc.status, "blocked_by_mandate");
	assert.equal(a.approvals().length, 0, "no approval was even offered");
	assert.equal((await a.refresh(vis2.record!.request_id)).state, "proposed");
	assert.equal(await hotelBookings(), before, "no booking was created");
});

test("person denies the exact terms: nothing runs", async () => {
	const { agent: a } = await fresh();
	const H = a.company(ref.hotelDomain).issuer;
	const before = await hotelBookings();
	const r = await a.createRequest(H, "reserva.crear", {}, stay("DBL-EST", 4));
	await linkAccount(ref, a, H, { forRequest: r.record!.request_id, capClp: 250_000 });
	await a.resubmit(r.record!.request_id);
	const first = await a.accept(r.record!.request_id);
	assert.equal(first.status, "needs_user_approval");
	if (first.status !== "needs_user_approval") return;
	await decideOnAgentPage(a.approvalUrl(first.approval)!, first.approval.person_code, false);
	const second = await a.accept(r.record!.request_id);
	assert.equal(second.status, "needs_user_approval", "a denied approval never becomes a yes");
	assert.equal((await a.refresh(r.record!.request_id)).state, "proposed");
	assert.equal(await hotelBookings(), before);
});

/** An agent with a booking and a relationship, ready for company messages. */
async function withRelationship(durationSeconds = 7 * 86_400) {
	const t = await fresh();
	const a = t.agent;
	const H = a.company(ref.hotelDomain).issuer;
	const r = await a.createRequest(H, "reserva.crear", {}, stay("DBL-EST", 5 + agents.length));
	const { grant } = await linkAccount(ref, a, H, { forRequest: r.record!.request_id, capClp: 250_000, relationship: { actions: ["alerta.mantener_o_liberar"], duration_seconds: durationSeconds } });
	await a.resubmit(r.record!.request_id);
	const ask = await a.accept(r.record!.request_id);
	if (ask.status === "needs_user_approval") await decideOnAgentPage(a.approvalUrl(ask.approval)!, ask.approval.person_code, true);
	const done = await a.accept(r.record!.request_id);
	assert.equal(done.status, "accepted");
	return { t, a, H, rel: grant.relationships![0], booking: (done as any).view.result.data.reserva as string };
}

const question = (booking: string) => ({ reservation_ref: booking, summary: "¿Mantenemos o liberamos tu reserva?" });

test("relationship revoked by the person at the company: the company cannot send, and a late answer is refused", async () => {
	const { a, H, rel, booking } = await withRelationship();
	const ok = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(ok.body.http, 202);
	const msg = a.inbox().messages.at(-1)!;
	assert.equal(msg.status, "new", "no standing answer: it waits for the person");
	assert.equal((await ref.companyRevokes(HOTEL_TENANT, rel.relationship_id, "usuario")).status, 200);
	const blocked = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(blocked.status, 409);
	assert.equal(blocked.body.error, "relationship_revoked");
	a.setReplyRule(H, "alerta.mantener_o_liberar", "liberar");
	const late = await a.reply(msg.id, "liberar");
	assert.equal(late.status, "replied");
	if (late.status !== "replied") return;
	assert.equal(late.http, 403);
	assert.equal(late.body.error, "relationship_revoked");
	assert.equal(a.message(msg.id).status, "new");
});

test("relationship revoked by the agent (DELETE /v1/relationships/{id}): the company can no longer send", async () => {
	const { a, rel, booking } = await withRelationship();
	const r = await a.revokeRelationship(rel.relationship_id);
	assert.equal(r.status, 200);
	assert.equal(r.body.state, "revoked");
	assert.equal((await a.readRelationship(rel.relationship_id)).body.state, "revoked");
	const blocked = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(blocked.body.error, "relationship_revoked");
});

test("revoked locally while the company still thinks it is active: the inbox rejects the message (403)", async () => {
	const { t, a, rel, booking } = await withRelationship();
	// The agent's DELETE never reached the company (e.g. no network): only the local record says revoked.
	t.agent.store.update<Record<string, any>, void>("relationships", {}, (all) => void ((all[rel.relationship_id].state = "revoked"), (all[rel.relationship_id].revoked_at = new Date().toISOString())));
	const sent = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(sent.status, 201);
	assert.equal(sent.body.http, 403, "the inbox refused it");
	assert.equal(a.inbox().messages.length, 0);
	assert.equal(a.inbox().rejected.at(-1)!.reason, "relationship_revoked");
});

test("relationship expired: the company cannot send, and the agent's inbox and reply refuse it", async () => {
	const { a, H, rel, booking } = await withRelationship(12);
	const sent = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(sent.body.http, 202);
	const msg = a.inbox().messages.at(-1)!;
	await new Promise((ok) => setTimeout(ok, Math.max(0, Date.parse(rel.expires_at) - Date.now()) + 1_500));
	const blocked = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(blocked.status, 409);
	assert.equal(blocked.body.error, "relationship_expired");
	assert.equal(a.relationshipUsable(a.relationships().find((r) => r.relationship_id === rel.relationship_id)!), false);
	a.setReplyRule(H, "alerta.mantener_o_liberar", "mantener");
	const late = await a.reply(msg.id, "mantener");
	assert.equal(late.status, "replied");
	if (late.status !== "replied") return;
	assert.equal(late.http, 0, "not even sent: the relationship is expired locally");
	assert.equal(a.message(msg.id).status, "new");
});

test("company message with a forged signature or a repeated jti is rejected", async () => {
	const { t, a, rel, booking } = await withRelationship();
	const inbox = `${t.origin}/vxp/inbox`;
	const post = async (message: string) => {
		const r = await fetch(inbox, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message }) });
		return { status: r.status, body: await r.json() };
	};
	const H = a.company(ref.hotelDomain);
	const realKid = ((await (await fetch(H.relationshipJwksUri!)).json()) as { keys: { kid: string }[] }).keys[0].kid;
	const nowS = Math.floor(Date.now() / 1000);
	const claims = { iss: H.issuer, aud: a.clientId, sub: a.userIdFor(H.issuer), rel: rel.relationship_id, action: "alerta.mantener_o_liberar", content: { order_ref: booking, summary: "x", alert_id: "alr_forged", options: ["mantener", "liberar"], reply_url: `${H.endpoint}/relationships/${rel.relationship_id}/replies` }, iat: nowS, exp: nowS + 600, jti: "forged-jti-0001" };
	// Signed by someone else's key, presenting the hotel's kid.
	const attacker = signingKey(generatePrivateJwk());
	const forged = signJwt(attacker, { typ: "vxp-company-request+jwt", kid: realKid }, claims);
	assert.deepEqual(await post(forged), { status: 401, body: { error: "invalid_signature" } });
	// A valid-looking JWS whose payload was edited after signing.
	const [h, , s] = forged.split(".");
	assert.equal((await post(`${h}.${Buffer.from(JSON.stringify({ ...claims, rel: "rel_other" })).toString("base64url")}.${s}`)).status, 401);
	assert.equal(a.inbox().messages.length, 0);

	// A genuine message, delivered once by the hotel, then replayed by whoever captured it.
	const ok = await ref.companyStarts(HOTEL_TENANT, rel.relationship_id, "alerta.mantener_o_liberar", question(booking));
	assert.equal(ok.body.http, 202);
	const genuine = ((await ref.internal(`relaciones/salida?tenant=${HOTEL_TENANT}`)).body as { relacionId: string; mensaje: string }[]).filter((x) => x.relacionId === rel.relationship_id).at(-1)!.mensaje;
	assert.deepEqual(await post(genuine), { status: 409, body: { error: "replayed_jti" } });
	assert.equal(a.inbox().messages.length, 1, "only the first delivery counts");
	assert.deepEqual(a.inbox().rejected.map((r) => r.reason), ["invalid_signature", "invalid_signature", "replayed_jti"]);
});

test("altered proof: valid false", async () => {
	const { t, a } = await withRelationship();
	const req = a.requests().find((r) => r.state === "succeeded")!.request_id;
	const p = await a.proof(req);
	assert.equal(p.verdict.valid, true);
	const { verifyWithMaterial } = await import("../src/verify.ts");
	const pkg = t.agent.store.readFile<any>(`${req}.package.json`)!;
	const material = t.agent.store.readFile<any>(`${req}.material.json`)!;
	// One character of one signed statement's payload.
	const tampered = structuredClone(pkg);
	const st = tampered.statements.at(-1);
	const key = typeof st === "string" ? null : Object.keys(st).find((k) => typeof st[k] === "string" && st[k].split(".").length >= 3);
	const jws: string = key ? st[key] : st;
	const parts = jws.split(".");
	const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
	payload.iat += 1;
	parts[1] = Buffer.from(JSON.stringify(payload)).toString("base64url");
	if (key) st[key] = parts.join(".");
	else tampered.statements[tampered.statements.length - 1] = parts.join(".");
	const v1 = await verifyWithMaterial(tampered, material);
	assert.equal(v1.valid, false, JSON.stringify(v1));
	// The operation the agent saw, with another total than the one signed.
	const op = t.agent.store.readFile<any>(`${req}.operation.json`)!;
	const v2 = await verifyWithMaterial(pkg, material, { operation: { ...op, terms: { ...op.terms, total: op.terms.total - 1 } } });
	assert.equal(v2.valid, false);
	assert.equal(v2.error, "operation_terms_mismatch");
	// Material that is not the issuer's (another key set): not anchored.
	const docs = { ...material.docs };
	const companyJwks = Object.keys(docs).find((u) => u.endsWith("/vxp/proof-jwks.json") && u.includes("/e/"))!;
	docs[companyJwks] = JSON.stringify({ keys: [{ ...signingKey(generatePrivateJwk()).publicJwk }] });
	const v3 = await verifyWithMaterial(pkg, { ...material, docs });
	assert.equal(v3.valid, false);
});

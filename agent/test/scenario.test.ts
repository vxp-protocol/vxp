// The hotel scenario, end to end, against the reference gateway in native-only mode, in another process:
// discover among several candidates → public quotes with breakfast → the person links their account on the
// hotel's page (cap + relationship in one consent) → same request again → counter-proposal → acceptance
// within the person's rules → one booking in the hotel's system → proof verified by two independent
// verifiers → the hotel's late-arrival question reaches the inbox and is answered within the agreement.

import assert from "node:assert/strict";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { amountOf } from "../src/agent.ts";
import { run } from "./helpers/run.ts";
import { type AgentUnderTest, HOTEL_TENANT, linkAccount, nextFriday, plusDays, type Reference, startAgent, startReference } from "./helpers/setup.ts";

const PY_VERIFIER = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
let ref: Reference;
let t: AgentUnderTest;

before(async () => {
	ref = await startReference({ port: 3830, agentOrigins: ["http://localhost:3831"] });
	t = await startAgent(ref, 3831);
});
after(async () => {
	t?.close();
	await ref?.stop();
});

/** Reference test aid (company console, not VXP): the hotel's PMS as the hotel sees it. */
async function hotelSystem() {
	return (await ref.internal(`estado?tenant=${HOTEL_TENANT}`)).body as { reservas: { id: string; total: number; estado: string; historial: { cambio: string }[] }[] };
}

test("hotel in Santiago, two nights with breakfast, up to $250.000: book, prove, and keep the relationship", async () => {
	const a = t.agent;
	const checkIn = nextFriday();
	const checkOut = plusDays(checkIn, 2);

	// 1. Discovery among candidates: one store, one hotel, one domain without VXP.
	const found = await a.discover([ref.storeDomain, ref.hotelDomain, "localhost:3839"]);
	assert.deepEqual(found.map((r) => r.ok), [true, true, false]);
	const hotel = found.flatMap((r) => (r.ok && r.company.capabilities.some((c) => c.id === "reserva.crear") ? [r.company] : []));
	assert.equal(hotel.length, 1);
	assert.equal(hotel[0].name, "Hotel Demo");
	const H = hotel[0].issuer;

	// The person's rules, set before the agent acts.
	a.setMandate(H, "reserva.crear", 250_000);
	a.setReplyRule(H, "alerta.mantener_o_liberar", "mantener");

	// 2. Availability with breakfast (public read: no operation), then the hotel's quote for the cheapest room.
	const av = await a.read(H, "hotel.disponibilidad", { check_in: checkIn, check_out: checkOut, adults: 2 });
	assert.equal(av.http, 200, JSON.stringify(av.body));
	assert.equal(av.body.effect, "read");
	const bf = av.body.result.services.find((x: { code: string }) => x.code === "DESAYUNO");
	const estimate = (code: string) => av.body.result.room_types.find((x: { tipo: string }) => x.tipo === code).directa + bf.price * 2 * 2;
	assert.ok(estimate("DBL-VIS") > 250_000, "on a weekend the view room with breakfast is above the cap");
	assert.ok(estimate("DBL-EST") <= 250_000);
	const q = await a.createRequest(H, "reserva.crear", {}, { room_type: "DBL-EST", check_in: checkIn, check_out: checkOut, adults: 2, services: [{ code: "DESAYUNO" }] });
	assert.equal(q.http, 202);
	assert.equal(q.body.state, "authorization_required");
	assert.equal(q.body.quote.total, estimate("DBL-EST"), "the availability read and the quote agree");
	const quotes = { "DBL-EST": { total: q.body.quote.total as number } };
	const req = q.record!.request_id;

	// 3. Authorization on the hotel's own page: the cap, not the quote; and the relationship, in one consent.
	const { page, grant } = await linkAccount(ref, a, H, { forRequest: req, capClp: 250_000, relationship: { actions: ["alerta.mantener_o_liberar"], max_per_day: 2, duration_seconds: 7 * 86_400 } });
	assert.match(page.consent.text, /hacer una reserva nueva a tu nombre por hasta \$250\.000/);
	assert.match(page.consent.text, /mantiene o libera tu reserva/);
	assert.equal(grant.status, "granted");
	assert.deepEqual((grant.authorization_details as any[])[0].limits, { max_total_clp: 250_000 });
	const rel = grant.relationships![0];
	assert.equal(rel.agreement_verified, true, "the signed agreement verifies with the hotel's relationship key");

	// 4. Same request, same Idempotency-Key: the hotel proposes signed terms.
	const p = await a.resubmit(req);
	assert.equal(p.http, 201);
	assert.equal(p.body.request_id, req);
	assert.equal(p.body.state, "proposed");
	assert.equal(amountOf(p.body), quotes["DBL-EST"].total);

	// 5. Counter-proposal on the rate: the hotel's policy has no extra discount, and says so.
	const c = await a.counter(req, { discount_pct: 10 });
	assert.equal(c.http, 409);
	assert.equal(c.body.error, "counter_rejected");
	assert.equal(c.body.reason, "sin_descuento_adicional");
	assert.equal(c.record.view.proposal.revision, 1);

	// 6. Accept: the revision is within the cap the person approved at the hotel and set as their rule.
	assert.equal(p.body.proposal.user_approval_required, false);
	const done = await a.accept(req);
	assert.equal(done.status, "accepted");
	if (done.status !== "accepted") return;
	assert.equal(done.approved_by, "standing_permission");
	assert.equal(a.approvals().length, 0, "the person was not asked again");
	assert.equal(done.view.state, "succeeded");
	const booking = done.view.result.data.reserva as string;
	assert.match(booking, /^R-\d{4}$/);

	// The effect, seen from the hotel's side (reference console): one booking, the approved total.
	const pms = (await hotelSystem()).reservas.filter((r) => r.historial.some((h) => h.cambio.includes(done.view.operation_id)));
	assert.equal(pms.length, 1);
	assert.equal(pms[0].id, booking);
	assert.equal(pms[0].total, quotes["DBL-EST"].total);

	// Accepting again does not execute again.
	const again = await a.call(a.company(H), "POST", `${a.company(H).endpoint}/proposals/${done.view.proposal.id}/accept`, { approved_by: "user" });
	assert.equal(again.status, 200);
	assert.equal((await hotelSystem()).reservas.filter((r) => r.historial.some((h) => h.cambio.includes(done.view.operation_id))).length, 1);

	// 7. Proof: verified locally (vxp-verify.js), and by the Python reference verifier with the same material.
	const proof = await a.proof(req);
	assert.equal(proof.verdict.valid, true, JSON.stringify(proof.verdict));
	assert.equal(proof.verdict.anchor, "issuer");
	assert.equal(proof.verdict.final_state, "succeeded");
	assert.equal(proof.verdict.operation, "matches");
	assert.equal(typeof proof.verdict.approval, "string");
	const py = await run("python", [PY_VERIFIER, "material", "--material", proof.material_file, "--paquete", proof.package_file, "--operacion", join(t.stateDir, "proofs", `${req}.operation.json`)]);
	assert.equal(JSON.parse(py.stdout.trim().split("\n").at(-1)!).valid, true, py.stdout + py.stderr);
	assert.equal((await a.verifySaved(req)).valid, true, "offline, with the saved material");

	// 8. The hotel's own late-arrival rule (run with the reference's simulated clock: test aid) asks the agent.
	const asked = (await ref.internal("relaciones/revisar-llegadas", { tenant: HOTEL_TENANT, at: `${checkIn}T23:35:00.000Z` })).body as { reserva: string; resultado: { http: number } }[];
	assert.deepEqual(asked.map((x) => x.reserva), [booking]);
	assert.equal(asked[0].resultado.http, 202, "delivered to the inbox declared in the CIMD");
	const msg = a.inbox().messages.at(-1)!;
	assert.equal(msg.action, "alerta.mantener_o_liberar");
	assert.deepEqual(msg.content.options, ["mantener", "liberar"]);
	assert.equal(msg.status, "answered");
	assert.equal(msg.reply!.decision, "mantener");
	assert.equal(msg.reply!.receipt_verified, true);
	const kept = (await hotelSystem()).reservas.find((r) => r.id === booking)!;
	assert.equal(kept.estado, "confirmada");
	assert.ok(kept.historial.some((h) => /mantenida por el asistente/.test(h.cambio)));
});

test("negotiation through the hotel's policy: the «Escapada» package lowers the view room with breakfast, within the cap", async () => {
	const a = t.agent;
	const H = a.company(ref.hotelDomain).issuer;
	// A Monday: weekday rates, two nights.
	const d = new Date(Date.parse(`${nextFriday(35)}T00:00:00Z`) + 3 * 86_400_000).toISOString().slice(0, 10);
	const r = await a.createRequest(H, "reserva.crear", {}, { room_type: "DBL-VIS", check_in: d, check_out: plusDays(d, 2), adults: 2, services: [{ code: "DESAYUNO" }] });
	// The grant from the first test (a new booking up to $250.000) still covers it: proposed at once.
	assert.equal(r.http, 201, JSON.stringify(r.body));
	const before = amountOf(r.body)!;
	assert.ok(before <= 250_000);
	const c = await a.counter(r.record!.request_id, { package: "ESCAPADA" });
	assert.equal(c.http, 200, JSON.stringify(c.body));
	assert.equal(c.body.proposal.revision, 2);
	const after = amountOf(c.body)!;
	assert.ok(after < before, `${after} < ${before}`);
	assert.equal(c.body.proposal.terms.descuento.pct, 10);
	assert.ok(c.body.proposal.terms.servicios.some((s: { codigo: string }) => s.codigo === "DESAYUNO"));
	assert.equal(c.body.proposal.user_approval_required, false, "still within the person's cap");
	const done = await a.accept(r.record!.request_id);
	assert.equal(done.status, "accepted");
	if (done.status !== "accepted") return;
	assert.equal(done.approved_by, "standing_permission");
	assert.equal(done.view.proposal.revision, 2, "the negotiated revision is the one executed");
	assert.equal(amountOf(done.view), after);
	assert.equal((await a.proof(r.record!.request_id)).verdict.valid, true);
});

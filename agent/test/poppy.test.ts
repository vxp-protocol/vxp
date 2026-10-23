// The hotel task through the optional Poppy adapter, against the reference gateway in its own process with
// VXP_ADAPTERS=poppy: poppy.json → session → conversation (quote, discount refused, «Escapada» package)
// → Device Sign-In on the hotel's page → proposal in the Operations extension → confirm only within the person's
// rules → one booking → VXP Proof from the operation's `vxpprotocol.org/proof` member, verified anchored by the
// Poppy domain, by vxp-verify.js and by the Python reference verifier.

import assert from "node:assert/strict";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { PoppyAdapter } from "../src/adapters/poppy.ts";
import { approveOnCompanyPage, decideOnAgentPage } from "./helpers/person.ts";
import { run } from "./helpers/run.ts";
import { type AgentUnderTest, HOTEL_TENANT, nextFriday, plusDays, type Reference, startAgent, startReference } from "./helpers/setup.ts";

const PY_VERIFIER = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
let ref: Reference;
let t: AgentUnderTest;

before(async () => {
	ref = await startReference({ port: 3870, agentOrigins: ["http://localhost:3871"], adapters: "poppy" });
	t = await startAgent(ref, 3871);
});
after(async () => {
	t?.close();
	await ref?.stop();
});

test("Poppy adapter: hotel booking with breakfast, negotiated by the hotel's package, confirmed within the person's rules, proof verified", async () => {
	const a = t.agent;
	const poppy = new PoppyAdapter(a);
	assert.deepEqual(a.clientMetadata().extensions.operations, { version: "1" }, "the agent declares Poppy Operations");

	const c = await poppy.detect(ref.hotelDomain);
	assert.ok(c, "Hotel Demo publishes poppy.json");
	assert.equal(c.name, "Hotel Demo");
	assert.ok("reservas:crear" in c.scopes);
	assert.equal(await poppy.detect(ref.storeDomain).then((x) => x?.name), "Ferretería Demo");

	// A Monday: weekday rates.
	const d1 = plusDays(nextFriday(21), 3);
	const d2 = plusDays(d1, 2);
	const q = await poppy.say(c.issuer, `Quiero reservar del ${d1} al ${d2} una habitación doble con vista para 2 adultos con desayuno`, { operation: "reserva.crear" });
	const quote = q.data.find((x: any) => x?.estadia)?.estadia as { total: number; tipo: string };
	assert.equal(quote.tipo, "DBL-VIS");
	assert.equal(quote.total, 244_000);
	const discount = await poppy.say(c.issuer, "¿Me pueden hacer un descuento?");
	assert.match(discount.texts.join(" "), /No tenemos otros descuentos/);
	const pkg = await poppy.say(c.issuer, "Entonces con el paquete escapada");
	const revised = pkg.data.find((x: any) => x?.estadia)?.estadia as { total: number; paquete: string };
	assert.equal(revised.paquete, "ESCAPADA");
	assert.equal(revised.total, 230_400, "the package lowers the stay");

	// Booking needs the person's account: Device Sign-In on the hotel's own page.
	const ask = await poppy.say(c.issuer, "Resérvala", { operation: "reserva.crear" });
	assert.equal(ask.authorization?.error, "sign_in_required");
	assert.equal(ask.operation, null, "nothing proposed without the person");
	const since = ref.lines.length;
	const auth = await poppy.authorize(c.issuer, ["reservas:crear"]);
	await approveOnCompanyPage(auth.verification_uri_complete, "+56 9 0000 0101", () => ref.waitForCode(since));
	assert.equal((await poppy.pollAuthorization(c.issuer, 20)).status, "granted");

	const proposed = await poppy.say(c.issuer, "Resérvala", { operation: "reserva.crear" });
	const op = proposed.operation;
	assert.equal(op?.state, "proposed");
	assert.equal(op.terms.total, 230_400);
	assert.equal(op.terms.descuento?.pct, 10, "the package discount is in the signed terms");
	assert.ok(op["vxpprotocol.org/proof"]?.bundle_url, "the operation carries the proof member");
	assert.equal(op.user_approval_required, true);

	// The person's rules: above their cap, nothing is confirmed; within it, the hotel still asks for their approval.
	await a.discover([ref.hotelDomain]);
	a.setMandate(c.issuer, "reserva.crear", 200_000);
	assert.equal((await poppy.accept(c.issuer, op.operation_id)).status, "blocked_by_mandate");
	a.setMandate(c.issuer, "reserva.crear", 250_000);
	const first = await poppy.accept(c.issuer, op.operation_id);
	assert.equal(first.status, "needs_user_approval");
	if (first.status !== "needs_user_approval") return;
	assert.equal((await poppy.status(c.issuer, op.operation_id)).state, "proposed", "nothing ran");
	await decideOnAgentPage(a.approvalUrl(first.approval)!, first.approval.person_code, true);
	const done = await poppy.accept(c.issuer, op.operation_id);
	assert.equal(done.status, "accepted");
	if (done.status !== "accepted") return;
	assert.equal(done.approved_by, "user");
	assert.equal(done.view.state, "succeeded");
	const booking = done.view.result.data.reserva as string;

	const pms = (await ref.internal(`estado?tenant=${HOTEL_TENANT}`)).body.reservas as { id: string; total: number; servicios: { codigo: string }[] }[];
	const r = pms.find((x) => x.id === booking)!;
	assert.equal(r.total, 230_400);
	assert.deepEqual(r.servicios.map((s) => s.codigo).sort(), ["DESAYUNO", "ESTAC"]);

	const proof = await poppy.proof(c.issuer, op.operation_id);
	assert.equal(proof.verdict.valid, true, JSON.stringify(proof.verdict));
	assert.equal(proof.verdict.anchor, "poppy_domain");
	assert.equal(proof.verdict.final_state, "succeeded");
	assert.equal(proof.verdict.operation, "matches");
	const py = await run("python", [PY_VERIFIER, "material", "--material", proof.material_file, "--paquete", proof.package_file, "--operacion", join(t.stateDir, "proofs", `poppy-${op.operation_id}.operation.json`)]);
	assert.equal(JSON.parse(py.stdout.trim().split("\n").at(-1)!).valid, true, py.stdout + py.stderr);
});

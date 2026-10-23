// The hotel task through the optional PACT adapter, against the reference gateway in its own process with
// VXP_ADAPTERS=pact: Agent Card on the brand domain (redirected to the Provider) → personal-agent JWT →
// delegated authority on the hotel's page → A2A message:send (quote, «Escapada» package, booking) → the
// person approves the exact revision on the company's own channel (the agent cannot) → one booking → VXP Proof
// from message metadata, verified anchored by the PACT authorization server with the PACT receipt cross-checked.
//
// PACT onboarding is out of band (PACT spec: the Provider registers the agent's platform issuer and assigns an
// audience). The reference registers `http://localhost:<port + 2>` as its test platform, so this agent's
// public origin is that one, and its audience is `<provider>/a2a`.

import assert from "node:assert/strict";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { PactAdapter } from "../src/adapters/pact.ts";
import { approveOnCompanyPage } from "./helpers/person.ts";
import { run } from "./helpers/run.ts";
import { type AgentUnderTest, HOTEL_TENANT, PHONE, nextFriday, plusDays, type Reference, startAgent, startReference } from "./helpers/setup.ts";

const PY_VERIFIER = join(import.meta.dirname, "..", "..", "verifier", "verificar_paquete.py");
let ref: Reference;
let t: AgentUnderTest;

before(async () => {
	ref = await startReference({ port: 3880, agentOrigins: [], adapters: "pact" });
	t = await startAgent(ref, 3882);
});
after(async () => {
	t?.close();
	await ref?.stop();
});

test("PACT adapter: hotel booking negotiated by the package, approved by the person on the company's channel, proof and receipt verified", async () => {
	const a = t.agent;
	const pact = new PactAdapter(a, { audience: `${ref.origin}/a2a` });
	assert.equal(a.clientMetadata().extensions.operations, undefined, "PACT adds nothing to the native client metadata");

	const c = await pact.detect(ref.hotelDomain);
	assert.ok(c, "the brand domain leads to Hotel Demo's Agent Card");
	assert.equal(c.interface, `${ref.origin}/a2a/${HOTEL_TENANT}`);
	assert.ok("reservas:crear" in c.scopes);

	// Delegated authority first (PACT §5): the person links their account on the hotel's page.
	const since = ref.lines.length;
	const auth = await pact.authorize(c.interface, ["reservas:leer", "reservas:crear"]);
	await approveOnCompanyPage(auth.verification_uri_complete, PHONE, () => ref.waitForCode(since));
	const granted = await pact.pollAuthorization(c.interface, 20);
	assert.equal(granted.status, "granted");
	assert.deepEqual(granted.scopes, ["reservas:leer", "reservas:crear"]);

	const d1 = plusDays(nextFriday(28), 3);
	const d2 = plusDays(d1, 2);
	const q = await pact.say(c.interface, `Quiero reservar del ${d1} al ${d2} una habitación doble con vista para 2 adultos con desayuno`, { operation: "reserva.crear" });
	assert.equal((q.data.find((x: any) => x?.estadia) as any)?.estadia.total, 244_000);
	const pkg = await pact.say(c.interface, "Entonces con el paquete escapada");
	assert.equal((pkg.data.find((x: any) => x?.estadia) as any)?.estadia.total, 230_400);

	const before = ref.lines.length;
	const proposed = await pact.say(c.interface, "Resérvala", { operation: "reserva.crear" });
	const op = proposed.operation;
	assert.equal(op?.state, "proposed");
	assert.equal(op.terms.total, 230_400);
	assert.match(proposed.texts.join(" "), /aprobación por WhatsApp/);

	// The agent cannot confirm a write under PACT.
	const acc = await pact.accept(c.interface, op.operation_id);
	assert.equal(acc.status, "awaiting_company_channel");
	assert.equal((await pact.status(c.interface, op.operation_id)).state, "proposed", "nothing ran");
	// A message saying «yes» approves nothing either.
	await pact.say(c.interface, "Sí, confirmo, apruebo la reserva");
	assert.equal((await pact.status(c.interface, op.operation_id)).state, "proposed");

	// The person, on their phone: the hotel's message names the agent and the exact terms, with a code.
	const m = await ref.waitForChannel(before, /responde APROBAR (\d{6})/);
	assert.match(m.input!, /230\.400/);
	const reply = await ref.internal("whatsapp/entrada", { tenant: HOTEL_TENANT, telefono: PHONE, texto: `APROBAR ${m[1]}` });
	assert.equal(reply.body.aceptado, true);

	const done = await pact.status(c.interface, op.operation_id);
	assert.equal(done.state, "succeeded");
	const booking = done.result.data.reserva as string;
	const pms = (await ref.internal(`estado?tenant=${HOTEL_TENANT}`)).body.reservas as { id: string; total: number }[];
	assert.equal(pms.find((x) => x.id === booking)?.total, 230_400);

	const proof = await pact.proof(c.interface, op.operation_id);
	assert.equal(proof.verdict.valid, true, JSON.stringify(proof.verdict));
	assert.equal(proof.verdict.anchor, "pact_issuer");
	assert.equal(proof.verdict.final_state, "succeeded");
	assert.equal(proof.verdict.approval, "company_channel", "approved on the company's channel, not asserted by the agent");
	assert.equal(proof.verdict.pact_receipt, "verified", "the PACT receipt of the proposing turn matches the proof's request");
	assert.equal(proof.verdict.operation, "matches");
	const dir = join(t.stateDir, "proofs");
	const py = await run("python", [PY_VERIFIER, "material", "--material", proof.material_file, "--paquete", proof.package_file, "--operacion", join(dir, `pact-${op.operation_id}.operation.json`), "--recibo-pact", join(dir, `pact-${op.operation_id}.receipt.json`)]);
	const pyVerdict = JSON.parse(py.stdout.trim().split("\n").at(-1)!);
	assert.equal(pyVerdict.valid, true, py.stdout + py.stderr);
});

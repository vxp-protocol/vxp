// Example personal agent, deterministic (no LLM), for the task:
//   «Necesito reservar un hotel en Santiago para dos noches. Busca opciones con desayuno, negocia la
//    mejor tarifa y reserva si no supera los $250.000.»
// against companies that implement VXP's native profile. Run it against the reference gateway in
// native-only mode (see README «Quickstart»). Everything the person does happens outside this program:
// they link their account on the hotel's own page (with a code the hotel sends to their phone) and, only
// if their cap does not cover a revision, they approve the exact terms on this agent's own approval page.
//
//   node examples/hotel-santiago.ts --state .vxp-example --origin http://localhost:3811 --port 3811 \
//     --allow-http http://localhost:3810,http://127.0.0.1:3810,http://localhost:3811 \
//     localhost:3810 127.0.0.1:3810 localhost:3899
//
// Options: --cap 250000 · --nights 2 · --check-in YYYY-MM-DD (default: the first Monday at least 14 days
// out) · --late-arrival mantener|liberar (the person's standing answer if the hotel asks; default mantener) ·
// --hotel-console URL --hotel-console-key KEY: runs the hotel's own late-arrival rule at once, with the
// simulated clock of the reference's test-only console (/interno/, NOT part of VXP), as if it were 20:35 on
// the arrival day. Without it, the example waits for the hotel to ask on its own (on the arrival day).

import { parseArgs } from "node:util";
import { VxpAgent, amountOf } from "../src/agent.ts";
import { offers } from "../src/discovery.ts";
import { startAgentServer } from "../src/server.ts";

const { values: o, positionals: candidates } = parseArgs({
	allowPositionals: true,
	options: {
		state: { type: "string", default: ".vxp-example" },
		origin: { type: "string", default: "http://localhost:3811" },
		port: { type: "string", default: "3811" },
		"allow-http": { type: "string", default: "" },
		cap: { type: "string", default: "250000" },
		nights: { type: "string", default: "2" },
		"check-in": { type: "string" },
		"late-arrival": { type: "string", default: "mantener" },
		"hotel-console": { type: "string" },
		"hotel-console-key": { type: "string" },
		"wait-minutes": { type: "string", default: "10" },
	},
});

const CAP = Number(o.cap);
const NIGHTS = Number(o.nights);
const ADULTS = 2;
const clp = (n: number) => `$${n.toLocaleString("es-CL")}`;
const say = (s: string) => console.log(s);
const step = (n: number, s: string) => console.log(`\n── ${n}. ${s}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const iso = (d: Date) => d.toISOString().slice(0, 10);

function defaultCheckIn(): string {
	const d = new Date(Date.now() + 14 * 86_400_000);
	while (d.getUTCDay() !== 1) d.setUTCDate(d.getUTCDate() + 1);
	return iso(d);
}

const checkIn = o["check-in"] ?? defaultCheckIn();
const checkOut = iso(new Date(Date.parse(`${checkIn}T00:00:00Z`) + NIGHTS * 86_400_000));
const deadline = Date.now() + Number(o["wait-minutes"]) * 60_000;

const agent = VxpAgent.open({ stateDir: o.state!, publicOrigin: o.origin, clientName: "Example travel assistant (VXP)", net: { allowHttpOrigins: o["allow-http"]!.split(",").filter(Boolean) } });
const server = await startAgentServer(agent, { port: Number(o.port), log: (l) => say(`   ${l}`) });

try {
	say(`Task: book a hotel for ${NIGHTS} nights (${checkIn} → ${checkOut}), ${ADULTS} adults, with breakfast; best rate; book only if the total is ≤ ${clp(CAP)}.`);
	say(`Agent: ${agent.clientId} (publishes its CIMD, JWKS and inbox at ${agent.origin})`);

	step(1, "Discover companies that implement VXP among the candidate domains");
	say("   VXP has no global registry: the candidates come from outside VXP (the person, a search, a website).");
	const found = await agent.discover(candidates);
	for (const r of found) say(`   ${r.domain}: ${r.ok ? `${r.company.name} · ${r.company.status ?? ""} · ${r.company.capabilities.map((c) => `${c.id}${c.access === "public" ? " (public)" : ""}`).join(", ")}` : `not usable — ${r.reason}`}`);
	const hotels = found.flatMap((r) => (r.ok && offers(r.company, "reserva.crear") && offers(r.company, "hotel.disponibilidad") ? [r.company] : []));
	if (!hotels.length) throw new Error("no candidate offers hotel bookings");
	const hotel = hotels[0];
	say(`   → ${hotel.name} offers hotel.disponibilidad and reserva.crear (issuer ${hotel.issuer}).`);
	say("   Note: vxp.json carries no location; «Santiago» is the person's criterion for choosing candidates, not something VXP checks.");

	step(2, "The person's own rules for this task (set by the person, not by the agent)");
	agent.setMandate(hotel.issuer, "reserva.crear", CAP, null, "reserva si no supera el tope");
	agent.setReplyRule(hotel.issuer, "alerta.mantener_o_liberar", o["late-arrival"]!);
	say(`   cap for reserva.crear: ${clp(CAP)} · if the hotel asks about a late arrival: «${o["late-arrival"]}»`);

	step(3, "Availability, rates and services: a public read (no authorization, no operation)");
	const av = await agent.read(hotel.issuer, "hotel.disponibilidad", { check_in: checkIn, check_out: checkOut, adults: ADULTS });
	if (av.http !== 200) throw new Error(`availability: ${av.http} ${JSON.stringify(av.body)}`);
	const breakfast = (av.body.result.services as any[]).find((s) => /desayuno|breakfast/i.test(`${s.code} ${s.name}`));
	if (!breakfast) throw new Error("the hotel offers no breakfast");
	const bf = breakfast.price * (breakfast.unit === "persona_noche" ? ADULTS * NIGHTS : breakfast.unit === "noche" ? NIGHTS : 1);
	const options = (av.body.result.room_types as any[]).filter((t) => t.apta && t.libres > 0).map((t) => ({ code: t.tipo as string, name: t.nombre as string, room: t.directa as number, estimate: (t.directa as number) + bf })).sort((a, b) => a.estimate - b.estimate);
	say(`   breakfast «${breakfast.name}» (${breakfast.code}): ${clp(breakfast.price)} per ${breakfast.unit} → ${clp(bf)} for the stay`);
	for (const x of options) say(`   ${x.code} «${x.name}»: room ${clp(x.room)} + breakfast ${clp(bf)} = ${clp(x.estimate)}${x.estimate <= CAP ? "  ✓ within the cap" : "  ✗ above the cap"}`);
	const within = options.filter((x) => x.estimate <= CAP);
	if (!within.length) throw new Error(`no room with breakfast is within ${clp(CAP)}: nothing booked`);
	// The best room the cap allows; its rate is negotiated below.
	const pick = within[within.length - 1];
	say(`   → the best room with breakfast within the cap: ${pick.code}, ${clp(pick.estimate)} before negotiating.`);
	// What the hotel publishes that could lower that rate: packages for this room and these nights that include breakfast.
	const packages = ((av.body.result.packages ?? []) as any[]).filter((p) => p.room_type === pick.code && p.nights === NIGHTS && p.services.includes(breakfast.code));
	for (const p of packages) say(`   package «${p.name}» (${p.code}): ${p.discount_pct}% off, includes ${p.services.join(", ")}`);

	step(4, "Ask for the stay: the hotel quotes under its own policy (the quote is public)");
	const q = await agent.createRequest(hotel.issuer, "reserva.crear", {}, { room_type: pick.code, check_in: checkIn, check_out: checkOut, adults: ADULTS, services: [{ code: breakfast.code }] });
	if (q.http !== 202 || !q.body.quote) throw new Error(`quote: ${q.http} ${JSON.stringify(q.body)}`);
	const quote = q.body.quote;
	const requestId = q.record!.request_id;
	say(`   ${requestId}: ${quote.id} total ${clp(quote.total)} VAT incl.${quote.tarifa_igualada ? ` (matched ${quote.tarifa_igualada.agencia})` : ""} · agencies (simulated): ${quote.comparacion.map((c: any) => `${c.agencia} ${c.total === null ? "n/a" : clp(c.total)}`).join("; ")}`);
	if (quote.total > CAP) throw new Error(`the hotel's quote ${clp(quote.total)} is above the cap: nothing booked`);

	step(5, "Authorization: the person links their account on the hotel's own page");
	const auth = await agent.authorize(hotel.issuer, { forRequest: requestId, capClp: CAP, relationship: { actions: ["alerta.mantener_o_liberar"], max_per_day: 2, duration_seconds: 30 * 86_400 } });
	say(`   Asked for: a new booking up to ${clp(CAP)} (the person's cap, not the quote), and a relationship so the hotel can ask about a late arrival (only «mantener» or «liberar»).`);
	say(`   PERSON: open ${auth.verification_uri_complete}`);
	say(`           check the code ${auth.user_code}, type your phone number, then the code ${hotel.name} sends you, and press «Permitir».`);
	let granted: Awaited<ReturnType<typeof agent.pollAuthorization>> | null = null;
	while (Date.now() < deadline) {
		const p = await agent.pollAuthorization(hotel.issuer, 15);
		if (p.status === "granted") {
			granted = p;
			break;
		}
		if (p.status !== "authorization_pending") throw new Error(`authorization ended: ${p.status}`);
	}
	if (!granted) throw new Error("the person did not authorize in time");
	say(`   granted: ${JSON.stringify(granted.authorization_details)}`);
	for (const r of granted.relationships ?? []) say(`   relationship ${r.relationship_id}: ${r.actions.join(", ")}, until ${r.expires_at}, signed agreement verified with the hotel's key: ${r.agreement_verified}`);

	step(6, "The same request again (same Idempotency-Key): now the hotel proposes signed terms");
	const prop = await agent.resubmit(requestId);
	if (prop.body.state !== "proposed") throw new Error(`expected a proposal, got ${prop.http} ${JSON.stringify(prop.body)}`);
	say(`   ${prop.body.proposal.id} · commitment ${JSON.stringify(prop.body.proposal.commitment)} · total ${clp(amountOf(prop.body)!)} · breakfast: ${prop.body.proposal.terms.servicios.some((s: any) => s.codigo === breakfast.code) ? "yes" : "no"} · user_approval_required: ${prop.body.proposal.user_approval_required}`);

	step(7, "Negotiate the rate (counter-proposals, within the hotel's policy)");
	let current = prop.body;
	const ask = await agent.counter(requestId, { discount_pct: 10 }, "¿Pueden mejorar la tarifa?");
	if (ask.http === 200) current = ask.body;
	say(ask.http === 200 ? `   discount asked: the hotel issued revision ${ask.body.proposal.revision} at ${clp(amountOf(ask.body)!)}` : `   discount asked: declined (${ask.body.error}: ${ask.body.reason}). The hotel gives no discretionary discount.`);
	for (const p of packages) {
		const c = await agent.counter(requestId, { package: p.code }, `Con el paquete ${p.name}`);
		if (c.http !== 200) {
			say(`   package ${p.code}: declined (${c.body.error}: ${c.body.reason})`);
			continue;
		}
		const before = amountOf(current)!;
		const after = amountOf(c.body)!;
		say(`   package ${p.code}: revision ${c.body.proposal.revision} at ${clp(after)} (was ${clp(before)}; ${c.body.proposal.terms.servicios.map((x: any) => x.nombre).join(", ")}${c.body.proposal.terms.descuento ? `; ${c.body.proposal.terms.descuento.pct}% off` : ""})`);
		current = c.body;
		if (after > before) {
			// Dearer than what it had: go back to the stay without the package, as a new revision.
			const back = await agent.counter(requestId, { package: null });
			if (back.http === 200) current = back.body;
			say(`   dearer, so back without the package: revision ${current.proposal.revision} at ${clp(amountOf(current)!)}`);
		}
	}
	say(`   → negotiated: ${clp(amountOf(current)!)} (revision ${current.proposal.revision}, user_approval_required: ${current.proposal.user_approval_required}).`);

	step(8, "Accept, within the person's rules");
	let acc = await agent.accept(requestId);
	if (acc.status === "needs_user_approval") {
		say(`   ${acc.reason}.`);
		say(`   PERSON: review the exact terms at ${agent.approvalUrl(acc.approval)} and type your approval code ${acc.approval.person_code}`);
		say("           (this program runs in your own terminal; an agent's model never receives that code).");
		while (Date.now() < deadline && agent.approval(acc.approval.id).status === "pending") await sleep(500);
		if (agent.approval(acc.approval.id).status !== "approved") throw new Error("the person did not approve the terms: nothing booked");
		acc = await agent.accept(requestId);
	}
	if (acc.status !== "accepted") throw new Error(`not accepted: ${JSON.stringify(acc)}`);
	const result = acc.view.result;
	say(`   approved_by: ${acc.approved_by}${acc.approved_by === "standing_permission" ? ` (the total is within the ${clp(CAP)} the person approved at the hotel and set as their rule)` : ""} · state: ${acc.view.state}`);
	say(`   ${result?.summary}`);
	const reservation = result?.data?.reserva;
	say(`   → reservation id in the hotel's system: ${reservation}`);

	step(9, "Proof: download and verify locally, anchored by the issuer learned from vxp.json");
	const pr = await agent.proof(requestId);
	const v = pr.verdict as any;
	say(`   valid: ${v.valid} · final_state: ${v.final_state} · revision: ${v.revision} · approval: ${v.approval} · operation: ${v.operation}`);
	say(`   derived_assurance: ${(v.derived_assurance ?? []).join(", ")} · single_root: ${v.single_root} · logged: ${v.logged}`);
	say(`   Reading: the chain is intact and signed by the keys the issuer publishes; it is the operator's attestation, not independent confirmation. Saved: ${pr.package_file}`);

	step(10, "Keep the relationship: the hotel asks about a late arrival");
	const rel = (granted.relationships ?? [])[0];
	if (!rel) throw new Error("the person did not leave the relationship ticked: the hotel cannot contact the agent");
	const before = agent.inbox().messages.length;
	if (o["hotel-console"] && o["hotel-console-key"]) {
		const at = `${checkIn}T23:35:00.000Z`;
		say(`   [reference test aid, not VXP] running the hotel's own late-arrival rule with its simulated clock at ${at} (20:35 in Chile on the arrival day):`);
		const r = await fetch(`${o["hotel-console"]}/interno/relaciones/revisar-llegadas`, { method: "POST", headers: { "x-sovras-prueba": o["hotel-console-key"], "content-type": "application/json" }, body: JSON.stringify({ tenant: "t_hotel_demo", at }) });
		say(`   hotel rule: ${r.status} ${JSON.stringify(((await r.json()) as any[]).map((x) => ({ reserva: x.reserva, delivery: x.resultado?.delivery })))}`);
	} else say("   waiting for the hotel's late-arrival rule (it runs on the arrival day, after 20:00 in Chile)…");
	while (Date.now() < deadline && agent.inbox().messages.length === before) await sleep(300);
	const m = agent.inbox().messages.at(-1);
	if (!m || agent.inbox().messages.length === before) throw new Error("no message from the hotel arrived");
	say(`   inbox: «${m.content.summary}» options ${JSON.stringify(m.content.options)} (signature checked with the hotel's relationship key; jti new)`);
	for (let i = 0; i < 20 && !agent.message(m.id).reply; i++) await sleep(200);
	const answered = agent.message(m.id);
	if (answered.reply) say(`   answered «${answered.reply.decision}» by the person's standing answer; hotel receipt verified: ${answered.reply.receipt_verified}`);
	else say("   not answered: no standing answer applied");

	step(11, "Summary");
	say(`   booked ${reservation} at ${hotel.name}, ${checkIn} → ${checkOut}, ${clp(amountOf(acc.view)!)} with breakfast (cap ${clp(CAP)}); proof valid: ${v.valid}; late-arrival answer: ${answered.reply?.decision ?? "none"}.`);
	say(`   state kept in ${agent.store.dir}`);
} catch (e) {
	console.error(`\nSTOPPED: ${(e as Error).message}`);
	process.exitCode = 1;
} finally {
	server.close();
	server.closeAllConnections();
}

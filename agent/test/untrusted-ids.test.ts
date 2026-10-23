// Identifiers that come from a company are untrusted: they must not choose where the agent writes, and one
// company must not overwrite a request the agent holds with another company. No server is needed.

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PactAdapter } from "../src/adapters/pact.ts";
import { VxpAgent } from "../src/agent.ts";
import { isUnder } from "../src/net.ts";
import { Store } from "../src/store.ts";

test("the proofs folder refuses file names that would leave it", () => {
	const s = new Store(mkdtempSync(join(tmpdir(), "vxp-agent-store-")));
	for (const bad of ["../identity.json", "..\\identity.json", "a/b.json", "..", "x/../../y.json"]) {
		assert.throws(() => s.saveFile(bad, {}), /refused file name/, bad);
		assert.throws(() => s.readFile(bad), /refused file name/, bad);
	}
	assert.ok(s.saveFile("req_abc.package.json", { ok: true }).endsWith("req_abc.package.json"));
});

test("a request id or proposal id with an unexpected shape is refused, and another company cannot take over a request", () => {
	const a = VxpAgent.open({ stateDir: mkdtempSync(join(tmpdir(), "vxp-agent-ids-")), publicOrigin: "https://agent.example" });
	const record = (a as unknown as { record: (c: unknown, view: unknown, base: unknown) => { issuer: string } }).record.bind(a);
	const base = { operation: "reserva.crear", target: {}, parameters: {}, idempotency_key: null, origin: "agent" };
	const hotel = { issuer: "https://hotel.example/e/hotel" };
	const other = { issuer: "https://other.example/e/other" };
	assert.throws(() => record(hotel, { request_id: "../../identity", state: "proposed" }, base), /unexpected shape/);
	assert.throws(() => record(hotel, { request_id: "req_1", state: "proposed", proposal: { id: "../x" } }, base), /unexpected shape/);
	assert.equal(record(hotel, { request_id: "req_1", state: "proposed", proposal: { id: "prop_op_1_r1" } }, base).issuer, hotel.issuer);
	assert.throws(() => record(other, { request_id: "req_1", state: "proposed", proposal: { id: "prop_op_9_r1" } }, base), /belongs to another company/);
	assert.equal(a.request("req_1").issuer, hotel.issuer, "the hotel's request is intact");
});

test("a URL a company gives is under its base only after parsing: no dot segments, encoded separators, look-alike hosts or sibling paths", () => {
	const base = "https://hotel.example/e/hotel";
	assert.equal(isUnder("https://hotel.example/e/hotel/v1/requests/req_1/proof", base), true);
	for (const bad of [
		"https://hotel.example/e/hotel/../other/v1/requests",
		"https://hotel.example/e/hotel/%2e%2e/other/v1",
		"https://hotel.example/e/hotel/x%2F..%2F..%2Fother",
		"https://hotel.example/e/hotel-other/v1",
		"https://hotel.example.attacker.example/e/hotel/v1",
		"https://user:pass@hotel.example/e/hotel/v1",
		"http://hotel.example/e/hotel/v1",
		"https://hotel.example/e/hotel",
		"not a url",
		String.raw`https:\\hotel.example\e\hotel\v1`,
		String.raw`https://hotel.example/e/hotel\..\..\other`,
		"HTTPS://HOTEL.EXAMPLE/e/hotel/v1",
		"https://hotel.example/e/hotel/./v1",
	])
		assert.equal(isUnder(bad, base), false, bad);
});

test("an approval the person gave at one company does not accept the same proposal text at another", () => {
	const a = VxpAgent.open({ stateDir: mkdtempSync(join(tmpdir(), "vxp-agent-approve-")), publicOrigin: "https://agent.example" });
	const revision = { operation: "reserva.crear", proposal_id: "prop_op_1_r1", summary: "Book a double room", terms: { total: 200000, vxp_salt: "s" }, user_approval_required: true, amount_clp: 200000 };
	const first = a.decideAcceptance({ issuer: "https://hotel-a.example/e/a", ...revision });
	assert.equal(first.status, "needs_user_approval");
	a.decide((first as { approval: { id: string } }).approval.id, true, { via: "cli" });
	assert.equal(a.decideAcceptance({ issuer: "https://hotel-a.example/e/a", ...revision }).status, "allowed", "the approved company");
	assert.equal(a.decideAcceptance({ issuer: "https://hotel-b.example/e/b", ...revision }).status, "needs_user_approval", "another company with the same proposal text");
});

test("PACT: a Card cannot point the agent's credentials at another server, nor rewrite a company already known", async () => {
	const IFACE = "https://provider.example/pact/hotel";
	const card = (domain: string, tokenUrl: string) => ({
		name: "Hotel",
		supportedInterfaces: [{ url: IFACE, protocolBinding: "HTTP+JSON", protocolVersion: "1.0" }],
		capabilities: { extensions: [{ uri: "https://vxpprotocol.org/ext/proof/v0.1", params: { company: "https://hotel.example/e/hotel", domains: [domain] } }] },
		securitySchemes: { userDelegation: { oauth2SecurityScheme: { oauth2MetadataUrl: `${IFACE}/oauth/.well-known/oauth-authorization-server`, flows: { deviceCode: { deviceAuthorizationUrl: `${IFACE}/oauth/device_authorization`, tokenUrl, scopes: {} } } } } },
	});
	const meta = { issuer: `${IFACE}/oauth`, token_endpoint: `${IFACE}/oauth/token`, device_authorization_endpoint: `${IFACE}/oauth/device_authorization`, vxp_proof: { company: "https://hotel.example/e/hotel" } };
	const docs: Record<string, unknown> = {
		"https://hotel.example/.well-known/agent-card.json": card("hotel.example", `${IFACE}/oauth/token`),
		"https://redirect.example/.well-known/agent-card.json": card("redirect.example", "https://attacker.example/token"),
		"https://lookalike.example/.well-known/agent-card.json": card("lookalike.example", `${IFACE}/oauth/token`),
		"https://elsewhere.example/.well-known/agent-card.json": { ...card("elsewhere.example", `${IFACE}/oauth/token`), supportedInterfaces: [{ url: "https://attacker.example/pact", protocolBinding: "HTTP+JSON", protocolVersion: "1.0" }] },
		[`${IFACE}/oauth/.well-known/oauth-authorization-server`]: meta,
	};
	const fetch = async (u: string) => new Response(JSON.stringify(docs[u] ?? {}), { status: docs[u] ? 200 : 404, headers: { "content-type": "application/json" } });
	const a = VxpAgent.open({ stateDir: mkdtempSync(join(tmpdir(), "vxp-agent-pact-")), publicOrigin: "https://agent.example", net: { fetch } });
	const pact = new PactAdapter(a, { audience: "aud" });
	assert.equal(await pact.detect("redirect.example"), null, "token endpoint that the authorization server does not publish");
	assert.equal(await pact.detect("elsewhere.example"), null, "an interface outside the authorization server's origin would receive the delegation");
	const ok = await pact.detect("hotel.example");
	assert.equal(ok?.tokenUrl, `${IFACE}/oauth/token`);
	assert.equal(await pact.detect("lookalike.example"), null, "another brand domain cannot take over the known interface");
	assert.equal(pact.company(IFACE).domain, "hotel.example", "the known company is intact");
});

// Identifiers that come from a company are untrusted: they must not choose where the agent writes, and one
// company must not overwrite a request the agent holds with another company. No server is needed.

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { VxpAgent } from "../src/agent.ts";
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

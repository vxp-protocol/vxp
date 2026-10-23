// The native profile stands alone: against a gateway with VXP_ADAPTERS=none, a native-only agent never asks
// for poppy.json, the Agent Card, A2A or any Poppy route; it declares no Poppy extension; none of the native
// modules imports the adapters; and the adapters themselves find nothing to use on such a gateway.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { VxpAgent } from "../src/agent.ts";
import { PactAdapter } from "../src/adapters/pact.ts";
import { PoppyAdapter } from "../src/adapters/poppy.ts";
import { startAgentServer } from "../src/server.ts";
import { allowHttp, linkAccount, nextFriday, plusDays, type Reference, startReference } from "./helpers/setup.ts";

const SRC = join(import.meta.dirname, "..", "src");
const AG = "http://localhost:3891";
let ref: Reference;
const seen: string[] = [];
let close = () => {};

before(async () => {
	ref = await startReference({ port: 3890, agentOrigins: [AG] });
});
after(async () => {
	close();
	await ref?.stop();
});

test("the native modules do not import the adapters", () => {
	for (const f of ["agent.ts", "discovery.ts", "jose.ts", "net.ts", "store.ts", "verify.ts", "server.ts", "mcp.ts"]) {
		const src = readFileSync(join(SRC, f), "utf8");
		assert.doesNotMatch(src, /from\s+["'][^"']*adapters/, `${f} imports an adapter`);
	}
	const cli = readFileSync(join(SRC, "..", "bin", "vxp-agent.ts"), "utf8");
	assert.doesNotMatch(cli, /from\s+["'][^"']*adapters/);
});

test("VXP_ADAPTERS=none: a native-only agent does the whole task without touching Poppy or PACT", async () => {
	const fetchSeen = (u: string, i?: RequestInit) => {
		seen.push(new URL(u).pathname);
		return globalThis.fetch(u, i);
	};
	const agent = VxpAgent.open({ stateDir: mkdtempSync(join(tmpdir(), "vxp-agent-native-")), publicOrigin: AG, net: { allowHttpOrigins: allowHttp(ref, AG), fetch: fetchSeen } });
	const server = await startAgentServer(agent, { port: 3891 });
	close = () => {
		server.close();
		server.closeAllConnections();
	};
	assert.equal(agent.clientMetadata().extensions.operations, undefined, "no Poppy Operations declared");
	assert.deepEqual(agent.profiles(), []);

	const [r] = await agent.discover([ref.hotelDomain]);
	assert.equal(r.ok, true);
	const H = agent.company(ref.hotelDomain).issuer;
	const d1 = plusDays(nextFriday(14), 3);
	const req = await agent.createRequest(H, "reserva.crear", {}, { room_type: "DBL-EST", check_in: d1, check_out: plusDays(d1, 2), adults: 2, services: [{ code: "DESAYUNO" }] });
	await linkAccount(ref, agent, H, { forRequest: req.record!.request_id, capClp: 250_000 });
	await agent.resubmit(req.record!.request_id);
	agent.setMandate(H, "reserva.crear", 250_000);
	const done = await agent.accept(req.record!.request_id);
	assert.equal(done.status, "accepted");
	assert.equal((await agent.proof(req.record!.request_id)).verdict.valid, true);

	assert.ok(seen.length > 5);
	const adapterPaths = seen.filter((p) => /poppy|agent-card|\/a2a\//.test(p));
	assert.deepEqual(adapterPaths, [], `the agent asked for: ${adapterPaths.join(", ")}`);
});

test("the adapters find nothing on a native-only gateway", async () => {
	const agent = VxpAgent.open({ stateDir: mkdtempSync(join(tmpdir(), "vxp-agent-native-ad-")), publicOrigin: "http://localhost:3893", net: { allowHttpOrigins: allowHttp(ref, "http://localhost:3893") } });
	assert.equal(await new PoppyAdapter(agent).detect(ref.hotelDomain), null);
	assert.equal(await new PactAdapter(agent, { audience: `${ref.origin}/a2a` }).detect(ref.hotelDomain), null);
});

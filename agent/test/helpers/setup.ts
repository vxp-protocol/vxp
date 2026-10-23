// Shared setup: the reference gateway in its own process (native only), one agent with its own state
// directory and HTTP server, and the helpers a test needs to play the person.

import { mkdtempSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VxpAgent } from "../../src/agent.ts";
import { startAgentServer } from "../../src/server.ts";
import { approveOnCompanyPage } from "./person.ts";
import { type Reference, startReference } from "./reference.ts";

export const PHONE = "+56 9 0000 0101";
export const HOTEL_TENANT = "t_hotel_demo";

export function nextFriday(daysOut = 14): string {
	const d = new Date(Date.now() + daysOut * 86_400_000);
	while (d.getUTCDay() !== 5) d.setUTCDate(d.getUTCDate() + 1);
	return d.toISOString().slice(0, 10);
}
export const plusDays = (iso: string, n: number) => new Date(Date.parse(`${iso}T00:00:00Z`) + n * 86_400_000).toISOString().slice(0, 10);

export function allowHttp(ref: Reference, agentOrigin: string) {
	return [ref.origin, `http://${ref.hotelDomain}`, agentOrigin];
}

export type AgentUnderTest = { agent: VxpAgent; server: Server; origin: string; stateDir: string; close(): void };

export async function startAgent(ref: Reference, port: number, stateDir = mkdtempSync(join(tmpdir(), "vxp-agent-state-"))): Promise<AgentUnderTest> {
	const origin = `http://localhost:${port}`;
	const agent = VxpAgent.open({ stateDir, publicOrigin: origin, net: { allowHttpOrigins: allowHttp(ref, origin) } });
	const server = await startAgentServer(agent, { port });
	return {
		agent,
		server,
		origin,
		stateDir,
		close() {
			server.close();
			server.closeAllConnections();
		},
	};
}

/** The agent asks for authorization; the person approves on the hotel's page; the agent polls. */
export async function linkAccount(ref: Reference, agent: VxpAgent, company: string, o: Parameters<VxpAgent["authorize"]>[1], person: { untick?: string[]; deny?: boolean } = {}) {
	const since = ref.lines.length;
	const a = await agent.authorize(company, o);
	const page = await approveOnCompanyPage(a.verification_uri_complete, PHONE, () => ref.waitForCode(since), person);
	const grant = await agent.pollAuthorization(company, 20);
	return { asked: a, page, grant };
}

export { type Reference, startReference };

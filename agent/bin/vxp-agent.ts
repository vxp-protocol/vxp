#!/usr/bin/env node
// vxp-agent: a command for each step of a VXP native-profile task. Every command is its own process and
// all state lives in the state directory, so a task can stop at any step and continue later.
//
//   node bin/vxp-agent.ts <command> [args] [--state DIR] [--allow-http ORIGINS]
//
// Run `node bin/vxp-agent.ts help` for the list.

import { createInterface } from "node:readline/promises";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { VxpAgent } from "../src/agent.ts";
import { offers } from "../src/discovery.ts";
import { startAgentServer } from "../src/server.ts";
import { verifyWithMaterial } from "../src/verify.ts";
import { runMcpServer } from "../src/mcp.ts";

const HELP = `vxp-agent — personal agent for companies that implement VXP (native profile)

Global options (or environment variables):
  --state DIR            state directory (VXP_AGENT_STATE; default ./.vxp-agent)
  --origin URL           the agent's public origin, needed on first run (VXP_AGENT_ORIGIN)
  --allow-http ORIGINS   comma-separated http:// origins allowed for local tests (VXP_AGENT_ALLOW_HTTP)

Identity and server
  init [--name NAME]                     create the identity (keys, client_id)
  whoami                                 client_id, CIMD and JWKS the agent publishes
  serve --port N                         serve CIMD, JWKS, inbox and approval pages
  mcp [--port N]                         MCP server over stdio (Claude Desktop, Claude Code, others);
                                         with --port it also serves what «serve» serves

Discovery
  discover DOMAIN... [--offers OP]       read vxp.json and issuer metadata of each candidate
  companies                              companies already discovered

Requests
  read COMPANY OPERATION [--params JSON]  a read capability (e.g. hotel.disponibilidad): no operation
  request COMPANY OPERATION [--target JSON] [--params JSON]
  resubmit REQUEST_ID                    same request, same Idempotency-Key (after authorizing)
  status REQUEST_ID | events REQUEST_ID | cancel REQUEST_ID
  counter REQUEST_ID --terms JSON [--note TEXT]
  accept REQUEST_ID                      accept under the person's rules (cap or exact approval)

The person's authorization at the company
  authorize COMPANY [--request ID] [--cap-clp N] [--relationship A,B] [--relationship-days N] [--relationship-per-day N]
  approve-url COMPANY                    the pending verification URL and code for the person
  wait-authorization COMPANY [--timeout S]

The person's own rules (only the person runs these)
  mandate set COMPANY OPERATION MAX_TOTAL_CLP [--expires ISO]
  mandate reply COMPANY ACTION DECISION
  mandate list
  approvals                              approvals waiting for the person
  approve APPROVAL_ID [--yes | --deny]   the person decides on exact terms, in this terminal

Proof
  proof REQUEST_ID                       download, gather material from the issuer, verify locally
  verify REQUEST_ID                      re-verify a saved proof with its saved material (offline)
  verify-file --package F --material F [--operation F] [--aud CLIENT_ID]

Relationship
  relationships | relationship ID | revoke-relationship ID
  inbox                                  messages the companies sent
  reply MESSAGE_OR_ALERT_ID DECISION     answer a closed question (needs a reply rule or an approval)
`;

const { values: opt, positionals } = parseArgs({
	allowPositionals: true,
	options: {
		state: { type: "string" },
		origin: { type: "string" },
		"allow-http": { type: "string" },
		name: { type: "string" },
		port: { type: "string" },
		offers: { type: "string" },
		target: { type: "string" },
		params: { type: "string" },
		terms: { type: "string" },
		note: { type: "string" },
		request: { type: "string" },
		"cap-clp": { type: "string" },
		relationship: { type: "string" },
		"relationship-days": { type: "string" },
		"relationship-per-day": { type: "string" },
		timeout: { type: "string" },
		expires: { type: "string" },
		yes: { type: "boolean" },
		deny: { type: "boolean" },
		package: { type: "string" },
		material: { type: "string" },
		operation: { type: "string" },
		aud: { type: "string" },
	},
});

const [cmd, ...args] = positionals;
const out = (v: unknown) => console.log(JSON.stringify(v, null, 1));
const json = (s: string | undefined, what: string) => {
	if (s === undefined) return {};
	try {
		return JSON.parse(s);
	} catch {
		throw new Error(`--${what} must be JSON`);
	}
};
const need = (v: string | undefined, what: string) => {
	if (!v) throw new Error(`missing ${what} (see: vxp-agent help)`);
	return v;
};

function open(): VxpAgent {
	return VxpAgent.open({
		stateDir: opt.state ?? process.env.VXP_AGENT_STATE ?? ".vxp-agent",
		publicOrigin: opt.origin ?? process.env.VXP_AGENT_ORIGIN,
		clientName: opt.name,
		net: { allowHttpOrigins: (opt["allow-http"] ?? process.env.VXP_AGENT_ALLOW_HTTP ?? "").split(",").filter(Boolean) },
	});
}

async function main() {
	if (!cmd || cmd === "help" || cmd === "--help") return console.log(HELP);
	const a = open();
	if (cmd === "mcp") {
		// With --port, the same process also serves the CIMD, JWKS, inbox and approval pages.
		if (opt.port) await startAgentServer(a, { port: Number(opt.port), log: (l) => console.error(l) });
		return runMcpServer(a);
	}
	switch (cmd) {
		case "init":
		case "whoami":
			return out({ client_id: a.clientId, client_metadata: a.clientMetadata(), jwks: a.jwks(), state_dir: a.store.dir });
		case "serve": {
			const port = Number(need(opt.port, "--port"));
			await startAgentServer(a, { port, log: (l) => console.error(l) });
			console.error(`[agent] ${a.clientId} · inbox ${a.inboxUri} · listening on ${port}`);
			return;
		}
		case "discover": {
			const res = await a.discover(args);
			return out(res.map((r) => (r.ok ? { domain: r.domain, ok: true, name: r.company.name, issuer: r.company.issuer, status: r.company.status, offers: opt.offers ? offers(r.company, opt.offers) : undefined, capabilities: r.company.capabilities.map((c) => `${c.id} (${c.effect})`), relationship_actions: r.company.relationshipActions } : r)));
		}
		case "companies":
			return out(a.companies().map((c) => ({ name: c.name, domain: c.domain, issuer: c.issuer, capabilities: c.capabilities.map((x) => x.id) })));
		case "read": {
			const r = await a.read(need(args[0], "COMPANY"), need(args[1], "OPERATION"), json(opt.params, "params"), json(opt.target, "target"));
			return out({ http: r.http, ...r.body });
		}
		case "request": {
			const r = await a.createRequest(need(args[0], "COMPANY"), need(args[1], "OPERATION"), json(opt.target, "target"), json(opt.params, "params"));
			return out({ http: r.http, ...r.body });
		}
		case "resubmit": {
			const r = await a.resubmit(need(args[0], "REQUEST_ID"));
			return out({ http: r.http, ...r.body });
		}
		case "status":
			return out((await a.refresh(need(args[0], "REQUEST_ID"))).view);
		case "events":
			return out(await a.events(need(args[0], "REQUEST_ID")));
		case "cancel":
			return out(await a.cancel(need(args[0], "REQUEST_ID")));
		case "counter":
			return out(await a.counter(need(args[0], "REQUEST_ID"), json(need(opt.terms, "--terms"), "terms"), opt.note).then((r) => ({ http: r.http, ...r.body })));
		case "accept": {
			const r = await a.accept(need(args[0], "REQUEST_ID"));
			if (r.status === "needs_user_approval") return out({ status: r.status, reason: r.reason, ...a.publicApproval(r.approval), the_person_decides_with: `vxp-agent approve ${r.approval.id}, or the page and the code from: vxp-agent approvals` });
			return out(r);
		}
		case "authorize": {
			const rel = opt.relationship ? { actions: opt.relationship.split(","), ...(opt["relationship-days"] ? { duration_seconds: Number(opt["relationship-days"]) * 86_400 } : {}), ...(opt["relationship-per-day"] ? { max_per_day: Number(opt["relationship-per-day"]) } : {}) } : undefined;
			const r = await a.authorize(need(args[0], "COMPANY"), { forRequest: opt.request, capClp: opt["cap-clp"] ? Number(opt["cap-clp"]) : undefined, relationship: rel });
			return out({ ...r, tell_the_person: `Open ${r.verification_uri_complete} and confirm the code ${r.user_code}. ${r.company} will send you a one-time code through its own channel.` });
		}
		case "approve-url":
			return out(a.pendingAuthorization(need(args[0], "COMPANY")) ?? { pending: false });
		case "wait-authorization":
			return out(await a.pollAuthorization(need(args[0], "COMPANY"), Number(opt.timeout ?? 0)));
		case "mandate": {
			const [sub, company, x, y] = args;
			if (sub === "set") return out(a.setMandate(need(company, "COMPANY"), need(x, "OPERATION"), Number(need(y, "MAX_TOTAL_CLP")), opt.expires ?? null));
			if (sub === "reply") return out(a.setReplyRule(need(company, "COMPANY"), need(x, "ACTION"), need(y, "DECISION")));
			return out(a.mandates());
		}
		case "approvals":
			// The person's own terminal: the only place the approval codes are printed.
			return out(a.approvals().filter((x) => x.status === "pending").map((x) => ({ id: x.id, kind: x.kind, summary: x.summary, amount_clp: x.amount_clp, url: a.approvalUrl(x), code_for_the_page: x.person_code })));
		case "approve": {
			const ap = a.approval(need(args[0], "APPROVAL_ID"));
			console.error(`\n${ap.summary}\n${ap.amount_clp !== null ? `Amount: ${ap.amount_clp.toLocaleString("es-CL")} CLP\n` : ""}`);
			let yes = !!opt.yes && !opt.deny;
			if (!opt.yes && !opt.deny) {
				if (!process.stdin.isTTY) throw new Error("approve needs --yes or --deny when there is no terminal");
				const rl = createInterface({ input: process.stdin, output: process.stderr });
				yes = /^(y|yes|s|si|sí)$/i.test((await rl.question("Approve these exact terms? [y/N] ")).trim());
				rl.close();
			}
			return out(a.publicApproval(a.decide(ap.id, yes, { via: "cli" })));
		}
		case "proof":
			return out(await a.proof(need(args[0], "REQUEST_ID")));
		case "verify":
			return out(await a.verifySaved(need(args[0], "REQUEST_ID")));
		case "verify-file": {
			const read = (f: string) => JSON.parse(readFileSync(f, "utf8"));
			return out(await verifyWithMaterial(read(need(opt.package, "--package")), read(need(opt.material, "--material")), { operation: opt.operation ? read(opt.operation) : undefined, aud: opt.aud }));
		}
		case "relationships":
			return out(a.relationships());
		case "relationship":
			return out(await a.readRelationship(need(args[0], "ID")));
		case "revoke-relationship":
			return out(await a.revokeRelationship(need(args[0], "ID")));
		case "inbox":
			return out(a.inbox().messages);
		case "reply": {
			const r = await a.reply(need(args[0], "MESSAGE_ID"), need(args[1], "DECISION"));
			if (r.status === "needs_user_approval") return out({ status: r.status, ...a.publicApproval(r.approval), the_person_decides_with: `vxp-agent approve ${r.approval.id}, or the page and the code from: vxp-agent approvals` });
			return out(r);
		}
		default:
			throw new Error(`unknown command «${cmd}» (see: vxp-agent help)`);
	}
}

main().catch((e) => {
	console.error(`error: ${(e as Error).message}`);
	process.exitCode = 1;
});

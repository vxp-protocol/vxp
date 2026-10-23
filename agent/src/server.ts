// The agent's own HTTP server (node:http). It publishes what companies need to reach and trust the
// agent, and gives the person a page to approve exact terms:
//   GET  /agent.json      Client ID Metadata Document (client_id), with the inbox_uri extension (R2)
//   GET  /jwks.json       the agent's public signing key
//   POST /vxp/inbox       signed company requests inside a relationship (R7)
//   GET  /approve/{id}    the person reads the exact terms; POST decides, with the code from their terminal
// In production it must be reachable over https at the agent's public origin.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { MAX_CODE_ATTEMPTS, type VxpAgent } from "./agent.ts";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const PAGE_HEADERS = { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", "referrer-policy": "no-referrer" };

function page(res: ServerResponse, status: number, title: string, body: string) {
	res.writeHead(status, PAGE_HEADERS).end(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font:16px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem">${body}</body></html>`);
}

async function readBody(req: IncomingMessage, max = 256_000): Promise<string> {
	let n = 0;
	const chunks: Buffer[] = [];
	for await (const c of req) {
		n += (c as Buffer).length;
		if (n > max) throw new Error("body too large");
		chunks.push(c as Buffer);
	}
	return Buffer.concat(chunks).toString("utf8");
}

export type AgentServerOptions = { port: number; host?: string; log?: (line: string) => void };

export function startAgentServer(agent: VxpAgent, o: AgentServerOptions): Promise<Server> {
	const log = o.log ?? (() => {});
	const json = (res: ServerResponse, status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
	const server = createServer(async (req, res) => {
		try {
			const url = new URL(req.url ?? "/", agent.origin);
			if (req.method === "GET" && url.pathname === new URL(agent.clientId).pathname) return json(res, 200, agent.clientMetadata());
			if (req.method === "GET" && url.pathname === "/jwks.json") return json(res, 200, agent.jwks());
			if (url.pathname === new URL(agent.inboxUri).pathname) {
				if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed" });
				let body: unknown;
				try {
					body = JSON.parse(await readBody(req));
				} catch {
					return json(res, 400, { error: "malformed_message" });
				}
				const r = await agent.receive(body);
				log(`[inbox] ${r.status} ${JSON.stringify(r.body)}`);
				return json(res, r.status, r.body);
			}
			const m = url.pathname.match(/^\/approve\/(apr_[A-Za-z0-9_-]+)$/);
			if (m) {
				let a;
				try {
					a = agent.approval(m[1]);
				} catch {
					return page(res, 404, "Not found", "<p>Unknown approval.</p>");
				}
				const company = agent.companies().find((c) => c.issuer === a.issuer)?.name ?? a.issuer;
				const terms = `<h1 style="font-size:1.3rem">Your agent asks for your approval</h1><p><b>${esc(company)}</b> · ${esc(a.kind === "accept" ? "accept a proposal" : "answer a question")}</p><p>${esc(a.summary)}</p>${a.amount_clp !== null ? `<p>Amount: <b>${esc(a.amount_clp.toLocaleString("es-CL"))} CLP</b></p>` : ""}`;
				const form = `<form method="post"><label>Your approval code<br><input name="code" inputmode="numeric" autocomplete="off" required></label><br><button name="decision" value="approve">Approve</button> <button name="decision" value="deny">Deny</button></form><p style="color:#555">The code is in your own terminal (<code>vxp-agent approvals</code>, or the console of this agent's server). Your agent never receives it.</p>`;
				if (req.method === "POST") {
					const f = new URLSearchParams(await readBody(req));
					try {
						const d = agent.decide(a.id, f.get("decision") === "approve", { via: "page", code: f.get("code") ?? "" });
						log(`[approval] ${d.id} ${d.status}`);
						return page(res, 200, "Done", `<p>${d.status === "approved" ? "Approved. Your agent may now act on exactly these terms." : "Denied. Your agent will not act on these terms."}</p>`);
					} catch (e) {
						const now = agent.approval(a.id);
						log(`[approval] ${a.id} refused: ${(e as Error).message} (${now.attempts}/${MAX_CODE_ATTEMPTS})`);
						return page(res, 403, "Wrong code", `${terms}<p><b>That code is not right.</b> ${now.status === "pending" ? `${MAX_CODE_ATTEMPTS - now.attempts} attempts left.` : "Too many attempts: this approval is now denied."}</p>${now.status === "pending" ? form : ""}`);
					}
				}
				// Printed where the person runs the agent, never in any response.
				if (a.status === "pending") log(`[approval] ${a.id} opened · code for the person: ${a.person_code}`);
				return page(res, 200, "Approve", `${terms}<p style="color:#555">Status: ${esc(a.status)}. This approval covers these exact terms only; if the company changes them, you will be asked again.</p>${a.status === "pending" ? form : ""}`);
			}
			return json(res, 404, { error: "not_found" });
		} catch (e) {
			log(`[server] ${(e as Error).message}`);
			return json(res, 500, { error: "server_error" });
		}
	});
	// Longer than common client pools keep idle sockets, so a company reusing one does not hit a closed socket.
	server.keepAliveTimeout = 65_000;
	return new Promise((ok, fail) => {
		server.once("error", fail);
		// No host: every interface, IPv4 and IPv6 («localhost» may resolve to either). Deciding on an approval page needs the person's code.
		if (o.host) server.listen(o.port, o.host, () => ok(server));
		else server.listen(o.port, () => ok(server));
	});
}

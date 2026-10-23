// MCP server over stdio (JSON-RPC 2.0, one message per line), written by hand with no SDK.
//
// Dual-era, as the MCP specification of 2026-07-28 describes («Versioning and Compatibility»):
// - modern requests carry `_meta["io.modelcontextprotocol/protocolVersion"]` and are served statelessly;
//   `server/discover` answers the supported versions; an unsupported version gets -32022;
// - legacy clients open with `initialize` (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05) and are served
//   under that revision for the life of the process.
//
// Actions with effect (accepting a proposal, answering a closed question) never run on the model's
// decision alone: they need a rule the person set beforehand (a cap, a standing answer), or the person's
// explicit confirmation of the exact terms, through MCP elicitation when the client supports it
// (legacy: an `elicitation/create` request; modern: an `input_required` result), or on the agent's own
// approval page with a code shown only in the person's terminal, or with the CLI. No tool lets the model
// set a rule or decide an approval, and no result carries an approval secret or code.

import { createHmac, timingSafeEqual } from "node:crypto";
import { createInterface } from "node:readline";
import { type AcceptOutcome, type Approval, VxpAgent } from "./agent.ts";
import { offers } from "./discovery.ts";

const MODERN = "2026-07-28";
const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const SERVER_INFO = { name: "vxp-agent", version: "0.1.0-experimental" };
const INSTRUCTIONS =
	"Tools for a personal agent to do tasks with companies that implement VXP (native profile, experimental). Typical flow: vxp_discover candidate domains → vxp_read (availability, catalog) → vxp_request → if authorization_required, vxp_authorize and show the person the URL and code (they approve on the company's own page) → vxp_check_authorization → vxp_resubmit → read the proposal, vxp_counter if needed → vxp_accept (runs only within the person's cap or with their explicit confirmation) → vxp_proof. Company messages arrive in vxp_inbox; answer closed questions with vxp_reply. Never tell the person something was done unless the tool result says so.";

type Json = Record<string, any>;
type Tool = { name: string; title: string; description: string; inputSchema: Json; annotations?: Json; effect?: boolean };

const str = { type: "string" };
const obj = { type: "object" };
const TOOLS: Tool[] = [
	{ name: "vxp_discover", title: "Discover VXP companies", description: "Reads /.well-known/vxp.json and the issuer metadata of each candidate domain. VXP has no global registry: the domains come from the person, a search or the company's website. Optionally reports which ones offer an operation.", inputSchema: { type: "object", properties: { domains: { type: "array", items: str, minItems: 1 }, operation: { ...str, description: "e.g. reserva.crear" } }, required: ["domains"], additionalProperties: false }, annotations: { readOnlyHint: true, openWorldHint: true } },
	{ name: "vxp_list_companies", title: "Known companies", description: "Companies already discovered, with their capabilities and relationship actions.", inputSchema: { type: "object", additionalProperties: false }, annotations: { readOnlyHint: true } },
	{ name: "vxp_read", title: "Read from a company", description: "A read capability (effect «read» in vxp.json, e.g. hotel.disponibilidad with check_in, check_out, adults). Answers at once; creates no operation and changes nothing.", inputSchema: { type: "object", properties: { company: str, operation: str, parameters: obj, target: obj }, required: ["company", "operation"], additionalProperties: false }, annotations: { readOnlyHint: true, openWorldHint: true } },
	{ name: "vxp_request", title: "Ask a company", description: "POST /v1/requests with a new Idempotency-Key. Returns the request: proposed (with signed terms), or authorization_required with what is missing (and, for new bookings, the public quote).", inputSchema: { type: "object", properties: { company: { ...str, description: "issuer, domain or name" }, operation: str, target: obj, parameters: obj }, required: ["company", "operation"], additionalProperties: false }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true } },
	{ name: "vxp_resubmit", title: "Re-send the same request", description: "Re-sends the same request with the same Idempotency-Key, after the person authorized; the company re-evaluates it.", inputSchema: { type: "object", properties: { request_id: str }, required: ["request_id"], additionalProperties: false }, annotations: { idempotentHint: true, openWorldHint: true } },
	{ name: "vxp_authorize", title: "Ask the person to authorize at the company", description: "Starts the Device Authorization with authorization_details. Returns a URL on the company's own page and a code to SHOW THE PERSON; they link their account there with a code the company sends them. cap_clp, if given, is the maximum the person said they accept; the agent never asks for more. relationship_actions asks, in the same consent, for a relationship so the company can contact the agent later (only those actions).", inputSchema: { type: "object", properties: { company: str, request_id: str, cap_clp: { type: "integer", minimum: 1 }, relationship_actions: { type: "array", items: str }, relationship_days: { type: "integer", minimum: 1 }, relationship_per_day: { type: "integer", minimum: 1 } }, required: ["company"], additionalProperties: false }, annotations: { openWorldHint: true } },
	{ name: "vxp_check_authorization", title: "Check the person's authorization", description: "Polls the token endpoint (respecting its interval), up to wait_seconds (max 30). Returns granted, authorization_pending, access_denied or expired_token, and any relationship created.", inputSchema: { type: "object", properties: { company: str, wait_seconds: { type: "integer", minimum: 0, maximum: 30 } }, required: ["company"], additionalProperties: false }, annotations: { openWorldHint: true } },
	{ name: "vxp_status", title: "Request status", description: "GET /v1/requests/{id}: state, projections, proposal, effects, result.", inputSchema: { type: "object", properties: { request_id: str }, required: ["request_id"], additionalProperties: false }, annotations: { readOnlyHint: true, openWorldHint: true } },
	{ name: "vxp_events", title: "Request events", description: "GET /v1/requests/{id}/events.", inputSchema: { type: "object", properties: { request_id: str }, required: ["request_id"], additionalProperties: false }, annotations: { readOnlyHint: true, openWorldHint: true } },
	{ name: "vxp_counter", title: "Counter-propose", description: "POST /v1/proposals/{id}/counter with proposed_terms. The company answers with a new revision or counter_rejected (with its reason). For hotel bookings: room_type, check_in, check_out, adults, package, add_services, remove_services.", inputSchema: { type: "object", properties: { request_id: str, proposed_terms: obj, note: str }, required: ["request_id", "proposed_terms"], additionalProperties: false }, annotations: { destructiveHint: false, openWorldHint: true } },
	{ name: "vxp_accept", title: "Accept the current proposal", description: "Accepts the exact current revision ONLY if the person's own rules allow it: within a cap the person set beforehand, or with the person's explicit confirmation (asked here if the client supports elicitation, otherwise an approval URL to show them). Blocked when the total is above the person's cap. Executes in the company's system once.", inputSchema: { type: "object", properties: { request_id: str }, required: ["request_id"], additionalProperties: false }, annotations: { destructiveHint: true, idempotentHint: true, openWorldHint: true }, effect: true },
	{ name: "vxp_cancel", title: "Cancel a request", description: "POST /v1/requests/{id}/cancel (asks to stop; before execution it ends cancelled without effect).", inputSchema: { type: "object", properties: { request_id: str }, required: ["request_id"], additionalProperties: false }, annotations: { destructiveHint: true, idempotentHint: true, openWorldHint: true } },
	{ name: "vxp_proof", title: "Get and verify the proof", description: "Downloads the VXP Proof package and verifies it locally with the independent verifier, anchored by the issuer learned from vxp.json. Report valid, final_state, approval and derived_assurance as they are: a valid chain is the operator's attestation, not independent confirmation.", inputSchema: { type: "object", properties: { request_id: str }, required: ["request_id"], additionalProperties: false }, annotations: { readOnlyHint: true, openWorldHint: true } },
	{ name: "vxp_inbox", title: "Company messages", description: "Signed messages that companies sent inside a relationship (already verified against the company's key; forged or replayed ones are rejected and listed separately).", inputSchema: { type: "object", additionalProperties: false }, annotations: { readOnlyHint: true } },
	{ name: "vxp_reply", title: "Answer a closed question", description: "Answers a company's closed question with one of its options. Runs only with a standing answer the person set, or with the person's explicit confirmation (like vxp_accept).", inputSchema: { type: "object", properties: { message_id: { ...str, description: "message id or alert_id" }, decision: str }, required: ["message_id", "decision"], additionalProperties: false }, annotations: { destructiveHint: true, openWorldHint: true }, effect: true },
	{ name: "vxp_relationships", title: "Relationships", description: "Relationships the agent holds, with actions, limits, expiry and whether the signed agreement verified.", inputSchema: { type: "object", additionalProperties: false }, annotations: { readOnlyHint: true } },
	{ name: "vxp_revoke_relationship", title: "Revoke a relationship", description: "DELETE /v1/relationships/{id}: the company can no longer contact the agent through it.", inputSchema: { type: "object", properties: { relationship_id: str }, required: ["relationship_id"], additionalProperties: false }, annotations: { destructiveHint: true, idempotentHint: true, openWorldHint: true } },
	{ name: "vxp_rules", title: "The person's rules", description: "Caps and standing answers the person set (read only: only the person changes them, with the CLI).", inputSchema: { type: "object", additionalProperties: false }, annotations: { readOnlyHint: true } },
];

const CONFIRM_SCHEMA = { type: "object", properties: { approve: { type: "boolean", title: "Approve these exact terms", description: "Your agent will act only on these terms." } }, required: ["approve"] };

class RpcError extends Error {
	readonly code: number;
	readonly data: unknown;
	constructor(code: number, message: string, data?: unknown) {
		super(message);
		this.code = code;
		this.data = data;
	}
}

type Era = { modern: boolean; elicitation: boolean; inputResponses?: Json; requestState?: string };

export class McpServer {
	private readonly agent: VxpAgent;
	private readonly write: (msg: Json) => void;
	private legacy: { version: string; elicitation: boolean } | null = null;
	private nextId = 1;
	private readonly waiting = new Map<number, (msg: Json) => void>();

	constructor(agent: VxpAgent, write: (msg: Json) => void) {
		this.agent = agent;
		this.write = write;
	}

	/** One incoming line. Responses to our own requests (legacy elicitation) are routed to their waiter. */
	async handleLine(line: string): Promise<void> {
		let msg: Json;
		try {
			msg = JSON.parse(line);
		} catch {
			return this.write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
		}
		if (msg && msg.id !== undefined && msg.method === undefined && this.waiting.has(msg.id)) {
			this.waiting.get(msg.id)!(msg);
			this.waiting.delete(msg.id);
			return;
		}
		if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
			if (msg?.id !== undefined) this.write({ jsonrpc: "2.0", id: msg.id, error: { code: -32600, message: "Invalid Request" } });
			return;
		}
		if (msg.id === undefined || msg.id === null) return; // notifications (initialized, cancelled, …): nothing to answer
		try {
			const result = await this.dispatch(msg.method, msg.params ?? {});
			this.write({ jsonrpc: "2.0", id: msg.id, result });
		} catch (e) {
			const err = e instanceof RpcError ? e : new RpcError(-32603, (e as Error).message);
			this.write({ jsonrpc: "2.0", id: msg.id, error: { code: err.code, message: err.message, ...(err.data !== undefined ? { data: err.data } : {}) } });
		}
	}

	private era(params: Json): Era {
		const meta = params?._meta ?? {};
		const v = meta["io.modelcontextprotocol/protocolVersion"];
		if (v !== undefined) {
			if (v !== MODERN) throw new RpcError(-32022, "Unsupported protocol version", { supported: [MODERN, ...LEGACY], requested: v });
			const caps = meta["io.modelcontextprotocol/clientCapabilities"];
			if (!caps || typeof caps !== "object") throw new RpcError(-32602, "Invalid params: missing io.modelcontextprotocol/clientCapabilities");
			return { modern: true, elicitation: !!caps.elicitation, inputResponses: params.inputResponses, requestState: params.requestState };
		}
		return { modern: false, elicitation: !!this.legacy?.elicitation };
	}

	private done(era: Era, result: Json): Json {
		return era.modern ? { resultType: "complete", ...result, _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO } } : result;
	}

	async dispatch(method: string, params: Json): Promise<Json> {
		if (method === "initialize") {
			const asked = String(params.protocolVersion ?? "");
			const version = LEGACY.includes(asked) ? asked : LEGACY[0];
			this.legacy = { version, elicitation: !!params.capabilities?.elicitation };
			return { protocolVersion: version, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS };
		}
		if (method === "ping") return this.era(params).modern ? this.done(this.era(params), {}) : {};
		const era = this.era(params);
		if (method === "server/discover") return this.done(era, { supportedVersions: [MODERN, ...LEGACY], capabilities: { tools: { listChanged: false } }, instructions: INSTRUCTIONS });
		if (method === "tools/list") return this.done(era, { tools: TOOLS.map(({ effect: _e, ...t }) => t) });
		if (method === "tools/call") {
			const tool = TOOLS.find((t) => t.name === params.name);
			if (!tool) throw new RpcError(-32602, `Unknown tool: ${params.name}`);
			try {
				const r = await this.call(tool.name, params.arguments ?? {}, era);
				if (r && r.resultType === "input_required") return r;
				return this.done(era, { content: [{ type: "text", text: JSON.stringify(r, null, 1) }], structuredContent: r, isError: false });
			} catch (e) {
				return this.done(era, { content: [{ type: "text", text: `Error: ${(e as Error).message}` }], isError: true });
			}
		}
		throw new RpcError(-32601, `Method not found: ${method}`);
	}

	// ── Confirmation by the person ─────────────────────────────────────────────────────────────

	private stateFor(a: Approval) {
		return `${a.id}.${createHmac("sha256", a.secret).update(`mcp-confirm|${a.id}`).digest("base64url")}`;
	}

	private stateOk(a: Approval, state: unknown) {
		const want = Buffer.from(this.stateFor(a));
		const got = Buffer.from(String(state ?? ""));
		return want.length === got.length && timingSafeEqual(want, got);
	}

	private async elicitLegacy(message: string): Promise<{ action: string; content?: Json } | null> {
		const id = this.nextId++;
		const params = { ...(this.legacy!.version >= "2025-11-25" ? { mode: "form" } : {}), message, requestedSchema: CONFIRM_SCHEMA };
		const answer = new Promise<Json>((ok) => this.waiting.set(id, ok));
		this.write({ jsonrpc: "2.0", id, method: "elicitation/create", params });
		const r = await Promise.race([answer, new Promise<null>((ok) => setTimeout(() => ok(null), 300_000))]);
		return r && r.result ? r.result : null;
	}

	private confirmText(a: Approval) {
		const company = this.agent.companies().find((c) => c.issuer === a.issuer)?.name ?? a.issuer;
		return `${company} — ${a.kind === "accept" ? "accept this proposal" : "answer this question"}:\n\n${a.summary}${a.amount_clp !== null ? `\n\nAmount: ${a.amount_clp.toLocaleString("es-CL")} CLP` : ""}`;
	}

	/**
	 * Asks the person to confirm `a`. Returns null when it was decided (the caller retries the action), an
	 * MRTR input_required result for modern clients, or a payload telling the model to show the approval URL.
	 */
	private async confirm(a: Approval, era: Era, retry: { name: string; arguments: Json }): Promise<Json | null> {
		if (era.modern && era.inputResponses?.confirm && this.stateOk(a, era.requestState)) {
			const r = era.inputResponses.confirm as { action?: string; content?: Json };
			this.agent.decide(a.id, r.action === "accept" && r.content?.approve === true, { via: "elicitation" });
			return null;
		}
		if (era.modern && era.elicitation)
			return { resultType: "input_required", inputRequests: { confirm: { method: "elicitation/create", params: { mode: "form", message: this.confirmText(a), requestedSchema: CONFIRM_SCHEMA } } }, requestState: this.stateFor(a), _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO } };
		if (!era.modern && era.elicitation) {
			const r = await this.elicitLegacy(this.confirmText(a));
			if (r) {
				this.agent.decide(a.id, r.action === "accept" && r.content?.approve === true, { via: "elicitation" });
				return null;
			}
		}
		void retry;
		// What the model gets: no secret and no person code. Deciding needs the code from the person's own terminal.
		const pub = this.agent.publicApproval(a);
		return { status: "needs_user_approval", ...pub, tell_the_person: `Please review the exact terms at ${pub.approval_url} and approve or deny them there with the approval code shown in your own terminal (vxp-agent approvals), or run: vxp-agent approve ${a.id}. Then ask me to continue.` };
	}

	// ── Tools ──────────────────────────────────────────────────────────────────────────────────

	private async call(name: string, x: Json, era: Era): Promise<Json> {
		const a = this.agent;
		switch (name) {
			case "vxp_discover": {
				const res = await a.discover(x.domains);
				return { note: "VXP has no global registry; only the domains given were checked.", results: res.map((r) => (r.ok ? { domain: r.domain, ok: true, name: r.company.name, issuer: r.company.issuer, status: r.company.status, ...(x.operation ? { offers_operation: offers(r.company, x.operation) } : {}), capabilities: r.company.capabilities.map((c) => ({ id: c.id, effect: c.effect })), relationship_actions: r.company.relationshipActions } : r)) };
			}
			case "vxp_list_companies":
				return { companies: a.companies().map((c) => ({ name: c.name, domain: c.domain, issuer: c.issuer, capabilities: c.capabilities.map((k) => k.id), relationship_actions: c.relationshipActions })) };
			case "vxp_read": {
				const r = await a.read(x.company, x.operation, x.parameters ?? {}, x.target ?? {});
				return { http: r.http, ...r.body };
			}
			case "vxp_request": {
				const r = await a.createRequest(x.company, x.operation, x.target ?? {}, x.parameters ?? {});
				return { http: r.http, ...r.body };
			}
			case "vxp_resubmit": {
				const r = await a.resubmit(x.request_id);
				return { http: r.http, ...r.body };
			}
			case "vxp_authorize": {
				const rel = x.relationship_actions?.length ? { actions: x.relationship_actions, ...(x.relationship_days ? { duration_seconds: x.relationship_days * 86_400 } : {}), ...(x.relationship_per_day ? { max_per_day: x.relationship_per_day } : {}) } : undefined;
				const r = await a.authorize(x.company, { forRequest: x.request_id, capClp: x.cap_clp, relationship: rel });
				return { ...r, tell_the_person: `Open ${r.verification_uri_complete} (this is ${r.company}'s own page), check the code ${r.user_code}, and follow the steps. ${r.company} will send you a one-time code through its own channel.` };
			}
			case "vxp_check_authorization":
				return a.pollAuthorization(x.company, Math.min(30, Number(x.wait_seconds ?? 0)));
			case "vxp_status":
				return (await a.refresh(x.request_id)).view;
			case "vxp_events":
				return a.events(x.request_id);
			case "vxp_counter": {
				const r = await a.counter(x.request_id, x.proposed_terms, x.note);
				return { http: r.http, ...r.body };
			}
			case "vxp_accept": {
				let r: AcceptOutcome = await a.accept(x.request_id);
				if (r.status === "needs_user_approval") {
					const ask = await this.confirm(r.approval, era, { name, arguments: x });
					if (ask) return { ...ask, reason: r.reason };
					if (a.approval(r.approval.id).status !== "approved") return { status: "denied_by_person", approval_id: r.approval.id };
					r = await a.accept(x.request_id);
				}
				if (r.status === "accepted") return { status: "accepted", approved_by: r.approved_by, state: r.view?.state, result: r.view?.result, proof_url: r.view?.proof_url };
				if (r.status === "needs_user_approval") return { status: r.status, ...a.publicApproval(r.approval) };
				return r;
			}
			case "vxp_cancel":
				return a.cancel(x.request_id);
			case "vxp_proof": {
				const p = await a.proof(x.request_id);
				return { verdict: p.verdict, saved: { package: p.package_file, material: p.material_file } };
			}
			case "vxp_inbox": {
				const ib = a.inbox();
				return { messages: ib.messages, rejected: ib.rejected.slice(-20) };
			}
			case "vxp_reply": {
				let r = await a.reply(x.message_id, x.decision);
				if (r.status === "needs_user_approval") {
					const ask = await this.confirm(r.approval, era, { name, arguments: x });
					if (ask) return ask;
					if (a.approval(r.approval.id).status !== "approved") return { status: "denied_by_person", approval_id: r.approval.id };
					r = await a.reply(x.message_id, x.decision);
				}
				return r;
			}
			case "vxp_relationships":
				return { relationships: a.relationships().map(({ agreement: _g, ...rest }) => rest) };
			case "vxp_revoke_relationship":
				return a.revokeRelationship(x.relationship_id);
			case "vxp_rules": {
				const m = a.mandates();
				return { caps: m.accept, standing_answers: m.replies };
			}
		}
		throw new Error(`unknown tool ${name}`);
	}
}

/** Runs the MCP server on this process's stdin/stdout. Logs go to stderr only. */
export function runMcpServer(agent: VxpAgent): Promise<void> {
	const server = new McpServer(agent, (m) => process.stdout.write(`${JSON.stringify(m)}\n`));
	const rl = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });
	rl.on("line", (l) => {
		if (l.trim()) server.handleLine(l).catch((e) => process.stderr.write(`[mcp] ${(e as Error).message}\n`));
	});
	return new Promise((ok) => rl.on("close", () => ok()));
}

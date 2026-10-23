// A personal agent for the VXP native profile (spec §8), with no dependency on any operator:
// discovery, identity (CIMD + JWKS), sessions with private_key_jwt and DPoP, requests with
// idempotency, Device Authorization with RAR for the person, proposals, counter-proposals and
// acceptance under the person's own rules, results, proofs verified locally, and VXP Relationship
// (agreement, signed company requests in an inbox, replies to closed questions).
//
// Everything that must survive a restart lives in the state directory (store.ts).

import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import { type Company, type DiscoveryResult, discover, metadataUrlFor } from "./discovery.ts";
import { type PrivateJwk, type SigningKey, assertion, decodeJws, dpopProof, generatePrivateJwk, now, randomToken, sha256b64u, signingKey, verifyJws } from "./jose.ts";
import { Net, type NetOptions, VxpHttpError } from "./net.ts";
import { Store } from "./store.ts";
import { type Material, collectMaterial, operationView, type Verdict, verifyWithMaterial } from "./verify.ts";

export const RAR_CAPABILITY = "https://vxpprotocol.org/rar/capability";
export const RAR_RELATIONSHIP = "https://vxpprotocol.org/rar/relationship";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
const CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export type CapabilityDetail = { type: string; actions: string[]; identifier: string; limits?: { max_total_clp: number } };
export type RelationshipAsk = { actions: string[]; max_per_day?: number; duration_seconds?: number };

type Identity = { version: 1; client_id: string; client_name: string; origin: string; signing: PrivateJwk; dpop: PrivateJwk; user_secret: string; created_at: string; profiles?: string[] };
type Session = { access_token: string; expires_at: number; kind: "session" | "grant"; authorization_details: CapabilityDetail[]; obtained_at: string };
type PendingAuthorization = { issuer: string; device_code: string; user_code: string; verification_uri: string; verification_uri_complete: string; expires_at: number; interval: number; details: unknown[]; for_request: string | null; started_at: string; last_poll: number };

export type RequestRecord = {
	request_id: string;
	issuer: string;
	operation: string;
	target: Record<string, unknown>;
	parameters: Record<string, unknown>;
	idempotency_key: string | null;
	origin: "agent" | "company";
	state: string;
	view: any;
	created_at: string;
	updated_at: string;
};

export type RelationshipRecord = {
	relationship_id: string;
	issuer: string;
	actions: string[];
	limits: Record<string, number>;
	expires_at: string;
	state: string;
	agreement: string | null;
	agreement_verified: boolean;
	created_at: string;
	revoked_at?: string;
};

export type InboxMessage = {
	id: string;
	received_at: string;
	issuer: string;
	relationship_id: string;
	action: string;
	content: Record<string, any>;
	jti: string;
	expires_at: string;
	status: "new" | "answered" | "accepted" | "seen";
	reply?: { decision: string; at: string; receipt_verified: boolean; source: string };
};
type Inbox = { messages: InboxMessage[]; seen_jti: Record<string, number>; rejected: { at: string; reason: string }[] };

/** What the person decided beforehand (the agent never writes these on its own; the CLI does, on the person's command). */
export type Mandate = { issuer: string; operation: string; max_total_clp: number; expires_at: string | null; created_at: string; note?: string };
export type ReplyRule = { issuer: string; action: string; decision: string; created_at: string };
type Mandates = { accept: Mandate[]; replies: ReplyRule[] };

export type Approval = {
	id: string;
	/** Never leaves the state directory: keys the MCP requestState HMAC. */
	secret: string;
	/**
	 * What the person types on the approval page. It is shown only where the person is (their terminal:
	 * `vxp-agent approvals`, the agent server's console), never in what the agent or the model receives.
	 */
	person_code: string;
	attempts: number;
	kind: "accept" | "reply";
	issuer: string;
	request_id?: string;
	proposal_id?: string;
	message_id?: string;
	decision?: string;
	summary: string;
	amount_clp: number | null;
	binding: string;
	status: "pending" | "approved" | "denied";
	created_at: string;
	decided_at?: string;
	source?: string;
};

/** How the person proves it is them when deciding. The model never holds any of these. */
export type ApprovalProof = { via: "cli" } | { via: "page"; code: string } | { via: "elicitation" };

/** What may be shown to the agent's model: no secret and no person code. */
export type PublicApproval = { approval_id: string; kind: Approval["kind"]; summary: string; amount_clp: number | null; approval_status: Approval["status"]; approval_url: string | null };

export const MAX_CODE_ATTEMPTS = 5;
/** Shape accepted for identifiers a company returns (request and proposal ids). */
export const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export type AcceptOutcome =
	| { status: "accepted"; approved_by: "user" | "standing_permission"; view: any }
	| { status: "needs_user_approval"; approval: Approval; reason: string; mandate: Mandate | null }
	| { status: "blocked_by_mandate"; reason: string; amount_clp: number | null; mandate: Mandate }
	| { status: "rejected_by_company"; http: number; body: any };

export type AgentOptions = {
	stateDir: string;
	/** Public origin where this agent serves its Client ID Metadata Document, JWKS and inbox (https in production). */
	publicOrigin?: string;
	clientName?: string;
	net?: NetOptions;
	/** Where the person approves exact terms on this agent's own server, if one runs (see server.ts). */
	approvalBaseUrl?: string;
};

/** The amount a revision commits the person to, in CLP, when its terms state one. */
export function amountOf(view: any): number | null {
	const t = view?.proposal?.terms ?? {};
	for (const k of ["total", "garantia", "cargo"]) if (typeof t[k] === "number") return t[k];
	return null;
}

/** Digest of what the person approves: the proposal id (carries the revision), its summary and its terms. */
export function bindingOf(view: any): string {
	return bindingFor(view?.proposal?.id, view?.proposal?.summary, view?.proposal?.terms);
}

/** The same digest for any profile: what is approved is one proposal id (with its revision), its summary and its terms. */
export function bindingFor(proposalId: unknown, summary: unknown, terms: unknown): string {
	return sha256b64u(JSON.stringify({ proposal: proposalId, summary, terms }));
}

/** A revision to be accepted, whatever profile it came through. */
export type RevisionToAccept = { issuer: string; operation: string; request_id?: string; proposal_id: string; summary: string; terms: unknown; user_approval_required: boolean; amount_clp: number | null };

/** What the person's rules say about one revision. */
export type AcceptanceDecision =
	| { status: "allowed"; approved_by: "user" | "standing_permission" }
	| { status: "needs_user_approval"; approval: Approval; reason: string; mandate: Mandate | null }
	| { status: "blocked_by_mandate"; reason: string; amount_clp: number | null; mandate: Mandate };

export class VxpAgent {
	readonly store: Store;
	readonly net: Net;
	private readonly id: Identity;
	private readonly sig: SigningKey;
	private readonly dpopKey: SigningKey;
	approvalBaseUrl: string | null;

	private constructor(store: Store, net: Net, id: Identity, approvalBaseUrl: string | null) {
		this.store = store;
		this.net = net;
		this.id = id;
		this.sig = signingKey(id.signing);
		this.dpopKey = signingKey(id.dpop);
		this.approvalBaseUrl = approvalBaseUrl;
	}

	/** Opens (or creates on first use) the agent whose state lives in `stateDir`. */
	static open(o: AgentOptions): VxpAgent {
		const store = new Store(o.stateDir);
		let id = store.read<Identity | null>("identity", null);
		if (!id) {
			if (!o.publicOrigin) throw new Error("first run: publicOrigin is required to create the agent's identity");
			const origin = new URL(o.publicOrigin).origin;
			id = { version: 1, client_id: `${origin}/agent.json`, client_name: o.clientName ?? "Personal agent (VXP)", origin, signing: generatePrivateJwk(), dpop: generatePrivateJwk(), user_secret: randomToken(32), created_at: new Date().toISOString() };
			store.write("identity", id, true);
		} else if (o.publicOrigin && new URL(o.publicOrigin).origin !== id.origin) {
			throw new Error(`this state belongs to the agent at ${id.origin}, not ${new URL(o.publicOrigin).origin}`);
		}
		const net = new Net(o.net);
		return new VxpAgent(store, net, id, o.approvalBaseUrl ?? `${id.origin}/approve`);
	}

	// ── Identity ───────────────────────────────────────────────────────────────────────────────

	get clientId() {
		return this.id.client_id;
	}
	get origin() {
		return this.id.origin;
	}
	get inboxUri() {
		return `${this.id.origin}/vxp/inbox`;
	}

	/** Client ID Metadata Document, served at the client_id URL. VXP extensions only. */
	/**
	 * Optional profiles this agent also speaks (`poppy-0.2`). They add only what their contract asks the
	 * agent to declare; a native-only agent declares nothing for them.
	 */
	profiles(): string[] {
		return this.store.read<Identity>("identity", this.id).profiles ?? [];
	}

	enableProfile(name: "poppy-0.2" | "pact-1.0"): void {
		this.store.update<Identity, void>("identity", this.id, (id) => void (id.profiles = [...new Set([...(id.profiles ?? []), name])]), true);
	}

	/** Keys and identifiers the optional adapters sign with. The native profile does not use this. */
	credentials(): { clientId: string; origin: string; signing: SigningKey; dpop: SigningKey } {
		return { clientId: this.id.client_id, origin: this.id.origin, signing: this.sig, dpop: this.dpopKey };
	}

	clientMetadata() {
		// Poppy Operations (Poppy §3.3 extension): declared only when the Poppy profile is enabled.
		const poppy = this.profiles().includes("poppy-0.2") ? { operations: { version: "1" } } : {};
		return {
			client_id: this.id.client_id,
			client_name: this.id.client_name,
			jwks_uri: `${this.id.origin}/jwks.json`,
			token_endpoint_auth_method: "private_key_jwt",
			grant_types: [JWT_BEARER, DEVICE_CODE],
			dpop_bound_access_tokens: true,
			extensions: {
				"vxpprotocol.org/proof": { version: "0.1" },
				"vxpprotocol.org/relationship": { version: "0.1", inbox_uri: this.inboxUri },
				...poppy,
			},
		};
	}

	jwks() {
		return { keys: [this.sig.publicJwk] };
	}

	/** The person's User ID for one company: a per-company pseudonym, stable across restarts. */
	userIdFor(issuer: string): string {
		return `usr_${createHmac("sha256", this.id.user_secret).update(issuer).digest("base64url").slice(0, 22)}`;
	}

	// ── Discovery ──────────────────────────────────────────────────────────────────────────────

	async discover(domains: string[]): Promise<DiscoveryResult[]> {
		const res = await discover(this.net, domains);
		this.store.update<Record<string, Company>, void>("companies", {}, (all) => {
			for (const r of res) if (r.ok) all[r.company.issuer] = r.company;
		});
		return res;
	}

	companies(): Company[] {
		return Object.values(this.store.read<Record<string, Company>>("companies", {}));
	}

	/** A known company, by issuer, domain or name. */
	company(ref: string): Company {
		const all = this.companies();
		const c = all.find((x) => x.issuer === ref) ?? all.find((x) => x.domain === ref.toLowerCase()) ?? all.find((x) => x.name.toLowerCase() === ref.toLowerCase());
		if (!c) throw new Error(`unknown company «${ref}»: discover it first`);
		return c;
	}

	// ── OAuth: private_key_jwt + DPoP, resource = native endpoint (RFC 8707) ─────────────────

	private clientAuth(c: Company) {
		return { client_id: this.id.client_id, client_assertion_type: CLIENT_ASSERTION, client_assertion: assertion(this.sig, this.id.client_id, this.id.client_id, c.issuer), resource: c.endpoint };
	}

	private async tokenRequest(c: Company, form: Record<string, string>) {
		const body = new URLSearchParams({ ...form, ...this.clientAuth(c), assertion: assertion(this.sig, this.id.client_id, this.userIdFor(c.issuer), c.issuer) });
		return this.net.json(c.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: dpopProof(this.dpopKey, "POST", c.tokenEndpoint) }, body: body.toString() });
	}

	private saveSession(c: Company, body: any, kind: Session["kind"]): Session {
		const s: Session = { access_token: String(body.access_token), expires_at: now() + Number(body.expires_in ?? 300), kind, authorization_details: Array.isArray(body.authorization_details) ? body.authorization_details : [], obtained_at: new Date().toISOString() };
		this.store.update<Record<string, Session>, void>("sessions", {}, (all) => void (all[c.issuer] = s), true);
		return s;
	}

	/** A live access token for this company: the stored one, or a new session (no delegated authority). */
	async token(c: Company): Promise<string> {
		const s = this.store.read<Record<string, Session>>("sessions", {})[c.issuer];
		if (s && s.expires_at - 30 > now()) return s.access_token;
		const r = await this.tokenRequest(c, { grant_type: JWT_BEARER });
		if (r.status !== 200) throw new VxpHttpError(`session token refused: ${JSON.stringify(r.body)}`, r.status, r.body);
		return this.saveSession(c, r.body, "session").access_token;
	}

	sessionInfo(c: Company): Omit<Session, "access_token"> | null {
		const s = this.store.read<Record<string, Session>>("sessions", {})[c.issuer];
		if (!s) return null;
		const { access_token: _t, ...rest } = s;
		return rest;
	}

	/** A DPoP-bound call to the company's native endpoint. Retries once with a fresh session on invalid_token. */
	async call(c: Company, method: string, url: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: any }> {
		if (!url.startsWith(`${c.endpoint}/`)) throw new Error(`refused: ${url} is not under ${c.endpoint}`);
		for (let i = 0; i < 2; i++) {
			const t = await this.token(c);
			const r = await this.net.json(url, { method, headers: { authorization: `DPoP ${t}`, dpop: dpopProof(this.dpopKey, method, url, t), "content-type": "application/json", accept: "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
			if (r.status === 401 && i === 0 && /invalid_token/.test(String(r.headers.get("www-authenticate") ?? ""))) {
				this.store.update<Record<string, Session>, void>("sessions", {}, (all) => void delete all[c.issuer], true);
				continue;
			}
			return { status: r.status, body: r.body };
		}
		throw new Error("unreachable");
	}

	// ── Requests ───────────────────────────────────────────────────────────────────────────────

	private saveRequest(rec: RequestRecord) {
		this.store.update<Record<string, RequestRecord>, void>("requests", {}, (all) => void (all[rec.request_id] = rec));
	}

	requests(): RequestRecord[] {
		return Object.values(this.store.read<Record<string, RequestRecord>>("requests", {}));
	}

	request(id: string): RequestRecord {
		const r = this.store.read<Record<string, RequestRecord>>("requests", {})[id];
		if (!r) throw new Error(`unknown request ${id}`);
		return r;
	}

	private record(c: Company, view: any, base: Partial<RequestRecord> & Pick<RequestRecord, "operation" | "target" | "parameters" | "idempotency_key" | "origin">): RequestRecord {
		// Identifiers come from the company: they become file names and URL segments, so only a safe shape is kept.
		if (typeof view?.request_id !== "string" || !SAFE_ID.test(view.request_id)) throw new Error("the company returned a request_id with an unexpected shape");
		if (view.proposal?.id !== undefined && (typeof view.proposal.id !== "string" || !SAFE_ID.test(view.proposal.id))) throw new Error("the company returned a proposal id with an unexpected shape");
		const prev = this.store.read<Record<string, RequestRecord>>("requests", {})[view.request_id];
		// A company can only update its own requests: the same id from another issuer is refused, not merged.
		if (prev && prev.issuer !== c.issuer) throw new Error(`request ${view.request_id} belongs to another company`);
		const rec: RequestRecord = { request_id: view.request_id, issuer: c.issuer, ...base, state: String(view.state ?? prev?.state ?? "unknown"), view, created_at: prev?.created_at ?? new Date().toISOString(), updated_at: new Date().toISOString() };
		this.saveRequest(rec);
		return rec;
	}

	/** POST /v1/requests with a fresh Idempotency-Key that is kept, so the same request can be re-sent later. */
	async createRequest(companyRef: string, operation: string, target: Record<string, unknown> = {}, parameters: Record<string, unknown> = {}): Promise<{ http: number; record: RequestRecord | null; body: any }> {
		const c = this.company(companyRef);
		const key = randomToken(18);
		const r = await this.call(c, "POST", `${c.endpoint}/requests`, { operation, target, parameters }, { "idempotency-key": key });
		if (!r.body?.request_id) return { http: r.status, record: null, body: r.body };
		return { http: r.status, record: this.record(c, r.body, { operation, target, parameters, idempotency_key: key, origin: "agent" }), body: r.body };
	}

	/**
	 * A read capability (effect «read», e.g. hotel.disponibilidad): the company answers at once, creates no
	 * operation and changes nothing. Public reads need no grant; delegated ones need the scope.
	 */
	async read(companyRef: string, operation: string, parameters: Record<string, unknown> = {}, target: Record<string, unknown> = {}): Promise<{ http: number; body: any }> {
		const c = this.company(companyRef);
		const cap = c.capabilities.find((x) => x.id === operation);
		if (cap && cap.effect !== "read") throw new Error(`${operation} is not a read; use createRequest`);
		const r = await this.call(c, "POST", `${c.endpoint}/requests`, { operation, target, parameters }, { "idempotency-key": randomToken(18) });
		return { http: r.status, body: r.body };
	}

	/** Re-sends the SAME request (same key, same body): the company re-evaluates it with the current token. */
	async resubmit(requestId: string): Promise<{ http: number; record: RequestRecord; body: any }> {
		const rec = this.request(requestId);
		if (!rec.idempotency_key) throw new Error("this request was started by the company; it has nothing to re-send");
		const c = this.company(rec.issuer);
		const r = await this.call(c, "POST", `${c.endpoint}/requests`, { operation: rec.operation, target: rec.target, parameters: rec.parameters }, { "idempotency-key": rec.idempotency_key });
		if (r.body?.request_id && r.body.request_id !== rec.request_id) throw new Error(`the company answered another request (${r.body.request_id})`);
		return { http: r.status, record: r.body?.request_id ? this.record(c, r.body, rec) : rec, body: r.body };
	}

	async refresh(requestId: string): Promise<RequestRecord> {
		const rec = this.request(requestId);
		const c = this.company(rec.issuer);
		const r = await this.call(c, "GET", `${c.endpoint}/requests/${rec.request_id}`);
		if (r.status !== 200) throw new VxpHttpError(`GET request → ${r.status}`, r.status, r.body);
		return this.record(c, r.body, rec);
	}

	async events(requestId: string): Promise<any> {
		const rec = this.request(requestId);
		const c = this.company(rec.issuer);
		return (await this.call(c, "GET", `${c.endpoint}/requests/${rec.request_id}/events`)).body;
	}

	async counter(requestId: string, proposedTerms: Record<string, unknown>, note?: string): Promise<{ http: number; body: any; record: RequestRecord }> {
		const rec = await this.refresh(requestId);
		const c = this.company(rec.issuer);
		const pid = rec.view?.proposal?.id;
		if (!pid) throw new Error("this request has no proposal to counter");
		const r = await this.call(c, "POST", `${c.endpoint}/proposals/${pid}/counter`, { proposed_terms: proposedTerms, ...(note ? { note } : {}) });
		const view = r.body?.request_id ? r.body : rec.view;
		return { http: r.status, body: r.body, record: this.record(c, view, rec) };
	}

	async cancel(requestId: string): Promise<{ http: number; body: any }> {
		const rec = this.request(requestId);
		const c = this.company(rec.issuer);
		const r = await this.call(c, "POST", `${c.endpoint}/requests/${rec.request_id}/cancel`, {});
		if (r.body?.request_id) this.record(c, r.body, rec);
		return { http: r.status, body: r.body };
	}

	// ── Device Authorization (RFC 8628) with authorization_details (RFC 9396) ────────────────

	/**
	 * Starts the person's approval on the company's own page. Returns the URL and code to show the
	 * person; the device_code stays in the state directory. `capClp` replaces the amount the company
	 * asked for with the person's own cap, if lower or equal (never raises it past what they said).
	 */
	async authorize(companyRef: string, o: { details?: CapabilityDetail[]; forRequest?: string; capClp?: number; relationship?: RelationshipAsk } = {}) {
		const c = this.company(companyRef);
		let details: unknown[] = [...(o.details ?? [])];
		if (o.forRequest) {
			const rec = this.request(o.forRequest);
			const missing = (rec.view?.authorization?.authorization_details ?? []) as CapabilityDetail[];
			if (!missing.length) throw new Error(`request ${o.forRequest} is not waiting for authorization (state ${rec.state})`);
			for (const d of missing) {
				const asked = d.limits?.max_total_clp;
				if (o.capClp !== undefined && asked !== undefined && asked > o.capClp) throw new Error(`the company needs authority for ${asked} CLP, above the cap of ${o.capClp} CLP: not requested`);
				details.push(o.capClp !== undefined && asked !== undefined ? { ...d, limits: { max_total_clp: o.capClp } } : d);
			}
		}
		if (o.relationship) {
			const bad = o.relationship.actions.filter((a) => !c.relationshipActions.includes(a));
			if (bad.length) throw new Error(`the company does not offer these relationship actions: ${bad.join(", ")}`);
			details.push({ type: RAR_RELATIONSHIP, actions: o.relationship.actions, identifier: "relationship", limits: { max_per_day: o.relationship.max_per_day ?? 2, duration_seconds: o.relationship.duration_seconds ?? 30 * 86_400 } });
		}
		if (!details.length) throw new Error("nothing to authorize");
		const r = await this.net.json(c.deviceEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...this.clientAuth(c), authorization_details: JSON.stringify(details) }).toString() });
		if (r.status !== 200) throw new VxpHttpError(`device authorization refused: ${JSON.stringify(r.body)}`, r.status, r.body);
		const verificationComplete = String(r.body.verification_uri_complete ?? `${r.body.verification_uri}?user_code=${r.body.user_code}`);
		// The person is sent to the company's own page: it must be on the issuer's origin.
		if (new URL(verificationComplete).origin !== new URL(c.issuer).origin) throw new Error(`refused: verification page ${verificationComplete} is not on the issuer's origin`);
		const p: PendingAuthorization = { issuer: c.issuer, device_code: String(r.body.device_code), user_code: String(r.body.user_code), verification_uri: String(r.body.verification_uri), verification_uri_complete: verificationComplete, expires_at: now() + Number(r.body.expires_in ?? 600), interval: Number(r.body.interval ?? 5), details, for_request: o.forRequest ?? null, started_at: new Date().toISOString(), last_poll: 0 };
		this.store.update<Record<string, PendingAuthorization>, void>("authorizations", {}, (all) => void (all[c.issuer] = p), true);
		return { company: c.name, verification_uri: p.verification_uri, verification_uri_complete: p.verification_uri_complete, user_code: p.user_code, expires_at: new Date(p.expires_at * 1000).toISOString(), details };
	}

	pendingAuthorization(companyRef: string) {
		const p = this.store.read<Record<string, PendingAuthorization>>("authorizations", {})[this.company(companyRef).issuer];
		if (!p) return null;
		const { device_code: _d, ...rest } = p;
		return rest;
	}

	/**
	 * Polls the token endpoint once (or until `waitSeconds` pass), respecting the interval (RFC 8628 §3.5).
	 * On approval, stores the delegated token and any relationship, verifying the signed agreement.
	 */
	async pollAuthorization(companyRef: string, waitSeconds = 0): Promise<{ status: "granted" | "authorization_pending" | "access_denied" | "expired_token" | "none"; authorization_details?: unknown[]; relationships?: RelationshipRecord[]; error?: unknown }> {
		const c = this.company(companyRef);
		const deadline = Date.now() + waitSeconds * 1000;
		for (;;) {
			const p = this.store.read<Record<string, PendingAuthorization>>("authorizations", {})[c.issuer];
			if (!p) return { status: "none" };
			if (p.expires_at < now()) {
				this.dropAuthorization(c.issuer);
				return { status: "expired_token" };
			}
			const wait = p.last_poll + p.interval * 1000 - Date.now();
			if (wait > 0) {
				if (Date.now() + wait > deadline) return { status: "authorization_pending" };
				await new Promise((ok) => setTimeout(ok, wait));
			}
			this.store.update<Record<string, PendingAuthorization>, void>("authorizations", {}, (all) => void (all[c.issuer] && (all[c.issuer].last_poll = Date.now())), true);
			const r = await this.tokenRequest(c, { grant_type: DEVICE_CODE, device_code: p.device_code });
			if (r.status === 200) {
				this.saveSession(c, r.body, "grant");
				this.dropAuthorization(c.issuer);
				const rels = await this.saveRelationships(c, (r.body.relationships ?? []) as any[]);
				return { status: "granted", authorization_details: r.body.authorization_details ?? [], relationships: rels };
			}
			const err = r.body?.error;
			if (err === "slow_down") {
				this.store.update<Record<string, PendingAuthorization>, void>("authorizations", {}, (all) => void (all[c.issuer] && (all[c.issuer].interval += 5)), true);
			} else if (err !== "authorization_pending") {
				this.dropAuthorization(c.issuer);
				return { status: err === "access_denied" ? "access_denied" : "expired_token", error: r.body };
			}
			if (Date.now() >= deadline) return { status: "authorization_pending" };
		}
	}

	private dropAuthorization(issuer: string) {
		this.store.update<Record<string, PendingAuthorization>, void>("authorizations", {}, (all) => void delete all[issuer], true);
	}

	// ── VXP Relationship ───────────────────────────────────────────────────────────────────────

	/** The company's relationship keys, from its issuer metadata (R5): the only key a company message is checked with. */
	private async relationshipJwks(c: Company): Promise<unknown> {
		const meta = await this.net.doc(metadataUrlFor(c.issuer));
		if (meta.issuer !== c.issuer) throw new Error("issuer metadata changed issuer");
		const uri = meta.vxp_relationship?.jwks_uri;
		if (typeof uri !== "string" || new URL(uri).origin !== new URL(c.issuer).origin) throw new Error("issuer metadata has no relationship key under the issuer's origin");
		return this.net.doc(uri);
	}

	private async saveRelationships(c: Company, list: any[]): Promise<RelationshipRecord[]> {
		if (!list.length) return [];
		const jwks = await this.relationshipJwks(c);
		const out: RelationshipRecord[] = [];
		for (const r of list) {
			const claims = typeof r.agreement === "string" ? verifyJws(r.agreement, jwks, "vxp-relationship+jwt") : null;
			const ok = !!claims && claims.iss === c.issuer && claims.aud === this.id.client_id && claims.sub === this.userIdFor(c.issuer) && claims.rel === r.relationship_id;
			out.push({ relationship_id: String(r.relationship_id), issuer: c.issuer, actions: r.actions ?? [], limits: r.limits ?? {}, expires_at: String(r.expires_at), state: String(r.state ?? "active"), agreement: r.agreement ?? null, agreement_verified: ok, created_at: new Date().toISOString() });
		}
		this.store.update<Record<string, RelationshipRecord>, void>("relationships", {}, (all) => {
			for (const r of out) all[r.relationship_id] = r;
		});
		return out;
	}

	relationships(): RelationshipRecord[] {
		return Object.values(this.store.read<Record<string, RelationshipRecord>>("relationships", {}));
	}

	private relationship(id: string): RelationshipRecord {
		const r = this.store.read<Record<string, RelationshipRecord>>("relationships", {})[id];
		if (!r) throw new Error(`unknown relationship ${id}`);
		return r;
	}

	/** Local view of whether a relationship can still be used: not revoked and not expired. */
	relationshipUsable(r: RelationshipRecord): boolean {
		return r.state === "active" && !r.revoked_at && Date.parse(r.expires_at) > Date.now();
	}

	async readRelationship(id: string): Promise<{ http: number; body: any }> {
		const rel = this.relationship(id);
		const c = this.company(rel.issuer);
		const r = await this.call(c, "GET", `${c.endpoint}/relationships/${id}`);
		if (r.status === 200) this.store.update<Record<string, RelationshipRecord>, void>("relationships", {}, (all) => void (all[id] && (all[id].state = String(r.body.state ?? all[id].state))));
		return r;
	}

	/** DELETE /v1/relationships/{id} (R10). The local record is marked revoked whatever the company answers. */
	async revokeRelationship(id: string): Promise<{ http: number; body: any }> {
		const rel = this.relationship(id);
		const c = this.company(rel.issuer);
		this.store.update<Record<string, RelationshipRecord>, void>("relationships", {}, (all) => void (all[id] && ((all[id].state = "revoked"), (all[id].revoked_at = new Date().toISOString()))));
		return this.call(c, "DELETE", `${c.endpoint}/relationships/${id}`);
	}

	// ── Inbox: signed company requests (R7) ───────────────────────────────────────────────────

	inbox(): Inbox {
		return this.store.read<Inbox>("inbox", { messages: [], seen_jti: {}, rejected: [] });
	}

	message(id: string): InboxMessage {
		const m = this.inbox().messages.find((x) => x.id === id || x.content?.alert_id === id);
		if (!m) throw new Error(`unknown message ${id}`);
		return m;
	}

	private reject(status: number, reason: string) {
		this.store.update<Inbox, void>("inbox", { messages: [], seen_jti: {}, rejected: [] }, (ib) => {
			ib.rejected.push({ at: new Date().toISOString(), reason });
			ib.rejected = ib.rejected.slice(-200);
		});
		return { status, body: { error: reason } };
	}

	/**
	 * Handles a POST to the inbox: {"message": "<JWS vxp-company-request+jwt>"}. Accepts it only if it is
	 * signed by the relationship key anchored to a known issuer, addressed to this agent and this person,
	 * inside a relationship this agent holds and can still use, for an action in it, unexpired, and with
	 * a jti never seen before.
	 */
	async receive(body: unknown): Promise<{ status: number; body: unknown }> {
		const jws = (body as { message?: unknown })?.message;
		const d = typeof jws === "string" ? decodeJws(jws) : null;
		if (!d || d.header.typ !== "vxp-company-request+jwt") return this.reject(400, "malformed_message");
		const issuer = String(d.payload.iss ?? "");
		const c = this.companies().find((x) => x.issuer === issuer);
		if (!c) return this.reject(403, "unknown_issuer");
		let claims: Record<string, unknown> | null = null;
		try {
			claims = verifyJws(jws as string, await this.relationshipJwks(c), "vxp-company-request+jwt");
		} catch {
			return this.reject(503, "relationship_keys_unavailable");
		}
		if (!claims) return this.reject(401, "invalid_signature");
		const t = now();
		if (claims.aud !== this.id.client_id) return this.reject(403, "wrong_audience");
		if (claims.sub !== this.userIdFor(issuer)) return this.reject(403, "wrong_subject");
		if (typeof claims.exp !== "number" || claims.exp <= t - 30 || typeof claims.iat !== "number" || claims.iat > t + 60) return this.reject(401, "message_expired");
		if (typeof claims.jti !== "string" || !claims.jti) return this.reject(400, "missing_jti");
		const rel = this.relationships().find((r) => r.relationship_id === claims!.rel && r.issuer === issuer);
		if (!rel) return this.reject(403, "relationship_not_found");
		if (!this.relationshipUsable(rel)) return this.reject(403, rel.revoked_at || rel.state === "revoked" ? "relationship_revoked" : "relationship_expired");
		if (!rel.actions.includes(String(claims.action))) return this.reject(403, "action_not_authorized");
		const content = (claims.content ?? {}) as Record<string, any>;
		for (const k of ["reply_url", "request_url"]) if (content[k] !== undefined && !String(content[k]).startsWith(`${c.endpoint}/`)) return this.reject(400, `${k}_outside_endpoint`);
		if (content.request_id !== undefined || content.proposal_id !== undefined) {
			if (typeof content.request_id !== "string" || !SAFE_ID.test(content.request_id) || typeof content.proposal_id !== "string" || !SAFE_ID.test(content.proposal_id)) return this.reject(400, "malformed_identifiers");
			const prev = this.store.read<Record<string, RequestRecord>>("requests", {})[content.request_id];
			if (prev && prev.issuer !== issuer) return this.reject(409, "request_of_another_company");
		}
		const fresh = this.store.update<Inbox, boolean>("inbox", { messages: [], seen_jti: {}, rejected: [] }, (ib) => {
			for (const [k, exp] of Object.entries(ib.seen_jti)) if (exp < t - 86_400) delete ib.seen_jti[k];
			const key = `${issuer}|${claims!.jti}`;
			if (key in ib.seen_jti) return false;
			ib.seen_jti[key] = Number(claims!.exp);
			ib.messages.push({ id: `msg_${randomToken(9)}`, received_at: new Date().toISOString(), issuer, relationship_id: rel.relationship_id, action: String(claims!.action), content, jti: String(claims!.jti), expires_at: new Date(Number(claims!.exp) * 1000).toISOString(), status: "new" });
			return true;
		});
		if (!fresh) return this.reject(409, "replayed_jti");
		const msg = this.inbox().messages.at(-1)!;
		// A change the company proposes inside the relationship becomes a request the agent tracks (R8).
		if (typeof content.request_id === "string" && typeof content.proposal_id === "string") {
			this.record(c, { request_id: content.request_id, state: "proposed", proposal: { id: content.proposal_id, summary: content.summary } }, { operation: String(claims.action), target: {}, parameters: {}, idempotency_key: null, origin: "company" });
		}
		await this.applyReplyRule(msg).catch(() => {});
		return { status: 202, body: { received: msg.id } };
	}

	/** If the person set a standing answer for this kind of closed question, the agent gives it now. */
	private async applyReplyRule(m: InboxMessage) {
		if (!m.content.alert_id) return;
		const rule = this.store.read<Mandates>("mandates", { accept: [], replies: [] }).replies.find((x) => x.issuer === m.issuer && x.action === m.action);
		if (rule && (m.content.options ?? []).includes(rule.decision)) await this.sendReply(m, rule.decision, "reply_rule");
	}

	/**
	 * Answers a closed question (R17) with one of its options. Allowed when the person set a reply rule
	 * for it, or approved this exact answer (approval of kind «reply»); otherwise it returns an approval to show.
	 */
	async reply(messageId: string, decision: string): Promise<{ status: "replied"; http: number; body: any; receipt_verified: boolean } | { status: "needs_user_approval"; approval: Approval } | { status: "refused"; reason: string }> {
		const m = this.message(messageId);
		if (!m.content.alert_id) return { status: "refused", reason: "this message is not a closed question" };
		if (!(m.content.options ?? []).includes(decision)) return { status: "refused", reason: `«${decision}» is not one of ${JSON.stringify(m.content.options)}` };
		const rule = this.store.read<Mandates>("mandates", { accept: [], replies: [] }).replies.find((x) => x.issuer === m.issuer && x.action === m.action && x.decision === decision);
		const binding = sha256b64u(JSON.stringify({ message: m.id, alert: m.content.alert_id, decision }));
		const ok = rule ? "reply_rule" : this.approvals().find((a) => a.kind === "reply" && a.binding === binding && a.status === "approved") ? "user_approval" : null;
		if (!ok) {
			const approval = this.newApproval({ kind: "reply", issuer: m.issuer, message_id: m.id, decision, summary: `${this.company(m.issuer).name} asks: ${m.content.summary ?? m.action}. Answer: «${decision}».`, amount_clp: null, binding });
			return { status: "needs_user_approval", approval };
		}
		return { status: "replied", ...(await this.sendReply(m, decision, ok)) };
	}

	private async sendReply(m: InboxMessage, decision: string, source: string) {
		const c = this.company(m.issuer);
		const rel = this.relationship(m.relationship_id);
		if (!this.relationshipUsable(rel)) return { http: 0, body: { error: "relationship not usable locally (revoked or expired)" }, receipt_verified: false };
		const r = await this.call(c, "POST", String(m.content.reply_url), { alert_id: m.content.alert_id, decision });
		let verified = false;
		if (r.status === 200 && typeof r.body?.receipt === "string") {
			const claims = verifyJws(r.body.receipt, await this.relationshipJwks(c), "vxp-reply-receipt+jwt");
			verified = !!claims && claims.iss === c.issuer && claims.aud === this.id.client_id && claims.alert === m.content.alert_id && claims.decision === decision;
		}
		if (r.status === 200) {
			this.store.update<Inbox, void>("inbox", { messages: [], seen_jti: {}, rejected: [] }, (ib) => {
				const x = ib.messages.find((y) => y.id === m.id);
				if (x) {
					x.status = "answered";
					x.reply = { decision, at: new Date().toISOString(), receipt_verified: verified, source };
				}
			});
		}
		return { http: r.status, body: r.body, receipt_verified: verified };
	}

	// ── The person's rules: mandates (caps) and approvals of exact terms ──────────────────────

	mandates(): Mandates {
		return this.store.read<Mandates>("mandates", { accept: [], replies: [] });
	}

	/** Set by the person (CLI), never by the model: accept `operation` at `issuer` up to `maxTotalClp`. */
	setMandate(companyRef: string, operation: string, maxTotalClp: number, expiresAt: string | null = null, note?: string): Mandate {
		const c = this.company(companyRef);
		if (!Number.isInteger(maxTotalClp) || maxTotalClp <= 0) throw new Error("max_total_clp must be a positive integer");
		const m: Mandate = { issuer: c.issuer, operation, max_total_clp: maxTotalClp, expires_at: expiresAt, created_at: new Date().toISOString(), ...(note ? { note } : {}) };
		this.store.update<Mandates, void>("mandates", { accept: [], replies: [] }, (all) => {
			all.accept = all.accept.filter((x) => !(x.issuer === c.issuer && x.operation === operation));
			all.accept.push(m);
		});
		return m;
	}

	/** Set by the person (CLI): always answer this closed question with this option. */
	setReplyRule(companyRef: string, action: string, decision: string): ReplyRule {
		const c = this.company(companyRef);
		const r: ReplyRule = { issuer: c.issuer, action, decision, created_at: new Date().toISOString() };
		this.store.update<Mandates, void>("mandates", { accept: [], replies: [] }, (all) => {
			all.replies = all.replies.filter((x) => !(x.issuer === c.issuer && x.action === action));
			all.replies.push(r);
		});
		return r;
	}

	mandateFor(issuer: string, operation: string): Mandate | null {
		const m = this.mandates().accept.find((x) => x.issuer === issuer && x.operation === operation);
		return m && (!m.expires_at || Date.parse(m.expires_at) > Date.now()) ? m : null;
	}

	approvals(): Approval[] {
		return Object.values(this.store.read<Record<string, Approval>>("approvals", {}));
	}

	approval(id: string): Approval {
		const a = this.store.read<Record<string, Approval>>("approvals", {})[id];
		if (!a) throw new Error(`unknown approval ${id}`);
		return a;
	}

	/** The approval page, without any secret: opening it shows the terms; deciding needs the person's code. */
	approvalUrl(a: Approval): string | null {
		return this.approvalBaseUrl ? `${this.approvalBaseUrl}/${a.id}` : null;
	}

	publicApproval(a: Approval): PublicApproval {
		return { approval_id: a.id, kind: a.kind, summary: a.summary, amount_clp: a.amount_clp, approval_status: a.status, approval_url: this.approvalUrl(a) };
	}

	private newApproval(a: Omit<Approval, "id" | "secret" | "person_code" | "attempts" | "status" | "created_at">): Approval {
		const existing = this.approvals().find((x) => x.binding === a.binding && x.status === "pending");
		if (existing) return existing;
		const code = String(randomInt(0, 100_000_000)).padStart(8, "0");
		const full: Approval = { ...a, id: `apr_${randomToken(9)}`, secret: randomToken(18), person_code: code, attempts: 0, status: "pending", created_at: new Date().toISOString() };
		this.store.update<Record<string, Approval>, void>("approvals", {}, (all) => void (all[full.id] = full), true);
		return full;
	}

	/**
	 * The person's decision on an approval. Every path carries the person's proof: the CLI run in their own
	 * terminal, the code they type on the approval page (wrong codes count; after MAX_CODE_ATTEMPTS the
	 * approval is denied), or an MCP elicitation answered in the host's own UI.
	 */
	decide(id: string, approve: boolean, proof: ApprovalProof): Approval {
		const r = this.store.update<Record<string, Approval>, Approval | Error>("approvals", {}, (all) => {
			const a = all[id];
			if (!a) return new Error(`unknown approval ${id}`);
			if (a.status !== "pending") return a;
			if (proof.via === "page") {
				const ok = proof.code.length === a.person_code.length && timingSafeEqual(Buffer.from(proof.code), Buffer.from(a.person_code));
				if (!ok) {
					a.attempts += 1;
					if (a.attempts >= MAX_CODE_ATTEMPTS) {
						a.status = "denied";
						a.decided_at = new Date().toISOString();
						a.source = "too_many_wrong_codes";
					}
					return new Error("wrong person code");
				}
			} else if (proof.via !== "cli" && proof.via !== "elicitation") return new Error("no proof from the person");
			a.status = approve ? "approved" : "denied";
			a.decided_at = new Date().toISOString();
			a.source = proof.via === "page" ? "agent_approval_page" : proof.via === "cli" ? "cli" : "mcp_elicitation";
			return a;
		}, true);
		if (r instanceof Error) throw r;
		return r;
	}

	/**
	 * Accepts the current revision only within the person's rules:
	 * - a mandate for this company and operation whose cap the amount exceeds blocks it (no call is made);
	 * - an approval the person gave for THIS exact revision accepts it as `user`;
	 * - a mandate that covers the amount accepts it as `standing_permission`, if the company allows that
	 *   for this revision (user_approval_required: false);
	 * - otherwise it returns an approval for the person to decide.
	 */
	/**
	 * The person's rules on one revision, for any profile:
	 * - a mandate for this company and operation whose cap the amount exceeds blocks it;
	 * - an approval the person gave for THIS exact revision allows it as `user`;
	 * - a mandate that covers the amount allows it as `standing_permission`, if the company does not
	 *   require approval of this revision (user_approval_required: false);
	 * - otherwise it returns an approval for the person to decide.
	 */
	decideAcceptance(r: RevisionToAccept): AcceptanceDecision {
		const mandate = this.mandateFor(r.issuer, r.operation);
		const amount = r.amount_clp;
		if (mandate && (amount === null || amount > mandate.max_total_clp))
			return { status: "blocked_by_mandate", reason: amount === null ? "the terms state no amount to compare with the cap" : `total ${amount} CLP is above the cap of ${mandate.max_total_clp} CLP`, amount_clp: amount, mandate };
		const binding = bindingFor(r.proposal_id, r.summary, r.terms);
		if (this.approvals().some((a) => a.kind === "accept" && a.binding === binding && a.status === "approved")) return { status: "allowed", approved_by: "user" };
		if (mandate && r.user_approval_required === false) return { status: "allowed", approved_by: "standing_permission" };
		const approval = this.newApproval({ kind: "accept", issuer: r.issuer, ...(r.request_id ? { request_id: r.request_id } : {}), proposal_id: r.proposal_id, summary: r.summary, amount_clp: amount, binding });
		const reason = mandate ? "the company requires the person to approve this exact revision (user_approval_required: true); a cap is not enough" : "no cap set by the person for this operation";
		return { status: "needs_user_approval", approval, reason, mandate };
	}

	async accept(requestId: string): Promise<AcceptOutcome> {
		const rec = await this.refresh(requestId);
		const c = this.company(rec.issuer);
		const v = rec.view;
		if (v?.state !== "proposed" || !v.proposal?.id) throw new Error(`request ${requestId} has no proposal to accept (state ${v?.state})`);
		const d = this.decideAcceptance({ issuer: c.issuer, operation: rec.operation, request_id: rec.request_id, proposal_id: v.proposal.id, summary: String(v.proposal.summary ?? ""), terms: v.proposal.terms, user_approval_required: v.proposal.user_approval_required !== false, amount_clp: amountOf(v) });
		if (d.status !== "allowed") return d;
		const approvedBy = d.approved_by;
		const r = await this.call(c, "POST", `${c.endpoint}/proposals/${v.proposal.id}/accept`, { approved_by: approvedBy });
		if (r.body?.request_id) this.record(c, r.body, rec);
		if (r.status >= 400) return { status: "rejected_by_company", http: r.status, body: r.body };
		return { status: "accepted", approved_by: approvedBy, view: r.body };
	}

	// ── Proof ──────────────────────────────────────────────────────────────────────────────────

	/** Downloads the proof, gathers the public material from the anchored issuer and verifies it locally. */
	async proof(requestId: string): Promise<{ verdict: Verdict; package_file: string; material_file: string }> {
		const rec = await this.refresh(requestId);
		const c = this.company(rec.issuer);
		const r = await this.call(c, "GET", `${c.endpoint}/requests/${rec.request_id}/proof`);
		if (r.status !== 200) throw new VxpHttpError(`no proof yet (${r.status})`, r.status, r.body);
		const material = await collectMaterial(this.net, c.issuer, r.body);
		const operation = operationView(rec.view);
		const verdict = await verifyWithMaterial(r.body, material, { operation, aud: this.id.client_id });
		const package_file = this.store.saveFile(`${rec.request_id}.package.json`, r.body);
		const material_file = this.store.saveFile(`${rec.request_id}.material.json`, material);
		this.store.saveFile(`${rec.request_id}.operation.json`, operation);
		this.store.saveFile(`${rec.request_id}.verdict.json`, verdict);
		return { verdict, package_file, material_file };
	}

	/** Re-verifies a saved proof offline, with the material saved when it was fetched. */
	async verifySaved(requestId: string): Promise<Verdict> {
		const pkg = this.store.readFile(`${requestId}.package.json`);
		const material = this.store.readFile<Material>(`${requestId}.material.json`);
		if (!pkg || !material) throw new Error(`no saved proof for ${requestId}`);
		return verifyWithMaterial(pkg, material, { operation: this.store.readFile(`${requestId}.operation.json`) ?? undefined, aud: this.id.client_id });
	}
}

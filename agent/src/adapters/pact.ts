// Agent side of the optional PACT adapter (PACT 1.0 over A2A 1.0.1 HTTP+JSON, used as written: spec §8
// «Adapters», I1).
//
// Discovery from the Agent Card on the brand domain (PACT §2.1: served there or redirected to the Provider);
// the personal-agent JWT (PACT §3.2: `iss` = this agent's platform issuer, `aud` = the audience the Provider
// assigned at onboarding); delegated authority with the device code of the Card's `userDelegation` scheme
// (PACT §5); `message:send` with text parts only (PACT §4.1). Under PACT every write is approved by the person
// on the company's own channel (spec §6, «Approval through the company's channel»): the agent never confirms.
// VXP Proof travels in message metadata under the A2A extension URI, next to `pact.receipt`, which is kept as
// received; the proof is verified anchored by the PACT authorization server, with the receipt cross-checked.
//
// It reuses the agent's identity and the person's rules from agent.ts. The native profile does not import it.

import { SAFE_ID, type VxpAgent, amountOf } from "../agent.ts";
import { metadataUrlFor } from "../discovery.ts";
import { now, randomToken, signJwt } from "../jose.ts";
import { isUnder, VxpHttpError } from "../net.ts";
import { collectAdapterMaterial, verifyWithMaterial } from "../verify.ts";
import type { AdapterAccept, AdapterAuthorization, AdapterProof, AdapterTurn, ProfileAdapter } from "../adapters.ts";

export const PACT_PROOF_EXTENSION = "https://vxpprotocol.org/ext/proof/v0.1";
const OPERATION_KEY = "vxpprotocol.org/operation";
const DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";

export type PactCompany = {
	profile: "pact-1.0";
	domain: string;
	name: string;
	interface: string;
	deviceUrl: string;
	tokenUrl: string;
	asIssuer: string;
	scopes: Record<string, string>;
	/** The company issuer named by the proof extension's block (`params.company`). */
	companyIssuer: string;
};
type Delegation = { access_token: string; refresh_token: string | null; expires_at: number; scopes: string[]; token_url: string };
type Pending = { device_code: string; user_code: string; verification_uri_complete: string; expires_at: number; interval: number; last_poll: number };
type OperationRecord = { iface: string; operation: string | null; view: any; proof: { operation_id: string; latest: string; bundle_url: string } | null; proposal_receipt: { jws: string } | null; updated_at: string };
type PactState = {
	companies: Record<string, PactCompany>;
	delegations: Record<string, Delegation>;
	devices: Record<string, Pending>;
	contexts: Record<string, string>;
	operations: Record<string, OperationRecord>;
};
const EMPTY: PactState = { companies: {}, delegations: {}, devices: {}, contexts: {}, operations: {} };

export type PactOptions = {
	/** The audience string the Provider assigned to this agent at onboarding (PACT: it goes in `aud` verbatim). */
	audience: string;
};

export class PactAdapter implements ProfileAdapter {
	readonly profile = "pact-1.0" as const;
	private readonly agent: VxpAgent;
	private readonly audience: string;

	constructor(agent: VxpAgent, o: PactOptions) {
		this.agent = agent;
		this.audience = o.audience;
		agent.enableProfile("pact-1.0");
	}

	private state(): PactState {
		return this.agent.store.read<PactState>("pact", structuredClone(EMPTY));
	}
	private update<R>(fn: (s: PactState) => R): R {
		return this.agent.store.update<PactState, R>("pact", structuredClone(EMPTY), fn, true);
	}

	company(ref: string): PactCompany {
		const all = Object.values(this.state().companies);
		const c = all.find((x) => x.interface === ref) ?? all.find((x) => x.domain === ref.toLowerCase());
		if (!c) throw new Error(`unknown PACT company «${ref}»: detect it first`);
		return c;
	}

	/** Personal-agent JWT (PACT §3.2). `iss` is this agent's platform issuer, which the Provider registered. */
	private platformJwt(c: PactCompany): string {
		const k = this.agent.credentials();
		const t = now();
		return signJwt(k.signing, { typ: "JWT", kid: k.signing.publicJwk.kid }, { iss: k.origin, sub: this.agent.userIdFor(c.interface), aud: this.audience, iat: t, exp: t + 120, jti: randomToken(16) });
	}

	// ── Discovery (PACT §2) ──────────────────────────────────────────────────────────────────

	async detect(domain: string): Promise<PactCompany | null> {
		const net = this.agent.net;
		const d = domain.trim().toLowerCase();
		let r = await net.raw(`${net.originFor(d)}/.well-known/agent-card.json`).catch(() => null);
		// PACT §2.1: the brand domain serves the Card or redirects to the Provider's copy. One hop only.
		if (r && r.status >= 300 && r.status < 400) {
			const loc = r.headers.get("location");
			if (!loc) return null;
			r = await net.raw(net.check(new URL(loc, `${net.originFor(d)}/`).toString()).toString()).catch(() => null);
		}
		if (!r || r.status !== 200) return null;
		const card = JSON.parse(r.text);
		const iface = (card.supportedInterfaces ?? []).find((i: any) => i?.protocolBinding === "HTTP+JSON" && i?.protocolVersion === "1.0")?.url;
		const ext = (card.capabilities?.extensions ?? []).find((x: any) => x?.uri === PACT_PROOF_EXTENSION);
		const scheme = card.securitySchemes?.userDelegation?.oauth2SecurityScheme;
		const flow = scheme?.flows?.deviceCode;
		if (typeof iface !== "string" || !ext?.params || !flow || typeof scheme.oauth2MetadataUrl !== "string") return null;
		if (!((ext.params.domains ?? []) as string[]).map((x) => x.toLowerCase()).includes(d)) return null;
		for (const u of [iface, flow.deviceAuthorizationUrl, flow.tokenUrl, scheme.oauth2MetadataUrl]) net.check(u);
		const as = await net.doc(scheme.oauth2MetadataUrl);
		// The PACT authorization server carries an identical copy of the company's trust block (spec §10).
		if (typeof as.issuer !== "string" || as.vxp_proof?.company !== ext.params.company) return null;
		// The Card's endpoints must be the authorization server's own: its metadata is at the issuer's well-known
		// location (RFC 8414, or the issuer followed by the well-known suffix), and the device and token endpoints
		// are the ones it publishes, on the issuer's origin. A Card cannot point the agent's credentials elsewhere.
		const metaAt = [metadataUrlFor(as.issuer), `${as.issuer.replace(/\/$/, "")}/.well-known/oauth-authorization-server`];
		const origin = new URL(as.issuer).origin;
		if (!metaAt.includes(scheme.oauth2MetadataUrl) || as.token_endpoint !== flow.tokenUrl || as.device_authorization_endpoint !== flow.deviceAuthorizationUrl) return null;
		// The interface that will receive the delegation is on the authorization server's origin too.
		if (new URL(flow.tokenUrl).origin !== origin || new URL(flow.deviceAuthorizationUrl).origin !== origin || new URL(iface).origin !== origin) return null;
		const c: PactCompany = { profile: "pact-1.0", domain: d, name: String(card.name ?? d), interface: iface, deviceUrl: flow.deviceAuthorizationUrl, tokenUrl: flow.tokenUrl, asIssuer: as.issuer, scopes: flow.scopes ?? {}, companyIssuer: String(ext.params.company) };
		// A company already known under this interface keeps its endpoints: another Card cannot rewrite them.
		const prev = this.state().companies[iface];
		if (prev && (prev.domain !== c.domain || prev.tokenUrl !== c.tokenUrl || prev.deviceUrl !== c.deviceUrl || prev.asIssuer !== c.asIssuer || prev.companyIssuer !== c.companyIssuer)) return null;
		this.update((s) => void (s.companies[iface] = c));
		return c;
	}

	// ── Delegated authority (PACT §5) ────────────────────────────────────────────────────────

	private oauth(c: PactCompany, url: string, form: Record<string, string>) {
		return this.agent.net.json(url, { method: "POST", headers: { authorization: `Bearer ${this.platformJwt(c)}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: this.agent.credentials().origin, ...form }).toString() });
	}

	private saveDelegation(c: PactCompany, body: any) {
		const del: Delegation = { access_token: String(body.access_token), refresh_token: body.refresh_token ? String(body.refresh_token) : null, expires_at: now() + Number(body.expires_in ?? 300), scopes: String(body.scope ?? "").split(" ").filter(Boolean), token_url: c.tokenUrl };
		this.update((s) => void (s.delegations[c.interface] = del));
		return del;
	}

	/** The delegation token, refreshed (and rotated, PACT §5) when it has expired. Null without a delegation. */
	private async delegation(c: PactCompany): Promise<string | null> {
		const del = this.state().delegations[c.interface];
		// A delegation is only ever used with, or refreshed at, the token endpoint that issued it.
		if (!del || del.token_url !== c.tokenUrl) return null;
		if (del.expires_at - 30 > now()) return del.access_token;
		if (!del.refresh_token) return null;
		const r = await this.oauth(c, c.tokenUrl, { grant_type: "refresh_token", refresh_token: del.refresh_token });
		if (r.status !== 200) {
			this.update((s) => void delete s.delegations[c.interface]);
			return null;
		}
		return this.saveDelegation(c, r.body).access_token;
	}

	async authorize(ref: string, scopes: string[]): Promise<AdapterAuthorization> {
		const c = this.company(ref);
		const bad = scopes.filter((x) => !(x in c.scopes));
		if (bad.length) throw new Error(`the company does not publish these scopes: ${bad.join(", ")}`);
		const r = await this.oauth(c, c.deviceUrl, { scope: scopes.join(" ") });
		if (r.status !== 200) throw new VxpHttpError(`device authorization refused: ${JSON.stringify(r.body)}`, r.status, r.body);
		const complete = String(r.body.verification_uri_complete ?? `${r.body.verification_uri}?user_code=${r.body.user_code}`);
		// The person is sent to the company's own sign-in page: the company's issuer origin.
		if (new URL(complete).origin !== new URL(c.companyIssuer).origin) throw new Error(`refused: verification page ${complete} is not on the company's origin`);
		const p: Pending = { device_code: String(r.body.device_code), user_code: String(r.body.user_code), verification_uri_complete: complete, expires_at: now() + Number(r.body.expires_in ?? 600), interval: Number(r.body.interval ?? 5), last_poll: 0 };
		this.update((s) => void (s.devices[c.interface] = p));
		return { company: c.name, verification_uri_complete: complete, user_code: p.user_code, expires_at: new Date(p.expires_at * 1000).toISOString(), scopes };
	}

	async pollAuthorization(ref: string, waitSeconds = 0) {
		const c = this.company(ref);
		const deadline = Date.now() + waitSeconds * 1000;
		for (;;) {
			const p = this.state().devices[c.interface];
			if (!p) return { status: "none" as const };
			if (p.expires_at < now()) return { status: "expired_token" as const };
			const wait = p.last_poll + p.interval * 1000 - Date.now();
			if (wait > 0) {
				if (Date.now() + wait > deadline) return { status: "authorization_pending" as const };
				await new Promise((ok) => setTimeout(ok, wait));
			}
			this.update((s) => void (s.devices[c.interface] && (s.devices[c.interface].last_poll = Date.now())));
			const r = await this.oauth(c, c.tokenUrl, { grant_type: DEVICE_CODE, device_code: p.device_code });
			if (r.status === 200) {
				const del = this.saveDelegation(c, r.body);
				this.update((s) => void delete s.devices[c.interface]);
				return { status: "granted" as const, scopes: del.scopes };
			}
			const err = r.body?.error;
			if (err === "slow_down") this.update((s) => void (s.devices[c.interface] && (s.devices[c.interface].interval += 5)));
			else if (err !== "authorization_pending") {
				this.update((s) => void delete s.devices[c.interface]);
				return { status: err === "access_denied" ? ("access_denied" as const) : ("expired_token" as const) };
			}
			if (Date.now() >= deadline) return { status: "authorization_pending" as const };
		}
	}

	// ── Messages (A2A 1.0.1 message:send, text parts only) ──────────────────────────────────

	private async headers(c: PactCompany): Promise<Record<string, string>> {
		const del = await this.delegation(c);
		return { authorization: `Bearer ${this.platformJwt(c)}`, ...(del ? { "x-a2a-user-delegation": `Bearer ${del}` } : {}) };
	}

	private keep(c: PactCompany, view: any, meta: any, receipt: any, operation: string | null) {
		if (typeof view?.operation_id !== "string" || !SAFE_ID.test(view.operation_id)) throw new Error("the company returned an operation id with an unexpected shape");
		if (meta && (meta.operation_id !== view.operation_id || !isUnder(String(meta.bundle_url ?? ""), c.interface))) throw new Error("the proof metadata does not match the operation or is not under the interface");
		this.update((s) => {
			const prev = s.operations[view.operation_id];
			if (prev && prev.iface !== c.interface) throw new Error(`operation ${view.operation_id} belongs to another company`);
			// The receipt of the turn that proposed the operation is the one its proof's `request` cites (spec §6).
			const proposing = prev?.proposal_receipt ?? (view.state === "proposed" && typeof receipt?.jws === "string" ? { jws: receipt.jws } : null);
			s.operations[view.operation_id] = { iface: c.interface, operation: operation ?? prev?.operation ?? null, view, proof: meta ?? prev?.proof ?? null, proposal_receipt: proposing, updated_at: new Date().toISOString() };
		});
	}

	async say(ref: string, text: string, o: { operation?: string } = {}): Promise<AdapterTurn> {
		const c = this.company(ref);
		const contextId = this.state().contexts[c.interface];
		const url = `${c.interface}/message:send`;
		const body = { message: { messageId: `m-${randomToken(12)}`, role: "ROLE_USER", parts: [{ text }], ...(contextId ? { contextId } : {}) } };
		const r = await this.agent.net.json(url, { method: "POST", headers: { ...(await this.headers(c)), "content-type": "application/json", "a2a-version": "1.0", "a2a-extensions": PACT_PROOF_EXTENSION }, body: JSON.stringify(body) });
		if (r.status !== 200) throw new VxpHttpError(`A2A message:send: ${r.status} ${JSON.stringify(r.body)}`, r.status, r.body);
		const msg = r.body.message ?? r.body.task?.status?.message;
		const ctx = r.body.message?.contextId ?? r.body.task?.contextId;
		if (typeof ctx === "string") this.update((s) => void (s.contexts[c.interface] = ctx));
		const turn: AdapterTurn = { conversation: String(ctx ?? ""), texts: [], data: [], operation: null, authorization: null };
		for (const p of (msg?.parts ?? []) as any[]) {
			if (typeof p?.text === "string") turn.texts.push(p.text);
			if (p?.data) turn.data.push(p.data);
		}
		if (r.body.task?.status?.state === "TASK_STATE_AUTH_REQUIRED") turn.authorization = { error: "auth_required", scopes: (r.body.task.metadata?.["pact.missingScopes"] ?? []) as string[] };
		const meta = r.body.message?.metadata ?? {};
		if (meta[OPERATION_KEY]) {
			this.keep(c, meta[OPERATION_KEY], meta[PACT_PROOF_EXTENSION] ?? null, meta["pact.receipt"] ?? null, o.operation ?? null);
			turn.operation = meta[OPERATION_KEY];
		}
		return turn;
	}

	/** PACT has no task read here: the agent asks in the same context, and the company answers with the operation. */
	async status(ref: string, operationId: string): Promise<any> {
		const c = this.company(ref);
		const rec = this.state().operations[operationId];
		if (!rec || rec.iface !== c.interface) throw new Error(`unknown operation ${operationId}`);
		const t = await this.say(c.interface, "¿Cómo va el estado de la operación?");
		if (t.operation?.operation_id !== operationId) throw new Error("the company did not report this operation");
		return t.operation;
	}

	/**
	 * Under PACT the agent never confirms a write: the company asked the person on its own channel, with a
	 * code bound to the exact revision. The person's cap still applies: above it, the agent says so.
	 */
	async accept(ref: string, operationId: string): Promise<AdapterAccept> {
		const c = this.company(ref);
		const rec = this.state().operations[operationId];
		if (!rec || rec.iface !== c.interface) throw new Error(`unknown operation ${operationId}`);
		const v = rec.view;
		const amount = amountOf({ proposal: { terms: v.terms } });
		const mandate = rec.operation ? this.agent.mandateFor(c.companyIssuer, rec.operation) : null;
		if (mandate && (amount === null || amount > mandate.max_total_clp))
			return { status: "blocked_by_mandate", reason: `total ${amount} CLP is above the person's cap of ${mandate.max_total_clp} CLP: tell the person not to approve it on the company's channel`, amount_clp: amount, mandate };
		return { status: "awaiting_company_channel", reason: "Under PACT the person approves this exact revision on the company's own channel (the company sent them a code); the agent cannot confirm it.", operation_id: operationId, summary: String(v.summary ?? "") };
	}

	/** Downloads the package (agent JWT + delegation) and verifies it anchored by the PACT authorization server, cross-checking the PACT receipt. */
	async proof(ref: string, operationId: string): Promise<AdapterProof> {
		const c = this.company(ref);
		const view = await this.status(c.interface, operationId);
		const rec = this.state().operations[operationId];
		const url = rec?.proof?.bundle_url;
		if (!url) throw new Error("the operation carries no proof metadata");
		const r = await this.agent.net.json(url, { headers: await this.headers(c) });
		if (r.status !== 200) throw new VxpHttpError(`proof: ${r.status}`, r.status, r.body);
		const material = await collectAdapterMaterial(this.agent.net, { pact_issuer: c.asIssuer }, r.body);
		const verdict = await verifyWithMaterial(r.body, material, { operation: view, aud: this.agent.credentials().origin, receipt: rec.proposal_receipt ?? undefined });
		const base = `pact-${operationId}`;
		const package_file = this.agent.store.saveFile(`${base}.package.json`, r.body);
		const material_file = this.agent.store.saveFile(`${base}.material.json`, material);
		this.agent.store.saveFile(`${base}.operation.json`, view);
		if (rec.proposal_receipt) this.agent.store.saveFile(`${base}.receipt.json`, rec.proposal_receipt);
		this.agent.store.saveFile(`${base}.verdict.json`, verdict);
		return { verdict, package_file, material_file };
	}
}

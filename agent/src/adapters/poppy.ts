// Agent side of the optional Poppy adapter (Poppy draft 0.2, used as written: spec §8 «Adapters», I1).
//
// Discovery from /.well-known/poppy.json; the agent's session (RFC 7523 assertion, private_key_jwt, DPoP);
// Device Sign-In with scopes; the conversation (Poppy §7), where the company's agent turns text into
// proposals; the Operations extension, where the agent confirms one exact revision; and VXP Proof in the
// domain-named member `vxpprotocol.org/proof` of each operation, verified anchored by the Poppy domain.
//
// It reuses the agent's identity and the person's rules from agent.ts. The native profile does not import it.

import { type AcceptOutcome, SAFE_ID, type VxpAgent, amountOf } from "../agent.ts";
import { metadataUrlFor } from "../discovery.ts";
import { assertion, dpopProof, now, randomToken } from "../jose.ts";
import { isUnder, VxpHttpError } from "../net.ts";
import { collectAdapterMaterial, verifyWithMaterial } from "../verify.ts";
import type { AdapterAuthorization, AdapterProof, AdapterTurn, ProfileAdapter } from "../adapters.ts";

export const POPPY_PROOF_EXTENSION = "vxpprotocol.org/proof";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
const CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export type PoppyCompany = {
	profile: "poppy-0.2";
	domain: string;
	name: string;
	issuer: string;
	tokenEndpoint: string;
	deviceEndpoint: string;
	conversations: string;
	operations: string;
	scopes: Record<string, string>;
	/** The company's VXP Proof block in poppy.json, if it offers the extension. */
	proof: Record<string, unknown> | null;
};
type Session = { session_id: string; access_token: string; expires_at: number; signed_in: boolean; scope: string; refresh_token?: string };
type Pending = { device_code: string; user_code: string; verification_uri_complete: string; expires_at: number; interval: number; last_poll: number };
type OperationRecord = { issuer: string; operation: string | null; view: any; updated_at: string };
type PoppyState = {
	companies: Record<string, PoppyCompany>;
	sessions: Record<string, Session>;
	devices: Record<string, Pending>;
	conversations: Record<string, { id: string; cursor: string | null }>;
	operations: Record<string, OperationRecord>;
};
const EMPTY: PoppyState = { companies: {}, sessions: {}, devices: {}, conversations: {}, operations: {} };

export class PoppyAdapter implements ProfileAdapter {
	readonly profile = "poppy-0.2" as const;
	private readonly agent: VxpAgent;

	constructor(agent: VxpAgent) {
		this.agent = agent;
		// Poppy only hands operations to an agent that declares the Operations extension in its client metadata.
		agent.enableProfile("poppy-0.2");
	}

	private state(): PoppyState {
		return this.agent.store.read<PoppyState>("poppy", structuredClone(EMPTY));
	}
	private update<R>(fn: (s: PoppyState) => R): R {
		return this.agent.store.update<PoppyState, R>("poppy", structuredClone(EMPTY), fn, true);
	}

	company(ref: string): PoppyCompany {
		const all = Object.values(this.state().companies);
		const c = all.find((x) => x.issuer === ref) ?? all.find((x) => x.domain === ref.toLowerCase());
		if (!c) throw new Error(`unknown Poppy company «${ref}»: detect it first`);
		return c;
	}

	// ── Discovery (Poppy §3) ───────────────────────────────────────────────────────────────

	async detect(domain: string): Promise<PoppyCompany | null> {
		const net = this.agent.net;
		const d = domain.trim().toLowerCase();
		const r = await net.json(`${net.originFor(d)}/.well-known/poppy.json`).catch(() => null);
		if (!r || r.status !== 200 || !r.body || typeof r.body !== "object") return null;
		const doc = r.body;
		if (doc.protocol_version !== "0.2" || String(doc.organization?.domain ?? "").toLowerCase() !== d || typeof doc.auth?.issuer !== "string") return null;
		const issuer: string = doc.auth.issuer;
		const meta = await net.doc(metadataUrlFor(issuer));
		// Poppy §3: the issuer's metadata names the domains that may speak for it.
		if (meta.issuer !== issuer || !((meta.poppy_domains ?? []) as string[]).map((x) => x.toLowerCase()).includes(d)) return null;
		const conversations = (doc.agent?.protocols ?? []).find((p: { type?: string }) => p?.type === "poppy")?.endpoint;
		const operations = doc.extensions?.operations?.endpoint;
		if (typeof conversations !== "string" || typeof operations !== "string") return null;
		for (const u of [meta.token_endpoint, meta.device_authorization_endpoint, conversations, operations]) net.check(u);
		const c: PoppyCompany = {
			profile: "poppy-0.2",
			domain: d,
			name: String(doc.organization?.name ?? d),
			issuer,
			tokenEndpoint: meta.token_endpoint,
			deviceEndpoint: meta.device_authorization_endpoint,
			conversations,
			operations,
			scopes: doc.auth?.custom_scopes ?? {},
			proof: doc.extensions?.[POPPY_PROOF_EXTENSION] ?? null,
		};
		this.update((s) => void (s.companies[issuer] = c));
		return c;
	}

	// ── Session and Device Sign-In (Poppy §4) ───────────────────────────────────────────────

	private clientAuth(c: PoppyCompany) {
		const k = this.agent.credentials();
		return { client_id: k.clientId, client_assertion_type: CLIENT_ASSERTION, client_assertion: assertion(k.signing, k.clientId, k.clientId, c.issuer) };
	}

	private tokenRequest(c: PoppyCompany, form: Record<string, string>) {
		const k = this.agent.credentials();
		return this.agent.net.json(c.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: dpopProof(k.dpop, "POST", c.tokenEndpoint) }, body: new URLSearchParams({ ...form, ...this.clientAuth(c) }).toString() });
	}

	private saveSession(c: PoppyCompany, body: any, keepRefresh?: string) {
		const s: Session = { session_id: String(body.session_id), access_token: String(body.access_token), expires_at: now() + Number(body.expires_in ?? 300), signed_in: body.signed_in === true, scope: String(body.scope ?? ""), ...(body.refresh_token ? { refresh_token: String(body.refresh_token) } : keepRefresh ? { refresh_token: keepRefresh } : {}) };
		this.update((st) => void (st.sessions[c.issuer] = s));
		return s;
	}

	/** A live Session Token: the stored one; else the account token (refresh); else a new signed-out session. */
	private async token(c: PoppyCompany): Promise<string> {
		const s = this.state().sessions[c.issuer];
		if (s && s.expires_at - 30 > now()) return s.access_token;
		if (s?.refresh_token) {
			const r = await this.tokenRequest(c, { grant_type: "refresh_token", refresh_token: s.refresh_token, session_id: s.session_id });
			if (r.status === 200) return this.saveSession(c, r.body, s.refresh_token).access_token;
		}
		const k = this.agent.credentials();
		const r = await this.tokenRequest(c, { grant_type: JWT_BEARER, assertion: assertion(k.signing, k.clientId, this.agent.userIdFor(c.issuer), c.issuer), ...(s?.session_id ? { session_id: s.session_id } : {}) });
		if (r.status !== 200) throw new VxpHttpError(`Poppy session refused: ${JSON.stringify(r.body)}`, r.status, r.body);
		return this.saveSession(c, r.body).access_token;
	}

	async authorize(ref: string, scopes: string[]): Promise<AdapterAuthorization> {
		const c = this.company(ref);
		const bad = scopes.filter((x) => !(x in c.scopes));
		if (bad.length) throw new Error(`the company does not publish these scopes: ${bad.join(", ")}`);
		await this.token(c); // the device code is bound to this session (Poppy §4.6)
		const r = await this.agent.net.json(c.deviceEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ scope: scopes.join(" "), ...this.clientAuth(c) }).toString() });
		if (r.status !== 200) throw new VxpHttpError(`device sign-in refused: ${JSON.stringify(r.body)}`, r.status, r.body);
		const complete = String(r.body.verification_uri_complete ?? `${r.body.verification_uri}?user_code=${r.body.user_code}`);
		if (new URL(complete).origin !== new URL(c.issuer).origin) throw new Error(`refused: verification page ${complete} is not on the issuer's origin`);
		const p: Pending = { device_code: String(r.body.device_code), user_code: String(r.body.user_code), verification_uri_complete: complete, expires_at: now() + Number(r.body.expires_in ?? 600), interval: Number(r.body.interval ?? 5), last_poll: 0 };
		this.update((s) => void (s.devices[c.issuer] = p));
		return { company: c.name, verification_uri_complete: complete, user_code: p.user_code, expires_at: new Date(p.expires_at * 1000).toISOString(), scopes };
	}

	async pollAuthorization(ref: string, waitSeconds = 0) {
		const c = this.company(ref);
		const deadline = Date.now() + waitSeconds * 1000;
		for (;;) {
			const st = this.state();
			const p = st.devices[c.issuer];
			const session = st.sessions[c.issuer];
			if (!p || !session) return { status: "none" as const };
			if (p.expires_at < now()) return { status: "expired_token" as const };
			const wait = p.last_poll + p.interval * 1000 - Date.now();
			if (wait > 0) {
				if (Date.now() + wait > deadline) return { status: "authorization_pending" as const };
				await new Promise((ok) => setTimeout(ok, wait));
			}
			this.update((s) => void (s.devices[c.issuer] && (s.devices[c.issuer].last_poll = Date.now())));
			const r = await this.tokenRequest(c, { grant_type: DEVICE_CODE, device_code: p.device_code, session_id: session.session_id });
			if (r.status === 200) {
				const s = this.saveSession(c, r.body);
				this.update((x) => void delete x.devices[c.issuer]);
				return { status: "granted" as const, scopes: s.scope.split(" ").filter(Boolean) };
			}
			const err = r.body?.error;
			if (err === "slow_down") this.update((s) => void (s.devices[c.issuer] && (s.devices[c.issuer].interval += 5)));
			else if (err !== "authorization_pending") {
				this.update((x) => void delete x.devices[c.issuer]);
				return { status: err === "access_denied" ? ("access_denied" as const) : ("expired_token" as const) };
			}
			if (Date.now() >= deadline) return { status: "authorization_pending" as const };
		}
	}

	// ── Calls with the Session Token ─────────────────────────────────────────────────────────

	private async call(c: PoppyCompany, method: string, url: string, body?: unknown): Promise<{ status: number; body: any }> {
		if (!isUnder(url, c.issuer)) throw new Error(`refused: ${url} is not under ${c.issuer}`);
		const k = this.agent.credentials();
		for (let i = 0; i < 2; i++) {
			const t = await this.token(c);
			const u = new URL(url);
			const r = await this.agent.net.json(url, { method, headers: { authorization: `DPoP ${t}`, dpop: dpopProof(k.dpop, method, `${u.origin}${u.pathname}`, t), "content-type": "application/json", accept: "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
			if (r.status === 401 && i === 0) {
				this.update((s) => void (s.sessions[c.issuer] && (s.sessions[c.issuer].expires_at = 0)));
				continue;
			}
			return { status: r.status, body: r.body };
		}
		throw new Error("unreachable");
	}

	private keepOperation(c: PoppyCompany, view: any, operation: string | null) {
		if (typeof view?.operation_id !== "string" || !SAFE_ID.test(view.operation_id)) throw new Error("the company returned an operation id with an unexpected shape");
		const member = view[POPPY_PROOF_EXTENSION];
		if (member?.bundle_url !== undefined && !isUnder(String(member.bundle_url), c.issuer)) throw new Error("the proof bundle_url is not under the company's issuer");
		this.update((s) => {
			const prev = s.operations[view.operation_id];
			if (prev && prev.issuer !== c.issuer) throw new Error(`operation ${view.operation_id} belongs to another company`);
			s.operations[view.operation_id] = { issuer: c.issuer, operation: operation ?? prev?.operation ?? null, view, updated_at: new Date().toISOString() };
		});
	}

	/**
	 * One message in the company's conversation (Poppy §7). The company's agent answers in text and may
	 * propose an operation; `operation` names the capability the agent is asking for (it keys the person's
	 * cap). A message never approves anything.
	 */
	async say(ref: string, text: string, o: { operation?: string } = {}): Promise<AdapterTurn> {
		const c = this.company(ref);
		const message = { id: `msg_${randomToken(9)}`, sender: "agent", text };
		let conv = this.state().conversations[c.issuer];
		let r = conv ? await this.call(c, "POST", `${c.conversations}/${conv.id}/messages?wait=0${conv.cursor ? `&cursor=${encodeURIComponent(conv.cursor)}` : ""}`, { message }) : null;
		if (!r || r.status === 404 || r.status === 409) {
			r = await this.call(c, "POST", `${c.conversations}?wait=0`, { message });
			conv = undefined;
		}
		if (r.status >= 400) throw new VxpHttpError(`Poppy conversation: ${r.status} ${JSON.stringify(r.body)}`, r.status, r.body);
		const id = String(r.body.conversation_id);
		if (!SAFE_ID.test(id)) throw new Error("the company returned a conversation id with an unexpected shape");
		this.update((s) => void (s.conversations[c.issuer] = { id, cursor: r!.body.cursor ?? conv?.cursor ?? null }));
		const turn: AdapterTurn = { conversation: id, texts: [], data: [], operation: null, authorization: null };
		for (const ev of (r.body.events ?? []) as any[]) {
			if (ev.type === "authorization") turn.authorization = { error: String(ev.error), scopes: String(ev.scope ?? "").split(" ").filter(Boolean) };
			if (ev.type !== "message" || ev.message?.role !== "company") continue;
			if (typeof ev.message.text === "string") turn.texts.push(ev.message.text);
			if (ev.message.data) turn.data.push(ev.message.data);
			if (ev.message.operation) {
				this.keepOperation(c, ev.message.operation, o.operation ?? null);
				turn.operation = ev.message.operation;
			}
		}
		return turn;
	}

	async status(ref: string, operationId: string): Promise<any> {
		const c = this.company(ref);
		if (!SAFE_ID.test(operationId)) throw new Error("bad operation id");
		const r = await this.call(c, "GET", `${c.operations}/${operationId}`);
		if (r.status !== 200) throw new VxpHttpError(`operation ${operationId}: ${r.status}`, r.status, r.body);
		this.keepOperation(c, r.body, null);
		return r.body;
	}

	/** Confirms the current revision (Operations `confirm`) only within the person's rules (agent.decideAcceptance). */
	async accept(ref: string, operationId: string): Promise<AcceptOutcome> {
		const c = this.company(ref);
		const v = await this.status(c.issuer, operationId);
		if (v.state !== "proposed") throw new Error(`operation ${operationId} is not proposed (state ${v.state})`);
		const rec = this.state().operations[operationId];
		const d = this.agent.decideAcceptance({ issuer: c.issuer, operation: rec?.operation ?? "unknown", proposal_id: `poppy:${operationId}:r${v.revision}`, summary: String(v.summary ?? ""), terms: v.terms, user_approval_required: v.user_approval_required !== false, amount_clp: amountOf({ proposal: { terms: v.terms } }) });
		if (d.status !== "allowed") return d;
		const r = await this.call(c, "POST", `${c.operations}/${operationId}/confirm`, { revision: v.revision, approved_by: d.approved_by });
		if (r.status >= 400) return { status: "rejected_by_company", http: r.status, body: r.body };
		this.keepOperation(c, r.body, null);
		return { status: "accepted", approved_by: d.approved_by, view: r.body };
	}

	/** Downloads the package from the operation's `vxpprotocol.org/proof` member and verifies it anchored by the Poppy domain. */
	async proof(ref: string, operationId: string): Promise<AdapterProof> {
		const c = this.company(ref);
		const v = await this.status(c.issuer, operationId);
		const url = v[POPPY_PROOF_EXTENSION]?.bundle_url;
		if (typeof url !== "string") throw new Error("the operation carries no proof member (does the agent list the extension?)");
		const r = await this.call(c, "GET", url);
		if (r.status !== 200) throw new VxpHttpError(`proof: ${r.status}`, r.status, r.body);
		const material = await collectAdapterMaterial(this.agent.net, { domain: c.domain }, r.body);
		const { [POPPY_PROOF_EXTENSION]: _member, ...operation } = v;
		const verdict = await verifyWithMaterial(r.body, material, { operation, aud: this.agent.clientId });
		const base = `poppy-${operationId}`;
		const package_file = this.agent.store.saveFile(`${base}.package.json`, r.body);
		const material_file = this.agent.store.saveFile(`${base}.material.json`, material);
		this.agent.store.saveFile(`${base}.operation.json`, operation);
		this.agent.store.saveFile(`${base}.verdict.json`, verdict);
		return { verdict, package_file, material_file };
	}
}

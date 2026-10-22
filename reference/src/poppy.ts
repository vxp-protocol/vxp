// Poppy face (Personal Agent Protocol, draft 0.2) over the core.
//
// SOVRAS hosts many companies, so each one has its own issuer
// (`https://auth.sovras…/e/<slug>`, Poppy 3.2) and its `poppy.json` is served on a subdomain the
// company points at SOVRAS. One company's user IDs, sessions and tokens are not valid at another.

import { responder } from "./agente.ts";
import type { Delegaciones, Directorio } from "./identidad.ts";
import { type Decoded, type Jwk, ahora, decodeJwt, publicOnly, randomId, sha256, thumbprint, verifyWith } from "./jose.ts";
import type { ActorExterno, Empresa, Nucleo, Operacion } from "./nucleo.ts";
import { VERSION_PRUEBA, bloqueConfianza, bloqueOutcomeProof } from "./prueba.ts";
import { sondeo } from "./vincular.ts";
import { mutado } from "./mutar.ts";

/** Own-domain extension (Poppy §3.3: «MUST start an extension's name with a domain»). */
export const EXT_PRUEBA = "vxpprotocol.org/proof";

/**
 * The agent lists the extension with the version this company speaks (Poppy §3.3: `version` is the
 * major one and an incompatible change brings another; SPEC §4.2.1). Any other version counts as not listing it.
 */
const listaPrueba = (doc: { extensions?: Record<string, { version?: unknown } | undefined> } | null | undefined) =>
	doc?.extensions?.[EXT_PRUEBA]?.version === VERSION_PRUEBA;

type Sesion = {
	id: string;
	tenantId: string;
	clientId: string;
	sub: string;
	/** Account it was ever linked to: it cannot switch to another (Poppy 4.4). */
	cuenta: string | null;
	grantId: string | null;
};

type SessionToken = { tenantId: string; sessionId: string; jkt: string; exp: number; alcances: string[]; grantId: string | null };

type Conv = {
	id: string;
	tenantId: string;
	clientId: string;
	sub: string;
	cuenta: string | null;
	caseId: string;
	status: "working" | "idle" | "queued" | "closed";
	responder: "agent" | "human";
	events: Record<string, unknown>[];
	primeraRespuesta: string;
	ops: boolean;
	/** The agent lists the outcome-proof extension: only such an agent is sent the member. */
	prueba: boolean;
};

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	new Response(body === null ? null : JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});
const noStore = { "cache-control": "no-store", pragma: "no-cache" };
const ID = /^[A-Za-z0-9_-]{1,256}$/;

/** What the Poppy conversation asks of VXP Relationship: answer an alert or offer the agreement. */
export type PuenteRelacion = {
	responder(a: ActorExterno, texto: string, datos?: Record<string, unknown>): RespuestaRelacion | null;
	ofrecer(a: ActorExterno, convId: string, texto: string): RespuestaRelacion | null;
};
export type RespuestaRelacion = { text: string; data?: Record<string, unknown>; necesita?: "sign_in" };

export class CaraPoppy {
	private readonly sesiones = new Map<string, Sesion>();
	private readonly tokens = new Map<string, SessionToken>();
	private readonly convs = new Map<string, Conv>();
	private readonly mensajes = new Map<string, { conv: string; contenido: string }>();
	private readonly jtiVistos = new Map<string, number>();
	private seq = 0;

	private readonly nucleo: Nucleo;
	private readonly dir: Directorio;
	private readonly del: Delegaciones;
	private readonly authOrigin: string;

	constructor(nucleo: Nucleo, dir: Directorio, del: Delegaciones, authOrigin: string) {
		this.nucleo = nucleo;
		this.dir = dir;
		this.del = del;
		this.authOrigin = authOrigin;
	}

	/** Access log: which agent and user a Session Token belongs to (without consuming anything). */
	quienToken(valor: string): { clientId: string; sub: string } | null {
		const t = this.tokens.get(valor);
		const s = t ? this.sesiones.get(t.sessionId) : undefined;
		return s ? { clientId: s.clientId, sub: s.sub } : null;
	}

	issuer(e: Empresa) {
		return `${this.authOrigin}/e/${e.slug}`;
	}

	// ── Discovery (Poppy 3) ───────────────────────────────────────────────────────────────────

	poppyJson(e: Empresa) {
		const base = this.issuer(e);
		return {
			protocol_version: "0.2",
			organization: { name: e.nombre, domain: e.dominio },
			auth: {
				issuer: base,
				// Device Sign-In only: sign-in is «Vincular con WhatsApp». No `mediated`:
				// passwords are never received from an agent.
				device: { scopes: Object.keys(e.alcances) },
				custom_scopes: e.alcances,
			},
			agent: { protocols: [{ type: "poppy", endpoint: `${base}/poppy/conversaciones` }] },
			feedback: { endpoint: `${base}/poppy/feedback` },
			extensions: {
				operations: { version: "1", endpoint: `${base}/poppy/operaciones` },
				// Outcome proof (SPEC §12.1). Under Poppy the user's approval is asserted by the agent
				// (`approved_by: "user"`), so `operator_reported_channel_approval` is not promised.
				[EXT_PRUEBA]: bloqueOutcomeProof({
					issuer: base,
					authOrigin: this.authOrigin,
					operadorIssuer: this.nucleo.pruebas?.operadorIssuer ?? "",
					origenRegistro: this.nucleo.pruebas?.origenRegistro ?? "",
					vinculos: this.nucleo.pruebas?.vinculos(e.tenantId),
					capacidades: e.release.capacidades
						.filter((c) => c.efecto === "write")
						.map((c) => ({ name: c.id, effect: c.efecto, aprobacion: "operator_reported_agent_approval" as const })),
					canales: [],
				}),
			},
		};
	}

	/**
	 * The operation as the agent sees it. If it lists the extension, it carries the domain member
	 * (SPEC §12.1.2): the latest statement and where to request the package. It is not sent to agents
	 * that do not list it: agents ignore unknown members (Poppy §3.3), but there is no need either.
	 */
	private operacionVisible(e: Empresa, op: Operacion, conPrueba: boolean) {
		const visible: Record<string, unknown> = this.nucleo.visible(op);
		const latest = this.nucleo.pruebas?.ultima(e.tenantId, op.operation_id);
		if (conPrueba && latest) visible[EXT_PRUEBA] = { latest, bundle_url: `${this.issuer(e)}/vxp/proof/operations/${op.operation_id}` };
		return visible;
	}

	/** The extension's own endpoints (SPEC §12.1.3), with the same DPoP Session Token. */
	async prueba(req: Request, e: Empresa, resto: string[]): Promise<Response> {
		if (resto[0] !== "operations" || !resto[1] || resto.length > 3) return json(404, { error: "not_found" });
		const r = this.actor(req, e);
		if (r instanceof Response) return r;
		const { actor: a, sesion } = r;
		const op = this.nucleo.operacionDe(a, resto[1], sesion.id);
		// Owner rules from operations §3.2: foreign and nonexistent operations get the same response.
		if (op === "not_found" || !this.nucleo.pruebas?.tiene(e.tenantId, resto[1])) return json(404, { error: "operation_not_found" });
		if (op === "sign_in_required") return json(403, { error: "sign_in_required" }, { "www-authenticate": 'DPoP error="sign_in_required"' });
		if (resto.length === 2 && req.method === "GET") {
			if (op.state === "in_progress" && op.interno.ejecutada) this.nucleo.verificar(e.tenantId, op);
			return json(200, this.nucleo.pruebas.paquete(e.tenantId, op.operation_id), { "cache-control": "no-store" });
		}
		if (resto[2] === "counter" && req.method === "POST") {
			let body: Record<string, unknown>;
			try {
				body = JSON.parse((await req.text()) || "{}");
			} catch {
				return json(400, { error: "invalid_request" });
			}
			const doc = await this.dir.cliente(a.clientId);
			const conPrueba = listaPrueba(doc);
			const res = this.nucleo.contraproponer(a, op, body as Parameters<Nucleo["contraproponer"]>[2]);
			if (!res.ok) {
				if (res.error === "counter_rejected") return json(409, { error: "counter_rejected", operation: this.operacionVisible(e, op, conPrueba) });
				return json(403, { error: res.error }, { "www-authenticate": `DPoP error="${res.error}"` });
			}
			return json(200, this.operacionVisible(e, res.operacion, conPrueba));
		}
		return json(404, { error: "not_found" });
	}

	metadata(e: Empresa) {
		const base = this.issuer(e);
		return {
			issuer: base,
			token_endpoint: `${base}/oauth/token`,
			revocation_endpoint: `${base}/oauth/revoke`,
			device_authorization_endpoint: `${base}/oauth/device`,
			dpop_signing_alg_values_supported: ["ES256"],
			token_endpoint_auth_methods_supported: ["private_key_jwt"],
			grant_types_supported: [
				"urn:ietf:params:oauth:grant-type:jwt-bearer",
				"urn:ietf:params:oauth:grant-type:device_code",
				"refresh_token",
			],
			poppy_domains: [e.dominio],
			// RFC 9396 §10: `authorization_details` types this AS accepts (native mode and operation grant).
			authorization_details_types_supported: ["https://vxpprotocol.org/rar/capability"],
			// RFC 8414 §2 allows additional parameters. This is the outcome-proof anchor (SPEC §9.9.1):
			// the verifier learns whose keys they are from here, not from poppy.json or the Agent Card.
			vxp_proof: bloqueConfianza({
				issuer: base,
				authOrigin: this.authOrigin,
				operadorIssuer: this.nucleo.pruebas?.operadorIssuer ?? "",
				origenRegistro: this.nucleo.pruebas?.origenRegistro ?? "",
				vinculos: this.nucleo.pruebas?.vinculos(e.tenantId),
			}),
		};
	}

	// ── Agent authentication (Poppy 4.1, 4.2) ─────────────────────────────────────────────────

	private jtiNuevo(clave: string, exp: number): boolean {
		const t = ahora();
		for (const [k, v] of this.jtiVistos) if (v < t - 120) this.jtiVistos.delete(k);
		if (this.jtiVistos.has(clave)) return false;
		this.jtiVistos.set(clave, exp);
		return true;
	}

	private async verificarAsercion(token: string, jwksUri: string, e: Empresa, clientId: string, tipo: "client" | "session"): Promise<Decoded | null> {
		const d = await this.dir.verificar(token, jwksUri, ["ES256", "RS256"]);
		if (!d) return null;
		const p = d.payload;
		const t = ahora();
		if (d.header.typ === "poppy-browser+jwt") return null;
		if (p.iss !== clientId || typeof p.aud !== "string" || p.aud !== this.issuer(e)) return null;
		if (tipo === "client" && p.sub !== clientId) return null;
		if (tipo === "session" && (typeof p.sub !== "string" || !p.sub)) return null;
		if (typeof p.iat !== "number" || typeof p.exp !== "number") return null;
		if (p.exp <= t || p.iat > t + 30 || p.exp - p.iat > 300) return null;
		if (typeof p.jti !== "string" || p.jti.length < 16) return null;
		if (!this.jtiNuevo(`${tipo}|${clientId}|${p.jti}`, p.exp)) return null;
		return d;
	}

	/** Authenticates the client (private_key_jwt). Returns the agent document or an OAuth error. */
	private async cliente(form: URLSearchParams, e: Empresa) {
		const clientId = form.get("client_id") ?? "";
		const doc = clientId ? await this.dir.cliente(clientId) : null;
		if (!doc || !this.nucleo.aceptaAgente(e.tenantId, clientId)) return { error: json(401, { error: "invalid_client" }, noStore) };
		if (form.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			return { error: json(401, { error: "invalid_client" }, noStore) };
		const ok = await this.verificarAsercion(form.get("client_assertion") ?? "", doc.jwks_uri, e, clientId, "client");
		if (!ok) return { error: json(401, { error: "invalid_client" }, noStore) };
		return { doc };
	}

	/** DPoP Proof (RFC 9449 §4.3, with the choices of Poppy 4.3). Returns the key thumbprint. */
	private dpop(req: Request, accessToken?: string, unaVez = false): string | null {
		const proof = req.headers.get("dpop");
		if (!proof || proof.includes(",")) return null;
		const d = decodeJwt(proof);
		if (!d || d.header.typ !== "dpop+jwt") return null;
		const jwk = d.header.jwk as Jwk | undefined;
		if (!jwk || typeof jwk !== "object" || ("d" in jwk && jwk.d)) return null;
		if (!verifyWith(d, publicOnly(jwk), ["ES256", "RS256"])) return null;
		const u = new URL(req.url);
		const p = d.payload;
		if (p.htm !== req.method || p.htu !== `${u.origin}${u.pathname}`) return null;
		if (typeof p.iat !== "number" || Math.abs(ahora() - p.iat) > 60) return null;
		if (typeof p.jti !== "string" || !p.jti) return null;
		if (accessToken !== undefined && p.ath !== sha256(accessToken)) return null;
		if (unaVez && !this.jtiNuevo(`dpop|${p.jti}`, p.iat + 60)) return null;
		return thumbprint(publicOnly(jwk));
	}

	private emitir(s: Sesion, jkt: string, alcances: string[], extra: Record<string, unknown> = {}) {
		const access = randomId("st_", 24);
		this.tokens.set(access, { tenantId: s.tenantId, sessionId: s.id, jkt, exp: ahora() + 3600, alcances, grantId: s.grantId });
		return json(
			200,
			{ access_token: access, token_type: "DPoP", expires_in: 3600, scope: alcances.join(" "), session_id: s.id, signed_in: s.grantId !== null, ...extra },
			noStore,
		);
	}

	async token(req: Request, e: Empresa): Promise<Response> {
		const form = new URLSearchParams(await req.text());
		const jkt = this.dpop(req, undefined, true);
		if (!jkt) return json(400, { error: "invalid_dpop_proof" }, noStore);
		const c = await this.cliente(form, e);
		if ("error" in c) return c.error;
		const clientId = c.doc.client_id;
		const grantType = form.get("grant_type");
		const sessionId = form.get("session_id");
		const sesionDe = (sub: string): Sesion | "invalid" | null => {
			if (!sessionId) return null;
			const s = this.sesiones.get(sessionId);
			if (!s || s.tenantId !== e.tenantId || s.clientId !== clientId || s.sub !== sub) return "invalid";
			return s;
		};

		if (grantType === "urn:ietf:params:oauth:grant-type:jwt-bearer") {
			const a = await this.verificarAsercion(form.get("assertion") ?? "", c.doc.jwks_uri, e, clientId, "session");
			if (!a) return json(400, { error: "invalid_grant" }, noStore);
			const sub = String(a.payload.sub);
			const existente = sesionDe(sub);
			if (existente === "invalid") return json(400, { error: "invalid_session" }, noStore);
			const s: Sesion = existente ?? { id: randomId("ses_", 9), tenantId: e.tenantId, clientId, sub, cuenta: null, grantId: null };
			this.sesiones.set(s.id, s);
			// Renewing with the assertion yields a token with no signed-in session (Poppy 4.2).
			return this.emitir({ ...s, grantId: null }, jkt, []);
		}

		if (grantType === "refresh_token") {
			const hit = this.del.porRefresh(form.get("refresh_token") ?? "", clientId);
			const g = hit?.grant;
			if (!g || hit.reuso || g.revocado || g.expira < ahora() || g.tenantId !== e.tenantId) return json(400, { error: "invalid_grant" }, noStore);
			const pedidos = (form.get("scope") ?? "").split(" ").filter(Boolean);
			if (pedidos.some((a) => !g.alcances.includes(a))) return json(400, { error: "invalid_scope" }, noStore);
			const existente = sesionDe(g.sub);
			if (existente === "invalid") return json(400, { error: "invalid_session" }, noStore);
			if (existente && existente.cuenta && existente.cuenta !== g.clienteId) return json(400, { error: "account_mismatch" }, noStore);
			const s: Sesion = existente ?? { id: randomId("ses_", 9), tenantId: e.tenantId, clientId, sub: g.sub, cuenta: null, grantId: null };
			s.cuenta = g.clienteId;
			s.grantId = g.id;
			this.sesiones.set(s.id, s);
			return this.emitir(s, jkt, pedidos.length ? pedidos : g.alcances);
		}

		if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
			const d = this.del.dispositivos.get(form.get("device_code") ?? "");
			if (!d || d.protocolo !== "poppy" || d.tenantId !== e.tenantId || d.clientId !== clientId) return json(400, { error: "invalid_grant" }, noStore);
			const estado = sondeo(d);
			if (estado !== "listo") return json(400, { error: estado }, noStore);
			// The session says who the user is: the device code does not know.
			const s = sessionId ? this.sesiones.get(sessionId) : undefined;
			if (!s || s.tenantId !== e.tenantId || s.clientId !== clientId) return json(400, { error: "invalid_session" }, noStore);
			if (s.cuenta && s.cuenta !== d.clienteId) {
				d.estado = "consumido";
				return json(400, { error: "account_mismatch" }, noStore);
			}
			// Expanding permissions: Poppy 0.2 §4.4 «The Company MUST NOT grant scopes beyond those requested». The new
			// token carries only what is requested and approved now; an agent that wants to keep the earlier scopes
			// requests them together (and revokes its old token, per Poppy guidance). We used to add the previous ones: non-conformant (22-oct).
			const previo = s.grantId ? this.del.grants.get(s.grantId) : undefined;
			if (mutado("permisos_suman") && previo && !previo.revocado && previo.clienteId === d.clienteId && previo.clientId === clientId && previo.sub === s.sub) {
				d.alcancesAprobados = [...new Set([...previo.alcances, ...d.alcancesAprobados])];
			}
			const { grant, refresh } = this.del.nuevoGrant(d, s.sub);
			d.estado = "consumido";
			s.cuenta = grant.clienteId;
			s.grantId = grant.id;
			return this.emitir(s, jkt, grant.alcances, { refresh_token: refresh, refresh_token_expires_in: 30 * 86_400 });
		}
		return json(400, { error: "unsupported_grant_type" }, noStore);
	}

	async device(req: Request, e: Empresa): Promise<Response> {
		const form = new URLSearchParams(await req.text());
		const c = await this.cliente(form, e);
		if ("error" in c) return c.error;
		const alcances = (form.get("scope") ?? "").split(" ").filter(Boolean);
		if (alcances.length === 0 || alcances.some((a) => !(a in e.alcances))) return json(400, { error: "invalid_scope" }, noStore);
		const d = this.del.nuevoDispositivo({
			tenantId: e.tenantId,
			protocolo: "poppy",
			clientId: c.doc.client_id,
			clientName: c.doc.client_name ?? new URL(c.doc.client_id).host,
			sub: null,
			alcancesPedidos: alcances,
		});
		const verificacion = `${this.authOrigin}/e/${e.slug}/vincular`;
		return json(
			200,
			{ device_code: d.deviceCode, user_code: d.userCode, verification_uri: verificacion, verification_uri_complete: `${verificacion}?user_code=${d.userCode}`, expires_in: 600, interval: d.intervalo },
			noStore,
		);
	}

	async revoke(req: Request, e: Empresa): Promise<Response> {
		const form = new URLSearchParams(await req.text());
		const c = await this.cliente(form, e);
		if ("error" in c) return c.error;
		const hit = this.del.porRefresh(form.get("token") ?? "", c.doc.client_id);
		if (hit && hit.grant.tenantId === e.tenantId) {
			hit.grant.revocado = true;
			// Sessions continue, signed out; they can only return to the same account.
			for (const s of this.sesiones.values()) if (s.grantId === hit.grant.id) s.grantId = null;
		}
		return json(200, {}, noStore);
	}

	// ── Resources with Session Token (Poppy 4.3) ─────────────────────────────────────────────

	private actor(req: Request, e: Empresa): { actor: ActorExterno; sesion: Sesion } | Response {
		const desafio = (error: string) => json(401, { error }, { "www-authenticate": `DPoP error="${error}", algs="ES256"` });
		const auth = req.headers.get("authorization") ?? "";
		const [esquema, valor] = auth.split(" ");
		const t = valor ? this.tokens.get(valor) : undefined;
		if (!t || esquema !== "DPoP" || t.exp < ahora() || t.tenantId !== e.tenantId) return desafio("invalid_token");
		const jkt = this.dpop(req, valor);
		if (!jkt || jkt !== t.jkt) return desafio("invalid_dpop_proof");
		const s = this.sesiones.get(t.sessionId)!;
		// Disconnection takes effect immediately: the grant is checked on every request (Poppy 4.9).
		const g = t.grantId ? this.del.grants.get(t.grantId) : undefined;
		const vigente = g && !g.revocado && g.expira > ahora() && s.grantId === g.id;
		return {
			sesion: s,
			actor: {
				tenantId: e.tenantId,
				via: "agente_personal",
				protocolo: "poppy",
				clientId: s.clientId,
				sub: s.sub,
				clienteId: vigente ? g.clienteId : null,
				alcances: vigente ? t.alcances.filter((a) => g.alcances.includes(a)) : [],
				grantId: vigente ? g.id : null,
			},
		};
	}

	// ── Conversations (Poppy 7) ───────────────────────────────────────────────────────────────

	private evento(c: Conv, ev: Record<string, unknown>) {
		c.events.push({ id: `evt_${(++this.seq).toString(36)}`, created_at: new Date().toISOString(), ...ev });
	}

	private estado(c: Conv, status: Conv["status"], resp: Conv["responder"] = c.responder) {
		if (c.status === status && c.responder === resp) return;
		c.status = status;
		c.responder = resp;
		this.evento(c, { type: "state", status, responder: resp });
	}

	private async leer(c: Conv, url: URL, status = 200): Promise<Response> {
		const wait = url.searchParams.get("wait");
		if (wait !== null && !/^\d+$/.test(wait)) return json(400, { error: "invalid_request" });
		const cursor = url.searchParams.get("cursor");
		let desde = 0;
		if (cursor) {
			const i = c.events.findIndex((ev) => ev.id === cursor);
			if (i === -1) return json(400, { error: "invalid_cursor" });
			desde = i + 1;
		}
		const hasta = Date.now() + Math.min(Number(wait ?? 0), 25) * 1000;
		while (c.events.length <= desde && Date.now() < hasta) await new Promise((r) => setTimeout(r, 50));
		const events = c.events.slice(desde, desde + 100);
		return json(status, {
			conversation_id: c.id,
			events,
			cursor: events.length ? events[events.length - 1].id : (cursor ?? null),
			has_more: c.events.length > desde + 100,
			status: c.status,
			responder: c.responder,
		});
	}

	private dueno(c: Conv, a: ActorExterno): boolean | "sign_in_required" {
		if (c.tenantId !== a.tenantId || c.clientId !== a.clientId || c.sub !== a.sub) return false;
		if (c.cuenta && !a.clienteId) return "sign_in_required";
		if (c.cuenta && c.cuenta !== a.clienteId) return false;
		return true;
	}

	/** VXP Relationship inside the conversation (wired up by the gateway). */
	relacion: PuenteRelacion | null = null;

	/**
	 * The company writes to the agent in its most recent open conversation (VXP Relationship without
	 * an inbox). The agent reads it like any event with `GET …/events?wait=`. With no open conversation,
	 * there is nowhere to deliver and it is recorded as failed in the outbox.
	 */
	escribir(tenantId: string, clientId: string, sub: string, msg: { text: string; data?: Record<string, unknown> }): boolean {
		const c = [...this.convs.values()].reverse().find((x) => x.tenantId === tenantId && x.clientId === clientId && x.sub === sub && x.status !== "closed");
		if (!c) return false;
		this.evento(c, { type: "message", message: { id: randomId("msg_", 9), role: "company", sender: "agent", text: msg.text, ...(msg.data ? { data: msg.data } : {}) } });
		this.estado(c, "idle");
		return true;
	}

	private atender(c: Conv, a: ActorExterno, sesion: Sesion, mensaje: Record<string, unknown>) {
		this.evento(c, { type: "message", message: { ...mensaje, role: "user" } });
		// Reply to a closed question from the company («confirmar o bloquear»), via text or via `data`.
		const datos = (mensaje.data as Record<string, unknown> | undefined)?.["vxpprotocol.org/relationship"] as Record<string, unknown> | undefined;
		if (this.relacion && (typeof mensaje.text === "string" || datos)) {
			const r = this.relacion.responder(a, typeof mensaje.text === "string" ? mensaje.text : "", datos) ?? (typeof mensaje.text === "string" ? this.relacion.ofrecer(a, c.id, mensaje.text) : null);
			if (r) {
				if (r.necesita === "sign_in") this.evento(c, { type: "authorization", error: "sign_in_required" });
				this.evento(c, { type: "message", message: { id: randomId("msg_", 9), role: "company", sender: "agent", text: r.text, ...(r.data ? { data: r.data } : {}) } });
				this.estado(c, "idle");
				return;
			}
		}
		if (typeof mensaje.text !== "string" || !mensaje.text.trim()) return;
		this.estado(c, "working");
		const r = responder(this.nucleo, a, c.caseId, mensaje.text, sesion.id);
		if (a.clienteId) c.cuenta = a.clienteId;
		const msg: Record<string, unknown> = { id: randomId("msg_", 9), role: "company", sender: "agent", text: r.text };
		if (r.data) msg.data = r.data;
		if (r.operacion) {
			if (c.ops) msg.operation = this.operacionVisible(this.nucleo.empresa(a.tenantId), r.operacion, c.prueba);
			else {
				// Without the extension there is no exact confirmation: SOVRAS does not execute writes from text.
				this.nucleo.cancelar(a.tenantId, r.operacion);
				msg.text = "Ese cambio necesita que tu asistente confirme la operación exacta (extensión operations), y no la declara. No hice ningún cambio.";
			}
		}
		if (r.necesita) {
			this.evento(c, {
				type: "authorization",
				error: r.necesita.tipo === "sign_in" ? "sign_in_required" : "insufficient_scope",
				...(r.necesita.tipo === "scope" ? { scope: r.necesita.alcances.join(" ") } : {}),
			});
		}
		this.evento(c, { type: "message", message: msg });
		this.estado(c, "idle");
	}

	async conversaciones(req: Request, e: Empresa, resto: string[]): Promise<Response> {
		const r = this.actor(req, e);
		if (r instanceof Response) return r;
		const { actor: a, sesion } = r;
		const url = new URL(req.url);
		let body: Record<string, unknown> = {};
		if (req.method === "POST") {
			try {
				const texto = await req.text();
				body = texto ? JSON.parse(texto) : {};
			} catch {
				return json(400, { error: "invalid_request" });
			}
		}
		const mensaje = body.message as Record<string, unknown> | undefined;
		const valido = () =>
			mensaje &&
			typeof mensaje.id === "string" &&
			ID.test(mensaje.id) &&
			(mensaje.sender === "agent" || mensaje.sender === "human") &&
			(mensaje.text !== undefined || mensaje.data !== undefined || mensaje.context !== undefined);
		const claveMsg = (id: string) => `${e.tenantId}|${a.clientId}|${a.sub}|${id}`;
		const doc = await this.dir.cliente(a.clientId);
		const conOps = Boolean(doc?.extensions?.operations);

		if (resto.length === 0 && req.method === "POST") {
			if (!valido()) return json(400, { error: "invalid_request" });
			const contenido = JSON.stringify(mensaje);
			const previo = this.mensajes.get(claveMsg(String(mensaje!.id)));
			if (previo) {
				if (previo.contenido !== contenido) return json(409, { error: "message_id_conflict" });
				const c = this.convs.get(previo.conv)!;
				return url.searchParams.has("wait") ? this.leer(c, url, 201) : new Response(c.primeraRespuesta, { status: 201, headers: { "content-type": "application/json" } });
			}
			const caso = this.nucleo.abrirCaso(e.tenantId, a);
			const c: Conv = {
				id: randomId("cnv_", 9),
				tenantId: e.tenantId,
				clientId: a.clientId,
				sub: a.sub,
				cuenta: null,
				caseId: caso.id,
				status: "idle",
				responder: "agent",
				events: [],
				primeraRespuesta: "",
				ops: conOps,
				prueba: listaPrueba(doc),
			};
			this.convs.set(c.id, c);
			this.mensajes.set(claveMsg(String(mensaje!.id)), { conv: c.id, contenido });
			this.atender(c, a, sesion, mensaje!);
			c.primeraRespuesta = JSON.stringify({ conversation_id: c.id, status: c.status, responder: c.responder });
			return url.searchParams.has("wait") ? this.leer(c, url, 201) : new Response(c.primeraRespuesta, { status: 201, headers: { "content-type": "application/json" } });
		}

		const c = this.convs.get(resto[0] ?? "");
		const d = c ? this.dueno(c, a) : false;
		if (!c || d === false) return json(404, { error: "conversation_not_found" });
		if (d === "sign_in_required") return json(403, { error: "sign_in_required" }, { "www-authenticate": 'DPoP error="sign_in_required"' });
		const accion = resto[1];
		if (accion === "events" && req.method === "GET" && resto.length === 2) return this.leer(c, url);
		if (accion === "close" && req.method === "POST") {
			if (c.status !== "closed") this.estado(c, "closed");
			return json(200, { status: c.status, responder: c.responder });
		}
		if ((accion === "messages" || accion === "handoff") && req.method === "POST") {
			if (c.status === "closed") return json(409, { error: "conversation_closed" });
			if (accion === "handoff") {
				if (c.status !== "queued" && c.responder !== "human") {
					this.estado(c, "queued");
					this.nucleo.evento(e.tenantId, c.caseId, "handoff.requested", { por: "agente_personal" });
				}
				return json(202, { status: c.status, responder: c.responder });
			}
			if (!valido()) return json(400, { error: "invalid_request" });
			const contenido = JSON.stringify(mensaje);
			const previo = this.mensajes.get(claveMsg(String(mensaje!.id)));
			if (previo) {
				if (previo.contenido !== contenido || previo.conv !== c.id) return json(409, { error: "message_id_conflict" });
			} else {
				this.mensajes.set(claveMsg(String(mensaje!.id)), { conv: c.id, contenido });
				this.atender(c, a, sesion, mensaje!);
			}
			return url.searchParams.has("wait") ? this.leer(c, url, 202) : json(202, { conversation_id: c.id, status: c.status, responder: c.responder });
		}
		return json(404, { error: "conversation_not_found" });
	}

	// ── Operations extension (Poppy Operations v1) ───────────────────────────────────────────

	async operaciones(req: Request, e: Empresa, resto: string[]): Promise<Response> {
		const r = this.actor(req, e);
		if (r instanceof Response) return r;
		const { actor: a, sesion } = r;
		const op = this.nucleo.operacionDe(a, resto[0] ?? "", sesion.id);
		if (op === "not_found") return json(404, { error: "operation_not_found" });
		if (op === "sign_in_required") return json(403, { error: "sign_in_required" }, { "www-authenticate": 'DPoP error="sign_in_required"' });
		const doc = await this.dir.cliente(a.clientId);
		const conPrueba = listaPrueba(doc);
		const conReintento = (o: Operacion, status = 200) =>
			json(status, this.operacionVisible(e, o, conPrueba), o.state === "in_progress" ? { "retry-after": "2" } : {});
		if (resto.length === 1 && req.method === "GET") {
			// Reading an in-progress operation attempts to verify it: «MUST NOT report failed while it doesn't know».
			if (op.state === "in_progress" && op.interno.ejecutada) this.nucleo.verificar(e.tenantId, op);
			return conReintento(op);
		}
		if (resto[1] === "confirm" && req.method === "POST") {
			let body: { revision?: unknown; approved_by?: unknown } = {};
			try {
				body = JSON.parse((await req.text()) || "{}");
			} catch {
				return json(400, { error: "invalid_request" });
			}
			if (typeof body.revision !== "number") return json(400, { error: "invalid_request" });
			const res = await this.nucleo.confirmar(a, op, body.revision, String(body.approved_by ?? ""));
			if (res.status === 403 && (res.body as { error: string }).error !== "user_approval_required") {
				const b = res.body as { error: string; scope?: string };
				return json(403, b, { "www-authenticate": `DPoP error="${b.error}"${b.scope ? `, scope="${b.scope}"` : ""}` });
			}
			return res.status === 200 ? conReintento(op) : json(res.status, res.body);
		}
		if (resto[1] === "cancel" && req.method === "POST") return conReintento(this.nucleo.cancelar(e.tenantId, op));
		return json(404, { error: "operation_not_found" });
	}

	// ── Feedback (Poppy 8) ────────────────────────────────────────────────────────────────────

	async feedback(req: Request, e: Empresa): Promise<Response> {
		const r = this.actor(req, e);
		if (r instanceof Response) return r;
		let body: Record<string, unknown>;
		try {
			body = JSON.parse(await req.text());
		} catch {
			return json(400, { error: "invalid_request" });
		}
		const { kind, task, description } = body;
		if (typeof kind !== "string" || typeof task !== "string" || typeof description !== "string" || task.length > 200 || description.length > 2000 || !task || !description)
			return json(400, { error: "invalid_request" });
		// This is demand the company's agent does not cover: input for a proposal, never an instruction.
		this.nucleo.base(e.tenantId).feedback.push({ clientId: r.actor.clientId, sub: r.actor.sub, task, description, at: new Date().toISOString() });
		return new Response(null, { status: 202 });
	}
}

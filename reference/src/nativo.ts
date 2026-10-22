// Native face of the VXP native profile (technical design 0.1, §3 and §4), over the same core
// as the Poppy and PACT faces: one operation, one log and one proof chain.
//
// - Discovery: `/.well-known/vxp.json` on the company's domain. It carries NO trust
//   members: proof keys come only from the issuer's RFC 8414 metadata
//   (`vxp_proof`, SPEC §4.2 and §9.9.1). A single source of truth.
// - Authorization: the SAME authorization server as the issuer (RFC 8414 publishes a single
//   token_endpoint), with `resource` = native endpoint (RFC 8707), private_key_jwt, DPoP (RFC 9449)
//   and per-order `authorization_details` (RFC 9396).
// - Requests: POST /v1/requests (Idempotency-Key required), GET /v1/requests/{id},
//   GET /v1/requests/{id}/events, POST /v1/proposals/{id}/accept, POST /v1/proposals/{id}/counter,
//   POST /v1/requests/{id}/cancel, GET /v1/requests/{id}/proof.

import type { ClienteMetadata, Delegaciones, Directorio, FetchLike } from "./identidad.ts";
import { type EstadoNativo, FINALES, proyectarA2A, proyectarPoppy, transicionLegal } from "./estados.ts";
import { type Decoded, type Jwk, ahora, decodeJwt, publicOnly, randomId, sha256, thumbprint, verifyWith } from "./jose.ts";
import { mutado } from "./mutar.ts";
import type { ActorExterno, Empresa, Nativo, Nucleo, Operacion } from "./nucleo.ts";
import { huellaJcs } from "./prueba.ts";
import { cotizar } from "./comercio.ts";
import { ACCIONES_EMPRESA, ALCANCE_RELACION, BUZON_CONVERSACION, type DetalleRelacion, type ErrorRelacion, RAR_RELACION, type Relacion, Relaciones } from "./relacion.ts";
import { sondeo } from "./vincular.ts";
import { CONECTORES, conectorDe, inputsDesdeApi, pideDesdeApi, rarPropio, textoRar } from "./conectores.ts";
import { cotizarEstadia } from "./hotel.ts";

/** RAR type of this profile: one capability over ONE company resource (RFC 9396 §2). */
export const RAR_CAPACIDAD = "https://vxpprotocol.org/rar/capability";

/** A concrete resource, or `nuevo` for pedido.crear, with the maximum amount the customer approved. */
type DetalleRar = { type: string; actions: string[]; identifier: string; limits?: { max_total_clp: number } };

type TokenNativo = {
	tenantId: string;
	clientId: string;
	sub: string;
	jkt: string;
	exp: number;
	grantId: string | null;
	rar: DetalleRar[];
};

/** The agent's inbox for company-initiated messages: declared in its CIMD, on the same origin as the client_id. */
function buzonDe(doc: ClienteMetadata): string | null {
	const ext = (doc.extensions?.["vxpprotocol.org/relationship"] ?? {}) as { inbox_uri?: unknown };
	if (typeof ext.inbox_uri !== "string") return null;
	try {
		return new URL(ext.inbox_uri).origin === new URL(doc.client_id).origin ? ext.inbox_uri : null;
	} catch {
		return null;
	}
}

type Solicitud = {
	id: string;
	tenantId: string;
	clientId: string;
	sub: string;
	caseId: string;
	operation: string;
	orderRef: string;
	fecha: string;
	bodyDigest: string;
	/** States before the operation exists (received, authorization_required, failed without a proposal). */
	estado: EstadoNativo;
	eventos: Nativo["eventos"];
	opId: string | null;
	faltan: DetalleRar[];
	motivo: string | null;
	/** pedido.crear: the quote it originates from. */
	cotizacion?: string;
	/** Connector-backed capabilities (stress sandbox): the operation's inputs. */
	inputs?: Record<string, string>;
};

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	new Response(body === null ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
const FECHA = /^\d{4}-\d{2}-\d{2}$/;

export class CaraNativa {
	private readonly tokens = new Map<string, TokenNativo>();
	private readonly solicitudes = new Map<string, Solicitud>();
	private readonly idem = new Map<string, string>();
	private readonly jtiVistos = new Map<string, number>();
	private readonly nucleo: Nucleo;
	private readonly dir: Directorio;
	private readonly del: Delegaciones;
	private readonly authOrigin: string;
	readonly relaciones: Relaciones;
	private readonly fetch: FetchLike;
	/** Lifetime of the pass (access token) in seconds: short by design (access ramp). */
	private readonly ttl: number;

	constructor(nucleo: Nucleo, dir: Directorio, del: Delegaciones, authOrigin: string, relaciones = new Relaciones(), fetch: FetchLike = (u, i) => globalThis.fetch(u, i), ttl = 3600) {
		this.nucleo = nucleo;
		this.dir = dir;
		this.del = del;
		this.authOrigin = authOrigin;
		this.relaciones = relaciones;
		this.fetch = fetch;
		this.ttl = ttl;
	}

	/** Access log: which agent a token belongs to (without consuming anything or verifying DPoP). */
	quienToken(valor: string): { clientId: string; sub: string } | null {
		const t = this.tokens.get(valor);
		return t ? { clientId: t.clientId, sub: t.sub } : null;
	}

	/** Simulator: expires a company's live native passes (expired approval). */
	vencerPases(tenantId: string): number {
		let n = 0;
		for (const t of this.tokens.values())
			if (t.tenantId === tenantId && t.exp >= ahora()) {
				t.exp = ahora() - 1;
				n++;
			}
		return n;
	}

	/** Actions this company may initiate toward agents: catalog entries whose capability is in its Release. */
	accionesEmpresa(e: Empresa): string[] {
		const caps = new Set(e.release.capacidades.map((c) => c.id));
		return Object.entries(ACCIONES_EMPRESA)
			.filter(([, a]) => !a.capacidad || caps.has(a.capacidad))
			.filter(([, a]) => !a.solo || a.solo === (e.hotel ? "hotel" : "comercio"))
			.map(([id]) => id);
	}

	/** A relationship is valid if it exists, is neither revoked nor expired, and the delegation that created it is still active. */
	relacionVigente(id: string, tenantId: string): Relacion | ErrorRelacion {
		const r = this.relaciones.vigente(id, tenantId);
		if (typeof r === "string") return r;
		const g = this.del.grants.get(r.grantId);
		if ((!g || g.revocado || g.expira <= ahora()) && !mutado("relacion_sin_grant")) return "relationship_revoked";
		return r;
	}

	issuer(e: Empresa) {
		return `${this.authOrigin}/e/${e.slug}`;
	}
	endpoint(e: Empresa) {
		return `${this.issuer(e)}/v1`;
	}

	// ── Discovery ───────────────────────────────────────────────────────────────────────────

	vxpJson(e: Empresa) {
		const lim = this.nucleo.limites(e.tenantId);
		return {
			protocol: "vxp",
			version: "0.1",
			organization: { name: e.nombre, domain: e.dominio },
			issuer: this.issuer(e),
			endpoint: this.endpoint(e),
			capabilities: e.release.capacidades.map((c) => ({
				id: c.id,
				effect: c.efecto,
				access: "delegated",
				// Admission of a specific order is decided at request time (owner, ownership and Policy).
				admission: c.efecto === "write" ? "dynamic" : "static",
				authorization_details_type: RAR_CAPACIDAD,
				...(c.efecto === "write" ? { commitment_modes: ["firm", "conditional"], outcome_proof: true } : {}),
			})),
			limits: lim,
			// Keys and custody do NOT go here: the verifier takes them from the RFC 8414 metadata.
			outcome_proof: { version: "0.1", trust: "issuer_metadata" },
			// VXP's own discovery and the /v1 endpoints: the EXPERIMENTAL native profile. A gateway can serve only
			// this profile; an agent that speaks Poppy or PACT can use those adapters instead.
			status: "experimental",
			vxp: {
				version: "0.1",
				relationship: { authorization_details_type: RAR_RELACION, company_initiated_actions: this.accionesEmpresa(e) },
				proof: { trust: "issuer_metadata" },
			},
		};
	}

	// ── OAuth (same AS as the issuer) ───────────────────────────────────────────────────────

	private jtiNuevo(clave: string, exp: number): boolean {
		const t = ahora();
		for (const [k, v] of this.jtiVistos) if (v < t - 120) this.jtiVistos.delete(k);
		if (this.jtiVistos.has(clave)) return false;
		this.jtiVistos.set(clave, exp);
		return true;
	}

	private async asercion(token: string, jwksUri: string, e: Empresa, clientId: string, tipo: "client" | "user"): Promise<Decoded | null> {
		const d = await this.dir.verificar(token, jwksUri, ["ES256", "RS256"]);
		if (!d) return null;
		const p = d.payload;
		const t = ahora();
		if (p.iss !== clientId || p.aud !== this.issuer(e)) return null;
		if (tipo === "client" && p.sub !== clientId) return null;
		if (tipo === "user" && (typeof p.sub !== "string" || !p.sub || p.sub === clientId)) return null;
		if (typeof p.iat !== "number" || typeof p.exp !== "number" || p.exp <= t || p.iat > t + 30 || p.exp - p.iat > 300) return null;
		if (typeof p.jti !== "string" || p.jti.length < 16 || !this.jtiNuevo(`n|${tipo}|${clientId}|${p.jti}`, p.exp)) return null;
		return d;
	}

	private async cliente(form: URLSearchParams, e: Empresa) {
		const clientId = form.get("client_id") ?? "";
		const doc = clientId ? await this.dir.cliente(clientId) : null;
		if (!doc || !this.nucleo.aceptaAgente(e.tenantId, clientId)) return null;
		if (form.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") return null;
		return (await this.asercion(form.get("client_assertion") ?? "", doc.jwks_uri, e, clientId, "client")) ? doc : null;
	}

	private dpop(req: Request, accessToken?: string, unaVez = false): string | null {
		const proof = req.headers.get("dpop");
		if (!proof || proof.includes(",")) return null;
		const d = decodeJwt(proof);
		if (!d || d.header.typ !== "dpop+jwt") return null;
		const jwk = d.header.jwk as Jwk | undefined;
		if (!jwk || typeof jwk !== "object" || ("d" in jwk && jwk.d)) return null;
		if (!verifyWith(d, publicOnly(jwk), ["ES256"])) return null;
		const u = new URL(req.url);
		const p = d.payload;
		if (p.htm !== req.method || p.htu !== `${u.origin}${u.pathname}`) return null;
		if (typeof p.iat !== "number" || Math.abs(ahora() - p.iat) > 60) return null;
		if (typeof p.jti !== "string" || !p.jti) return null;
		if (accessToken !== undefined && p.ath !== sha256(accessToken)) return null;
		if (unaVez && !this.jtiNuevo(`ndpop|${p.jti}`, p.iat + 60)) return null;
		return thumbprint(publicOnly(jwk));
	}

	/**
	 * Validates `authorization_details` (RFC 9396 §2). Two types: a capability over ONE resource
	 * (`RAR_CAPACIDAD`), and the bilateral relationship (`RAR_RELACION`, VXP Relationship), at most one.
	 */
	private detalles(e: Empresa, crudo: string | null): { caps: DetalleRar[]; relacion: DetalleRelacion | null } | null {
		let v: unknown;
		try {
			v = JSON.parse(crudo ?? "");
		} catch {
			return null;
		}
		if (!Array.isArray(v) || v.length === 0) return null;
		const ids = new Set(e.release.capacidades.map((c) => c.id));
		const caps: DetalleRar[] = [];
		let relacion: DetalleRelacion | null = null;
		for (const d of v as Record<string, unknown>[]) {
			if (d?.type === RAR_RELACION) {
				const r = Relaciones.validar(d, this.accionesEmpresa(e));
				if (!r || relacion) return null;
				relacion = r;
				continue;
			}
			if (d?.type !== RAR_CAPACIDAD || !Array.isArray(d.actions) || d.actions.length === 0 || typeof d.identifier !== "string" || !d.identifier) return null;
			if (!d.actions.every((a) => typeof a === "string" && ids.has(a))) return null;
			const lim = d.limits as { max_total_clp?: unknown } | undefined;
			if (lim !== undefined && (!Number.isInteger(lim?.max_total_clp) || Number(lim?.max_total_clp) <= 0)) return null;
			caps.push({ type: RAR_CAPACIDAD, actions: d.actions as string[], identifier: d.identifier, ...(lim ? { limits: { max_total_clp: Number(lim.max_total_clp) } } : {}) });
		}
		return { caps, relacion };
	}

	/** Device Authorization (RFC 8628 §3.1) with `authorization_details`. */
	async device(e: Empresa, form: URLSearchParams): Promise<Response> {
		const doc = await this.cliente(form, e);
		if (!doc) return json(401, { error: "invalid_client" });
		const det = this.detalles(e, form.get("authorization_details"));
		if (!det) return json(400, { error: "invalid_authorization_details" });
		// A relationship requires an inbox declared by the agent: otherwise the company would have nowhere to reach it.
		if (det.relacion && !buzonDe(doc)) return json(400, { error: "invalid_authorization_details", error_description: "relationship requires extensions[\"vxpprotocol.org/relationship\"].inbox_uri" });
		const caps = new Map(e.release.capacidades.map((c) => [c.id, c]));
		const alcancesRel = det.relacion ? det.relacion.actions.map((a) => ACCIONES_EMPRESA[a].capacidad).filter((c): c is string => !!c).map((c) => caps.get(c)!.alcance) : [];
		const alcances = [...new Set([...det.caps.flatMap((d) => d.actions.map((a) => caps.get(a)!.alcance)), ...alcancesRel])];
		// The relationship has its own checkbox: if the person unticks it, it is not created (specific consent).
		if (det.relacion) alcances.push(ALCANCE_RELACION);
		const d = this.del.nuevoDispositivo({ tenantId: e.tenantId, protocolo: "vxp", clientId: doc.client_id, clientName: doc.client_name ?? new URL(doc.client_id).host, sub: null, alcancesPedidos: alcances });
		d.detalles = {
			rar: [...det.caps, ...(det.relacion ? [det.relacion] : [])],
			texto: [
				...det.caps.map((x) => textoRar(e, x)),
				...(det.relacion ? [Relaciones.texto(det.relacion, e.nombre)] : []),
			],
		};
		const uri = `${this.issuer(e)}/vincular`;
		return json(200, { device_code: d.deviceCode, user_code: d.userCode, verification_uri: uri, verification_uri_complete: `${uri}?user_code=${d.userCode}`, expires_in: 600, interval: d.intervalo });
	}

	private emitir(t: TokenNativo, extra: Record<string, unknown> = {}) {
		const access = randomId("nt_", 24);
		this.tokens.set(access, t);
		return json(200, { access_token: access, token_type: "DPoP", expires_in: this.ttl, ...(t.rar.length ? { authorization_details: t.rar } : {}), ...extra }, { pragma: "no-cache" });
	}

	async token(req: Request, e: Empresa, form: URLSearchParams): Promise<Response> {
		const jkt = this.dpop(req, undefined, true);
		if (!jkt) return json(400, { error: "invalid_dpop_proof" });
		const doc = await this.cliente(form, e);
		if (!doc) return json(401, { error: "invalid_client" });
		// The agent's User ID for this company travels as an RFC 7523 assertion on every token request.
		const a = await this.asercion(form.get("assertion") ?? "", doc.jwks_uri, e, doc.client_id, "user");
		if (!a) return json(400, { error: "invalid_grant" });
		const sub = String(a.payload.sub);
		const base = { tenantId: e.tenantId, clientId: doc.client_id, sub, jkt, exp: ahora() + this.ttl };
		const gt = form.get("grant_type");
		if (gt === "urn:ietf:params:oauth:grant-type:jwt-bearer") return this.emitir({ ...base, grantId: null, rar: [] });
		if (gt === "urn:ietf:params:oauth:grant-type:device_code") {
			const d = this.del.dispositivos.get(form.get("device_code") ?? "");
			if (!d || d.protocolo !== "vxp" || d.tenantId !== e.tenantId || d.clientId !== doc.client_id) return json(400, { error: "invalid_grant" });
			const estado = sondeo(d);
			if (estado !== "listo") return json(400, { error: estado });
			// Every resource in the grant must belong to the linked customer: the server does not trust the
			// `identifier` the agent sent (design 0.1 §3.C).
			const todos = (d.detalles?.rar ?? []) as (DetalleRar | DetalleRelacion)[];
			const rar = todos.filter((x): x is DetalleRar => x.type === RAR_CAPACIDAD);
			const pedidaRelacion = todos.find((x): x is DetalleRelacion => x.type === RAR_RELACION) ?? null;
			// Round 4 (M6): orders name the ERP customer, not the canonical one; without a link, nothing is owned.
			const erp = this.nucleo.empresa(e.tenantId).clientes.find((c) => c.id === d.clienteId)?.erp?.id ?? null;
			// A new order (`nuevo`) belongs to no one yet: it is enough for the customer to be linked to the ERP.
			const propios = rar.filter((x) => rarPropio(this.nucleo.empresa(e.tenantId), x, erp, this.nucleo.base(e.tenantId)));
			d.estado = "consumido";
			if (propios.length !== rar.length) return json(400, { error: "invalid_authorization_details" });
			const { grant } = this.del.nuevoGrant(d, sub);
			// VXP Relationship: created only if the person left its checkbox ticked.
			const relacion = pedidaRelacion && d.alcancesAprobados.includes(ALCANCE_RELACION) && d.clienteId ? this.crearRelacion(e, doc, sub, d.clienteId, grant.id, pedidaRelacion) : null;
			return this.emitir({ ...base, grantId: grant.id, rar: propios }, relacion ? { relationships: [relacion] } : {});
		}
		return json(400, { error: "unsupported_grant_type" });
	}

	// ── VXP Relationship ─────────────────────────────────────────────────────────────────────

	/**
	 * The agent's reply to a closed question from the company (via `/v1/relationships/{id}/replies` or
	 * inside its Poppy conversation). Only one of the options, once, and before it expires.
	 */
	responderAlerta(e: Empresa, rel: Relacion, alertId: string, decision: string): { status: number; body: Record<string, unknown> } {
		const a = this.relaciones.alertas.get(alertId);
		if (!a || a.relacionId !== rel.id) return { status: 404, body: { error: "alert_not_found" } };
		if (a.respuesta && !mutado("alerta_dos_respuestas")) return { status: 409, body: { error: "already_answered", decision: a.respuesta.decision } };
		if (a.vence <= ahora() && !mutado("alerta_vencida")) return { status: 410, body: { error: "alert_expired" } };
		if (!a.opciones.includes(decision) && !mutado("alerta_opcion_libre")) return { status: 400, body: { error: "option_not_allowed", options: a.opciones } };
		a.respuesta = { decision, at: ahora() };
		// The effect is only that of the option: «bloquear» holds the order's shipment; «confirmar» lets it
		// proceed. At the hotel, «liberar» releases the booking and «mantener» keeps it for a late arrival.
		const sistema = this.nucleo.empresa(e.tenantId).sistema;
		const pedido = sistema.pedidos.find((p) => p.id === a.ordenRef);
		if (pedido) pedido.retenido = decision === "bloquear";
		const reserva = sistema.hotel?.reservas.find((x) => x.id === a.ordenRef);
		if (reserva) {
			if (decision === "liberar") reserva.estado = "cancelada";
			reserva.historial.push({ at: new Date().toISOString(), cambio: decision === "liberar" ? "liberada por el asistente del huésped (llegada tardía)" : "mantenida por el asistente del huésped (llegada tardía)" });
		}
		this.nucleo.evento(e.tenantId, "-", "relationship.alert_answered", { relationship: rel.id, alert: a.id, decision, order_ref: a.ordenRef, human_involved: false });
		return { status: 200, body: { alert_id: a.id, decision, receipt: this.relaciones.recibo(rel, a) } };
	}

	/**
	 * Relationship for a Poppy agent without an inbox: the person approved it on the company's page, with
	 * a code sent to their WhatsApp. It is bound to the same client_id, sub and delegation as its Poppy
	 * session, and the company writes to it in its conversation.
	 */
	crearRelacionEnConversacion(e: Empresa, quien: { clientId: string; sub: string; clienteId: string; grantId: string }, detalle: DetalleRelacion) {
		const { relacion, acuerdo } = this.relaciones.crear({ tenantId: e.tenantId, issuer: this.issuer(e), ...quien, inbox: BUZON_CONVERSACION, detalle });
		this.nucleo.evento(e.tenantId, "-", "relationship.created", { relationship: relacion.id, agent: quien.clientId, actions: relacion.acciones, limits: relacion.limites, expires_at: relacion.expira, delivery: "poppy_conversation" });
		return { relacion, acuerdo };
	}

	private crearRelacion(e: Empresa, doc: ClienteMetadata, sub: string, clienteId: string, grantId: string, detalle: DetalleRelacion) {
		const { relacion, acuerdo } = this.relaciones.crear({ tenantId: e.tenantId, issuer: this.issuer(e), clientId: doc.client_id, sub, clienteId, grantId, inbox: buzonDe(doc)!, detalle });
		this.nucleo.evento(e.tenantId, "-", "relationship.created", { relationship: relacion.id, agent: doc.client_id, actions: relacion.acciones, limits: relacion.limites, expires_at: relacion.expira });
		return this.vistaRelacion(relacion, acuerdo);
	}

	private vistaRelacion(r: Relacion, acuerdo?: string) {
		const estado = this.relacionVigente(r.id, r.tenantId);
		return {
			relationship_id: r.id,
			state: typeof estado === "string" ? estado.replace("relationship_", "") : "active",
			actions: r.acciones,
			limits: r.limites,
			expires_at: new Date(r.expira * 1000).toISOString(),
			...(r.revocada ? { revoked: { by: r.revocada.por, at: new Date(r.revocada.at * 1000).toISOString() } } : {}),
			...(acuerdo ? { agreement: acuerdo } : {}),
		};
	}

	/**
	 * The company initiates an action toward the agent, within an active relationship (VXP Relationship).
	 * `despacho.proponer_cambio` opens a native request with its signed proposal, which the agent accepts
	 * via `/v1/proposals/{id}/accept` with the user's approval; `incidencia.avisar` only informs.
	 * The signed message is placed in the outbox and delivered over HTTP to the agent's inbox.
	 */
	async iniciarPorEmpresa(e: Empresa, relId: string, accion: string, params: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
		const autorizada = this.relaciones.autorizarInicio(relId, e.tenantId, accion);
		if (typeof autorizada === "string") return { status: 409, body: { error: autorizada } };
		const vigente = this.relacionVigente(relId, e.tenantId);
		if (typeof vigente === "string") return { status: 409, body: { error: vigente } };
		const r = vigente;
		const empresa = this.nucleo.empresa(e.tenantId);
		const erp = empresa.clientes.find((c) => c.id === r.clienteId)?.erp?.id ?? null;
		const orden = typeof params.order_ref === "string" ? params.order_ref : typeof params.reservation_ref === "string" ? params.reservation_ref : "";
		const pedido = empresa.sistema.pedidos.find((p) => p.id === orden);
		const reserva = empresa.sistema.hotel?.reservas.find((x) => x.id === orden);
		// The company may only write to the agent about THAT customer's resources.
		const duenoObjetivo = pedido?.clienteId ?? reserva?.huespedId ?? null;
		if (!erp || (duenoObjetivo !== erp && !mutado("relacion_recurso_ajeno"))) return { status: 404, body: { error: "target_not_found" } };
		let contenido: Record<string, unknown>;
		const capAccion = ACCIONES_EMPRESA[accion]?.capacidad;
		const con = capAccion ? conectorDe(e, capAccion) : null;
		if (con) {
			// A connector-backed action (e.g. `reserva.proponer_cambio`): a normal operation, proposed, not executed.
			const inputs = inputsDesdeApi(con.capacidad, { [con.objetivo ?? "order_ref"]: orden }, params);
			if (!inputs) return { status: 400, body: { error: "invalid_request" } };
			const cap = e.release.capacidades.find((c) => c.id === con.capacidad)!;
			const actor: ActorExterno = { tenantId: e.tenantId, via: "agente_personal", protocolo: "vxp", clientId: r.clientId, sub: r.sub, clienteId: r.clienteId, alcances: [cap.alcance], grantId: r.grantId };
			const caso = this.nucleo.abrirCaso(e.tenantId, actor);
			const solicitudRel = { binding: "vxp.company_request", relationship: r.id, action: accion, operation: cap.id, target: { [con.objetivo ?? "order_ref"]: orden }, parameters: params };
			const s: Solicitud = { id: randomId("req_", 9), tenantId: e.tenantId, clientId: r.clientId, sub: r.sub, caseId: caso.id, operation: cap.id, orderRef: orden, fecha: "", bodyDigest: huellaJcs(solicitudRel), estado: "received", eventos: [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "company_initiated" }], opId: null, faltan: [], motivo: null, inputs };
			const res = this.nucleo.proponerOperacion(actor, caso.id, cap.id, inputs, null, solicitudRel, s.eventos);
			if (!res.ok) return { status: res.falta === "en_curso" ? 409 : res.falta === "no_encontrado" ? 404 : 422, body: { error: res.falta === "en_curso" ? "resource_busy" : res.falta === "no_encontrado" ? "target_not_found" : "proposal_unavailable", reason: res.falta } };
			res.operacion.interno.relacionId = r.id;
			s.opId = res.operacion.operation_id;
			this.solicitudes.set(s.id, s);
			const v = this.vista(e, s) as { proposal: { id: string } };
			contenido = { request_id: s.id, request_url: `${this.endpoint(e)}/requests/${s.id}`, proposal_id: v.proposal.id, operation_id: res.operacion.operation_id, summary: res.operacion.summary, terms_digest: res.operacion.interno.termsDigest };
		} else if (accion === "despacho.proponer_cambio") {
			if (!pedido) return { status: 404, body: { error: "target_not_found" } };
			const fecha = params.delivery_date;
			if (typeof fecha !== "string" || !FECHA.test(fecha)) return { status: 400, body: { error: "invalid_request" } };
			const cap = e.release.capacidades.find((c) => c.id === ACCIONES_EMPRESA[accion].capacidad)!;
			const actor: ActorExterno = { tenantId: e.tenantId, via: "agente_personal", protocolo: "vxp", clientId: r.clientId, sub: r.sub, clienteId: r.clienteId, alcances: [cap.alcance], grantId: r.grantId };
			const caso = this.nucleo.abrirCaso(e.tenantId, actor);
			const s: Solicitud = {
				id: randomId("req_", 9),
				tenantId: e.tenantId,
				clientId: r.clientId,
				sub: r.sub,
				caseId: caso.id,
				operation: cap.id,
				orderRef: orden,
				fecha,
				bodyDigest: huellaJcs({ operation: cap.id, target: { order_ref: orden }, parameters: { delivery_date: fecha }, relationship: r.id }),
				estado: "received",
				eventos: [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "company_initiated" }],
				opId: null,
				faltan: [],
				motivo: null,
			};
			const res = this.nucleo.proponerReprogramacion(actor, caso.id, orden, fecha, null, { binding: "vxp.company_request", relationship: r.id, action: accion, operation: cap.id, target: { order_ref: orden }, parameters: { delivery_date: fecha } }, s.eventos);
			if (!res.ok) return { status: res.falta === "en_curso" ? 409 : 404, body: { error: res.falta === "en_curso" ? "resource_busy" : "target_not_found" } };
			res.operacion.interno.relacionId = r.id;
			s.opId = res.operacion.operation_id;
			this.solicitudes.set(s.id, s);
			const v = this.vista(e, s) as { proposal: { id: string } };
			contenido = { request_id: s.id, request_url: `${this.endpoint(e)}/requests/${s.id}`, proposal_id: v.proposal.id, operation_id: res.operacion.operation_id, summary: res.operacion.summary, terms_digest: res.operacion.interno.termsDigest };
		} else {
			const resumen = typeof params.summary === "string" ? params.summary.slice(0, 500) : "";
			if (!resumen) return { status: 400, body: { error: "invalid_request" } };
			contenido = { order_ref: orden, summary: resumen };
			// Closed question («confirmar o bloquear»): the agent replies with only one of the options.
			if (ACCIONES_EMPRESA[accion].respuestas) {
				const a = this.relaciones.nuevaAlerta(r, accion, orden, typeof params.expires_in === "number" ? params.expires_in : 3600);
				contenido = { ...contenido, alert_id: a.id, options: a.opciones, reply_url: `${this.endpoint(e)}/relationships/${r.id}/replies`, expires_at: new Date(a.vence * 1000).toISOString() };
			}
		}
		const salida = this.relaciones.emitir(r, accion, contenido);
		this.nucleo.evento(e.tenantId, "-", "relationship.company_request", { relationship: r.id, action: accion, outbox: salida.id });
		await this.relaciones.entregar(salida, this.fetch);
		return { status: 201, body: { outbox_id: salida.id, delivery: salida.entrega, http: salida.http ?? null, content: contenido } };
	}

	// ── Resources ────────────────────────────────────────────────────────────────────────────

	private actor(req: Request, e: Empresa): { actor: ActorExterno; token: TokenNativo } | Response {
		const desafio = (error: string) => json(401, { error }, { "www-authenticate": `DPoP error="${error}", algs="ES256"` });
		const [esquema, valor] = (req.headers.get("authorization") ?? "").split(" ");
		const t = valor ? this.tokens.get(valor) : undefined;
		if (!t || esquema !== "DPoP" || t.exp < ahora() || t.tenantId !== e.tenantId) return desafio("invalid_token");
		const jkt = this.dpop(req, valor);
		if (!jkt || jkt !== t.jkt) return desafio("invalid_dpop_proof");
		const g = t.grantId ? this.del.grants.get(t.grantId) : undefined;
		const vigente = g && !g.revocado && g.expira > ahora();
		return {
			token: vigente ? t : { ...t, rar: [] },
			actor: {
				tenantId: e.tenantId,
				via: "agente_personal",
				protocolo: "vxp",
				clientId: t.clientId,
				sub: t.sub,
				clienteId: vigente ? g.clienteId : null,
				alcances: vigente ? g.alcances : [],
				grantId: vigente ? g.id : null,
			},
		};
	}

	private rarPermite(t: TokenNativo, capacidad: string, recurso: string): boolean {
		return t.rar.some((d) => d.type === RAR_CAPACIDAD && d.actions.includes(capacidad) && (mutado("rar_por_pedido") || d.identifier === recurso));
	}

	private mover(s: Solicitud, hacia: EstadoNativo, motivo: string) {
		if (!transicionLegal(s.estado, hacia)) throw new Error(`transicion_ilegal:${s.estado}->${hacia}`);
		s.eventos.push({ seq: s.eventos.length, from: s.estado, to: hacia, at: new Date().toISOString(), reason: motivo });
		s.estado = hacia;
		if (FINALES.has(hacia)) s.motivo = motivo;
	}

	private op(s: Solicitud): Operacion | null {
		return s.opId ? (this.nucleo.base(s.tenantId).operaciones.get(s.opId) ?? null) : null;
	}

	private vista(e: Empresa, s: Solicitud) {
		const op = this.op(s);
		const estado = op ? op.interno.nativo.estado : s.estado;
		const lim = this.nucleo.limites(e.tenantId);
		const v: Record<string, unknown> = {
			request_id: s.id,
			operation: s.operation,
			target: { [CONECTORES[s.operation]?.objetivo ?? "order_ref"]: s.orderRef },
			state: estado,
			// Normative projection: what a Poppy or A2A agent would see, using only values from its enums.
			projections: { poppy: proyectarPoppy(estado), a2a: proyectarA2A(estado) },
		};
		if (estado === "authorization_required")
			v.authorization = {
				error: "authorization_required",
				authorization_details: s.faltan,
				device_authorization_endpoint: `${this.issuer(e)}/oauth/device`,
				resource: this.endpoint(e),
			};
		if (!op) {
			if (s.motivo) v.reason = s.motivo;
			return v;
		}
		const n = op.interno.nativo;
		v.operation_id = op.operation_id;
		v.proposal = {
			id: `prop_${op.operation_id}_r${op.revision}`,
			revision: op.revision,
			state: estado === "proposed" ? "proposed" : op.confirmation ? "accepted" : estado,
			summary: op.summary,
			terms: op.terms,
			commitment: n.compromiso,
			expires_at: op.expires_at,
			user_approval_required: op.user_approval_required,
			limits: {
				max_revisions: lim.max_revisions,
				revisions_left: Math.max(0, lim.max_revisions - op.revision),
				max_accept_attempts: lim.max_accept_attempts,
				accept_attempts_left: Math.max(0, lim.max_accept_attempts - n.intentosAceptar),
			},
		};
		v.effects = n.efectos;
		v.cancellation = n.cancelacion;
		v.result = op.result;
		if (n.motivoFinal) v.reason = n.motivoFinal;
		v.proof_url = `${this.endpoint(e)}/requests/${s.id}/proof`;
		return v;
	}

	/**
	 * POST /v1/requests with `pedido.crear`: the company quotes with its policy (prices, discounts, shipping)
	 * and the quote becomes the proposal as soon as the customer authorizes the amount.
	 * parameters: { items: [{ sku, quantity }], delivery: { address, comuna, date? }, discount_pct? }
	 */
	private pedirCompra(e: Empresa, actor: ActorExterno, token: TokenNativo, body: Record<string, unknown>, llave: string | null): Response {
		const c = e.comercio;
		const p = (body.parameters ?? {}) as Record<string, unknown>;
		const items = Array.isArray(p.items) ? (p.items as Record<string, unknown>[]).map((x) => ({ sku: String(x?.sku ?? ""), cantidad: Number(x?.quantity) })) : [];
		const entrega = (p.delivery ?? {}) as Record<string, unknown>;
		if (!c || items.length === 0 || items.some((x) => !x.sku || !Number.isInteger(x.cantidad) || x.cantidad < 1) || typeof entrega.address !== "string" || typeof entrega.comuna !== "string")
			return json(400, { error: "invalid_request" });
		if (entrega.date !== undefined && (typeof entrega.date !== "string" || !FECHA.test(entrega.date))) return json(400, { error: "invalid_request" });
		const digest = huellaJcs({ operation: "pedido.crear", parameters: p });
		const clave = `${e.tenantId}|${actor.clientId}|${actor.sub}|${llave}`;
		const previa = llave && !mutado("idempotencia") ? this.solicitudes.get(this.idem.get(clave) ?? "") : undefined;
		if (previa) {
			if (previa.bodyDigest !== digest) return json(409, { error: "idempotency_key_reused", request_id: previa.id });
			if (previa.estado === "authorization_required" && !previa.opId) return this.evaluar(e, previa, actor, token);
			return json(200, this.vista(e, previa));
		}
		const caso = this.nucleo.abrirCaso(e.tenantId, actor);
		const cot = cotizar(c, e.tenantId, caso.id, { items, comuna: String(entrega.comuna).toLowerCase(), direccion: entrega.address, fecha: entrega.date as string | undefined, descuento: typeof p.discount_pct === "number" ? p.discount_pct : undefined });
		if (!cot.ok) return json(422, { error: "quote_unavailable", reason: cot.motivo });
		this.nucleo.guardarCotizacion(e.tenantId, cot.cot);
		this.nucleo.evento(e.tenantId, caso.id, "quote.issued", { cotizacion: cot.cot.id, total: cot.cot.total, via: "vxp.request" });
		const s: Solicitud = {
			id: randomId("req_", 9),
			tenantId: e.tenantId,
			clientId: actor.clientId,
			sub: actor.sub,
			caseId: caso.id,
			operation: "pedido.crear",
			orderRef: "nuevo",
			fecha: cot.cot.despacho.fecha,
			bodyDigest: digest,
			estado: "received",
			eventos: [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "request" }],
			opId: null,
			faltan: [],
			motivo: null,
			cotizacion: cot.cot.id,
		};
		this.solicitudes.set(s.id, s);
		if (llave) this.idem.set(clave, s.id);
		const r = this.evaluar(e, s, actor, token);
		return cot.notas.length ? new Response(r.body, { status: r.status, headers: { ...Object.fromEntries(r.headers), "x-quote-notes": encodeURIComponent(cot.notas.join(" ")) } }) : r;
	}

	/**
	 * POST /v1/requests with a connector-backed capability (stress sandbox).
	 * - reserva.crear: parameters { room_type, check_in, check_out, adults, services?: [{ code, quantity? }], package? }:
	 *   the hotel quotes (public) and the quote becomes the proposal when the customer authorizes the amount.
	 * - reserva.modificar_fechas | reserva.agregar_servicio | reserva.cancelar: target { reservation_ref }.
	 * - pedido.devolver: target { order_ref }.
	 */
	private pedirConector(e: Empresa, actor: ActorExterno, token: TokenNativo, body: Record<string, unknown>, llave: string | null): Response {
		const con = conectorDe(e, String(body.operation))!;
		const target = (body.target ?? {}) as Record<string, unknown>;
		const p = (body.parameters ?? {}) as Record<string, unknown>;
		const digest = huellaJcs({ operation: con.capacidad, target, parameters: p });
		const clave = `${e.tenantId}|${actor.clientId}|${actor.sub}|${llave}`;
		const previa = llave && !mutado("idempotencia") ? this.solicitudes.get(this.idem.get(clave) ?? "") : undefined;
		if (previa) {
			if (previa.bodyDigest !== digest) return json(409, { error: "idempotency_key_reused", request_id: previa.id });
			// Expansion (B.5): the same request was waiting for a permission; with the new permission it is re-evaluated, not duplicated.
			if (previa.estado === "authorization_required" && !previa.opId && !mutado("ampliacion_nueva_solicitud")) return this.evaluar(e, previa, actor, token);
			if (!(previa.estado === "authorization_required" && !previa.opId)) return json(200, this.vista(e, previa));
		}
		let inputs: Record<string, string> | null;
		let orderRef: string;
		const caso = this.nucleo.abrirCaso(e.tenantId, actor);
		if (con.capacidad === "reserva.crear") {
			const h = e.hotel;
			const servicios = Array.isArray(p.services) ? (p.services as Record<string, unknown>[]).map((x) => ({ codigo: String(x?.code ?? ""), ...(Number.isInteger(x?.quantity) ? { cantidad: Number(x.quantity) } : {}) })) : [];
			if (!h || typeof p.room_type !== "string" || typeof p.check_in !== "string" || typeof p.check_out !== "string" || !Number.isInteger(p.adults)) return json(400, { error: "invalid_request" });
			const r = cotizarEstadia(h, e.sistema.hotel!, { tipo: p.room_type, llegada: p.check_in, salida: p.check_out, adultos: Number(p.adults), servicios, paquete: typeof p.package === "string" ? p.package : null }, { tenantId: e.tenantId, caseId: caso.id });
			if (r.contradiccion) this.nucleo.evento(e.tenantId, caso.id, "hotel.fuentes_contradictorias", { detalle: r.contradiccion });
			if (!r.ok) return json(422, { error: "quote_unavailable", reason: r.motivo, notes: r.notas });
			this.nucleo.base(e.tenantId).estadias.set(r.est.id, r.est);
			this.nucleo.evento(e.tenantId, caso.id, "quote.issued", { estadia: r.est.id, total: r.est.total, via: "vxp.request" });
			inputs = { estadia: r.est.id };
			orderRef = "nuevo";
		} else {
			inputs = inputsDesdeApi(con.capacidad, target, p);
			if (!inputs) return json(400, { error: "invalid_request" });
			orderRef = con.recurso(inputs);
		}
		const s: Solicitud = { id: randomId("req_", 9), tenantId: e.tenantId, clientId: actor.clientId, sub: actor.sub, caseId: caso.id, operation: con.capacidad, orderRef, fecha: inputs.llegada ?? "", bodyDigest: digest, estado: "received", eventos: [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "request" }], opId: null, faltan: [], motivo: null, inputs };
		this.solicitudes.set(s.id, s);
		if (llave) this.idem.set(clave, s.id);
		return this.evaluar(e, s, actor, token);
	}

	/** The cap (CLP) the customer approved for this capability over this resource; null if there is no grant; ∞ if unlimited. */
	private topeDe(t: TokenNativo, capacidad: string, recurso: string): number | null {
		const d = t.rar.find((x) => x.type === RAR_CAPACIDAD && x.actions.includes(capacidad) && (mutado("rar_por_pedido") || x.identifier === recurso));
		return d ? (d.limits?.max_total_clp ?? Number.POSITIVE_INFINITY) : null;
	}

	/** Where and how to request the missing permission (B.5: the agent requests it and returns to the SAME request). */
	private comoAutorizar(e: Empresa) {
		return { device_authorization_endpoint: `${this.issuer(e)}/oauth/device`, resource: this.endpoint(e) };
	}

	private evaluarConector(e: Empresa, s: Solicitud, actor: ActorExterno, token: TokenNativo): Response {
		const necesario: DetalleRar = { type: RAR_CAPACIDAD, actions: [s.operation], identifier: s.orderRef };
		const tope = this.topeDe(token, s.operation, s.orderRef);
		const pedirPermiso = (faltan: DetalleRar[], motivo: string, extra: Record<string, unknown> = {}) => {
			s.faltan = faltan;
			if (s.estado !== "authorization_required") this.mover(s, "authorization_required", motivo);
			return json(202, { ...this.vista(e, s), ...extra });
		};
		// Account data is not drafted (nor is its existence revealed) before the customer authorizes. The quote
		// for a new booking is public: its total goes in the permission being requested.
		const estadia = s.orderRef === "nuevo" ? this.nucleo.base(e.tenantId).estadias.get(s.inputs?.estadia ?? "") : undefined;
		if (!actor.clienteId || tope === null)
			return pedirPermiso([estadia ? { ...necesario, limits: { max_total_clp: estadia.total } } : necesario], "authorization_details_missing", estadia ? { quote: estadia } : {});
		const red = this.nucleo.redactarConector(e.tenantId, s.operation, s.inputs ?? {});
		if (red.ok && red.r.monto > tope && !mutado("tope_conector"))
			return pedirPermiso([{ ...necesario, limits: { max_total_clp: red.r.monto } }], "amount_above_approved_limit", estadia ? { quote: estadia } : {});
		const viva = [...this.solicitudes.values()].find((x) => x !== s && x.tenantId === s.tenantId && x.clientId === s.clientId && x.sub === s.sub && x.operation === s.operation && x.orderRef === s.orderRef && x.orderRef !== "nuevo" && this.op(x)?.interno.nativo.estado === "proposed");
		if (viva) return json(409, { error: "request_exists", request_id: viva.id });
		const r = this.nucleo.proponerOperacion(actor, s.caseId, s.operation, s.inputs ?? {}, null, { binding: "vxp.request", operation: s.operation, target: { [CONECTORES[s.operation]?.objetivo ?? "order_ref"]: s.orderRef }, inputs: s.inputs ?? {} }, s.eventos);
		if (!r.ok) {
			const motivo = r.falta === "en_curso" ? "resource_busy" : r.falta === "no_encontrado" ? "target_not_found" : r.falta === "sin_vinculo" ? "customer_not_linked" : Array.isArray(r.falta) || r.falta === "sign_in" ? "not_authorized" : String(r.falta);
			this.mover(s, "failed", motivo);
			return json(motivo === "target_not_found" ? 404 : 409, { error: motivo, ...this.vista(e, s) });
		}
		s.opId = r.operacion.operation_id;
		return json(201, this.vista(e, s));
	}

	/** The maximum total the customer approved for creating orders, or null if there is no grant for it. */
	private topeCompra(t: TokenNativo): number | null {
		const d = t.rar.find((x) => x.type === RAR_CAPACIDAD && x.identifier === "nuevo" && x.actions.includes("pedido.crear"));
		return d ? (d.limits?.max_total_clp ?? Number.POSITIVE_INFINITY) : null;
	}

	private evaluarCompra(e: Empresa, s: Solicitud, actor: ActorExterno, token: TokenNativo): Response {
		const cot = this.nucleo.cotizacionDe(e.tenantId, s.cotizacion ?? "");
		if (!cot) return json(404, { error: "quote_not_found" });
		const tope = this.topeCompra(token);
		if (!actor.clienteId || tope === null || (cot.total > tope && !mutado("tope_compra"))) {
			s.faltan = [{ type: RAR_CAPACIDAD, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: cot.total } }];
			if (s.estado !== "authorization_required") this.mover(s, "authorization_required", tope !== null && cot.total > tope ? "amount_above_approved_limit" : "authorization_details_missing");
			return json(202, { ...this.vista(e, s), quote: cot });
		}
		const r = this.nucleo.proponerCompra(actor, s.caseId, cot.id, null, { binding: "vxp.request", operation: "pedido.crear", quote: cot.id }, s.eventos);
		if (!r.ok) {
			const motivo = r.falta === "cotizacion_vencida" ? "quote_expired" : r.falta === "sin_vinculo" ? "customer_not_linked" : "not_authorized";
			this.mover(s, "failed", motivo);
			return json(409, { error: motivo, ...this.vista(e, s) });
		}
		s.opId = r.operacion.operation_id;
		return json(201, this.vista(e, s));
	}

	private evaluar(e: Empresa, s: Solicitud, actor: ActorExterno, token: TokenNativo): Response {
		if (s.operation === "pedido.crear") return this.evaluarCompra(e, s, actor, token);
		if (conectorDe(e, s.operation)) return this.evaluarConector(e, s, actor, token);
		const necesario: DetalleRar = { type: RAR_CAPACIDAD, actions: [s.operation], identifier: s.orderRef };
		if (!actor.clienteId || !this.rarPermite(token, s.operation, s.orderRef)) {
			s.faltan = [necesario];
			if (s.estado !== "authorization_required") this.mover(s, "authorization_required", "authorization_details_missing");
			return json(202, this.vista(e, s));
		}
		// A live native request on the same order and from the same owner: it is not overwritten.
		const viva = [...this.solicitudes.values()].find((x) => x !== s && x.tenantId === s.tenantId && x.clientId === s.clientId && x.sub === s.sub && x.orderRef === s.orderRef && this.op(x)?.interno.nativo.estado === "proposed");
		if (viva) return json(409, { error: "request_exists", request_id: viva.id });
		const r = this.nucleo.proponerReprogramacion(actor, s.caseId, s.orderRef, s.fecha, null, { binding: "vxp.request", operation: s.operation, target: { order_ref: s.orderRef }, parameters: { delivery_date: s.fecha } }, s.eventos);
		if (!r.ok) {
			// Foreign and nonexistent resources get the same response (Operations §3.2).
			const motivo = r.falta === "en_curso" ? "resource_busy" : r.falta === "no_encontrado" ? "target_not_found" : "not_authorized";
			this.mover(s, "failed", motivo);
			return json(r.falta === "en_curso" ? 409 : 404, { error: motivo, ...this.vista(e, s) });
		}
		s.opId = r.operacion.operation_id;
		return json(201, this.vista(e, s));
	}

	private async cuerpo(req: Request): Promise<Record<string, unknown> | null> {
		try {
			const t = await req.text();
			const v = t ? JSON.parse(t) : {};
			return v && typeof v === "object" && !Array.isArray(v) ? v : null;
		} catch {
			return null;
		}
	}

	async atender(req: Request, e: Empresa, resto: string[]): Promise<Response> {
		const r = this.actor(req, e);
		if (r instanceof Response) return r;
		const { actor, token } = r;
		const [coleccion, id, accion, ...sobra] = resto;
		if (sobra.length) return json(404, { error: "not_found" });

		// VXP Relationship: the agent answers a closed question from the company. Only one of the options,
		// once, before it expires and with the relationship active. Nothing else: the reply opens no other action.
		if (coleccion === "relationships" && id && accion === "replies" && req.method === "POST") {
			const rel = this.relaciones.todas.get(id);
			if (!rel || rel.tenantId !== e.tenantId || rel.clientId !== actor.clientId || rel.sub !== actor.sub) return json(404, { error: "relationship_not_found" });
			const vigente = this.relacionVigente(id, e.tenantId);
			if (typeof vigente === "string") return json(403, { error: vigente });
			const body = (await this.cuerpo(req)) ?? {};
			const r = this.responderAlerta(e, rel, String(body.alert_id ?? ""), String(body.decision));
			return json(r.status, r.body);
		}

		// VXP Relationship: the agent reads or revokes ITS relationship (same client_id and sub).
		if (coleccion === "relationships" && id && !accion) {
			const rel = this.relaciones.todas.get(id);
			if (!rel || rel.tenantId !== e.tenantId || rel.clientId !== actor.clientId || rel.sub !== actor.sub) return json(404, { error: "relationship_not_found" });
			if (req.method === "GET") return json(200, this.vistaRelacion(rel));
			if (req.method === "DELETE") {
				this.relaciones.revocar(id, "agente");
				this.nucleo.evento(e.tenantId, "-", "relationship.revoked", { relationship: id, by: "agente" });
				return json(200, this.vistaRelacion(rel));
			}
			return json(405, { error: "method_not_allowed" });
		}

		if (coleccion === "requests" && !id && req.method === "POST") {
			const llave = req.headers.get("idempotency-key");
			if (!llave && !mutado("idempotencia")) return json(400, { error: "idempotency_key_required" });
			const body = await this.cuerpo(req);
			const target = body?.target as Record<string, unknown> | undefined;
			const params = body?.parameters as Record<string, unknown> | undefined;
			const cap = e.release.capacidades.find((c) => c.id === body?.operation);
			if (body && cap?.id === "pedido.crear") return this.pedirCompra(e, actor, token, body, llave);
			if (body && cap && conectorDe(e, cap.id)) return this.pedirConector(e, actor, token, body, llave);
			if (!body || !cap || cap.efecto !== "write" || typeof target?.order_ref !== "string" || typeof params?.delivery_date !== "string" || !FECHA.test(params.delivery_date))
				return json(400, { error: "invalid_request" });
			const digest = huellaJcs({ operation: body.operation, target: { order_ref: target.order_ref }, parameters: { delivery_date: params.delivery_date } });
			const clave = `${e.tenantId}|${actor.clientId}|${actor.sub}|${llave}`;
			const previa = llave && !mutado("idempotencia") ? this.solicitudes.get(this.idem.get(clave) ?? "") : undefined;
			if (previa) {
				if (previa.bodyDigest !== digest) return json(409, { error: "idempotency_key_reused", request_id: previa.id });
				// Same key and same body: the same request. If it was waiting for permissions, it is re-evaluated.
				if (previa.estado === "authorization_required" && !previa.opId) return this.evaluar(e, previa, actor, token);
				return json(200, this.vista(e, previa));
			}
			const caso = this.nucleo.abrirCaso(e.tenantId, actor);
			const s: Solicitud = {
				id: randomId("req_", 9),
				tenantId: e.tenantId,
				clientId: actor.clientId,
				sub: actor.sub,
				caseId: caso.id,
				operation: cap.id,
				orderRef: target.order_ref,
				fecha: params.delivery_date,
				bodyDigest: digest,
				estado: "received",
				eventos: [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "request" }],
				opId: null,
				faltan: [],
				motivo: null,
			};
			this.solicitudes.set(s.id, s);
			if (llave) this.idem.set(clave, s.id);
			return this.evaluar(e, s, actor, token);
		}

		if (coleccion === "requests" && id) {
			const s = this.solicitudes.get(id);
			if (!s || s.tenantId !== e.tenantId || s.clientId !== actor.clientId || s.sub !== actor.sub) return json(404, { error: "request_not_found" });
			const op = s.opId ? this.nucleo.operacionDe(actor, s.opId, null) : null;
			if (op === "not_found") return json(404, { error: "request_not_found" });
			if (op === "sign_in_required") return json(403, { error: "sign_in_required" });
			if (req.method === "GET" && !accion) {
				// Reading reconciles: it queries the system and the carrier. It never repeats the action.
				if (op && op.state === "in_progress" && op.interno.ejecutada) this.nucleo.verificar(e.tenantId, op);
				return json(200, this.vista(e, s));
			}
			if (req.method === "GET" && accion === "events") {
				const eventos = op ? op.interno.nativo.eventos : s.eventos;
				return json(200, { request_id: s.id, events: eventos.map((x) => ({ ...x, poppy: proyectarPoppy(x.to), a2a: proyectarA2A(x.to) })) });
			}
			if (req.method === "GET" && accion === "proof") {
				if (!op || !this.nucleo.pruebas?.tiene(e.tenantId, op.operation_id)) return json(404, { error: "request_not_found" });
				return json(200, this.nucleo.pruebas.paquete(e.tenantId, op.operation_id));
			}
			if (req.method === "POST" && accion === "cancel") {
				if (!op) {
					if (!FINALES.has(s.estado)) this.mover(s, "cancelled", "cancelled_before_proposal");
					return json(200, this.vista(e, s));
				}
				this.nucleo.cancelar(e.tenantId, op);
				return json(FINALES.has(op.interno.nativo.estado) ? 200 : 202, this.vista(e, s));
			}
			return json(404, { error: "not_found" });
		}

		if (coleccion === "proposals" && id && req.method === "POST" && (accion === "accept" || accion === "counter")) {
			const m = id.match(/^prop_(op_[A-Za-z0-9_-]+)_r(\d+)$/);
			const s = m ? [...this.solicitudes.values()].find((x) => x.opId === m[1] && x.clientId === actor.clientId && x.sub === actor.sub && x.tenantId === e.tenantId) : undefined;
			const op = s?.opId ? this.nucleo.operacionDe(actor, s.opId, null) : "not_found";
			if (!s || !m || op === "not_found") return json(404, { error: "proposal_not_found" });
			if (op === "sign_in_required") return json(403, { error: "sign_in_required" });
			const rev = Number(m[2]);
			const body = (await this.cuerpo(req)) ?? {};
			const n = op.interno.nativo;
			if (accion === "counter") {
				const fecha = (body.proposed_terms as Record<string, unknown> | undefined)?.delivery_date;
				if (n.estado !== "proposed") return json(409, { error: "proposal_not_acceptable", ...this.vista(e, s) });
				if (conectorDe(e, op.interno.intent.capability)) {
					if (rev !== op.revision) return json(409, { error: "terms_changed", ...this.vista(e, s) });
					const res = this.nucleo.contraproponerOperacion(actor, op, pideDesdeApi(op.interno.intent.capability, (body.proposed_terms ?? {}) as Record<string, unknown>));
					if (!res.ok) return json(409, { error: res.motivo === "negotiation_limit_exceeded" ? "negotiation_limit_exceeded" : "counter_rejected", reason: res.motivo, ...this.vista(e, s) });
					return json(200, { ...this.vista(e, s), notes: res.notas });
				}
				if (op.interno.intent.capability === "pedido.crear") {
					if (rev !== op.revision) return json(409, { error: "terms_changed", ...this.vista(e, s) });
					const pt = (body.proposed_terms ?? {}) as Record<string, unknown>;
					const res = this.nucleo.contraproponerCompra(actor, op, { ...(typeof pt.discount_pct === "number" ? { descuento: pt.discount_pct } : {}), ...(typeof fecha === "string" && FECHA.test(fecha) ? { fecha } : {}) });
					if (!res.ok) return json(409, { error: res.motivo === "negotiation_limit_exceeded" ? "negotiation_limit_exceeded" : "counter_rejected", reason: res.motivo, ...this.vista(e, s) });
					return json(200, { ...this.vista(e, s), notes: res.notas });
				}
				const res = this.nucleo.contraproponer(actor, op, { base_revision: rev, proposed_terms: { despacho_nuevo: fecha }, note: body.note });
				if (n.estado === "failed" && n.motivoFinal === "negotiation_limit_exceeded") return json(409, { error: "negotiation_limit_exceeded", ...this.vista(e, s) });
				if (!res.ok) return json(409, { error: "counter_rejected", ...this.vista(e, s) });
				return json(200, this.vista(e, s));
			}
			// accept
			if (op.confirmation?.revision === rev) return json(200, this.vista(e, s));
			if (n.estado === "expired") return json(409, { error: "proposal_expired", ...this.vista(e, s) });
			if (n.estado !== "proposed") return json(409, { error: "proposal_not_acceptable", ...this.vista(e, s) });
			if (rev !== op.revision) {
				n.intentosAceptar += 1;
				if (n.intentosAceptar >= this.nucleo.limites(e.tenantId).max_accept_attempts && !mutado("intentos")) {
					op.result = { summary: "Se superó el número de intentos de aceptación. No se hizo ningún cambio.", data: { effects: [] } };
					this.nucleo.transicion(op, "failed", "attempt_limit_exceeded");
					this.nucleo.firmarResultadoPublico(e.tenantId, op);
					return json(409, { error: "attempt_limit_exceeded", ...this.vista(e, s) });
				}
				return json(409, { error: "terms_changed", ...this.vista(e, s) });
			}
			// The server re-verifies permissions before executing (design 0.1 §3.E). A company-initiated
			// proposal is accepted with the relationship's delegation, if the relationship is still active.
			// Who approves and with which delegation. A company-initiated proposal is accepted with the delegation
			// of the RELATIONSHIP (the one the customer approved for that), if the relationship and that delegation are
			// still active and the acceptor is the same agent, the same user and the same customer. Stress sandbox (failure
			// confirmed in B-H): previously the token of that same grant was required, and after an expansion (new grant)
			// or when the 1 h pass expired, no relationship proposal could be accepted.
			let quienAprueba = actor;
			if (op.interno.relacionId) {
				const rel = this.relacionVigente(op.interno.relacionId, e.tenantId);
				if (typeof rel === "string") return json(403, { error: rel });
				if ((rel.clientId !== actor.clientId || rel.sub !== actor.sub || rel.clienteId !== actor.clienteId) && !mutado("relacion_otra_identidad")) return json(403, { error: "authorization_required", ...this.comoAutorizar(e) });
				const g = this.del.grants.get(rel.grantId)!;
				if (!mutado("aceptar_con_permiso_del_llamador")) quienAprueba = { ...actor, alcances: g.alcances, grantId: g.id };
			} else if (conectorDe(e, op.interno.intent.capability)) {
				const monto = op.interno.monto ?? 0;
				const tope = this.topeDe(token, op.interno.intent.capability, s.orderRef);
				if (!actor.clienteId || tope === null || (monto > tope && !mutado("tope_conector")))
					return json(403, { error: "authorization_required", authorization_details: [{ type: RAR_CAPACIDAD, actions: [op.interno.intent.capability], identifier: s.orderRef, ...(monto > 0 ? { limits: { max_total_clp: monto } } : {}) }], ...this.comoAutorizar(e) });
			} else if (op.interno.intent.capability === "pedido.crear") {
				const tope = this.topeCompra(token);
				if (!actor.clienteId || tope === null || (Number(op.terms.total) > tope && !mutado("tope_compra")))
					return json(403, { error: "authorization_required", authorization_details: [{ type: RAR_CAPACIDAD, actions: ["pedido.crear"], identifier: "nuevo", limits: { max_total_clp: Number(op.terms.total) } }], ...this.comoAutorizar(e) });
			} else if (!mutado("reverificar_al_aceptar") && (!actor.clienteId || !this.rarPermite(token, s.operation, s.orderRef))) {
				return json(403, { error: "authorization_required", authorization_details: [{ type: RAR_CAPACIDAD, actions: [s.operation], identifier: s.orderRef }], ...this.comoAutorizar(e) });
			}
			const aprobado = typeof body.approved_by === "string" ? body.approved_by : "user";
			const res = await this.nucleo.confirmar(quienAprueba, op, rev, aprobado);
			if (res.status !== 200) return json(res.status, res.body);
			return json(FINALES.has(op.interno.nativo.estado) ? 200 : 202, this.vista(e, s));
		}
		return json(404, { error: "not_found" });
	}
}

// PACT 1.0 face (A2A 1.0 HTTP+JSON) over the core. SOVRAS is the «Provider»: it hosts each
// company's agent («Brand»), and a personal agent registers once to talk to all of them.
//
// PACT has no step to confirm an exact action: with the delegated token, a message is enough.
// SOVRAS does not execute writes from text, so approval of the frozen revision is requested
// out of band, over the company's WhatsApp line (CIBA-style).

import { responder } from "./agente.ts";
import type { Delegaciones, Directorio, PlataformaPact } from "./identidad.ts";
import { type ClaveFirma, ahora, decodeJwt, nuevaClaveEs256, randomId, sha256, signJwt, verifyWith } from "./jose.ts";
import type { ActorExterno, Empresa, Nucleo, Operacion } from "./nucleo.ts";
import { VERSION_PRUEBA, bloqueConfianza, bloqueOutcomeProof, codigoVisible } from "./prueba.ts";
import { sondeo } from "./vincular.ts";
import { URI_PROTOCOLO, proyectarA2A } from "./estados.ts";

/** Under A2A the native state goes in metadata, next to the A2A value (extensions.md «Limitations»). */
const anotar = (op: Operacion) => ({ [URI_PROTOCOLO]: { state: op.interno.nativo.estado, a2a_state: proyectarA2A(op.interno.nativo.estado) } });

/**
 * A2A extension URI; the key in `message.metadata` is the same URI (A2A 1.0.1 §4.6.2). It carries
 * the version: an incompatible change requires a new URI (A2A 1.0.1 §4.6.3; SPEC §4.2.1).
 */
export const EXT_PRUEBA_URI = `https://vxpprotocol.org/ext/proof/v${VERSION_PRUEBA}`;
const MAX_INTENTOS_APROBACION = 5;

type Contexto = {
	id: string;
	tenantId: string;
	iss: string;
	sub: string;
	cuenta: string | null;
	caseId: string;
	respuestas: Map<string, unknown>;
	operacion: string | null;
};

type AprobacionWhatsapp = { tenantId: string; operationId: string; revision: number; codigoHash: string; actor: ActorExterno; telefono: string };

const A2A = { "content-type": "application/a2a+json" };
const a2a = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: A2A });
const vacio = (status: number, headers: Record<string, string> = {}) => new Response(null, { status, headers });
const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const STATUS: Record<string, [number, string]> = {
	INVALID_PARAMS: [400, "INVALID_ARGUMENT"],
	CONTENT_TYPE_NOT_SUPPORTED: [400, "INVALID_ARGUMENT"],
	UNSUPPORTED_OPERATION: [400, "FAILED_PRECONDITION"],
	PUSH_NOTIFICATION_NOT_SUPPORTED: [400, "FAILED_PRECONDITION"],
	TASK_NOT_FOUND: [404, "NOT_FOUND"],
	INTERNAL: [500, "INTERNAL"],
};
function error(reason: string, message: string): Response {
	const [code, status] = STATUS[reason];
	return a2a(code, {
		error: { code, status, message, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason, domain: "a2a-protocol.org" }] },
	});
}
const noAutenticado = (extra = "") => vacio(401, { "www-authenticate": `Bearer realm="a2a"${extra}` });

/** A2A routes: [pattern, methods]. Routing happens before authentication (PACT §2.2). */
const RUTAS: [RegExp, string[], string][] = [
	[/^message:send$/, ["POST"], "send"],
	[/^message:stream$/, ["POST"], "unsupported"],
	[/^tasks$/, ["GET"], "list"],
	[/^tasks\/[^/:]+$/, ["GET"], "get"],
	[/^tasks\/[^/:]+:cancel$/, ["POST"], "cancel"],
	[/^tasks\/[^/:]+:subscribe$/, ["POST", "GET"], "unsupported"],
	[/^extendedAgentCard$/, ["GET"], "unsupported"],
	[/^tasks\/[^/:]+\/pushNotificationConfigs$/, ["GET", "POST"], "push"],
	[/^tasks\/[^/:]+\/pushNotificationConfigs\/[^/]+$/, ["GET", "DELETE"], "push"],
];

export class CaraPact {
	private readonly contextos = new Map<string, Contexto>();
	private readonly aprobaciones = new Map<string, AprobacionWhatsapp>();
	/** WhatsApp replies that did not match, per company and phone (SPEC §6.3 rule 3). */
	private readonly intentos = new Map<string, number>();
	/** One signing key per company: one company's tokens and receipts do not validate at another. */
	private readonly claves = new Map<string, ClaveFirma>();

	private readonly nucleo: Nucleo;
	private readonly dir: Directorio;
	private readonly del: Delegaciones;
	private readonly plataformas: PlataformaPact[];
	private readonly providerOrigin: string;
	private readonly authOrigin: string;
	private readonly delegacion: Set<string>;

	constructor(
		nucleo: Nucleo,
		dir: Directorio,
		del: Delegaciones,
		plataformas: PlataformaPact[],
		providerOrigin: string,
		authOrigin: string,
		delegacion: Set<string>,
	) {
		this.nucleo = nucleo;
		this.dir = dir;
		this.del = del;
		this.plataformas = plataformas;
		this.providerOrigin = providerOrigin;
		this.authOrigin = authOrigin;
		this.delegacion = delegacion;
	}

	/** Access log: the `iss`/`sub` the agent's JWT CLAIMS (verified later, when handling the request). */
	quienJwt(header: string | null): { clientId: string; sub: string } | null {
		const [esquema, token] = (header ?? "").split(" ");
		const d = esquema === "Bearer" && token ? decodeJwt(token) : null;
		return d && typeof d.payload.iss === "string" ? { clientId: d.payload.iss, sub: String(d.payload.sub ?? "") } : null;
	}

	audience() {
		return `${this.providerOrigin}/a2a`;
	}
	private iface(e: Empresa) {
		return `${this.providerOrigin}/a2a/${e.tenantId}`;
	}
	private clave(e: Empresa) {
		let k = this.claves.get(e.tenantId);
		if (!k) {
			k = nuevaClaveEs256();
			this.claves.set(e.tenantId, k);
		}
		return k;
	}

	/** `outcome-proof` block (SPEC §4.2). Under PACT every write requires `company_channel` (§6.3 rule 6). */
	private bloque(e: Empresa) {
		const issuer = this.nucleo.pruebas?.issuer(e.tenantId) ?? `${this.authOrigin}/e/${e.slug}`;
		return bloqueOutcomeProof({
			issuer,
			authOrigin: this.authOrigin,
			operadorIssuer: this.nucleo.pruebas?.operadorIssuer ?? "",
			origenRegistro: this.nucleo.pruebas?.origenRegistro ?? "",
			vinculos: this.nucleo.pruebas?.vinculos(e.tenantId),
			// Under PACT the endpoint is the interface's one, with PACT credentials (§12.2.7); the Poppy one
			// requires a DPoP Session Token that a PACT client does not have.
			endpoint: `${this.iface(e)}/vxp/proof`,
			capacidades: e.release.capacidades
				.filter((c) => c.efecto === "write")
				.map((c) => ({ name: c.id, effect: c.efecto, aprobacion: "operator_reported_channel_approval" as const })),
			canales: ["whatsapp"],
		});
	}

	/** Extension metadata for an operation: goes next to `pact.receipt`, which is left untouched (§12.2.2). */
	private metaPrueba(e: Empresa, op: Operacion): Record<string, unknown> {
		const latest = this.nucleo.pruebas?.ultima(e.tenantId, op.operation_id);
		if (!latest) return {};
		return { [EXT_PRUEBA_URI]: { operation_id: op.operation_id, latest, bundle_url: `${this.iface(e)}/vxp/proof/operations/${op.operation_id}` } };
	}

	/** Package over the same PACT credentials: agent JWT + delegation (SPEC §12.2.7). */
	private async paquete(req: Request, e: Empresa, ruta: string): Promise<Response> {
		const contra = ruta.endsWith("/counter");
		if (req.method !== (contra ? "POST" : "GET")) return vacio(405);
		const quien = await this.agente(req);
		if (!quien) return noAutenticado();
		const del = await this.delegado(req, e, quien);
		if (del instanceof Response) return del;
		if (!del) return noAutenticado(', error="invalid_token"');
		const id = decodeURIComponent(ruta.replace(/^(?:vxp|sovras)\/proof\/operations\//, "").replace(/\/counter$/, ""));
		const op = this.nucleo.operacionDe(del, id, null);
		if (typeof op === "string" || !this.nucleo.pruebas?.tiene(e.tenantId, id)) return json(404, { error: "operation_not_found" });
		if (contra) return this.contrapropuesta(req, e, del, op);
		if (op.state === "in_progress" && op.interno.ejecutada) this.nucleo.verificar(e.tenantId, op);
		return json(200, this.nucleo.pruebas.paquete(e.tenantId, id));
	}

	/**
	 * Structured counterproposal under PACT (SPEC §7.2, §12.2.6): PACT §4.1 only allows text parts
	 * in `message:send`, so it goes through this extension endpoint, with PACT credentials. The
	 * company signs the new revision and its approval is requested again over WhatsApp.
	 */
	private async contrapropuesta(req: Request, e: Empresa, actor: ActorExterno, op: Operacion): Promise<Response> {
		let body: Record<string, unknown>;
		try {
			body = JSON.parse((await req.text()) || "{}");
		} catch {
			return json(400, { error: "invalid_request" });
		}
		const res = this.nucleo.contraproponer(actor, op, body as Parameters<Nucleo["contraproponer"]>[2]);
		if (!res.ok) {
			if (res.error === "counter_rejected") return json(409, { error: "counter_rejected", operation: this.nucleo.visible(op), ...this.metaPrueba(e, op) });
			return json(403, { error: res.error });
		}
		const texto = this.pedirAprobacion(e, actor, res.operacion);
		return json(200, { text: texto, operation: this.nucleo.visible(res.operacion), ...this.metaPrueba(e, res.operacion) });
	}

	/** RFC 8414 metadata of the PACT authorization server, with the copy of the trust block (SPEC §9.9.1). */
	metadataAs(e: Empresa): Response {
		return this.delegacion.has(e.tenantId) ? json(200, this.metadata(e)) : vacio(404);
	}

	card(e: Empresa) {
		const iface = this.iface(e);
		const delegada = this.delegacion.has(e.tenantId);
		return {
			name: e.nombre,
			description: e.descripcion,
			supportedInterfaces: [{ url: iface, protocolBinding: "HTTP+JSON", protocolVersion: "1.0" }],
			provider: { organization: "SOVRAS", url: "https://sovras.io" },
			version: e.release.version,
			capabilities: {
				streaming: false,
				pushNotifications: false,
				extendedAgentCard: false,
				// A2A 1.0.1 AgentExtension (SPEC §12.2.1). `required: false`: it is data-only, and the
				// official PACT client never sends `A2A-Extensions`.
				extensions: [
					{
						uri: EXT_PRUEBA_URI,
						description: "Prueba firmada del resultado de cada operación con efecto (VXP Proof 0.1).",
						required: false,
						params: this.bloque(e),
					},
				],
			},
			securitySchemes: {
				platformJwt: { httpAuthSecurityScheme: { scheme: "Bearer", bearerFormat: "JWT" } },
				...(delegada
					? {
							userDelegation: {
								oauth2SecurityScheme: {
									flows: {
										deviceCode: {
											deviceAuthorizationUrl: `${iface}/oauth/device_authorization`,
											tokenUrl: `${iface}/oauth/token`,
											scopes: e.alcances,
										},
									},
									oauth2MetadataUrl: `${iface}/oauth/.well-known/oauth-authorization-server`,
								},
							},
						}
					: {}),
			},
			securityRequirements: [
				{ schemes: { platformJwt: { list: [] } } },
				...(delegada ? [{ schemes: { platformJwt: { list: [] }, userDelegation: { list: [] } } }] : []),
			],
			defaultInputModes: ["text/plain"],
			defaultOutputModes: ["text/plain"],
			skills: e.hotel
				? [{ id: "reservas", name: "Reservas", description: "Disponibilidad, tarifas, reservas, cambios de fecha, servicios y cancelaciones del hotel.", tags: ["hotel", "reservas"] }]
				: [{ id: "pedidos", name: "Pedidos", description: "Estado de pedidos y cambio de fecha de despacho.", tags: ["pedidos", "despacho"] }],
		};
	}

	/** Personal agent JWT (PACT §3.2). Returns (iss, sub) or null. */
	private async agente(req: Request): Promise<{ iss: string; sub: string } | null> {
		const [esquema, token] = (req.headers.get("authorization") ?? "").split(" ");
		if (esquema !== "Bearer" || !token) return null;
		const d = decodeJwt(token);
		if (!d || (d.header.alg !== "ES256" && d.header.alg !== "RS256")) return null;
		const p = d.payload;
		const plataforma = this.plataformas.find((x) => x.issuer === p.iss);
		if (!plataforma?.enabled) return null;
		if (!(await this.dir.verificar(token, plataforma.jwksUri, ["ES256", "RS256"]))) return null;
		const t = ahora();
		if (p.aud !== this.audience()) return null;
		if (typeof p.iat !== "number" || p.iat > t + 30) return null;
		if (typeof p.exp !== "number" || p.exp < t - 30 || p.exp - p.iat > 300) return null;
		if (typeof p.sub !== "string" || !p.sub) return null;
		return { iss: plataforma.issuer, sub: p.sub };
	}

	async atender(req: Request, e: Empresa | undefined, ruta: string): Promise<Response> {
		if (ruta === ".well-known/agent-card.json") {
			if (req.method !== "GET") return vacio(405);
			return e ? json(200, this.card(e)) : vacio(404);
		}
		if (ruta.startsWith("oauth/")) return this.oauth(req, e, ruta.slice(6));
		if (/^(?:vxp|sovras)\/proof\/operations\/[^/]+(\/counter)?$/.test(ruta)) return e ? this.paquete(req, e, ruta) : vacio(404);
		const match = RUTAS.find(([re]) => re.test(ruta));
		if (!match) return vacio(404);
		if (!match[1].includes(req.method)) return vacio(405);
		const quien = await this.agente(req);
		if (!quien) return noAutenticado();
		if (!e) return vacio(404);
		const tipo = match[2];
		if (tipo === "unsupported") return error("UNSUPPORTED_OPERATION", "Unsupported operation");
		if (tipo === "push") return error("PUSH_NOTIFICATION_NOT_SUPPORTED", "Push notifications are not supported");
		if (tipo === "get" || tipo === "cancel") {
			const id = ruta.split("/")[1].replace(/:cancel$/, "");
			return error("TASK_NOT_FOUND", `Task not found: ${id}`);
		}
		if (tipo === "list") {
			const size = new URL(req.url).searchParams.get("pageSize");
			const pageSize = size === null ? 50 : Number(size);
			if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) return error("INVALID_PARAMS", "pageSize must be 1-100");
			return a2a(200, { tasks: [], nextPageToken: "", pageSize, totalSize: 0 });
		}
		const r = await this.enviar(req, e, quien);
		// A2A 1.0.1 (extensions, «Extension Activation»): if the client activates the extension, the response
		// SHOULD list it. The metadata goes to every client anyway (SPEC §12.2.2): it is data and ignorable.
		const pedidas = (req.headers.get("a2a-extensions") ?? "").split(",").map((x) => x.trim());
		if (pedidas.includes(EXT_PRUEBA_URI)) r.headers.set("a2a-extensions", EXT_PRUEBA_URI);
		return r;
	}

	private async delegado(req: Request, e: Empresa, quien: { iss: string; sub: string }): Promise<ActorExterno | Response | null> {
		const header = req.headers.get("x-a2a-user-delegation");
		if (!header) return null;
		const malo = noAutenticado(', error="invalid_token"');
		const [esquema, token] = header.split(" ");
		const d = esquema === "Bearer" && token ? decodeJwt(token) : null;
		if (!d || !verifyWith(d, this.clave(e).publicJwk, ["ES256"])) return malo;
		const p = d.payload;
		const g = this.del.grants.get(String(p.grant_id));
		if (p.iss !== `${this.iface(e)}/oauth` || p.aud !== this.iface(e) || typeof p.exp !== "number" || p.exp < ahora()) return malo;
		if (p.client_id !== quien.iss || !g || g.revocado || g.tenantId !== e.tenantId || g.clientId !== quien.iss) return malo;
		// The grant belongs to the pseudonymous user who requested it: another `sub` of the same agent cannot use it.
		if (g.sub !== quien.sub || p.sub !== g.clienteId) return malo;
		const alcances = String(p.scope).split(" ").filter((a) => g.alcances.includes(a));
		return { tenantId: e.tenantId, via: "agente_personal", protocolo: "pact", clientId: quien.iss, sub: quien.sub, clienteId: g.clienteId, alcances, grantId: g.id };
	}

	private async enviar(req: Request, e: Empresa, quien: { iss: string; sub: string }): Promise<Response> {
		let body: { message?: Record<string, unknown> };
		try {
			body = JSON.parse(await req.text());
		} catch {
			return error("INVALID_PARAMS", "Invalid JSON");
		}
		const m = body?.message;
		if (!m || typeof m !== "object") return error("INVALID_PARAMS", "message is required");
		if (m.taskId !== undefined) return error("TASK_NOT_FOUND", "Task not found");
		if (m.role !== "ROLE_USER") return error("INVALID_PARAMS", "role must be ROLE_USER");
		const parts = Array.isArray(m.parts) ? (m.parts as Record<string, unknown>[]) : [];
		if (parts.length === 0) return error("INVALID_PARAMS", "parts is required");
		if (parts.some((p) => typeof p?.text !== "string")) return error("CONTENT_TYPE_NOT_SUPPORTED", "Only text parts are supported");
		const texto = parts.map((p) => String(p.text)).join("\n");
		if (!texto.trim()) return error("INVALID_PARAMS", "text is blank");
		if (typeof m.messageId !== "string" || !m.messageId) return error("INVALID_PARAMS", "messageId is required");

		const del = await this.delegado(req, e, quien);
		if (del instanceof Response) return del;
		const actor: ActorExterno = del ?? {
			tenantId: e.tenantId,
			via: "agente_personal",
			protocolo: "pact",
			clientId: quien.iss,
			sub: quien.sub,
			clienteId: null,
			alcances: [],
			grantId: null,
		};

		let ctx: Contexto | undefined;
		if (m.contextId !== undefined) {
			ctx = this.contextos.get(String(m.contextId));
			if (!ctx || ctx.tenantId !== e.tenantId || ctx.iss !== quien.iss || ctx.sub !== quien.sub) return error("INVALID_PARAMS", "Unknown contextId");
			if (ctx.cuenta && actor.clienteId && ctx.cuenta !== actor.clienteId) return error("INVALID_PARAMS", "Context belongs to another user");
			const guardada = ctx.respuestas.get(m.messageId);
			if (guardada) return a2a(200, guardada);
		} else {
			const caso = this.nucleo.abrirCaso(e.tenantId, { clientId: quien.iss, sub: quien.sub });
			ctx = { id: crypto.randomUUID(), tenantId: e.tenantId, iss: quien.iss, sub: quien.sub, cuenta: null, caseId: caso.id, respuestas: new Map(), operacion: null };
			this.contextos.set(ctx.id, ctx);
		}
		if (actor.clienteId) ctx.cuenta = actor.clienteId;

		const respuesta = this.turno(e, ctx, actor, texto);
		ctx.respuestas.set(m.messageId, respuesta);
		return a2a(200, respuesta);
	}

	private turno(e: Empresa, ctx: Contexto, actor: ActorExterno, texto: string): unknown {
		// Follow-up on an operation in this context: what happened, according to verification.
		if (ctx.operacion && /(c[oó]mo va|estado|listo|status|qu[eé] pas[oó])/i.test(texto)) {
			const op = this.nucleo.operacionDe(actor, ctx.operacion, null);
			if (typeof op !== "string") {
				if (op.state === "in_progress" && op.interno.ejecutada) this.nucleo.verificar(e.tenantId, op);
				const estado = op.result?.summary ?? (op.state === "proposed" ? "Esperando que apruebes el cambio en WhatsApp." : "En curso.");
				return this.mensaje(e, ctx, actor, estado, { usados: [], acciones: [] }, { "vxpprotocol.org/operation": this.nucleo.visible(op), ...anotar(op), ...this.metaPrueba(e, op) });
			}
		}
		const r = responder(this.nucleo, actor, ctx.caseId, texto, null);
		if (r.necesita && this.delegacion.has(e.tenantId)) {
			return {
				task: {
					id: randomId("t-", 9),
					contextId: ctx.id,
					status: { state: "TASK_STATE_AUTH_REQUIRED", message: { messageId: randomId("r-", 9), contextId: ctx.id, role: "ROLE_AGENT", parts: [{ text: r.text }] } },
					metadata: {
						"pact.missingScopes": r.necesita.alcances,
						"pact.verificationUriComplete": `${this.authOrigin}/e/${e.slug}/vincular/inicio`,
					},
				},
			};
		}
		const extra: Record<string, unknown> = {};
		let text = r.text;
		if (r.operacion) {
			ctx.operacion = r.operacion.operation_id;
			// The `request` already cites this turn's PACT receipt, unmodified (SPEC §9.4.1, §12.2.4).
			text = this.pedirAprobacion(e, actor, r.operacion);
			extra["vxpprotocol.org/operation"] = this.nucleo.visible(r.operacion);
			Object.assign(extra, anotar(r.operacion));
			Object.assign(extra, this.metaPrueba(e, r.operacion));
		}
		return this.mensaje(e, ctx, actor, text, r, extra, r.data);
	}

	/** Out-of-band WhatsApp approval of the exact revision (digest), like CIBA with binding_message. */
	private pedirAprobacion(e: Empresa, actor: ActorExterno, op: Operacion): string {
		const cliente = e.clientes.find((c) => c.id === actor.clienteId);
		if (!cliente) return "No pude pedir la aprobación: la cuenta no tiene un WhatsApp verificado. No hice ningún cambio.";
		// `display_code` derived from the terms digest (SPEC §6.3 rule 2): not a secret; it binds the
		// reply to this revision. Security comes from the channel: the linked number must reply.
		const codigo = codigoVisible(op.interno.termsDigest);
		// A pending approval for an earlier revision of the same operation stops being valid.
		for (const [k, v] of this.aprobaciones) if (v.tenantId === e.tenantId && v.operationId === op.operation_id) this.aprobaciones.delete(k);
		// Round 4 (M5): outside the 24 h window only a Meta-approved approval template goes out
		// (with company, agent, `summary` and code as variables; its category is yet to be
		// validated with Meta). Without service consent, or with neither window nor template, nothing is
		// delivered: the operation stays `proposed`, is not executed, and the caller is told what to do.
		const agente = new URL(actor.clientId).host;
		const entrega = this.nucleo.enviarWhatsApp(e.tenantId, cliente, {
			proposito: "aprobacion",
			texto: `${e.nombre}: tu asistente (${agente}) pidió esto: ${op.summary} Para aprobarlo responde APROBAR ${codigo}. Si no lo pediste tú, no respondas.`,
			textoPlantilla: `[plantilla de aprobación] ${e.nombre}: tu asistente (${agente}) pidió esto: ${op.summary} Para aprobarlo responde APROBAR ${codigo}. Si no lo pediste tú, no respondas.`,
		});
		if (!entrega.entregado) {
			this.nucleo.evento(e.tenantId, op.interno.caseId, "approval.not_delivered", { canal: "whatsapp", revision: op.revision, motivo: entrega.motivo, huella: op.interno.huella });
			return entrega.motivo === "sin_consentimiento"
				? `${op.summary} No pude pedir la aprobación por WhatsApp: el cliente no tiene autorizados mensajes de servicio de ${e.nombre}. No hice ningún cambio.`
				: `${op.summary} No pude enviar la aprobación por WhatsApp: el cliente no le ha escrito a ${e.nombre} en las últimas 24 horas. Cuando el cliente le escriba a la línea de ${e.nombre}, vuelve a pedírmelo y se la envío. No hice ningún cambio.`;
		}
		this.aprobaciones.set(sha256(`${e.tenantId}:${cliente.telefono}:${codigo}`), {
			tenantId: e.tenantId,
			operationId: op.operation_id,
			revision: op.revision,
			codigoHash: sha256(codigo),
			actor,
			telefono: cliente.telefono,
		});
		this.nucleo.evento(e.tenantId, op.interno.caseId, "approval.requested_out_of_band", { canal: "whatsapp", via: entrega.via, revision: op.revision, huella: op.interno.huella });
		return `${op.summary} Le envié al cliente la aprobación por WhatsApp, al número de su cuenta. No se hace ningún cambio hasta que la apruebe ahí.`;
	}

	/** Customer reply on the company's WhatsApp line (channel inbound). */
	async whatsappEntrante(tenantId: string, telefono: string, texto: string): Promise<boolean> {
		// Every inbound message opens the 24 h window (round 4, M5), whether or not it approves anything.
		this.nucleo.whatsappRecibido(tenantId, telefono);
		const codigo = texto.match(/APROBAR\s+(\d{6})/i)?.[1];
		if (!codigo) return false;
		const quien = `${tenantId}:${telefono}`;
		if ((this.intentos.get(quien) ?? 0) >= MAX_INTENTOS_APROBACION) return false;
		const clave = sha256(`${tenantId}:${telefono}:${codigo}`);
		const ap = this.aprobaciones.get(clave);
		if (!ap) {
			this.intentos.set(quien, (this.intentos.get(quien) ?? 0) + 1);
			return false;
		}
		// Single use.
		this.aprobaciones.delete(clave);
		this.intentos.delete(quien);
		// The delegation may have been revoked between the proposal and the reply.
		const g = ap.actor.grantId ? this.del.grants.get(ap.actor.grantId) : undefined;
		if (!g || g.revocado || g.expira < ahora()) return false;
		const op = this.nucleo.operacionDe(ap.actor, ap.operationId, null);
		if (typeof op === "string") return false;
		// Round 3 (m4): an operation that is no longer proposed (expired, cancelled, already confirmed) is
		// not approved, and the reply is not reported as accepted.
		if (op.state !== "proposed") {
			this.nucleo.evento(tenantId, op.interno.caseId, "approval.ignored_out_of_band", { canal: "whatsapp", estado: op.state });
			return false;
		}
		this.nucleo.evento(tenantId, op.interno.caseId, "approval.received_out_of_band", { canal: "whatsapp", telefono_verificado: true });
		const r = await this.nucleo.confirmar(ap.actor, op, ap.revision, "user", {
			canal: "whatsapp",
			display_code: codigo,
			inbound_text: texto,
			// In production this is the id the provider returns (Meta's wamid); the test simulates it.
			provider_message_id: randomId("wamid.PRUEBA.", 9),
		});
		return r.status === 200 && op.confirmation?.revision === ap.revision;
	}

	private mensaje(
		e: Empresa,
		ctx: Contexto,
		actor: ActorExterno,
		text: string,
		uso: { usados: string[]; acciones: { tool: string; argsHash?: string }[] },
		extra: Record<string, unknown>,
		data?: Record<string, unknown>,
	) {
		const metadata: Record<string, unknown> = { ...extra };
		if (actor.grantId) {
			// Signed receipt on every response under delegation (PACT §5.6).
			const claims = {
				grantId: actor.grantId,
				user: actor.clienteId!,
				pa: actor.clientId,
				brand: this.iface(e),
				scopesUsed: uso.usados,
				actions: uso.acciones,
				ts: new Date().toISOString(),
			};
			const k = this.clave(e);
			metadata["pact.receipt"] = { jws: signJwt({ alg: "ES256", kid: k.publicJwk.kid }, claims, k.privateKey), claims };
		}
		return {
			message: {
				messageId: randomId("r-", 9),
				contextId: ctx.id,
				role: "ROLE_AGENT",
				parts: [{ text }, ...(data ? [{ data }] : [])],
				...(Object.keys(metadata).length ? { metadata } : {}),
			},
		};
	}

	// ── Delegated authority (PACT §5): device code + «Vincular con WhatsApp» ─────────────────

	private metadata(e: Empresa) {
		const iface = this.iface(e);
		return {
			issuer: `${iface}/oauth`,
			device_authorization_endpoint: `${iface}/oauth/device_authorization`,
			token_endpoint: `${iface}/oauth/token`,
			jwks_uri: `${iface}/oauth/jwks.json`,
			scopes_supported: Object.keys(e.alcances),
			grant_types_supported: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
			// Identical copy of the company's trust block. The company, in turn, lists this issuer
			// in `pact` of its own metadata: so a PACT-only client anchors the proof with what PACT gives
			// it (SPEC §9.9.1, anchor via the PACT authorization server).
			...(this.nucleo.pruebas
				? {
						vxp_proof: bloqueConfianza({
							issuer: this.nucleo.pruebas.issuer(e.tenantId),
							authOrigin: this.authOrigin,
							operadorIssuer: this.nucleo.pruebas.operadorIssuer,
							origenRegistro: this.nucleo.pruebas.origenRegistro,
							vinculos: this.nucleo.pruebas.vinculos(e.tenantId),
						}),
					}
				: {}),
		};
	}

	private async oauth(req: Request, e: Empresa | undefined, ruta: string): Promise<Response> {
		if (!e || !this.delegacion.has(e.tenantId)) return vacio(404);
		if (ruta === ".well-known/oauth-authorization-server" && req.method === "GET") return json(200, this.metadata(e));
		if (ruta === "jwks.json" && req.method === "GET") return json(200, { keys: [this.clave(e).publicJwk] });
		if (req.method !== "POST" || (ruta !== "device_authorization" && ruta !== "token")) return vacio(404);
		const quien = await this.agente(req);
		if (!quien) return noAutenticado();
		const form = new URLSearchParams(await req.text());
		if (form.get("client_id") !== quien.iss) return json(401, { error: "invalid_client" });

		if (ruta === "device_authorization") {
			const alcances = (form.get("scope") ?? "").split(" ").filter(Boolean);
			if (alcances.length === 0 || alcances.some((a) => !(a in e.alcances))) return json(400, { error: "invalid_scope" });
			const d = this.del.nuevoDispositivo({ tenantId: e.tenantId, protocolo: "pact", clientId: quien.iss, clientName: new URL(quien.iss).host, sub: quien.sub, alcancesPedidos: alcances });
			const uri = `${this.authOrigin}/e/${e.slug}/vincular`;
			return json(200, { device_code: d.deviceCode, user_code: d.userCode, verification_uri: uri, verification_uri_complete: `${uri}?user_code=${d.userCode}`, expires_in: 600, interval: d.intervalo });
		}

		const grantType = form.get("grant_type");
		if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
			const d = this.del.dispositivos.get(form.get("device_code") ?? "");
			if (!d || d.protocolo !== "pact" || d.tenantId !== e.tenantId || d.clientId !== quien.iss || d.sub !== quien.sub) return json(400, { error: "invalid_grant" });
			const estado = sondeo(d);
			if (estado !== "listo") return json(400, { error: estado });
			const { grant, refresh } = this.del.nuevoGrant(d, quien.sub);
			d.estado = "consumido";
			return json(200, this.tokenDe(e, grant.id, refresh));
		}
		if (grantType === "refresh_token") {
			const hit = this.del.porRefresh(form.get("refresh_token") ?? "", quien.iss);
			if (!hit || hit.grant.tenantId !== e.tenantId || hit.grant.sub !== quien.sub) return json(400, { error: "invalid_grant" });
			if (hit.reuso) {
				// Reuse of a rotated refresh token = possible theft: the whole delegation is revoked (RFC 9700 §4.14).
				hit.grant.revocado = true;
				return json(400, { error: "invalid_grant" });
			}
			if (hit.grant.revocado || hit.grant.expira < ahora()) return json(400, { error: "invalid_grant" });
			return json(200, this.tokenDe(e, hit.grant.id, this.del.rotar(hit.grant)));
		}
		return json(400, { error: "unsupported_grant_type" });
	}

	private tokenDe(e: Empresa, grantId: string, refresh: string) {
		const g = this.del.grants.get(grantId)!;
		const t = ahora();
		const k = this.clave(e);
		const access = signJwt(
			{ alg: "ES256", kid: k.publicJwk.kid, typ: "JWT" },
			{ iss: `${this.iface(e)}/oauth`, aud: this.iface(e), sub: g.clienteId, client_id: g.clientId, scope: g.alcances.join(" "), grant_id: g.id, iat: t, exp: t + 3600 },
			k.privateKey,
		);
		return { token_type: "Bearer", access_token: access, refresh_token: refresh, expires_in: 3600, scope: g.alcances.join(" ") };
	}
}

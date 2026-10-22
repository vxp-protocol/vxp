// Operational core of the reference implementation, small and in memory: capabilities frozen
// per version, action intent, policy with its own authority (`agente_personal`), prepared
// execution with a digest (exact human review), outcome verification and an event log. The
// protocols (Poppy, PACT and the native profile) are faces of this core: none of them executes
// anything on its own.
//
// Isolation: all state lives in `bases.get(tenantId)`, and the tenantId always comes from the
// verified credential, never from the request body.

import { randomBytes } from "node:crypto";
import { randomId, sha256 } from "./jose.ts";
import { type EmisorPruebas, type Kind, type Rol, huellaJcs, huellaTerminos, jcs } from "./prueba.ts";
import { type EstadoNativo, FINALES, proyectarPoppy, transicionLegal } from "./estados.ts";
import { mutado } from "./mutar.ts";
import type { Carriles } from "./carriles.ts";
import { type Comercio, type Cotizacion, negociar, textoCotizacion } from "./comercio.ts";
import type { Estadia, Hotel, SistemaHotel } from "./hotel.ts";
import type { Pagos } from "./pagos.ts";
import { type Conector, type Ctx, type Redaccion, CONECTORES, conectorDe, pideDesdeApi } from "./conectores.ts";

/** Evidence of an approval that arrived over the channel the company already authenticates (SPEC §6.3). */
export type AprobacionCanal = { canal: "whatsapp"; display_code: string; inbound_text: string; provider_message_id: string };

export type Efecto = "read" | "write";

export type Capacidad = {
	id: string;
	efecto: Efecto;
	/** Delegated scope that enables it. A scope is what the end customer approves. */
	alcance: string;
	descripcion: string;
	/**
	 * Read-back (SPEC §9.4.2 and §9.4.7): for each term that describes the effect, the field of the
	 * company system that confirms it. The `read_back` observes those terms under the same name.
	 */
	lecturaDeVuelta?: Record<string, string>;
};

/**
 * The operator's canonical customer.
 *
 * Round 4 (M6): the canonical customer is NOT the ERP customer. `erp` is the link between the two, with
 * its evidence, just as a contact identity ties a number to a customer: without a link, the agent
 * neither sees nor changes anything in the company system. `whatsapp` is what the line knows about
 * that person (round 4, M5): when they last wrote (opens Meta's 24 h window) and whether they gave
 * service consent (`communication_consent`, purpose `service`).
 */
export type Cliente = {
	id: string;
	nombre: string;
	telefono: string;
	erp: { id: string; evidencia: string } | null;
	whatsapp: { ultimaEntrada: string | null; consentimientoServicio: "inbound_message" | "form" | null };
};

export type Pedido = {
	id: string;
	/** The **ERP** customer (not the operator's canonical one). */
	clienteId: string;
	producto: string;
	despacho: string;
	direccion: string;
	estado: "preparando" | "en_ruta" | "entregado" | "anulado" | "devolucion_en_curso";
	/** External carrier that must accept the change (design 0.1 §3.D, `carrier_acceptance`). */
	transportista?: string;
	/** Shipment held by the customer's decision (VXP Relationship, «bloquear»). */
	retenido?: boolean;
	/** Order born from a purchase: its quote, items and total (what verification reads back). */
	cotizacion?: string;
	articulos?: { sku: string; cantidad: number; precio_unitario: number; descuento_pct: number }[];
	total?: number;
	pago?: string;
	anulado?: boolean;
};

/**
 * Simulated carrier: a third party with its own API. `solicitar` is the only call with an effect;
 * `consultar` only reads. The test sets the response to `solicitar` per order.
 */
export type Transportista = {
	respuesta: Record<string, "acepta" | "rechaza" | "no_responde">;
	confirmado: Record<string, "accepted" | "rejected" | "pending">;
	solicitudes: { pedidoId: string; fecha: string; at: string }[];
	consultas: number;
};

/** Negotiation limits (design 0.1 §3.D): revisions, validity and attempts. */
export type Limites = { max_revisions: number; proposal_ttl_seconds: number; max_accept_attempts: number };
export const LIMITES_POR_DEFECTO: Limites = { max_revisions: 3, proposal_ttl_seconds: 900, max_accept_attempts: 3 };

export type Efecto_ = { system: "erp" | "carrier" | "pms" | "payment"; change: string; applied: boolean; reverted?: boolean; status?: string };

/** What the native protocol knows about an operation, beyond its Poppy projection. */
export type Nativo = {
	estado: EstadoNativo;
	eventos: { seq: number; from: EstadoNativo | null; to: EstadoNativo; at: string; reason: string }[];
	compromiso: { mode: "firm" | "conditional"; requires: string[] };
	efectos: Efecto_[];
	cancelacion: null | { requested_at: string; status: "requested" | "not_stopped" | "stopped"; reversal_promised: false };
	intentosAceptar: number;
	motivoFinal: string | null;
};

export type Empresa = {
	tenantId: string;
	slug: string;
	nombre: string;
	/** Subdomain the company points to SOVRAS (CNAME), where poppy.json is published. */
	dominio: string;
	descripcion: string;
	alcances: Record<string, string>;
	release: { version: string; capacidades: Capacidad[] };
	agentesPersonales: { modo: "abierto" | "lista"; permitidos: string[] };
	/** Institutional rule: shifting by more than this many days requires a person to decide. */
	diasSinRevision: number;
	/**
	 * Round 4 (M1): written review rule of the `agente_personal` authority. What an agent sends is
	 * third-party content. `regla_de_la_empresa`: the customer's exact approval of the frozen
	 * revision authorizes the write, and a company person decides only if the company's rule requires
	 * it (SPEC §6.5). `toda_escritura`: every write additionally waits for a company person, which is
	 * the strictest rule for untrusted content. Choosing between the two, and for which
	 * capabilities, is each company's decision.
	 */
	reglaRevisionAgentes: "regla_de_la_empresa" | "toda_escritura";
	/** Round 4 (M5): Meta-approved templates on the company's line, by purpose. */
	plantillasWhatsApp: { autenticacion: boolean; aprobacion: boolean };
	horario: string;
	clientes: Cliente[];
	/** The company system (ERP). The test simulates it; in production it is a connector. */
	sistema: {
		pedidos: Pedido[];
		proximaFalla?: "definitiva" | "desconocida";
		transportista?: Transportista;
		/** Stress sandbox: hotel PMS, simulated payment provider and recorded returns. */
		hotel?: SistemaHotel;
		pagos?: Pagos;
		devoluciones?: { id: string; pedido: string; tipo: "devolucion" | "anulacion"; articulos: { sku: string; cantidad: number; precio_unitario: number }[]; reembolso: number; retiro: string | null; at: string }[];
	};
	limites?: Limites;
	/** Catalog and commercial policy, if the company sells (quote, negotiate, new order). */
	comercio?: Comercio;
	/** Traditional channels the company has (VXP). WhatsApp is not required of every company: by default, all of them. */
	canales?: Partial<{ whatsapp: boolean; chat_web: boolean; voz: boolean }>;
	/** Hotel (stress sandbox): room types, services, package, policy and simulated channel manager. */
	hotel?: Hotel;
	/** Returns policy (stress sandbox). */
	politicaDevolucion?: { diasDesdeEntrega: number; despachoReembolsable: boolean; retiro: string };
};

/** Who is asking, verified: the personal agent, the user it names and, if they linked their account, the customer. */
export type ActorExterno = {
	tenantId: string;
	via: "agente_personal";
	protocolo: "poppy" | "pact" | "vxp";
	clientId: string;
	sub: string;
	clienteId: string | null;
	alcances: string[];
	grantId: string | null;
};

export type ActionIntent = {
	capability: string;
	inputs: Record<string, string>;
	reason: string;
	expectedEffect: Efecto;
};

export type EstadoOperacion =
	| "proposed"
	| "in_progress"
	| "succeeded"
	| "failed"
	| "cancelled"
	| "expired";

export type Operacion = {
	operation_id: string;
	revision: number;
	state: EstadoOperacion;
	summary: string;
	terms: Record<string, unknown>;
	expires_at?: string;
	user_approval_required: boolean;
	confirmation: { revision: number; approved_by: "user" | "standing_permission"; confirmed_at: string } | null;
	result: { summary: string; data?: Record<string, unknown> } | null;
	// What does not go out over the protocol.
	interno: {
		caseId: string;
		intent: ActionIntent;
		huella: string;
		dueno: { protocolo: ActorExterno["protocolo"]; clientId: string; sub: string; clienteId: string | null; sesion: string | null };
		revisionEmpresa: { id: string; estado: "pendiente" | "aprobada" | "rechazada"; motivo: string } | null;
		ejecutada: boolean;
		/** Terms digest of the current revision (SPEC §9.3), the one the company signs. */
		termsDigest: string;
		/** Digest of the `counter` the next revision answers (SPEC §7.2). */
		counterPendiente: string | null;
		metodoAprobacion: "agent_asserted" | "company_channel" | null;
		nativo: Nativo;
		/** Digest of the last signed `outcome` or `correction` (VXP Proof): what a correction cites. */
		ultimoFinal: string | null;
		/** If the company proposed it within a bilateral relationship (VXP Relationship), its id. */
		relacionId?: string;
		/** What this revision may charge the customer (CLP): against the cap of their authorization (RFC 9396 `limits`). */
		monto?: number;
	};
};

export type EstadoCaso = "open" | "running" | "waiting_review" | "completed" | "failed" | "needs_attention";

export type Caso = { id: string; origin: "external"; estado: EstadoCaso; externalActorRef: string };

export type EventoCaso = { caseId: string; eventType: string; payload: Record<string, unknown>; at: string };

/** Why the customer is being messaged (round 4, M5). Each purpose has its template on Meta. */
export type PropositoWhatsApp = "autenticacion" | "aprobacion";

export type EntregaWhatsApp =
	| { entregado: true; via: "ventana_de_servicio" | "plantilla" }
	| { entregado: false; motivo: "sin_consentimiento" | "ventana_cerrada_sin_plantilla" };

/** Meta's customer service window: 24 h since the person's last message. */
export const VENTANA_WHATSAPP_MS = 24 * 3_600_000;

/**
 * Facts that the tool gateway's pre-read hands to Policy (round 4, M6). Policy does not read the
 * company system: it decides on these facts.
 */
export type HechosDePolicy = {
	/** What the ERP said about the named resource, compared with the ERP customer linked to the canonical one. */
	recurso?: "propio" | "ajeno_o_inexistente" | "sin_vinculo";
	/** If the company's institutional rule requires a person for these terms, its reason. */
	reglaEmpresa?: string | null;
};

export type DecisionPolicy = { decision: "allow" | "deny" | "review"; basis: string; falta?: string[] | "sign_in"; motivo?: string };

export type Base = {
	casos: Map<string, Caso>;
	eventos: EventoCaso[];
	operaciones: Map<string, Operacion>;
	whatsappSalida: { telefono: string; texto: string; at: string; via: "ventana_de_servicio" | "plantilla"; proposito: PropositoWhatsApp }[];
	feedback: { clientId: string; sub: string; task: string; description: string; at: string }[];
	/** Issued quotes (public: no account required). */
	cotizaciones: Map<string, Cotizacion>;
	/** Hotel stay quotes (public, like the hardware store's). */
	estadias: Map<string, Estadia>;
};

export class Nucleo {
	readonly empresas = new Map<string, Empresa>();
	private readonly bases = new Map<string, Base>();
	/** Outcome proof issuer. Every step with an effect leaves its signed link. */
	readonly pruebas: EmisorPruebas | null;
	/** Anti-insistence lanes and caps (null = disabled, as in the contract tests). */
	carriles: Carriles | null = null;
	/** Public origin of the gateway (for links the company hands out, such as the customer approval link). */
	urlBase: string | null = null;
	/**
	 * Origin of the links a company hands to ITS customer (approve, change, authorize, agreement): the
	 * company's own domain, never another's (test agent B, Oct 21 11:03: the hotel's link went out with the
	 * hardware store's domain). The /e/<slug>/… routes are served the same on the company's domain.
	 */
	urlDe(e: Empresa): string | null {
		if (!this.urlBase) return null;
		const local = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(e.dominio);
		return `${local ? "http" : "https"}://${e.dominio}`;
	}
	/** Sandbox policy clock (hours ahead): lets tests cross cancellation or modification deadlines. */
	desfaseMs = 0;

	constructor(empresas: Empresa[], pruebas: EmisorPruebas | null = null) {
		this.pruebas = pruebas;
		for (const empresa of empresas) {
			this.empresas.set(empresa.tenantId, empresa);
			this.bases.set(empresa.tenantId, {
				casos: new Map(),
				eventos: [],
				operaciones: new Map(),
				whatsappSalida: [],
				feedback: [],
				cotizaciones: new Map(),
					estadias: new Map(),
			});
		}
	}

	// ── Company WhatsApp line (round 4, M5) ─────────────────────────────────────────────────

	/**
	 * Message the customer over the company's line, under Meta's and SOVRAS's rules:
	 * - approving terms requires service consent (`communication_consent`, purpose `service`); the
	 *   linking code was requested by the person on the page, so it does not require it;
	 * - within the 24 h window since the person's last message, free text;
	 * - outside it, only a Meta-approved template for that purpose. The authentication template has
	 *   fixed text: it names neither the agent nor the permissions (the page shows that);
	 * - if it cannot be delivered, nothing is faked: the caller leaves the operation `proposed`.
	 */
	enviarWhatsApp(tenantId: string, cliente: Cliente, m: { proposito: PropositoWhatsApp; texto: string; textoPlantilla: string }): EntregaWhatsApp {
		const empresa = this.empresa(tenantId);
		if (m.proposito === "aprobacion" && !cliente.whatsapp.consentimientoServicio) return { entregado: false, motivo: "sin_consentimiento" };
		const ultima = cliente.whatsapp.ultimaEntrada ? Date.parse(cliente.whatsapp.ultimaEntrada) : Number.NaN;
		const abierta = Number.isFinite(ultima) && Date.now() - ultima < VENTANA_WHATSAPP_MS;
		const via = abierta ? "ventana_de_servicio" : empresa.plantillasWhatsApp[m.proposito] ? "plantilla" : null;
		if (!via) return { entregado: false, motivo: "ventana_cerrada_sin_plantilla" };
		this.base(tenantId).whatsappSalida.push({
			telefono: cliente.telefono,
			texto: via === "plantilla" ? m.textoPlantilla : m.texto,
			at: new Date().toISOString(),
			via,
			proposito: m.proposito,
		});
		return { entregado: true, via };
	}

	/** An inbound message from the person opens (or renews) the 24 h window and supports `service`. */
	whatsappRecibido(tenantId: string, telefono: string): Cliente | undefined {
		const norm = (t: string) => t.replace(/[^\d+]/g, "");
		const cliente = this.empresa(tenantId).clientes.find((c) => norm(c.telefono) === norm(telefono));
		if (cliente) {
			cliente.whatsapp.ultimaEntrada = new Date().toISOString();
			cliente.whatsapp.consentimientoServicio ??= "inbound_message";
		}
		return cliente;
	}

	/** Linking with WhatsApp records service consent with its source (`form`) and its evidence. */
	registrarConsentimientoServicio(tenantId: string, clienteId: string, evidencia: string): void {
		const cliente = this.empresa(tenantId).clientes.find((c) => c.id === clienteId);
		if (!cliente) return;
		cliente.whatsapp.consentimientoServicio ??= "form";
		this.base(tenantId).eventos.push({ caseId: "-", eventType: "consent.granted", payload: { cliente: clienteId, canal: "whatsapp", proposito: "service", fuente: cliente.whatsapp.consentimientoServicio, evidencia }, at: new Date().toISOString() });
	}

	porSlug(slug: string): Empresa | undefined {
		return [...this.empresas.values()].find((e) => e.slug === slug);
	}

	base(tenantId: string): Base {
		const base = this.bases.get(tenantId);
		if (!base) throw new Error("tenant_desconocido");
		return base;
	}

	empresa(tenantId: string): Empresa {
		const empresa = this.empresas.get(tenantId);
		if (!empresa) throw new Error("tenant_desconocido");
		return empresa;
	}

	/** Does this company accept this personal agent? The list belongs to the company, not the platform. */
	aceptaAgente(tenantId: string, clientId: string): boolean {
		const { agentesPersonales } = this.empresa(tenantId);
		return agentesPersonales.modo === "abierto" || agentesPersonales.permitidos.includes(clientId);
	}

	abrirCaso(tenantId: string, actor: { clientId: string; sub: string }): Caso {
		const caso: Caso = {
			id: randomId("case_", 9),
			origin: "external",
			estado: "open",
			// Same pattern as `whatsapp:<contacto>` and `phone:<From>`: the agent and its pseudonymous user.
			externalActorRef: `agent:${actor.clientId}#${actor.sub}`,
		};
		this.base(tenantId).casos.set(caso.id, caso);
		this.evento(tenantId, caso.id, "case.opened", { origin: "external", externalActorRef: caso.externalActorRef });
		return caso;
	}

	evento(tenantId: string, caseId: string, eventType: string, payload: Record<string, unknown>): void {
		this.base(tenantId).eventos.push({ caseId, eventType, payload, at: new Date().toISOString() });
	}

	// ── Outcome proof (SPEC §9) ───────────────────────────────────────────────────────────────

	private eslabon(tenantId: string, op: Operacion, rol: Rol, kind: Kind, body: Record<string, unknown>, ocultos: Record<string, Record<string, unknown>> = {}): string | null {
		if (!this.pruebas || !this.pruebas.tiene(tenantId, op.operation_id)) return null;
		return this.pruebas.emitir(tenantId, op.operation_id, rol, kind, body, ocultos).digest;
	}

	/** The company signs every revision it issues; an unsigned revision is not confirmed (SPEC §7.1). */
	private firmarTerminos(tenantId: string, op: Operacion): void {
		this.eslabon(tenantId, op, "empresa", "terms", {
			revision: op.revision,
			terms_digest: op.interno.termsDigest,
			capability: op.interno.intent.capability,
			expires_at: op.expires_at ?? null,
			user_approval_required: op.user_approval_required,
			// Round 3 (m3): the institutional rule is signed into the revision. If it is `true`, an
			// `execution` without `company_review: approved` is an `order_violation` for any verifier.
			company_review_required: op.interno.revisionEmpresa !== null,
			// Round 3 (M1): which terms describe the effect and must be observed by the read-back, under
			// the same name, for `succeeded` to hold (SPEC §9.4.2, §9.4.7).
			read_back_terms: [...Object.keys(this.capacidad(tenantId, op).lecturaDeVuelta ?? {}), ...op.interno.nativo.compromiso.requires],
			// The commitment of this revision (design 0.1 §3.D). A condition in `requires` is one more
			// term the read-back must observe with its value (`carrier_acceptance`).
			commitment: op.interno.nativo.compromiso,
			...(op.interno.counterPendiente ? { answers: op.interno.counterPendiente } : {}),
		});
		op.interno.counterPendiente = null;
	}

	private capacidad(tenantId: string, op: Operacion): Capacidad {
		return this.empresa(tenantId).release.capacidades.find((c) => c.id === op.interno.intent.capability)!;
	}

	/**
	 * Outcome asserted by the company. The system writes the `summary`: only its digest is included.
	 *
	 * VXP Proof: the first outcome goes as `outcome`; everything learned afterwards goes as a `correction`
	 * on the last final one (SPEC 11.1), never as a second `outcome`. `unknown` is a signed outcome, not
	 * the absence of one: the agent receives evidence that the company does not know yet.
	 * `lectura` is the digest of the `read_back` backing a correction to `succeeded` (SPEC 8.3).
	 */
	private firmarResultado(tenantId: string, op: Operacion, opciones: { estado?: "unknown"; lectura?: string | null } = {}): void {
		const kinds = new Set(this.pruebas?.declaraciones(tenantId, op.operation_id).map((d) => d.kind) ?? []);
		// What the company claims (the verifier does not use it): named after the actual root of each level (SPEC §9.7).
		const asegura = ["issuer_key_attested"];
		if (kinds.has("execution")) asegura.push("operator_observed");
		if (kinds.has("read_back")) asegura.push("operator_reported_read_back");
		if (op.interno.metodoAprobacion) asegura.push(op.interno.metodoAprobacion === "company_channel" ? "operator_reported_channel_approval" : "operator_reported_agent_approval");
		const estado = opciones.estado ?? op.state;
		const comun = { state: estado, revision: op.revision, terms_digest: op.interno.termsDigest, result_summary_digest: huellaJcs(op.result?.summary ?? "") };
		const digest = op.interno.ultimoFinal
			? this.eslabon(tenantId, op, "empresa", "correction", { ...comun, corrects: op.interno.ultimoFinal, ...(opciones.lectura ? { read_back: opciones.lectura } : {}) })
			: this.eslabon(tenantId, op, "empresa", "outcome", { ...comun, claimed_assurance: asegura, third_party: [] });
		if (digest) op.interno.ultimoFinal = digest;
	}

	/**
	 * VXP Proof, outcome not known: the company signs `unknown` with what is known in the summary.
	 * The operation stays open (`pending_verification` or `waiting_human`) and Poppy sees it as
	 * `in_progress`: never `failed` without knowing (operations §6).
	 */
	private firmarIncierto(tenantId: string, op: Operacion, resumen: string): void {
		op.result = { summary: resumen, data: { effects: op.interno.nativo.efectos } };
		this.firmarResultado(tenantId, op, { estado: "unknown" });
	}

	// ── Native state machine (design 0.1 §4; src/estados.ts) ──────────────────────────────

	/**
	 * The only way to change an operation's state. The native state is the source; `op.state`
	 * (Poppy) is its projection. An illegal transition is a programming error: it throws.
	 */
	transicion(op: Operacion, hacia: EstadoNativo, motivo: string): void {
		const n = op.interno.nativo;
		if (!transicionLegal(n.estado, hacia)) throw new Error(`transicion_ilegal:${n.estado}->${hacia}`);
		n.eventos.push({ seq: n.eventos.length, from: n.estado, to: hacia, at: new Date().toISOString(), reason: motivo });
		n.estado = hacia;
		if (FINALES.has(hacia)) n.motivoFinal = motivo;
		const poppy = proyectarPoppy(hacia);
		if (poppy) op.state = poppy;
	}

	limites(tenantId: string): Limites {
		return this.empresa(tenantId).limites ?? LIMITES_POR_DEFECTO;
	}

	private transportista(tenantId: string): Transportista {
		const s = this.empresa(tenantId).sistema;
		s.transportista ??= { respuesta: {}, confirmado: {}, solicitudes: [], consultas: 0 };
		return s.transportista;
	}

	/** Commitment of the revision (design 0.1 §3.D): firm, or conditional on what is missing. */
	private compromisoDe(pedido: Pedido): Nativo["compromiso"] {
		return pedido.transportista ? { mode: "conditional", requires: ["carrier_acceptance"] } : { mode: "firm", requires: [] };
	}

	/** For the native face: signs the outcome of an operation it closed (e.g. by the attempt limit). */
	firmarResultadoPublico(tenantId: string, op: Operacion): void {
		this.firmarResultado(tenantId, op);
		this.estadoCaso(tenantId, op.interno.caseId, "completed");
	}

	private releaseDigest(tenantId: string): string {
		const { release } = this.empresa(tenantId);
		return huellaJcs({ version: release.version, capacidades: release.capacidades });
	}

	private estadoCaso(tenantId: string, caseId: string, estado: EstadoCaso): void {
		const caso = this.base(tenantId).casos.get(caseId);
		if (caso) caso.estado = estado;
		this.evento(tenantId, caseId, "case.state", { estado });
	}

	// ── Reads ────────────────────────────────────────────────────────────────────────────────

	/**
	 * Read by the `agente_personal` authority: requires scope, and returns only the customer's own
	 * data. The owner filter is the counterpart of per-company RLS, one level below.
	 */
	leerPedidos(actor: ActorExterno, caseId: string): { ok: true; pedidos: Pedido[] } | { ok: false; falta: string[] | "sign_in" } {
		const decision = this.decidir(actor, {
			capability: "pedido.consultar",
			inputs: {},
			reason: "El cliente pregunta por sus pedidos",
			expectedEffect: "read",
		});
		this.evento(actor.tenantId, caseId, decision.decision === "allow" ? "policy.allowed" : "policy.denied", decision);
		if (decision.decision !== "allow") return { ok: false, falta: decision.falta ?? "sign_in" };
		// Round 4 (M6): the filter is by the **ERP** customer linked with evidence to the canonical one, not
		// by the operator's id. No link, no rows: nobody guesses who they are in the company system.
		const erp = this.clienteErpDe(actor);
		const pedidos = erp ? this.empresa(actor.tenantId).sistema.pedidos.filter((p) => p.clienteId === erp) : [];
		this.evento(actor.tenantId, caseId, "tool.executed", { capability: "pedido.consultar", filas: pedidos.length });
		return { ok: true, pedidos };
	}

	/** The ERP customer linked to the actor's canonical customer, or null if there is no link (M6). */
	private clienteErpDe(actor: ActorExterno): string | null {
		const cliente = this.empresa(actor.tenantId).clientes.find((c) => c.id === actor.clienteId);
		return cliente?.erp?.id ?? null;
	}

	/**
	 * Tool gateway pre-read (round 4, M6): reads the resource in the company system and compares it
	 * with the linked ERP customer before authorizing: Policy receives the fact, it does not read the
	 * ERP.
	 */
	private lecturaPrevia(actor: ActorExterno, intent: ActionIntent): HechosDePolicy {
		const empresa = this.empresa(actor.tenantId);
		const hechos: HechosDePolicy = {};
		// Connector-backed capabilities (hospitality, returns): the connector knows who owns the resource.
		const con = conectorDe(empresa, intent.capability);
		if (con) {
			const erp = this.clienteErpDe(actor);
			const recurso = con.recurso(intent.inputs);
			hechos.recurso = erp === null ? "sin_vinculo" : recurso === "nuevo" || con.dueno(this.ctx(actor.tenantId), recurso) === erp ? "propio" : "ajeno_o_inexistente";
			return hechos;
		}
		const { pedidoId, nuevaFecha } = intent.inputs;
		if (!pedidoId) return hechos;
		const erp = this.clienteErpDe(actor);
		const pedido = empresa.sistema.pedidos.find((p) => p.id === pedidoId);
		hechos.recurso = !erp ? "sin_vinculo" : pedido && pedido.clienteId === erp ? "propio" : "ajeno_o_inexistente";
		if (intent.expectedEffect === "write" && pedido && nuevaFecha && hechos.recurso === "propio")
			hechos.reglaEmpresa = this.revisionRequerida(empresa, pedido, nuevaFecha)?.motivo ?? null;
		return hechos;
	}

	/** Tool gateway → Policy: the pre-read and the decision, in that order. */
	decidir(actor: ActorExterno, intent: ActionIntent): DecisionPolicy {
		return this.autorizar(actor, intent, this.lecturaPrevia(actor, intent));
	}

	// ── Policy ───────────────────────────────────────────────────────────────────────────────

	/**
	 * `agente_personal` authority (round 4, M1). It does not return before the review rules: incoming
	 * content is third-party by definition, and its review rule is written here.
	 *
	 * - `allow` on a write means "permitted, subject to the customer's exact approval of the frozen
	 *   revision" (the operation is born with `user_approval_required: true` and a message never
	 *   approves). Whether that approval suffices for untrusted content is each company's decision.
	 * - `review` = a company person also decides, after the customer and on the same digest
	 *   (SPEC §6.5). These are two decisions, each with its own principal and event.
	 */
	autorizar(actor: ActorExterno, intent: ActionIntent, hechos: HechosDePolicy = {}): DecisionPolicy {
		const empresa = this.empresa(actor.tenantId);
		const entry = empresa.release.capacidades.find((c) => c.id === intent.capability);
		if (!entry) return { decision: "deny", basis: "capability_not_in_release" };
		if (entry.efecto !== intent.expectedEffect)
			return { decision: "deny", basis: "action_effect_mismatch_with_release" };
		if (!actor.clienteId) return { decision: "deny", basis: "sign_in_required", falta: "sign_in" };
		// The standing purchase permission includes creating orders.
		const tieneAlcance = actor.alcances.includes(entry.alcance) || (entry.alcance === "compras:crear" && actor.alcances.includes("compras:sin_confirmar"));
		if (!tieneAlcance)
			return { decision: "deny", basis: "delegated_scope_missing", falta: [entry.alcance] };
		// Someone else's resource, a nonexistent one and one of a customer not linked to the ERP all
		// look the same from outside: it reveals neither which orders exist nor who is a customer.
		if ((intent.inputs.pedidoId || hechos.recurso) && hechos.recurso !== "propio")
			return { decision: "deny", basis: hechos.recurso === "sin_vinculo" ? "customer_not_linked_to_company_system" : "resource_not_owned_by_customer" };
		if (intent.expectedEffect === "write") {
			if (empresa.reglaRevisionAgentes === "toda_escritura")
				return { decision: "review", basis: "personal_agent_write_requires_company_review", motivo: "la empresa revisa toda escritura pedida por un agente personal" };
			if (hechos.reglaEmpresa)
				return { decision: "review", basis: "company_rule_requires_review", motivo: hechos.reglaEmpresa };
			return { decision: "allow", basis: "delegated_scope_release_and_exact_customer_approval" };
		}
		return { decision: "allow", basis: "delegated_scope_and_release" };
	}

	/** The company review that Policy requests, or null. */
	private revisionDe(decision: DecisionPolicy): Operacion["interno"]["revisionEmpresa"] {
		return decision.decision === "review" ? { id: randomId("rev_", 6), estado: "pendiente", motivo: decision.motivo ?? decision.basis } : null;
	}

	// ── Writes: propose, confirm, review, execute, verify ───────────────────────────────────

	/** Freezes the exact request (revision + digest). Proposing executes nothing. */
	proponerReprogramacion(
		actor: ActorExterno,
		caseId: string,
		pedidoId: string,
		nuevaFecha: string,
		sesion: string | null,
		/** The request as it arrived (message text or API body): goes as a digest in `request`. */
		solicitud: Record<string, unknown> | null = null,
		/** Native states prior to the proposal (received, authorization_required), if any. */
		historia: Nativo["eventos"] = [],
	): { ok: true; operacion: Operacion } | { ok: false; falta: string[] | "sign_in" | "no_encontrado" | "en_curso" | "limite_revisiones"; operacion?: Operacion } {
		const intent: ActionIntent = {
			capability: "pedido.reprogramar_despacho",
			inputs: { pedidoId, nuevaFecha },
			reason: "El cliente pide cambiar la fecha de despacho",
			expectedEffect: "write",
		};
		const decision = this.decidir(actor, intent);
		this.evento(actor.tenantId, caseId, decision.decision === "allow" ? "policy.allowed" : decision.decision === "review" ? "policy.review_required" : "policy.denied", { ...decision, fase: "proponer" });
		if (decision.decision === "deny")
			return { ok: false, falta: decision.basis === "resource_not_owned_by_customer" || decision.basis === "customer_not_linked_to_company_system" ? "no_encontrado" : (decision.falta ?? "sign_in") };
		const empresa = this.empresa(actor.tenantId);
		const pedido = empresa.sistema.pedidos.find((p) => p.id === pedidoId)!;
		const base = this.base(actor.tenantId);
		// The same action requested again by another path is the same operation (Operations 4), but only
		// for the same full owner: agent, `sub`, customer and, without an account, session (round 3, M2).
		// Another agent or another `sub` of the same customer opens its own operation; it does not rewrite theirs.
		for (const existente of base.operaciones.values()) {
			if (existente.state === "proposed" && existente.interno.intent.inputs.pedidoId === pedidoId && this.esDueno(existente, actor, sesion)) {
				if (existente.interno.intent.inputs.nuevaFecha === nuevaFecha) return { ok: true, operacion: existente };
				// Revision limit (design 0.1 §3.D): once exceeded, the negotiation closes without effect.
				if (existente.revision >= this.limites(actor.tenantId).max_revisions && !mutado("limite_revisiones")) {
					existente.result = { summary: "Se alcanzó el máximo de revisiones de esta solicitud. No se hizo ningún cambio.", data: { effects: [] } };
					this.transicion(existente, "failed", "negotiation_limit_exceeded");
					this.firmarResultado(actor.tenantId, existente);
					this.estadoCaso(actor.tenantId, existente.interno.caseId, "completed");
					return { ok: false, falta: "limite_revisiones", operacion: existente };
				}
				// The request that originates the new revision goes into the chain as a `counter`, and the
				// revision cites it in `answers` (round 3, M2). If it came via `contraproponer`, it is already recorded.
				if (!existente.interno.counterPendiente)
					existente.interno.counterPendiente = this.eslabon(actor.tenantId, existente, "operador", "counter", {
						base_revision: existente.revision,
						counter_digest: huellaJcs(solicitud ?? { binding: "vxp.intent", capability: intent.capability, inputs: intent.inputs }),
						from: "personal_agent",
					});
				// The terms change: a new revision of the same operation, with its own digest.
				existente.revision += 1;
				existente.interno.intent = intent;
				// The institutional rule is evaluated on the new terms, not on those of revision 1.
				const revisionNueva = this.revisionDe(decision);
				if (!revisionNueva) existente.interno.revisionEmpresa = null;
				else if (!existente.interno.revisionEmpresa) existente.interno.revisionEmpresa = revisionNueva;
				this.redactar(existente, empresa, pedido, nuevaFecha);
				this.transicion(existente, "proposed", `revision_${existente.revision}`);
				this.firmarTerminos(actor.tenantId, existente);
				this.evento(actor.tenantId, existente.interno.caseId, "tool.previewed", { revision: existente.revision, huella: existente.interno.huella });
				return { ok: true, operacion: existente };
			}
		}
		// Only one operation in progress per resource (round 3, M3): while another already confirmed on this
		// order has not finished (executing, under company review or not knowing whether it had an effect),
		// no other is opened. The precondition of `ejecutar` covers what was already proposed.
		if ([...base.operaciones.values()].some((o) => o.state === "in_progress" && o.interno.intent.inputs.pedidoId === pedidoId))
			return { ok: false, falta: "en_curso" };
		const operacion: Operacion = {
			operation_id: randomId("op_", 9),
			revision: 1,
			state: "proposed",
			summary: "",
			terms: {},
			user_approval_required: true,
			confirmation: null,
			result: null,
			interno: {
				caseId,
				intent,
				huella: "",
				dueno: { protocolo: actor.protocolo, clientId: actor.clientId, sub: actor.sub, clienteId: actor.clienteId, sesion },
				revisionEmpresa: this.revisionDe(decision),
				ejecutada: false,
				termsDigest: "",
				counterPendiente: null,
				metodoAprobacion: null,
				ultimoFinal: null,
				nativo: {
					estado: "received",
					eventos: historia.length ? historia.map((e) => ({ ...e })) : [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "request" }],
					compromiso: this.compromisoDe(pedido),
					efectos: [],
					cancelacion: null,
					intentosAceptar: 0,
					motivoFinal: null,
				},
			},
		};
		operacion.interno.nativo.estado = operacion.interno.nativo.eventos.at(-1)!.to;
		this.transicion(operacion, "proposed", "revision_1");
		this.redactar(operacion, empresa, pedido, nuevaFecha);
		base.operaciones.set(operacion.operation_id, operacion);
		if (this.pruebas) {
			// seq 0: what the operator received; seq 1: the first revision, signed by the company.
			this.pruebas.iniciar(actor.tenantId, operacion.operation_id, actor.clientId, this.seudonimo(actor));
			const requestDigest = huellaJcs(solicitud ?? { binding: "vxp.intent", capability: intent.capability, inputs: intent.inputs });
			this.eslabon(actor.tenantId, operacion, "operador", "request", {
				channel: actor.protocolo,
				client_id: actor.clientId,
				request_digest: requestDigest,
				// Under PACT, the citation of the proposing turn's receipt (SPEC §9.4.1, §12.2.4): its `argsHash`
				// is this same digest, which the agent recomputes from the text it sent.
				...(actor.protocolo === "pact" && actor.grantId ? { pact_proposal_receipt: { grantId: actor.grantId, argsHash: requestDigest } } : {}),
			});
			this.firmarTerminos(actor.tenantId, operacion);
		}
		this.evento(actor.tenantId, caseId, "tool.previewed", { operation_id: operacion.operation_id, revision: 1, huella: operacion.interno.huella });
		return { ok: true, operacion };
	}

	private redactar(op: Operacion, empresa: Empresa, pedido: Pedido, nuevaFecha: string): void {
		op.terms = {
			pedido: pedido.id,
			producto: pedido.producto,
			despacho_actual: pedido.despacho,
			despacho_nuevo: nuevaFecha,
			direccion: pedido.direccion,
			costo: { amount: "0", currency: "CLP" },
			// Round 3 (m2): 128 random bits per revision. `terms_digest` covers `summary` and `terms`, which
			// carry the address; without salt, anyone who suspects an address can confirm it with a digest.
			// The agent has it (it is in the operation), a third party does not.
			vxp_salt: randomBytes(16).toString("base64url"),
			// Commitment condition: the outcome is `succeeded` only if the carrier accepts.
			...(op.interno.nativo.compromiso.requires.includes("carrier_acceptance") ? { transportista: pedido.transportista, carrier_acceptance: "accepted" } : {}),
		};
		const revision =
			(op.interno.revisionEmpresa ? " Antes de ejecutarse lo revisa una persona de la empresa." : "") +
			(op.interno.nativo.compromiso.mode === "conditional" ? ` Queda sujeto a que ${pedido.transportista} acepte la nueva fecha; si no la acepta, no hay cambio.` : "");
		op.summary = `Cambiar el despacho del pedido ${pedido.id} (${pedido.producto}) del ${pedido.despacho} al ${nuevaFecha}, a ${pedido.direccion}, sin costo.${revision}`;
		op.expires_at = new Date(Date.now() + this.limites(empresa.tenantId).proposal_ttl_seconds * 1000).toISOString();
		// The digest covers what will be approved: capability, inputs, terms and revision. JCS (RFC 8785),
		// so that another implementation computes the same digest from the same object (SPEC §16.1).
		op.interno.huella = sha256(jcs({ c: op.interno.intent.capability, i: op.interno.intent.inputs, t: op.terms, r: op.revision }));
		op.interno.termsDigest = huellaTerminos({
			company: this.pruebas ? this.pruebas.issuer(empresa.tenantId) : empresa.tenantId,
			operation_id: op.operation_id,
			revision: op.revision,
			summary: op.summary,
			terms: op.terms,
			expires_at: op.expires_at ?? null,
			user_approval_required: op.user_approval_required,
		});
	}

	private revisionRequerida(empresa: Empresa, pedido: Pedido, nuevaFecha: string): Operacion["interno"]["revisionEmpresa"] {
		const dias = Math.round((Date.parse(nuevaFecha) - Date.parse(pedido.despacho)) / 86_400_000);
		return Math.abs(dias) > empresa.diasSinRevision
			? { id: randomId("rev_", 6), estado: "pendiente", motivo: `corrimiento de ${dias} días supera ${empresa.diasSinRevision}` }
			: null;
	}

	/** Per-company user pseudonym (SPEC §6.2): the Poppy User ID or the `sub` of the PACT delegation. */
	private seudonimo(actor: ActorExterno): string {
		return actor.protocolo === "pact" ? (actor.clienteId ?? actor.sub) : actor.sub;
	}

	/**
	 * Structured counter-proposal from the agent (SPEC §7.2). It is third-party content: it is never
	 * executed; the company answers with a new revision (which it signs) or with a rejection.
	 */
	contraproponer(
		actor: ActorExterno,
		op: Operacion,
		body: { base_revision?: unknown; proposed_terms?: { despacho_nuevo?: unknown }; note?: unknown },
	): { ok: true; operacion: Operacion } | { ok: false; error: "counter_rejected" | "insufficient_scope" | "sign_in_required" } {
		// Connector-backed capabilities (stress sandbox): the counter-proposal goes through their policy.
		if (conectorDe(this.empresa(actor.tenantId), op.interno.intent.capability)) {
			if (op.state !== "proposed" || body.base_revision !== op.revision) return { ok: false, error: "counter_rejected" };
			const r = this.contraproponerOperacion(actor, op, pideDesdeApi(op.interno.intent.capability, (body.proposed_terms ?? {}) as Record<string, unknown>));
			if (r.ok) return { ok: true, operacion: r.operacion };
			return { ok: false, error: r.motivo === "sign_in_required" || r.motivo === "insufficient_scope" ? r.motivo : "counter_rejected" };
		}
		if (op.state !== "proposed" || body.base_revision !== op.revision) return { ok: false, error: "counter_rejected" };
		const nueva = body.proposed_terms?.despacho_nuevo;
		if (typeof nueva !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(nueva) || Number.isNaN(Date.parse(nueva)) || nueva === op.terms.despacho_nuevo)
			return { ok: false, error: "counter_rejected" };
		const decision = this.decidir(actor, { ...op.interno.intent, inputs: { ...op.interno.intent.inputs, nuevaFecha: nueva } });
		if (decision.decision === "deny") return { ok: false, error: decision.falta === "sign_in" ? "sign_in_required" : "insufficient_scope" };
		const counter = { base_revision: body.base_revision, proposed_terms: { despacho_nuevo: nueva }, ...(typeof body.note === "string" ? { note: body.note } : {}) };
		op.interno.counterPendiente = this.eslabon(actor.tenantId, op, "operador", "counter", {
			base_revision: op.revision,
			counter_digest: huellaJcs(counter),
			from: "personal_agent",
		});
		const r = this.proponerReprogramacion(actor, op.interno.caseId, op.interno.intent.inputs.pedidoId, nueva, op.interno.dueno.sesion, counter);
		return r.ok ? { ok: true, operacion: r.operacion } : { ok: false, error: "counter_rejected" };
	}

	// ── Purchase: quote → signed proposal → exact approval → new order → read-back ──

	guardarCotizacion(tenantId: string, cot: Cotizacion): void {
		this.base(tenantId).cotizaciones.set(cot.id, cot);
	}

	cotizacionDe(tenantId: string, id: string): Cotizacion | undefined {
		return this.base(tenantId).cotizaciones.get(id);
	}

	/** The last open quote of a conversation: the «esta cotización» ("this quote") of the following messages. */
	ultimaCotizacion(tenantId: string, caseId: string, origen?: string): Cotizacion | undefined {
		const abiertas = [...this.base(tenantId).cotizaciones.values()].filter((c) => c.estado === "abierta" && Date.parse(c.vence) > Date.now());
		// First the one from this conversation; if none, the last one from the same agent and user in another conversation
		// (test agent B reconnected, opened another conversation and the company quoted it from scratch: Oct 21, 05:05:56).
		return abiertas.filter((c) => c.caseId === caseId).at(-1) ?? (origen && !mutado("cotizacion_por_conversacion") ? abiertas.filter((c) => c.origen === origen).at(-1) : undefined);
	}

	/**
	 * Proposes creating an order from a quote. It is an operation like any other: exact terms signed
	 * by the company, customer approval of that revision, a single execution.
	 */
	proponerCompra(
		actor: ActorExterno,
		caseId: string,
		cotId: string,
		sesion: string | null,
		solicitud: Record<string, unknown> | null = null,
		historia: Nativo["eventos"] = [],
	): { ok: true; operacion: Operacion } | { ok: false; falta: string[] | "sign_in" | "no_encontrado" | "cotizacion_vencida" | "sin_vinculo" } {
		const empresa = this.empresa(actor.tenantId);
		const cot = this.cotizacionDe(actor.tenantId, cotId);
		if (!cot || !empresa.comercio) return { ok: false, falta: "no_encontrado" };
		if (Date.parse(cot.vence) < Date.now() && !mutado("vigencia")) return { ok: false, falta: "cotizacion_vencida" };
		const intent: ActionIntent = { capability: "pedido.crear", inputs: { cotizacion: cot.id }, reason: "El cliente pide hacer un pedido desde una cotización", expectedEffect: "write" };
		const decision = this.decidir(actor, intent);
		this.evento(actor.tenantId, caseId, decision.decision === "allow" ? "policy.allowed" : decision.decision === "review" ? "policy.review_required" : "policy.denied", { ...decision, fase: "proponer" });
		if (decision.decision === "deny") return { ok: false, falta: decision.falta ?? "sign_in" };
		// A new order belongs to the linked ERP customer: without a link, it is not created in anyone's name.
		if (!this.clienteErpDe(actor)) return { ok: false, falta: "sin_vinculo" };
		const base = this.base(actor.tenantId);
		for (const existente of base.operaciones.values()) {
			if (existente.state === "proposed" && existente.interno.intent.inputs.cotizacion === cot.id && this.esDueno(existente, actor, sesion)) {
				if (existente.terms.revision_cotizacion === cot.revision) return { ok: true, operacion: existente };
				existente.revision += 1;
				this.redactarCompra(existente, empresa, cot);
				this.transicion(existente, "proposed", `revision_${existente.revision}`);
				this.firmarTerminos(actor.tenantId, existente);
				return { ok: true, operacion: existente };
			}
		}
		// Standing permission (Poppy `standing_permission`): if the customer granted it and the order is within the
		// company's cap, the operation does not require customer approval for THIS revision. This is stated in the signed terms.
		const permanente = actor.alcances.includes("compras:sin_confirmar") && (cot.total <= (empresa.comercio.politica.topePermanente ?? 0) || mutado("permanente_sin_tope"));
		const revisionEmpresa =
			this.revisionDe(decision) ?? (cot.total > empresa.comercio.politica.revisionSobre ? { id: randomId("rev_", 6), estado: "pendiente" as const, motivo: `pedido de ${cot.total} CLP supera ${empresa.comercio.politica.revisionSobre}` } : null);
		const operacion: Operacion = {
			operation_id: randomId("op_", 9),
			revision: 1,
			state: "proposed",
			summary: "",
			terms: {},
			user_approval_required: !permanente,
			confirmation: null,
			result: null,
			interno: {
				caseId,
				intent,
				huella: "",
				dueno: { protocolo: actor.protocolo, clientId: actor.clientId, sub: actor.sub, clienteId: actor.clienteId, sesion },
				revisionEmpresa,
				ejecutada: false,
				termsDigest: "",
				counterPendiente: null,
				metodoAprobacion: null,
				ultimoFinal: null,
				nativo: {
					estado: "received",
					eventos: historia.length ? historia.map((e) => ({ ...e })) : [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "request" }],
					compromiso: { mode: "firm", requires: [] },
					efectos: [],
					cancelacion: null,
					intentosAceptar: 0,
					motivoFinal: null,
				},
			},
		};
		operacion.interno.nativo.estado = operacion.interno.nativo.eventos.at(-1)!.to;
		this.transicion(operacion, "proposed", "revision_1");
		this.redactarCompra(operacion, empresa, cot);
		base.operaciones.set(operacion.operation_id, operacion);
		if (this.pruebas) {
			this.pruebas.iniciar(actor.tenantId, operacion.operation_id, actor.clientId, this.seudonimo(actor));
			const requestDigest = huellaJcs(solicitud ?? { binding: "vxp.intent", capability: intent.capability, inputs: intent.inputs });
			this.eslabon(actor.tenantId, operacion, "operador", "request", {
				channel: actor.protocolo,
				client_id: actor.clientId,
				request_digest: requestDigest,
				...(actor.protocolo === "pact" && actor.grantId ? { pact_proposal_receipt: { grantId: actor.grantId, argsHash: requestDigest } } : {}),
			});
			this.firmarTerminos(actor.tenantId, operacion);
		}
		this.evento(actor.tenantId, caseId, "tool.previewed", { operation_id: operacion.operation_id, capability: "pedido.crear", cotizacion: cot.id, huella: operacion.interno.huella });
		return { ok: true, operacion };
	}

	/** Counter-proposal on a purchase: the company answers within its policy (new revision) or declines. */
	contraproponerCompra(actor: ActorExterno, op: Operacion, pide: { descuento?: number; fecha?: string; antesDe?: string }): { ok: true; operacion: Operacion; notas: string[] } | { ok: false; motivo: string } {
		const empresa = this.empresa(actor.tenantId);
		const cot = this.cotizacionDe(actor.tenantId, String(op.terms.cotizacion));
		if (op.state !== "proposed" || !cot || !empresa.comercio) return { ok: false, motivo: "counter_rejected" };
		if (op.revision >= this.limites(actor.tenantId).max_revisions && !mutado("limite_revisiones")) {
			op.result = { summary: "Se alcanzó el máximo de revisiones de esta solicitud. No se hizo ningún cambio.", data: { effects: [] } };
			this.transicion(op, "failed", "negotiation_limit_exceeded");
			this.firmarResultado(actor.tenantId, op);
			return { ok: false, motivo: "negotiation_limit_exceeded" };
		}
		const r = negociar(empresa.comercio, cot, pide);
		if (!r.ok) return { ok: false, motivo: r.motivo };
		this.guardarCotizacion(actor.tenantId, r.cot);
		op.interno.counterPendiente = this.eslabon(actor.tenantId, op, "operador", "counter", { base_revision: op.revision, counter_digest: huellaJcs(pide), from: "personal_agent" });
		op.revision += 1;
		this.redactarCompra(op, empresa, r.cot);
		this.transicion(op, "proposed", `revision_${op.revision}`);
		this.firmarTerminos(actor.tenantId, op);
		return { ok: true, operacion: op, notas: r.notas };
	}

	private redactarCompra(op: Operacion, empresa: Empresa, cot: Cotizacion): void {
		op.terms = {
			cotizacion: cot.id,
			revision_cotizacion: cot.revision,
			articulos: cot.lineas.map((l) => ({ sku: l.sku, cantidad: l.cantidad, precio_unitario: l.precio_unitario, descuento_pct: l.descuento_pct })),
			despacho: cot.despacho,
			total: cot.total,
			moneda: cot.moneda,
			pago: cot.pago,
			vxp_salt: randomBytes(16).toString("base64url"),
		};
		op.summary = `Hacer el pedido de la ${textoCotizacion(cot, empresa.nombre)}${op.interno.revisionEmpresa ? " Antes de crearse lo revisa una persona de la empresa." : ""}${op.user_approval_required ? "" : " Dentro de tu permiso permanente: tu asistente lo puede confirmar sin preguntarte."}`;
		const ttl = Date.now() + this.limites(empresa.tenantId).proposal_ttl_seconds * 1000;
		op.expires_at = new Date(Math.min(ttl, Date.parse(cot.vence))).toISOString();
		op.interno.huella = sha256(jcs({ c: op.interno.intent.capability, i: op.interno.intent.inputs, t: op.terms, r: op.revision }));
		op.interno.termsDigest = huellaTerminos({
			company: this.pruebas ? this.pruebas.issuer(empresa.tenantId) : empresa.tenantId,
			operation_id: op.operation_id,
			revision: op.revision,
			summary: op.summary,
			terms: op.terms,
			expires_at: op.expires_at ?? null,
			user_approval_required: op.user_approval_required,
		});
	}

	/** Creates the order. Precondition: valid quote, same prices and enough stock at execution time. */
	private async ejecutarCompra(tenantId: string, op: Operacion): Promise<void> {
		const empresa = this.empresa(tenantId);
		const cot = this.cotizacionDe(tenantId, String(op.terms.cotizacion));
		this.estadoCaso(tenantId, op.interno.caseId, "running");
		const falla = empresa.sistema.proximaFalla;
		empresa.sistema.proximaFalla = undefined;
		if (op.interno.ejecutada) return;
		const articulos = op.terms.articulos as { sku: string; cantidad: number; precio_unitario: number }[];
		const problema = !cot || cot.estado !== "abierta"
			? "la cotización ya no está disponible"
			: Date.parse(cot.vence) < Date.now()
				? "la cotización venció"
				: articulos.map((a) => ({ a, p: empresa.comercio?.catalogo.find((x) => x.sku === a.sku) })).find(({ a, p }) => !p || p.stock < a.cantidad)
					? "ya no hay stock suficiente de algún artículo"
					: null;
		if (problema && !mutado("precondicion_compra")) {
			empresa.sistema.proximaFalla = falla;
			op.result = { summary: `No se creó el pedido: ${problema}. Pide una cotización nueva.`, data: { effects: [] } };
			this.transicion(op, "failed", "precondition_failed");
			this.firmarResultado(tenantId, op);
			this.estadoCaso(tenantId, op.interno.caseId, "failed");
			return;
		}
		this.transicion(op, "executing", "execution_started");
		this.eslabon(tenantId, op, "operador", "execution", { revision: op.revision, terms_digest: op.interno.termsDigest, capability: "pedido.crear", release: this.releaseDigest(tenantId), attempt: 1 });
		if (falla === "definitiva") {
			op.result = { summary: `El sistema de ${empresa.nombre} rechazó el pedido. No se creó nada.`, data: { effects: [] } };
			this.transicion(op, "failed", "company_system_rejected");
			this.firmarResultado(tenantId, op);
			this.estadoCaso(tenantId, op.interno.caseId, "failed");
			return;
		}
		const erp = empresa.clientes.find((c) => c.id === op.interno.dueno.clienteId)?.erp?.id ?? "";
		const id = `P-${8001 + empresa.sistema.pedidos.filter((p) => p.cotizacion).length}`;
		const despacho = op.terms.despacho as Cotizacion["despacho"];
		empresa.sistema.pedidos.push({
			id,
			clienteId: erp,
			producto: articulos.map((a) => `${a.cantidad} × ${a.sku}`).join(", "),
			despacho: despacho.fecha,
			direccion: `${despacho.direccion}, ${despacho.comuna.replace(/(^|\s)(\p{L})/gu, (_m: string, a: string, b: string) => a + b.toUpperCase())}`,
			estado: "preparando",
			cotizacion: String(op.terms.cotizacion),
			articulos: articulos.map((a) => ({ ...a })) as Pedido["articulos"],
			total: Number(op.terms.total),
			pago: "pendiente: al recibir o por transferencia",
		});
		for (const a of articulos) {
			const p = empresa.comercio!.catalogo.find((x) => x.sku === a.sku)!;
			p.stock -= a.cantidad;
		}
		cot!.estado = "usada";
		op.interno.ejecutada = true;
		op.interno.nativo.efectos.push({ system: "erp", change: `pedido ${id} creado (${op.terms.total} CLP, sin pago en línea)`, applied: true });
		this.evento(tenantId, op.interno.caseId, "tool.executed", { capability: "pedido.crear", pedido: id, huella: op.interno.huella });
		if (falla === "desconocida") {
			this.transicion(op, "pending_verification", "erp_response_lost");
			this.firmarIncierto(tenantId, op, `Todavía no se sabe si el sistema de ${empresa.nombre} creó el pedido: no llegó su respuesta. No se repetirá; se confirmará leyendo el sistema.`);
			this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
			return;
		}
		this.verificarCompra(tenantId, op);
	}

	/** Reads the system: the order exists with the approved quote, items and total. */
	private verificarCompra(tenantId: string, op: Operacion): void {
		const empresa = this.empresa(tenantId);
		const n = op.interno.nativo;
		if (n.estado === "waiting_human" && op.interno.ejecutada) return;
		const leido = empresa.sistema.pedidos.find((p) => p.cotizacion === op.terms.cotizacion && !p.anulado);
		const observado = leido ? { cotizacion: leido.cotizacion, articulos: leido.articulos, total: leido.total } : { cotizacion: null };
		const coincide = !!leido && ["cotizacion", "articulos", "total"].every((t) => jcs((observado as Record<string, unknown>)[t]) === jcs(op.terms[t]));
		if (coincide && !mutado("contradiccion_es_exito")) {
			op.result = {
				summary: `Listo: pedido ${leido!.id} creado por ${(op.terms.total as number).toLocaleString("es-CL")} CLP con despacho el ${leido!.despacho}. Pagas al recibir o por transferencia. Verificado en el sistema de ${empresa.nombre}.`,
				data: { pedido: leido!.id, total: op.terms.total, despacho: leido!.despacho, pago: leido!.pago, verificado: "lectura_del_sistema", effects: n.efectos },
			};
			this.transicion(op, "succeeded", "read_back_matches");
			const lectura = this.eslabon(tenantId, op, "operador", "read_back", { method: "system_read_back", source: "company_system", matches_terms: true, observed: observado }, { observed: { direccion: leido!.direccion } });
			this.firmarResultado(tenantId, op, { lectura });
			this.evento(tenantId, op.interno.caseId, "tool.verified", { method: "read_back", operation_id: op.operation_id, pedido: leido!.id, huella: op.interno.huella });
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
			return;
		}
		this.eslabon(tenantId, op, "operador", "read_back", { method: "system_read_back", source: "company_system", matches_terms: false, observed: observado });
		if (n.estado === "executing") this.transicion(op, "pending_verification", "read_back_contradicts_terms");
		this.transicion(op, "waiting_human", "read_back_contradicts_terms");
		this.firmarIncierto(tenantId, op, `El sistema de ${empresa.nombre} no muestra el pedido con lo aprobado. Una persona de la empresa lo revisa; no se reintenta.`);
		this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
	}

	/** Voids an order born from a purchase (by the company, before shipment): restocks. Reversibility for the tests. */
	anularPedido(tenantId: string, pedidoId: string): Pedido | null {
		const empresa = this.empresa(tenantId);
		const p = empresa.sistema.pedidos.find((x) => x.id === pedidoId && x.cotizacion && !x.anulado);
		if (!p || p.estado !== "preparando") return null;
		p.anulado = true;
		for (const a of p.articulos ?? []) {
			const prod = empresa.comercio?.catalogo.find((x) => x.sku === a.sku);
			if (prod) prod.stock += a.cantidad;
		}
		this.evento(tenantId, "-", "order.cancelled_by_company", { pedido: pedidoId });
		return p;
	}

	visible(op: Operacion): Omit<Operacion, "interno"> {
		const { interno: _interno, ...rest } = op;
		return rest;
	}

	/** Full owner of an operation (Operations 3.2): agent, `sub`, customer or, without an account, session. */
	private esDueno(op: Operacion, actor: ActorExterno, sesion: string | null): boolean {
		const d = op.interno.dueno;
		// Identities separated by protocol (design 0.1 §5): never crossed because they happen to match.
		if (d.protocolo !== actor.protocolo && !mutado("separar_protocolos")) return false;
		if (d.clientId !== actor.clientId || d.sub !== actor.sub) return false;
		return d.clienteId ? actor.clienteId === d.clienteId : d.sesion === sesion;
	}

	/** Reads an operation only if it belongs to this actor (Operations 3.2). */
	operacionDe(actor: ActorExterno, operationId: string, sesion: string | null): Operacion | "not_found" | "sign_in_required" {
		const op = this.base(actor.tenantId).operaciones.get(operationId);
		if (!op) return "not_found";
		this.expirar(actor.tenantId, op);
		const d = op.interno.dueno;
		if (d.protocolo !== actor.protocolo && !mutado("separar_protocolos")) return "not_found";
		if (d.clientId !== actor.clientId || d.sub !== actor.sub) return "not_found";
		if (d.clienteId) {
			if (!actor.clienteId) return "sign_in_required";
			if (actor.clienteId !== d.clienteId) return "not_found";
		} else if (d.sesion !== sesion) return "not_found";
		return op;
	}

	private expirar(tenantId: string, op: Operacion): void {
		if (mutado("vigencia")) return;
		if (op.state === "proposed" && op.expires_at && Date.parse(op.expires_at) < Date.now()) {
			this.transicion(op, "expired", "proposal_expired");
			op.result = { summary: "No se confirmó a tiempo. No se hizo ningún cambio." };
			this.firmarResultado(tenantId, op);
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
		}
	}

	/**
	 * The end customer's approval arrives through the operations endpoint, with the exact
	 * revision. Never through the text of a message.
	 */
	async confirmar(
		actor: ActorExterno,
		op: Operacion,
		revision: number,
		approvedBy: string,
		canal: AprobacionCanal | null = null,
	): Promise<{ status: number; body: unknown }> {
		const tenantId = actor.tenantId;
		if (op.state !== "proposed") return { status: 200, body: this.visible(op) };
		const decision = this.decidir(actor, op.interno.intent);
		if (decision.decision === "deny") {
			const falta = decision.falta === "sign_in" ? "sign_in_required" : "insufficient_scope";
			return { status: 403, body: { error: falta, ...(Array.isArray(decision.falta) ? { scope: decision.falta.join(" ") } : {}) } };
		}
		if (revision !== op.revision) return { status: 409, body: { error: "terms_changed", operation: this.visible(op) } };
		if (approvedBy !== "user" && approvedBy !== "standing_permission") return { status: 400, body: { error: "invalid_request" } };
		if (approvedBy === "standing_permission" && op.user_approval_required)
			return { status: 403, body: { error: "user_approval_required", operation: this.visible(op) } };
		op.confirmation = { revision, approved_by: approvedBy, confirmed_at: new Date().toISOString() };
		this.transicion(op, "accepted", "accepted_exact_revision");
		this.evento(tenantId, op.interno.caseId, "customer.approved", {
			operation_id: op.operation_id,
			revision,
			approved_by: approvedBy,
			huella: op.interno.huella,
			agente: actor.clientId,
			grant: actor.grantId,
			// Round 4 (M1): the customer's decision is their own, with their principal; it is not a row of the
			// company review, nor is it decided by a member.
			principal: { tipo: "cliente", cliente: actor.clienteId, ref: `agent:${actor.clientId}#${actor.sub}` },
		});
		// What this approval proves, stated plainly (SPEC §6.3): either the agent asserted it, or
		// whoever controls the number the company has linked replied. The channel evidence goes as a
		// selective disclosure, never in the clear.
		op.interno.metodoAprobacion = canal ? "company_channel" : "agent_asserted";
		this.eslabon(
			tenantId,
			op,
			"operador",
			"user_approval",
			{
				revision,
				terms_digest: op.interno.termsDigest,
				method: op.interno.metodoAprobacion,
				...(canal ? { channel: canal.canal, display_code: canal.display_code } : {}),
				...(actor.protocolo === "poppy" ? { poppy_confirmation: { approved_by: approvedBy, confirmed_at: op.confirmation.confirmed_at } } : {}),
				// Confirmed by standing permission: the customer did not see this revision; they authorized it earlier, with a cap.
				...(approvedBy === "standing_permission" ? { basis: "standing_permission" } : {}),
			},
			canal ? { evidence: { inbound_text: canal.inbound_text, provider_message_id: canal.provider_message_id } } : {},
		);
		if (op.interno.revisionEmpresa?.estado === "pendiente") {
			// Customer approval ≠ company approval: the institutional rule still governs.
			this.transicion(op, "waiting_human", "company_review_required");
			this.estadoCaso(tenantId, op.interno.caseId, "waiting_review");
			this.evento(tenantId, op.interno.caseId, "review.requested", { review_id: op.interno.revisionEmpresa.id, huella: op.interno.huella, motivo: op.interno.revisionEmpresa.motivo });
			return { status: 200, body: this.visible(op) };
		}
		await this.ejecutar(tenantId, op);
		return { status: 200, body: this.visible(op) };
	}

	/** A company person decides on the frozen request (Human Review). */
	async decidirRevision(tenantId: string, reviewId: string, decision: "aprobada" | "rechazada"): Promise<Operacion | null> {
		const op = [...this.base(tenantId).operaciones.values()].find((o) => o.interno.revisionEmpresa?.id === reviewId);
		if (!op || op.interno.revisionEmpresa?.estado !== "pendiente") return null;
		op.interno.revisionEmpresa.estado = decision;
		// Second decision, on the same digest the customer approved, with another principal: a company
		// member (the admin, because the customer is not a member) (round 4, M1).
		this.evento(tenantId, op.interno.caseId, "review.decided", { review_id: reviewId, decision, huella: op.interno.huella, principal: { tipo: "miembro_empresa", rol: "admin" } });
		// After the customer's approval and on the same digest (SPEC §6.5). Who decided is recorded
		// as a role, never as a name.
		this.eslabon(tenantId, op, "empresa", "company_review", {
			revision: op.revision,
			terms_digest: op.interno.termsDigest,
			decision: decision === "aprobada" ? "approved" : "denied",
			role: "revisor_empresa",
		});
		if (decision === "rechazada") {
			// Company rejection after confirmation: `failed` («The action wasn't completed»,
			// operations §3). `cancelled` is for what the agent declines (operations §3 and §7).
			op.result = { summary: "La empresa no aprobó el cambio. El despacho sigue en su fecha original; no se hizo ningún cambio.", data: { effects: [] } };
			this.transicion(op, "failed", "company_declined");
			this.firmarResultado(tenantId, op);
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
			return op;
		}
		await this.ejecutar(tenantId, op);
		return op;
	}

	/**
	 * Tool Gateway → company system → verification by reading back. A timeout is not `failed`:
	 * the operation stays `in_progress` and the case `needs_attention` until it is known.
	 */
	private async ejecutar(tenantId: string, op: Operacion): Promise<void> {
		if (op.interno.intent.capability === "pedido.crear") return this.ejecutarCompra(tenantId, op);
		const con = conectorDe(this.empresa(tenantId), op.interno.intent.capability);
		if (con) return this.ejecutarConector(tenantId, op, con);
		const empresa = this.empresa(tenantId);
		const { pedidoId, nuevaFecha } = op.interno.intent.inputs;
		this.estadoCaso(tenantId, op.interno.caseId, "running");
		const falla = empresa.sistema.proximaFalla;
		empresa.sistema.proximaFalla = undefined;
		if (op.interno.ejecutada) return;
		// Precondition (round 3, M3): it executes only if the system is still as the approved terms
		// describe it («del 24 al 28»). If another operation changed it meanwhile, `failed` without effect:
		// never two contradictory `succeeded` on the same order, nor signed terms that are no longer true.
		const actual = empresa.sistema.pedidos.find((p) => p.id === pedidoId);
		if (!actual || actual.despacho !== op.terms.despacho_actual) {
			empresa.sistema.proximaFalla = falla;
			op.result = { summary: `No se hizo ningún cambio: el despacho del pedido ${pedidoId} cambió después de que se propuso este cambio. Pide una propuesta nueva.`, data: { effects: [] } };
			this.transicion(op, "failed", "precondition_failed");
			this.firmarResultado(tenantId, op);
			this.evento(tenantId, op.interno.caseId, "tool.precondition_failed", { capability: op.interno.intent.capability, huella: op.interno.huella });
			this.estadoCaso(tenantId, op.interno.caseId, "failed");
			return;
		}
		this.transicion(op, "executing", "execution_started");
		// What the operator executed, on the approved digest and with the Release it acted under.
		this.eslabon(tenantId, op, "operador", "execution", {
			revision: op.revision,
			terms_digest: op.interno.termsDigest,
			capability: op.interno.intent.capability,
			release: this.releaseDigest(tenantId),
			attempt: 1,
		});
		if (falla === "definitiva") {
			op.result = { summary: "El sistema de la empresa rechazó el cambio. El despacho sigue en su fecha original.", data: { effects: [] } };
			this.transicion(op, "failed", "company_system_rejected");
			this.firmarResultado(tenantId, op);
			this.evento(tenantId, op.interno.caseId, "tool.failed", { capability: op.interno.intent.capability });
			this.estadoCaso(tenantId, op.interno.caseId, "failed");
			return;
		}
		const pedido = empresa.sistema.pedidos.find((p) => p.id === pedidoId)!;
		const anterior = pedido.despacho;
		pedido.despacho = nuevaFecha;
		op.interno.ejecutada = true;
		op.interno.nativo.efectos.push({ system: "erp", change: `despacho ${anterior} → ${nuevaFecha}`, applied: true });
		this.evento(tenantId, op.interno.caseId, "tool.executed", { capability: op.interno.intent.capability, huella: op.interno.huella });
		if (falla === "desconocida") {
			// The system applied the change but the response never arrived: SOVRAS does not know yet.
			this.evento(tenantId, op.interno.caseId, "tool.outcome_unknown", { capability: op.interno.intent.capability });
			this.transicion(op, "pending_verification", "erp_response_lost");
			this.firmarIncierto(tenantId, op, `Todavía no se sabe si el sistema de ${empresa.nombre} aplicó el cambio: no llegó su respuesta. No se repetirá; se confirmará leyendo el sistema.`);
			this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
			return;
		}
		if (op.interno.nativo.compromiso.mode === "conditional" && !mutado("condicion")) {
			// The condition: the carrier must accept. It is asked ONCE (at most once).
			const t = this.transportista(tenantId);
			t.solicitudes.push({ pedidoId, fecha: nuevaFecha, at: new Date().toISOString() });
			const resp = t.respuesta[pedidoId] ?? "acepta";
			t.confirmado[pedidoId] = resp === "acepta" ? "accepted" : resp === "rechaza" ? "rejected" : "pending";
			op.interno.nativo.efectos.push({ system: "carrier", change: `solicitud de reprogramación al ${nuevaFecha}`, applied: resp === "acepta", status: resp === "no_responde" ? "sent_unconfirmed" : resp === "acepta" ? "accepted" : "rejected" });
			if (resp === "no_responde") {
				this.evento(tenantId, op.interno.caseId, "carrier.no_response", { pedidoId });
				if (mutado("no_failed_incierto")) {
					op.result = { summary: "El transportista no respondió.", data: { effects: op.interno.nativo.efectos } };
					this.transicion(op, "failed", "carrier_timeout");
					this.firmarResultado(tenantId, op);
					return;
				}
				// It is unknown whether the carrier applied it: neither retry nor `failed` (operations §6).
				this.transicion(op, "pending_verification", "carrier_no_response");
				this.firmarIncierto(tenantId, op, `Todavía no se sabe si ${pedido.transportista} aceptó el ${nuevaFecha}: no respondió. No se le vuelve a pedir; se le consultará.`);
				this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
				return;
			}
			if (resp === "rechaza") return this.rechazoTransportista(tenantId, op, anterior);
		}
		this.verificar(tenantId, op, anterior);
	}

	/**
	 * The carrier rejected: `failed` with declared partial effects. The ERP change is compensated
	 * and read again; the outcome states what was done and what was undone.
	 */
	private rechazoTransportista(tenantId: string, op: Operacion, anterior: string): void {
		const empresa = this.empresa(tenantId);
		const { pedidoId, nuevaFecha } = op.interno.intent.inputs;
		const pedido = empresa.sistema.pedidos.find((p) => p.id === pedidoId)!;
		const erp = op.interno.nativo.efectos.find((e) => e.system === "erp");
		if (!mutado("efectos_parciales")) {
			pedido.despacho = anterior;
			if (erp) erp.reverted = true;
		}
		const leido = empresa.sistema.pedidos.find((p) => p.id === pedidoId)!;
		this.eslabon(tenantId, op, "operador", "read_back", {
			method: "system_read_back",
			source: "company_system",
			matches_terms: false,
			observed: { pedido: leido.id, despacho_nuevo: leido.despacho, carrier_acceptance: "rejected" },
		});
		op.result = mutado("efectos_parciales")
			? { summary: "No se pudo cambiar la fecha." }
			: {
					summary: `No se cambió la fecha: ${pedido.transportista} rechazó el ${nuevaFecha}. El sistema de ${empresa.nombre} se había actualizado y se revirtió; el despacho sigue el ${leido.despacho}.`,
					data: { effects: op.interno.nativo.efectos },
				};
		this.transicion(op, "failed", "carrier_rejected");
		this.firmarResultado(tenantId, op);
		this.evento(tenantId, op.interno.caseId, "carrier.rejected", { pedidoId });
		this.estadoCaso(tenantId, op.interno.caseId, "failed");
	}

	/** Outcome Verification: the system is read; the adapter's 200 closes nothing. */
	verificar(tenantId: string, op: Operacion, anterior?: string): void {
		if (op.interno.intent.capability === "pedido.crear") return this.verificarCompra(tenantId, op);
		const con = conectorDe(this.empresa(tenantId), op.interno.intent.capability);
		if (con) return this.verificarConector(tenantId, op, con);
		const empresa = this.empresa(tenantId);
		const { pedidoId, nuevaFecha } = op.interno.intent.inputs;
		const leido = empresa.sistema.pedidos.find((p) => p.id === pedidoId);
		// Round 3 (M1): what is observed carries the name of the term it confirms (`despacho_nuevo`, not
		// `despacho`), so the verifier really compares the effect with what was approved.
		const mapa = this.capacidad(tenantId, op).lecturaDeVuelta ?? {};
		const observado: Record<string, unknown> = {};
		if (leido) for (const [termino, campo] of Object.entries(mapa)) observado[termino] = leido[campo];
		const n = op.interno.nativo;
		// VXP Proof · not verifiable: the capability has no way to read back its effect. The most that
		// can be signed is `unknown` (SPEC 8.3), once; never `succeeded`.
		if (Object.keys(mapa).length === 0 && !mutado("sin_lectura_succeeded")) {
			if (n.estado === "executing") {
				this.eslabon(tenantId, op, "operador", "read_back", { method: "none", source: "company_system", matches_terms: false, observed: {} });
				this.transicion(op, "pending_verification", "not_verifiable");
				this.firmarIncierto(tenantId, op, `El cambio se envió al sistema de ${empresa.nombre}, pero esta capacidad no permite comprobarlo leyendo el sistema. No se informa como hecho.`);
				this.evento(tenantId, op.interno.caseId, "tool.not_verifiable", { capability: op.interno.intent.capability, huella: op.interno.huella });
				this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
			}
			return;
		}
		// VXP Proof · contradictory: it was already recorded that what was read does not match what was approved; waits for a person.
		if (n.estado === "waiting_human" && op.interno.ejecutada) return;
		if (n.compromiso.requires.includes("carrier_acceptance")) {
			const t = this.transportista(tenantId);
			if (mutado("condicion")) observado.carrier_acceptance = "accepted";
			else if (t.confirmado[pedidoId] === "pending" || t.confirmado[pedidoId] === undefined) {
				// The later read QUERIES the carrier; it never asks it for the change again.
				if (mutado("sin_reintento")) t.solicitudes.push({ pedidoId, fecha: nuevaFecha, at: new Date().toISOString() });
				t.consultas += 1;
				return;
			} else {
				t.consultas += 1;
				observado.carrier_acceptance = t.confirmado[pedidoId];
				if (t.confirmado[pedidoId] === "rejected") return this.rechazoTransportista(tenantId, op, String(op.terms.despacho_actual));
				const c = n.efectos.find((e) => e.system === "carrier");
				if (c) {
					c.applied = true;
					c.status = "accepted";
				}
			}
		}
		const terminos = [...Object.keys(mapa), ...n.compromiso.requires];
		const coincide = leido !== undefined && Object.keys(mapa).length > 0 && terminos.every((t) => jcs(observado[t]) === jcs(op.terms[t]));
		if (leido && coincide && leido.despacho === nuevaFecha) {
			if (n.cancelacion) n.cancelacion.status = "not_stopped";
			op.result = {
				summary: `Listo: el pedido ${pedidoId} se despacha el ${nuevaFecha}${anterior ? ` (antes ${anterior})` : ""}. Verificado en el sistema de ${empresa.nombre}.`,
				data: { pedido: pedidoId, despacho: nuevaFecha, verificado: "lectura_del_sistema", effects: n.efectos },
			};
			this.transicion(op, "succeeded", "read_back_matches");
			// `succeeded` only after a matching read-back (SPEC §8.3). The compared values are stored, not
			// the body that was read; the address goes as a disclosure.
			const lectura = this.eslabon(
				tenantId,
				op,
				"operador",
				"read_back",
				{ method: "system_read_back", source: "company_system", matches_terms: true, observed: observado },
				{ observed: { direccion: leido.direccion } },
			);
			// If `unknown` was signed before, this is a correction that cites THIS read (SPEC 8.3, 11.1).
			this.firmarResultado(tenantId, op, { lectura });
			// Round 4 (M3): the truth of ONE operation is the final state of its execution (`tool.verified`),
			// not `outcome.verified`, which is the case closure a model proposes. The chain's `outcome` is
			// projected from here.
			this.evento(tenantId, op.interno.caseId, "tool.verified", { method: "read_back", operation_id: op.operation_id, revision: op.revision, huella: op.interno.huella });
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
			return;
		}
		// VXP Proof · contradictory: it executed, but the system says something other than what was approved
		// (another value, or the resource is gone). It is not `succeeded` nor known to be `failed`: the
		// mismatching read and the `unknown` outcome are signed and the case goes to a person. No retry.
		if (mutado("contradiccion_es_exito")) {
			this.transicion(op, "succeeded", "read_back_ignored");
			op.result = { summary: `Listo: el pedido ${pedidoId} se despacha el ${nuevaFecha}.` };
			this.firmarResultado(tenantId, op);
			return;
		}
		this.eslabon(tenantId, op, "operador", "read_back", {
			method: "system_read_back",
			source: "company_system",
			matches_terms: false,
			observed: leido ? observado : { [Object.keys(mapa)[0]]: null },
		});
		if (n.estado === "executing") this.transicion(op, "pending_verification", "read_back_contradicts_terms");
		this.transicion(op, "waiting_human", "read_back_contradicts_terms");
		this.firmarIncierto(
			tenantId,
			op,
			leido
				? `El sistema de ${empresa.nombre} muestra el despacho del pedido ${pedidoId} el ${leido.despacho}, no el ${nuevaFecha} aprobado. Una persona de la empresa lo revisa; no se reintenta.`
				: `El pedido ${pedidoId} ya no aparece en el sistema de ${empresa.nombre}. Una persona de la empresa lo revisa; no se reintenta.`,
		);
		this.evento(tenantId, op.interno.caseId, "tool.read_back_contradicts", { operation_id: op.operation_id, huella: op.interno.huella });
		this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
	}

	cancelar(tenantId: string, op: Operacion): Operacion {
		const n = op.interno.nativo;
		if (n.estado === "executing" || n.estado === "pending_verification") {
			// Once started, cancelling is asking it to stop: it does not promise to revert (design 0.1
			// §3.E; operations §7: «stays `in_progress` until the Company knows whether the action was stopped»).
			if (mutado("cancelacion_honesta")) {
				op.result = { summary: "Cancelado. No se hizo ningún cambio." };
				this.transicion(op, "cancelled", "cancelled");
				this.firmarResultado(tenantId, op);
				return op;
			}
			n.cancelacion ??= { requested_at: new Date().toISOString(), status: "requested", reversal_promised: false };
			this.evento(tenantId, op.interno.caseId, "operation.stop_requested", { operation_id: op.operation_id, estado: n.estado });
			return op;
		}
		if (n.estado === "accepted" || n.estado === "waiting_human") {
			// Before execution there was no effect: it is truly cancelled.
			if (op.interno.revisionEmpresa?.estado === "pendiente") op.interno.revisionEmpresa.estado = "rechazada";
			op.result = { summary: "Cancelado antes de ejecutar. No se hizo ningún cambio.", data: { effects: [] } };
			this.transicion(op, "cancelled", "cancelled_before_execution");
			this.firmarResultado(tenantId, op);
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
			return op;
		}
		if (op.state === "proposed") {
			op.result = { summary: "Cancelado antes de confirmar. No se hizo ningún cambio." };
			this.transicion(op, "cancelled", "declined");
			this.firmarResultado(tenantId, op);
			this.evento(tenantId, op.interno.caseId, "operation.cancelled", { operation_id: op.operation_id });
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
		}
		return op;
	}

	// ── Connector-backed operations (stress sandbox: hospitality and returns) ──────────────────────
	//
	// The same path as rescheduling and purchasing: Policy → frozen revision (digest, company
	// signature) → exact customer approval → [company review] → ONE execution with a
	// precondition → read-back → signed outcome. The connector only provides the system.

	/** The ERP/PMS customer linked to the actor (to read only their own data). */
	erpDe(actor: ActorExterno): string | null {
		return this.clienteErpDe(actor);
	}

	ctx(tenantId: string, clienteId?: string | null): Ctx {
		const titular = clienteId ? this.empresa(tenantId).clientes.find((c) => c.id === clienteId)?.nombre : undefined;
		return { e: this.empresa(tenantId), base: this.base(tenantId), ahora: Date.now() + this.desfaseMs, ...(titular ? { titular } : {}) };
	}

	/** Drafts without proposing: what it would cost (to ask for the exact cap before creating the operation). */
	redactarConector(tenantId: string, capacidad: string, inputs: Record<string, string>): ReturnType<Conector["redactar"]> {
		const con = conectorDe(this.empresa(tenantId), capacidad);
		return con ? con.redactar(this.ctx(tenantId), inputs) : { ok: false, motivo: "capability_not_in_release" };
	}

	private mismoRecurso(con: Conector, op: Operacion, inputs: Record<string, string>): boolean {
		if (op.interno.intent.capability !== con.capacidad) return false;
		const r = con.recurso(inputs);
		return r === "nuevo" ? jcs(op.interno.intent.inputs) === jcs(inputs) : con.recurso(op.interno.intent.inputs) === r;
	}

	private sinSal(t: Record<string, unknown>): string {
		const { vxp_salt: _s, ...resto } = t;
		return jcs(resto);
	}

	proponerOperacion(
		actor: ActorExterno,
		caseId: string,
		capacidad: string,
		inputs: Record<string, string>,
		sesion: string | null,
		solicitud: Record<string, unknown> | null = null,
		historia: Nativo["eventos"] = [],
	): { ok: true; operacion: Operacion } | { ok: false; falta: string[] | string; operacion?: Operacion } {
		const empresa = this.empresa(actor.tenantId);
		const con = conectorDe(empresa, capacidad);
		if (!con) return { ok: false, falta: "no_encontrado" };
		const cap = empresa.release.capacidades.find((c) => c.id === capacidad)!;
		const intent: ActionIntent = { capability: capacidad, inputs, reason: `El cliente pide: ${cap.descripcion.toLowerCase()}`, expectedEffect: "write" };
		const decision = this.decidir(actor, intent);
		this.evento(actor.tenantId, caseId, decision.decision === "allow" ? "policy.allowed" : decision.decision === "review" ? "policy.review_required" : "policy.denied", { ...decision, fase: "proponer" });
		if (decision.decision === "deny") {
			if (decision.basis === "customer_not_linked_to_company_system") return { ok: false, falta: con.recurso(inputs) === "nuevo" ? "sin_vinculo" : "no_encontrado" };
			if (decision.basis === "resource_not_owned_by_customer") return { ok: false, falta: "no_encontrado" };
			return { ok: false, falta: decision.falta ?? "sign_in" };
		}
		const red = con.redactar(this.ctx(actor.tenantId, actor.clienteId), inputs);
		if (!red.ok) return { ok: false, falta: red.motivo };
		const base = this.base(actor.tenantId);
		for (const existente of base.operaciones.values()) {
			if (existente.state !== "proposed" || !this.mismoRecurso(con, existente, inputs) || !this.esDueno(existente, actor, sesion)) continue;
			// The same request with the same business terms is the same operation (Operations 4).
			if (jcs(existente.interno.intent.inputs) === jcs(inputs) && this.sinSal(existente.terms) === this.sinSal(red.r.terms)) return { ok: true, operacion: existente };
			return this.revisarOperacion(actor, existente, inputs, red.r, decision, solicitud);
		}
		const recurso = con.recurso(inputs);
		// Only one operation in progress per resource: while another confirmed one has not finished, no other is opened.
		if (recurso !== "nuevo" && [...base.operaciones.values()].some((o) => o.state === "in_progress" && CONECTORES[o.interno.intent.capability]?.recurso(o.interno.intent.inputs) === recurso))
			return { ok: false, falta: "en_curso" as const };
		const operacion: Operacion = {
			operation_id: randomId("op_", 9),
			revision: 1,
			state: "proposed",
			summary: "",
			terms: {},
			user_approval_required: true,
			confirmation: null,
			result: null,
			interno: {
				caseId,
				intent,
				huella: "",
				dueno: { protocolo: actor.protocolo, clientId: actor.clientId, sub: actor.sub, clienteId: actor.clienteId, sesion },
				revisionEmpresa: this.revisionDe(decision) ?? (red.r.revision && !mutado("revision_conector") ? { id: randomId("rev_", 6), estado: "pendiente", motivo: red.r.revision } : null),
				ejecutada: false,
				termsDigest: "",
				counterPendiente: null,
				metodoAprobacion: null,
				ultimoFinal: null,
				nativo: {
					estado: "received",
					eventos: historia.length ? historia.map((x) => ({ ...x })) : [{ seq: 0, from: null, to: "received", at: new Date().toISOString(), reason: "request" }],
					compromiso: { mode: "firm", requires: [] },
					efectos: [],
					cancelacion: null,
					intentosAceptar: 0,
					motivoFinal: null,
				},
			},
		};
		operacion.interno.nativo.estado = operacion.interno.nativo.eventos.at(-1)!.to;
		this.transicion(operacion, "proposed", "revision_1");
		this.redactarOperacion(operacion, empresa, red.r);
		base.operaciones.set(operacion.operation_id, operacion);
		if (this.pruebas) {
			this.pruebas.iniciar(actor.tenantId, operacion.operation_id, actor.clientId, this.seudonimo(actor));
			const requestDigest = huellaJcs(solicitud ?? { binding: "vxp.intent", capability: capacidad, inputs });
			this.eslabon(actor.tenantId, operacion, "operador", "request", {
				channel: actor.protocolo,
				client_id: actor.clientId,
				request_digest: requestDigest,
				...(actor.protocolo === "pact" && actor.grantId ? { pact_proposal_receipt: { grantId: actor.grantId, argsHash: requestDigest } } : {}),
			});
			this.firmarTerminos(actor.tenantId, operacion);
		}
		this.evento(actor.tenantId, caseId, "tool.previewed", { operation_id: operacion.operation_id, capability: capacidad, revision: 1, huella: operacion.interno.huella });
		return { ok: true, operacion };
	}

	private limiteRevisiones(tenantId: string, op: Operacion): boolean {
		if (op.revision < this.limites(tenantId).max_revisions || mutado("limite_revisiones")) return false;
		op.result = { summary: "Se alcanzó el máximo de revisiones de esta solicitud. No se hizo ningún cambio.", data: { effects: [] } };
		this.transicion(op, "failed", "negotiation_limit_exceeded");
		this.firmarResultado(tenantId, op);
		this.estadoCaso(tenantId, op.interno.caseId, "completed");
		return true;
	}

	/** New revision of the same operation: the request is recorded as a `counter` and the revision cites it. */
	private revisarOperacion(actor: ActorExterno, op: Operacion, inputs: Record<string, string>, r: Redaccion, decision: DecisionPolicy, solicitud: Record<string, unknown> | null): { ok: true; operacion: Operacion } | { ok: false; falta: string; operacion: Operacion } {
		const t = actor.tenantId;
		if (this.limiteRevisiones(t, op)) return { ok: false, falta: "limite_revisiones", operacion: op };
		if (!op.interno.counterPendiente)
			op.interno.counterPendiente = this.eslabon(t, op, "operador", "counter", { base_revision: op.revision, counter_digest: huellaJcs(solicitud ?? { binding: "vxp.intent", capability: op.interno.intent.capability, inputs }), from: "personal_agent" });
		op.revision += 1;
		op.interno.intent = { ...op.interno.intent, inputs };
		// The review rule is evaluated on the new terms.
		const nueva = this.revisionDe(decision) ?? (r.revision && !mutado("revision_conector") ? { id: randomId("rev_", 6), estado: "pendiente" as const, motivo: r.revision } : null);
		if (!nueva) op.interno.revisionEmpresa = null;
		else if (!op.interno.revisionEmpresa) op.interno.revisionEmpresa = nueva;
		this.redactarOperacion(op, this.empresa(t), r);
		this.transicion(op, "proposed", `revision_${op.revision}`);
		this.firmarTerminos(t, op);
		this.evento(t, op.interno.caseId, "tool.previewed", { operation_id: op.operation_id, revision: op.revision, huella: op.interno.huella });
		return { ok: true, operacion: op };
	}

	private redactarOperacion(op: Operacion, empresa: Empresa, r: Redaccion): void {
		op.terms = r.terms;
		op.summary = r.summary + (op.interno.revisionEmpresa && !/revisa una persona/.test(r.summary) ? " Antes de ejecutarse lo revisa una persona de la empresa." : "");
		const ttl = Date.now() + this.limites(empresa.tenantId).proposal_ttl_seconds * 1000;
		op.expires_at = new Date(Math.min(ttl, r.vence ? Date.parse(r.vence) : ttl)).toISOString();
		op.interno.monto = r.monto;
		op.interno.huella = sha256(jcs({ c: op.interno.intent.capability, i: op.interno.intent.inputs, t: op.terms, r: op.revision }));
		op.interno.termsDigest = huellaTerminos({
			company: this.pruebas ? this.pruebas.issuer(empresa.tenantId) : empresa.tenantId,
			operation_id: op.operation_id,
			revision: op.revision,
			summary: op.summary,
			terms: op.terms,
			expires_at: op.expires_at ?? null,
			user_approval_required: op.user_approval_required,
		});
	}

	/** Structured counter-proposal on a connector-backed operation: a new revision within policy, or a no. */
	contraproponerOperacion(actor: ActorExterno, op: Operacion, pide: Record<string, unknown>): { ok: true; operacion: Operacion; notas: string[] } | { ok: false; motivo: string } {
		const t = actor.tenantId;
		const con = conectorDe(this.empresa(t), op.interno.intent.capability);
		if (op.state !== "proposed" || !con?.contraoferta) return { ok: false, motivo: "counter_rejected" };
		if (this.limiteRevisiones(t, op)) return { ok: false, motivo: "negotiation_limit_exceeded" };
		const c = con.contraoferta(this.ctx(t), op, pide);
		if (!c.ok) return { ok: false, motivo: c.motivo };
		const decision = this.decidir(actor, { ...op.interno.intent, inputs: c.inputs });
		if (decision.decision === "deny") return { ok: false, motivo: decision.falta === "sign_in" ? "sign_in_required" : "insufficient_scope" };
		const red = con.redactar(this.ctx(t, actor.clienteId), c.inputs);
		if (!red.ok) return { ok: false, motivo: red.motivo };
		op.interno.counterPendiente = this.eslabon(t, op, "operador", "counter", { base_revision: op.revision, counter_digest: huellaJcs(pide), from: "personal_agent" });
		const r = this.revisarOperacion(actor, op, c.inputs, red.r, decision, null);
		return r.ok ? { ok: true, operacion: r.operacion, notas: c.notas } : { ok: false, motivo: r.falta === "limite_revisiones" ? "negotiation_limit_exceeded" : r.falta };
	}

	private async ejecutarConector(tenantId: string, op: Operacion, con: Conector): Promise<void> {
		const empresa = this.empresa(tenantId);
		this.estadoCaso(tenantId, op.interno.caseId, "running");
		const falla = empresa.sistema.proximaFalla;
		empresa.sistema.proximaFalla = undefined;
		if (op.interno.ejecutada) return;
		const ctx = this.ctx(tenantId);
		// Precondition: the system is still as the approved terms describe it (stock, availability,
		// dates, policy deadline). If not, `failed` without effect and with its evidence.
		const problema = mutado("precondicion_conector") ? null : con.precondicion(ctx, op);
		if (problema) {
			empresa.sistema.proximaFalla = falla;
			op.result = { summary: `No se hizo ningún cambio: ${problema}. Pide una propuesta nueva.`, data: { effects: [] } };
			this.transicion(op, "failed", "precondition_failed");
			this.firmarResultado(tenantId, op);
			this.evento(tenantId, op.interno.caseId, "tool.precondition_failed", { capability: op.interno.intent.capability, motivo: problema, huella: op.interno.huella });
			this.estadoCaso(tenantId, op.interno.caseId, "failed");
			return;
		}
		this.transicion(op, "executing", "execution_started");
		this.eslabon(tenantId, op, "operador", "execution", { revision: op.revision, terms_digest: op.interno.termsDigest, capability: op.interno.intent.capability, release: this.releaseDigest(tenantId), attempt: 1 });
		const erp = empresa.clientes.find((c) => c.id === op.interno.dueno.clienteId)?.erp?.id ?? "";
		const r = con.ejecutar(ctx, op, erp, falla);
		op.interno.nativo.efectos.push(...r.efectos);
		if (r.estado === "rechazado") {
			op.result = { summary: r.motivo ?? "El sistema de la empresa rechazó la operación. No se hizo ningún cambio.", data: { effects: op.interno.nativo.efectos } };
			this.transicion(op, "failed", "company_system_rejected");
			this.firmarResultado(tenantId, op);
			this.evento(tenantId, op.interno.caseId, "tool.failed", { capability: op.interno.intent.capability, efectos: r.efectos.length });
			this.estadoCaso(tenantId, op.interno.caseId, "failed");
			return;
		}
		op.interno.ejecutada = true;
		this.evento(tenantId, op.interno.caseId, "tool.executed", { capability: op.interno.intent.capability, huella: op.interno.huella, efectos: r.efectos.map((x) => x.change) });
		if (r.estado === "desconocido") {
			this.evento(tenantId, op.interno.caseId, "tool.outcome_unknown", { capability: op.interno.intent.capability });
			this.transicion(op, "pending_verification", "system_response_lost");
			this.firmarIncierto(tenantId, op, r.motivo ?? "Todavía no se sabe si la operación tuvo efecto. No se repetirá; se confirmará leyendo el sistema.");
			this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
			return;
		}
		this.verificarConector(tenantId, op, con);
	}

	/** Read-back of the company system (PMS/ERP and payment provider): `succeeded` only if it matches. */
	private verificarConector(tenantId: string, op: Operacion, con: Conector): void {
		const n = op.interno.nativo;
		if (n.estado === "waiting_human" && op.interno.ejecutada) return;
		const ctx = this.ctx(tenantId);
		const l = con.leer(ctx, op);
		const terminos = Object.keys(this.capacidad(tenantId, op).lecturaDeVuelta ?? {});
		const observado = Object.fromEntries(terminos.map((t) => [t, l.observado[t] ?? null]));
		const coincide = terminos.length > 0 && terminos.every((t) => (mutado("lectura_pago_ignorada") && t === "garantia") || jcs(observado[t]) === jcs(op.terms[t] ?? null));
		if (coincide) {
			const ex = con.exito(ctx, op);
			op.result = { summary: ex.summary, data: { ...ex.data, effects: n.efectos } };
			this.transicion(op, "succeeded", "read_back_matches");
			const lectura = this.eslabon(tenantId, op, "operador", "read_back", { method: "system_read_back", source: "company_system", matches_terms: true, observed: mutado("lectura_pago_ignorada") ? Object.fromEntries(terminos.map((t) => [t, op.terms[t] ?? null])) : observado }, l.divulgacion ? { observed: l.divulgacion } : {});
			this.firmarResultado(tenantId, op, { lectura });
			this.evento(tenantId, op.interno.caseId, "tool.verified", { method: "read_back", capability: op.interno.intent.capability, operation_id: op.operation_id, revision: op.revision, huella: op.interno.huella });
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
			return;
		}
		// Contradictory: it executed and the system (or the payment ledger) says otherwise. Neither success nor retry.
		this.eslabon(tenantId, op, "operador", "read_back", { method: "system_read_back", source: "company_system", matches_terms: false, observed: observado });
		if (n.estado === "executing") this.transicion(op, "pending_verification", "read_back_contradicts_terms");
		this.transicion(op, "waiting_human", "read_back_contradicts_terms");
		const distintos = terminos.filter((t) => jcs(observado[t]) !== jcs(op.terms[t] ?? null));
		this.firmarIncierto(tenantId, op, `Lo que muestran los sistemas de ${this.empresa(tenantId).nombre} no calza con lo aprobado (${distintos.join(", ")}). Una persona de la empresa lo revisa; no se reintenta ni se informa como hecho.`);
		this.evento(tenantId, op.interno.caseId, "tool.read_back_contradicts", { operation_id: op.operation_id, terminos: distintos, huella: op.interno.huella });
		this.estadoCaso(tenantId, op.interno.caseId, "needs_attention");
	}

	/** Sandbox reset: open proposals expire with their signed outcome (nothing is deleted). */
	vencerPropuestas(tenantId: string, motivo: string): number {
		let n = 0;
		for (const op of this.base(tenantId).operaciones.values()) {
			if (op.state !== "proposed") continue;
			op.result = { summary: "No se confirmó: el entorno de prueba se reinició. No se hizo ningún cambio." };
			this.transicion(op, "expired", motivo);
			this.firmarResultado(tenantId, op);
			this.estadoCaso(tenantId, op.interno.caseId, "completed");
			n++;
		}
		return n;
	}
}

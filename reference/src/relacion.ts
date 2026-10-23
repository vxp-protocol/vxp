// VXP Relationship: the bilateral relationship between a company and a customer's personal agent.
//
// - It arises only from a user authorization: an `authorization_details` (RFC 9396) of type
//   `RAR_RELACION`, requested by the agent in the Device Authorization and approved by the person in
//   «Vincular con WhatsApp». Without it there is no relationship and the company cannot initiate anything.
// - It fixes both identities (the company's issuer; the agent's client_id + sub, and the customer who
//   linked), the actions the company may initiate, their limits, validity and revocation.
// - What the company initiates is signed with a company key dedicated to this purpose
//   (`vxp-company-request+jwt`), separate from the proof, Poppy and PACT keys. The key is published in the
//   issuer's RFC 8414 metadata (`vxp_relationship.jwks_uri`), just like the proof anchor.
// - Delivery is a POST to the inbox the agent declared in its Client ID Metadata Document
//   (`extensions["vxpprotocol.org/relationship"].inbox_uri`, same host as the client_id). With no real
//   external counterpart, what is verified is the signed outbox and its HTTP delivery to a local test inbox.

import type { FetchLike } from "./identidad.ts";
import { createPrivateKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type ClaveFirma, type Jwk, ahora, nuevaClaveEs256, randomId, signJwt, thumbprint } from "./jose.ts";
import { mutado } from "./mutar.ts";

export const RAR_RELACION = "https://vxpprotocol.org/rar/relationship";
/**
 * Relationship consent checkbox in «Vincular». It is NOT a company scope: it does not go into the
 * scope catalog published by poppy.json or the PACT Agent Card (their contract is left untouched).
 */
export const ALCANCE_RELACION = "vxp:relationship";
export const ETIQUETA_RELACION = "Que la empresa contacte a tu asistente sólo para lo que se indica arriba";
/**
 * Inbox for a Poppy agent that declares no `inbox_uri`: the company writes to it inside its Poppy
 * conversation (a `message` event with `role: company`), which the agent already reads with `GET …/events?wait=`. This way
 * a current Poppy agent receives the request without implementing anything new (finding with test agent B, Oct 21 06:28).
 */
export const BUZON_CONVERSACION = "poppy:conversation";

/** Actions a company may initiate toward the agent, if the relationship includes them. */
export const ACCIONES_EMPRESA: Record<string, { descripcion: string; capacidad?: string; respuestas?: string[]; solo?: "comercio" | "hotel"; descripcionHotel?: string }> = {
	"despacho.proponer_cambio": { descripcion: "proponerte cambios de fecha de despacho de tus pedidos", capacidad: "pedido.reprogramar_despacho" },
	// Stress-test sandbox: the hotel proposes changing a reservation's dates (a normal operation, not executed).
	"reserva.proponer_cambio": { descripcion: "proponerte cambios de fechas de tus reservas", capacidad: "reserva.modificar_fechas" },
	"incidencia.avisar": { descripcion: "avisarte incidencias de tus pedidos", descripcionHotel: "avisarte incidencias de tus reservas" },
	// «Confirmar o bloquear, nada más»: the company asks and the agent may only choose one of these
	// answers, once and before it expires. It opens no other action.
	"alerta.confirmar_o_bloquear": { descripcion: "pedirle a tu asistente que confirme o bloquee un despacho sospechoso (sólo esas dos respuestas)", respuestas: ["confirmar", "bloquear"], solo: "comercio" },
	// Hotel: the guest arriving today has not checked in. «Mantener» keeps the room; «liberar» releases it.
	"alerta.mantener_o_liberar": { descripcion: "preguntarle a tu asistente si mantiene o libera tu reserva cuando no has llegado (sólo esas dos respuestas)", respuestas: ["mantener", "liberar"], solo: "hotel" },
};

/** How an action is described to the person, in their industry's words (test agent B, Oct 21 11:03: the hotel said «pedidos»). */
export function describir(accion: string, hotel = false): string {
	const a = ACCIONES_EMPRESA[accion];
	return (hotel ? a?.descripcionHotel : undefined) ?? a?.descripcion ?? accion;
}

/** A closed question the company asked the agent within a relationship. */
export type Alerta = {
	id: string;
	relacionId: string;
	tenantId: string;
	ordenRef: string;
	opciones: string[];
	vence: number;
	respuesta: null | { decision: string; at: number };
};

/** Maximum limits the company accepts, even if the agent asks for more. */
export const TOPE_POR_DIA = 10;
export const TOPE_DURACION_S = 90 * 86_400;

export type DetalleRelacion = { type: string; actions: string[]; identifier: "relationship"; limits: { max_per_day: number; duration_seconds: number } };

export type Relacion = {
	id: string;
	tenantId: string;
	issuer: string;
	clientId: string;
	sub: string;
	clienteId: string;
	grantId: string;
	acciones: string[];
	limites: { max_per_day: number };
	creada: number;
	expira: number;
	revocada: null | { por: "usuario" | "agente" | "empresa"; at: number };
	inbox: string;
	/** Instants (s) of each company-initiated request, for the per-day limit. */
	iniciadas: number[];
};

export type Salida = {
	id: string;
	tenantId: string;
	relacionId: string;
	accion: string;
	destino: string;
	mensaje: string;
	at: string;
	entrega: "pendiente" | "entregado" | "fallido";
	http?: number;
};

export type ErrorRelacion =
	| "relationship_not_found"
	| "relationship_revoked"
	| "relationship_expired"
	| "action_not_authorized"
	| "relationship_limit_exceeded";

export class Relaciones {
	readonly todas = new Map<string, Relacion>();
	readonly salida: Salida[] = [];
	readonly alertas = new Map<string, Alerta>();

	/** The company opens a closed question; it expires in `segundos`. */
	nuevaAlerta(r: Relacion, accion: string, ordenRef: string, segundos = 3600): Alerta {
		const a: Alerta = { id: randomId("alr_", 9), relacionId: r.id, tenantId: r.tenantId, ordenRef, opciones: ACCIONES_EMPRESA[accion].respuestas ?? [], vence: ahora() + segundos, respuesta: null };
		this.alertas.set(a.id, a);
		return a;
	}

	/** Company-signed receipt of the agent's reply: what was asked, what it answered and when. */
	recibo(r: Relacion, a: Alerta): string {
		const k = this.llave(r.tenantId);
		return signJwt(
			{ alg: "ES256", typ: "vxp-reply-receipt+jwt", kid: k.publicJwk.kid },
			{ iss: r.issuer, aud: r.clientId, sub: r.sub, rel: r.id, alert: a.id, order_ref: a.ordenRef, decision: a.respuesta?.decision, answered_at: a.respuesta?.at, iat: ahora(), jti: randomId("", 12) },
			k.privateKey,
		);
	}
	private readonly llaves = new Map<string, ClaveFirma>();
	/** Where the relationship keys persist (one file per company); null keeps them in memory. */
	dirLlaves: string | null = null;

	/**
	 * The company's relationship key (R5). With a key directory it survives restarts, so agreements and requests
	 * signed before a restart still verify against the published key.
	 */
	llave(tenantId: string): ClaveFirma {
		let k = this.llaves.get(tenantId);
		if (k) return k;
		const ruta = this.dirLlaves ? join(this.dirLlaves, `relationship-${tenantId}.json`) : null;
		if (ruta && existsSync(ruta)) {
			const privateKey = createPrivateKey({ key: JSON.parse(readFileSync(ruta, "utf8")).current, format: "jwk" });
			const j = privateKey.export({ format: "jwk" }) as Jwk;
			const publicJwk: Jwk = { kty: "EC", crv: j.crv, x: j.x, y: j.y };
			publicJwk.kid = thumbprint(publicJwk);
			publicJwk.alg = "ES256";
			publicJwk.use = "sig";
			k = { privateKey, publicJwk };
		} else {
			k = nuevaClaveEs256();
			if (ruta) {
				mkdirSync(this.dirLlaves!, { recursive: true });
				writeFileSync(ruta, JSON.stringify({ current: k.privateKey.export({ format: "jwk" }) }), { encoding: "utf8", mode: 0o600 });
			}
		}
		this.llaves.set(tenantId, k);
		return k;
	}

	jwks(tenantId: string) {
		return { keys: [this.llave(tenantId).publicJwk] };
	}

	/** Validates a relationship RAR detail. Caps limits and duration at the company's maximums. */
	static validar(d: Record<string, unknown>, permitidas: string[]): DetalleRelacion | null {
		if (d?.type !== RAR_RELACION || d.identifier !== "relationship" || !Array.isArray(d.actions) || d.actions.length === 0) return null;
		if (!d.actions.every((a) => typeof a === "string" && permitidas.includes(a))) return null;
		const lim = (d.limits ?? {}) as Record<string, unknown>;
		const porDia = Number(lim.max_per_day ?? 3);
		const dur = Number(lim.duration_seconds ?? 30 * 86_400);
		if (!Number.isInteger(porDia) || porDia < 1 || !Number.isInteger(dur) || dur < 1) return null;
		return { type: RAR_RELACION, actions: [...new Set(d.actions as string[])], identifier: "relationship", limits: { max_per_day: Math.min(porDia, TOPE_POR_DIA), duration_seconds: Math.min(dur, TOPE_DURACION_S) } };
	}

	static texto(d: DetalleRelacion, empresa: string, hotel = false): string {
		const dias = Math.max(1, Math.round(d.limits.duration_seconds / 86_400));
		return `permitir que ${empresa} contacte a tu asistente para ${d.actions.map((a) => describir(a, hotel)).join(" y ")}, hasta ${d.limits.max_per_day} veces por día, durante ${dias} día${dias === 1 ? "" : "s"}`;
	}

	crear(input: Omit<Relacion, "id" | "creada" | "expira" | "revocada" | "iniciadas" | "acciones" | "limites"> & { detalle: DetalleRelacion }): { relacion: Relacion; acuerdo: string } {
		const t = ahora();
		const r: Relacion = {
			id: randomId("rel_", 9),
			tenantId: input.tenantId,
			issuer: input.issuer,
			clientId: input.clientId,
			sub: input.sub,
			clienteId: input.clienteId,
			grantId: input.grantId,
			inbox: input.inbox,
			acciones: input.detalle.actions,
			limites: { max_per_day: input.detalle.limits.max_per_day },
			creada: t,
			expira: t + input.detalle.limits.duration_seconds,
			revocada: null,
			iniciadas: [],
		};
		this.todas.set(r.id, r);
		return { relacion: r, acuerdo: this.acuerdo(r) };
	}

	/** The signed agreement the agent receives: what the company may initiate, until when and how often. */
	acuerdo(r: Relacion): string {
		const k = this.llave(r.tenantId);
		return signJwt(
			{ alg: "ES256", typ: "vxp-relationship+jwt", kid: k.publicJwk.kid },
			{ iss: r.issuer, aud: r.clientId, sub: r.sub, rel: r.id, actions: r.acciones, limits: r.limites, iat: r.creada, exp: r.expira, jti: randomId("", 12) },
			k.privateKey,
		);
	}

	/** Valid and belonging to this agent, or the exact reason why not. */
	vigente(id: string, tenantId: string): Relacion | ErrorRelacion {
		const r = this.todas.get(id);
		if (!r || r.tenantId !== tenantId) return "relationship_not_found";
		if (r.revocada && !mutado("relacion_revocada")) return "relationship_revoked";
		if (r.expira <= ahora() && !mutado("relacion_vencida")) return "relationship_expired";
		return r;
	}

	revocar(id: string, por: "usuario" | "agente" | "empresa"): Relacion | null {
		const r = this.todas.get(id);
		if (!r) return null;
		r.revocada ??= { por, at: ahora() };
		return r;
	}

	/**
	 * The company initiates a request within the relationship. Checks validity, authorized action and
	 * per-day limit BEFORE signing anything; if it passes, it leaves the signed message in the outbox.
	 */
	autorizarInicio(id: string, tenantId: string, accion: string): Relacion | ErrorRelacion {
		const r = this.vigente(id, tenantId);
		if (typeof r === "string") return r;
		if (!r.acciones.includes(accion) && !mutado("accion_relacion")) return "action_not_authorized";
		const t = ahora();
		r.iniciadas = r.iniciadas.filter((x) => x > t - 86_400);
		if (r.iniciadas.length >= r.limites.max_per_day && !mutado("limite_relacion")) return "relationship_limit_exceeded";
		return r;
	}

	emitir(r: Relacion, accion: string, contenido: Record<string, unknown>): Salida {
		r.iniciadas.push(ahora());
		const k = this.llave(r.tenantId);
		const t = ahora();
		const mensaje = signJwt(
			{ alg: "ES256", typ: "vxp-company-request+jwt", kid: k.publicJwk.kid },
			{ iss: r.issuer, aud: r.clientId, sub: r.sub, rel: r.id, action: accion, content: contenido, iat: t, exp: t + 3600, jti: randomId("", 12) },
			k.privateKey,
		);
		const s: Salida = { id: randomId("out_", 9), tenantId: r.tenantId, relacionId: r.id, accion, destino: r.inbox, mensaje, at: new Date().toISOString(), entrega: "pendiente" };
		this.salida.push(s);
		return s;
	}

	/** Delivery inside the agent's Poppy conversation; wired up by the gateway. */
	entregaConversacion: ((s: Salida, r: Relacion) => boolean) | null = null;

	/** Delivers over HTTP to the agent's inbox, or in its Poppy conversation. A failure is recorded; it is not retried here. */
	async entregar(s: Salida, fetch: FetchLike): Promise<Salida> {
		if (s.destino === BUZON_CONVERSACION) {
			const r = this.todas.get(s.relacionId);
			s.entrega = r && this.entregaConversacion?.(s, r) ? "entregado" : "fallido";
			return s;
		}
		try {
			const res = await fetch(s.destino, { method: "POST", redirect: "manual", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: s.mensaje }) });
			s.http = res.status;
			s.entrega = res.status >= 200 && res.status < 300 ? "entregado" : "fallido";
		} catch {
			s.entrega = "fallido";
		}
		return s;
	}
}

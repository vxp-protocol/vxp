// VXP Relationship over Poppy, for present-day Poppy agents (finding with test agent B, Oct 21 06:28:
// the agent had no way to discover the relationship nor an inbox to receive it).
//
// - Discover and request: the agent asks for it in its own words in the Poppy conversation («avísame si pasa algo
//   raro, para confirmar o bloquear»). The company replies with the agreement in business language and a
//   link that only the customer of the linked account can approve (code sent to their WhatsApp).
// - Receive: the company writes to the agent in its Poppy conversation, a `message` event with
//   `role: company`, the question text and, in `data["vxpprotocol.org/relationship"]`, the signed message.
// - Respond: the agent answers in the same conversation with one of the options, as text or via
//   `data`. Once, before it expires and while the relationship is valid; a signed receipt is kept.
// None of this touches the Poppy contract: they are conversation messages with `data` (Poppy 7.4).

import type { AprobacionRelacion } from "./aprobar-relacion.ts";
import { ahora, decodeJwt } from "./jose.ts";
import type { CaraNativa } from "./nativo.ts";
import type { ActorExterno, Nucleo } from "./nucleo.ts";
import type { CaraPoppy, RespuestaRelacion } from "./poppy.ts";
import { type Alerta, type Relacion, Relaciones, describir } from "./relacion.ts";

const norm = (t: string) => t.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");

/** How each option is recognized in the agent's free text. */
const OPCION: Record<string, RegExp> = {
	confirmar: /\bconfirm/,
	bloquear: /\bbloque/,
	mantener: /\bmant(en|ien)/,
	liberar: /\bliber/,
};

/** The agent asks that the company be able to contact it (not «de acuerdo», which in Chile means «ok»). */
const PIDE_RELACION =
	/(confirmar o bloquear|mantener o liberar|avis\w*me\b|\bme avis\w*|que me (avisen|contacten|escriban)|puedan? contactar(me|te|lo|la)?\b|contactarme|acuerdo (para|de) (contacto|aviso|avisos|relacion)|relacion bilateral|vxp relationship|\balertas?\b)/;

const hora = (s: number) => new Date(s * 1000).toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "America/Santiago" });
const fecha = (s: number) => new Date(s * 1000).toLocaleDateString("es-CL", { timeZone: "America/Santiago" });

export function conectarRelacionPoppy(nucleo: Nucleo, poppy: CaraPoppy, nativo: CaraNativa, aprobacion: AprobacionRelacion) {
	const rels = nativo.relaciones;
	const delAgente = (a: ActorExterno) => [...rels.todas.values()].filter((r) => r.tenantId === a.tenantId && r.clientId === a.clientId && r.sub === a.sub);

	/** Open questions for this agent, most recent first. */
	const abiertas = (a: ActorExterno): { alerta: Alerta; rel: Relacion }[] => {
		const mias = new Map(delAgente(a).map((r) => [r.id, r]));
		return [...rels.alertas.values()]
			.filter((x) => mias.has(x.relacionId) && !x.respuesta && x.vence > ahora())
			.reverse()
			.map((alerta) => ({ alerta, rel: mias.get(alerta.relacionId)! }));
	};

	poppy.relacion = {
		responder(a, texto, datos): RespuestaRelacion | null {
			const pendientes = abiertas(a);
			if (!pendientes.length) return null;
			const pedida = typeof datos?.alert_id === "string" ? pendientes.find((p) => p.alerta.id === datos.alert_id) : pendientes[0];
			if (!pedida) return null;
			let decision = typeof datos?.decision === "string" ? datos.decision : null;
			if (!decision) {
				const t = norm(texto);
				const calzan = pedida.alerta.opciones.filter((o) => OPCION[o]?.test(t));
				if (calzan.length === 0) return null;
				if (calzan.length > 1) return { text: `Responde sólo una opción: ${pedida.alerta.opciones.map((o) => `«${o}»`).join(" o ")}.` };
				decision = calzan[0];
			}
			const e = nucleo.empresa(a.tenantId);
			const vigente = nativo.relacionVigente(pedida.rel.id, a.tenantId);
			if (typeof vigente === "string") return { text: `El acuerdo con ${e.nombre} ya no está vigente (${vigente}). No se registró la respuesta.` };
			const r = nativo.responderAlerta(e, vigente, pedida.alerta.id, decision);
			if (r.status !== 200) return { text: `No se registró la respuesta (${String(r.body.error)}).`, data: { "vxpprotocol.org/relationship": { type: "reply_error", alert_id: pedida.alerta.id, ...r.body } } };
			const ref = pedida.alerta.ordenRef;
			const efecto: Record<string, string> = {
				confirmar: `confirmaste ${ref}; el despacho sigue su curso`,
				bloquear: `bloqueaste ${ref}; el despacho quedó retenido y una persona de ${e.nombre} lo revisará`,
				mantener: `la habitación de ${ref} queda guardada para tu llegada`,
				liberar: `la reserva ${ref} quedó liberada`,
			};
			return {
				text: `Registrado: ${efecto[decision] ?? decision}. Constancia firmada adjunta.`,
				data: { "vxpprotocol.org/relationship": { type: "reply_receipt", relationship_id: vigente.id, alert_id: pedida.alerta.id, decision, receipt: r.body.receipt } },
			};
		},

		ofrecer(a, convId, texto): RespuestaRelacion | null {
			if (!PIDE_RELACION.test(norm(texto))) return null;
			const e = nucleo.empresa(a.tenantId);
			if (!a.clienteId || !a.grantId) return { text: `Para dejar un acuerdo de contacto con ${e.nombre}, primero vincula tu cuenta (Vincular con WhatsApp).`, necesita: "sign_in" };
			const vigente = delAgente(a).map((r) => nativo.relacionVigente(r.id, a.tenantId)).find((r): r is Relacion => typeof r !== "string");
			if (vigente) {
				return {
					text: `Ya tienes un acuerdo vigente con ${e.nombre} hasta el ${fecha(vigente.expira)}: puede contactarte para ${vigente.acciones.map((x) => describir(x, Boolean(e.hotel))).join(" y ")}. Te escribiré en esta conversación.`,
					data: { "vxpprotocol.org/relationship": { type: "relationship", relationship_id: vigente.id, actions: vigente.acciones, expires_at: new Date(vigente.expira * 1000).toISOString() } },
				};
			}
			// Only what the agent asked for is offered (test agent B, Oct 21 11:03: the agreement also included «incidencias»).
			const t = norm(texto);
			const pedidas = [
				...(/(mantener|liberar|no lleg|llegada|check.?in)/.test(t) ? ["alerta.mantener_o_liberar"] : []),
				...(/(confirmar|bloquear|compra (rara|extrana|sospechosa)|sospech|fraude)/.test(t) ? ["alerta.confirmar_o_bloquear"] : []),
				...(/(incidencia|retras|atras|problema|novedad)/.test(t) ? ["incidencia.avisar"] : []),
			];
			const { oferta, enlace } = aprobacion.ofrecer(e, { tenantId: a.tenantId, clientId: a.clientId, agente: a.clientId, sub: a.sub, clienteId: a.clienteId, grantId: a.grantId, convId }, pedidas);
			const terminos = Relaciones.texto(oferta.detalle, e.nombre, Boolean(e.hotel));
			return {
				text: `Puedo dejar un acuerdo para ${terminos}. Tú sólo podrás responder con las opciones que te pregunten; nada más. Lo aprueba la persona aquí: ${enlace} (ve el acuerdo y confirma con un código a su WhatsApp registrado). Cuando esté aprobado, ${e.nombre} te escribirá en esta conversación: léela con GET …/events?wait=25 y responde aquí mismo.`,
				data: { "vxpprotocol.org/relationship": { type: "relationship_offer", approval_url: enlace, actions: oferta.detalle.actions, limits: oferta.detalle.limits } },
			};
		},
	};

	// The company delivers, in the Poppy conversation, what it initiates within the relationship.
	rels.entregaConversacion = (s, r) => {
		const p = decodeJwt(s.mensaje)?.payload ?? {};
		const c = (p.content ?? {}) as Record<string, unknown>;
		const e = nucleo.empresa(r.tenantId);
		const resumen = String(c.summary ?? "");
		const opciones = Array.isArray(c.options) ? (c.options as string[]) : [];
		const vence = typeof c.expires_at === "string" ? Math.floor(Date.parse(c.expires_at) / 1000) : null;
		const text = opciones.length
			? `${e.nombre}: ${resumen} ¿${opciones.map((o) => o[0].toUpperCase() + o.slice(1)).join(" o ")}? Responde «${opciones.join("» o «")}»${vence ? ` antes de las ${hora(vence)}` : ""}. Es lo único que puedo preguntarte en este acuerdo.`
			: c.proposal_id
				? `${e.nombre} te propone un cambio: ${resumen} Para aceptarlo, confirma la operación ${String(c.operation_id ?? "")} con la aprobación de la persona.`
				: `${e.nombre} te avisa: ${resumen}`;
		return poppy.escribir(r.tenantId, r.clientId, r.sub, { text, data: { "vxpprotocol.org/relationship": { type: "company_request", relationship_id: r.id, action: s.accion, ...c, message: s.mensaje } } });
	};

	aprobacion.alAprobar = (_o, r, acuerdo) => {
		const e = nucleo.empresa(r.tenantId);
		poppy.escribir(r.tenantId, r.clientId, r.sub, {
			text: `La persona aprobó el acuerdo: ${e.nombre} puede contactarte sólo para ${r.acciones.map((x) => describir(x, Boolean(e.hotel))).join(" y ")}, hasta ${r.limites.max_per_day} veces por día, hasta el ${fecha(r.expira)}. Te escribiré en esta conversación.`,
			data: { "vxpprotocol.org/relationship": { type: "relationship_agreement", relationship_id: r.id, actions: r.acciones, limits: r.limites, expires_at: new Date(r.expira * 1000).toISOString(), agreement: acuerdo } },
		});
	};
}

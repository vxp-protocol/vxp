// Deterministic agent for Hotel Demo: the same role `agente.ts` plays for the hardware store. It turns
// a message into public reads (availability, rates, comparison with the simulated channel
// manager) or into core operations (book, change dates, add a service, cancel).
// It never executes anything: it proposes. A message never approves. It does not invent services or packages.

import { AprobacionOperacion } from "./aprobar-operacion.ts";
import type { ActorExterno, Nucleo, Operacion } from "./nucleo.ts";
import type { Respuesta } from "./agente.ts";
import { huellaJcs } from "./prueba.ts";
import { cargoCancelacion } from "./conectores.ts";
import { mutado } from "./mutar.ts";
import { type Estadia, clp, cotizarEstadia, disponibilidad, interpretarHotel, isoDia, masDias, revisarEstadia, textoCancelacion, textoEstadia } from "./hotel.ts";

const MOTIVOS: Record<string, string> = {
	sin_disponibilidad: "No tenemos disponibilidad de ese tipo de habitación para esas fechas.",
	llegada_en_el_pasado: "La fecha de llegada ya pasó.",
	salida_antes_de_llegada: "La salida tiene que ser después de la llegada.",
	fechas_invalidas: "No entendí las fechas. Escríbelas así: «del 2026-11-14 al 2026-11-16».",
	demasiadas_noches: "Por este canal reservamos hasta 14 noches; para más, escríbenos a recepción.",
	paquete_no_ofrecido: "Ese paquete no existe en el hotel.",
	estadia_vencida: "La cotización venció. Te preparo una nueva si me repites las fechas.",
	cotizacion_vencida: "La cotización venció. Te preparo una nueva si me repites las fechas.",
	estadia_usada: "Esa cotización ya se usó para una reserva.",
	sin_descuento_adicional: "No tenemos otros descuentos: la tarifa directa ya es la mejor que publicamos (si una agencia publica menos por las mismas noches, la igualamos), y las estadías de 4 noches o más tienen 10% automático.",
	mismas_fechas: "Esas ya son las fechas de la reserva.",
	reserva_cancelada: "Esa reserva está cancelada.",
	ya_incluido: "Ese servicio ya está incluido en la reserva.",
	sin_cupo: "Ya no quedan cupos de traslado para ese día.",
	servicio_no_ofrecido: "Ese servicio no lo ofrece el hotel.",
	no_encontrado: "No encuentro esa reserva en la cuenta vinculada.",
	en_curso: "Ya hay un cambio en curso para esa reserva. Cuando termine puedo proponer otro; no hice ningún cambio.",
	limite_revisiones: "Se alcanzó el máximo de cambios a esta propuesta. No hice ningún cambio.",
	sin_vinculo: "La cuenta vinculada no está asociada a un huésped en el sistema del hotel; no puedo reservar a su nombre.",
	negotiation_limit_exceeded: "Se alcanzó el máximo de revisiones de esta propuesta. No se hizo ningún cambio.",
};
const motivo = (m: string) => MOTIVOS[m] ?? (m.startsWith("capacidad:") ? `Esa habitación es para hasta ${m.split(":")[1]} personas.` : m.startsWith("paquete_no_aplica") ? `La Escapada Demo es sólo en doble con vista y por exactamente 2 noches.` : m.startsWith("sin_cupo") ? MOTIVOS.sin_cupo : m.startsWith("servicio_no_ofrecido") ? MOTIVOS.servicio_no_ofrecido : `No pude hacerlo (${m}).`);

const CAMBIAR = /\b(cambi|mover|mueve|muev|modific|corr[ea]|posterg|adelant|reprogram)/;
const CANCELAR = /\b(cancel|anul)/;
const AGREGAR = /\b(agreg|anad|añad|sum[ae]|inclu|quiero|tambien|agregar)/;
const RESERVAR = /\b(reserv(a|ar|ala|amela|emos|en)?|resérv|hazla|haz la reserva|tomala|la tomo|me la quedo|proced|adelante con)\b/;
const INFO = /\b(servicio|servicios|politica|cancelaci|check.?in|check.?out|horario|paquete|paquetes|ofrecen|incluye|donde|ubicaci|iva|extranjer)/;

export function responderHotel(nucleo: Nucleo, actor: ActorExterno, caseId: string, texto: string, sesion: string | null): Respuesta {
	const e = nucleo.empresa(actor.tenantId);
	const h = e.hotel!;
	const s = e.sistema.hotel!;
	const t = texto.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
	const base = nucleo.base(actor.tenantId);
	const nada = { usados: [] as string[], acciones: [] as { tool: string; argsHash?: string }[] };
	const solicitud = { binding: actor.protocolo === "pact" ? "pact.message" : actor.protocolo === "poppy" ? "poppy.message" : "web.message", text: texto };

	if (/\b(confirmo|apruebo|aprobado|autorizo|i approve|approved)\b/.test(t)) {
		nucleo.evento(actor.tenantId, caseId, "message.approval_text_ignored", {});
		return { ...nada, text: "Un mensaje no confirma cambios. Para ejecutar una operación, confírmala en el endpoint de operaciones con la revisión que aprobó el usuario." };
	}
	const it = interpretarHotel(h, texto);
	// «¿A nombre de quién queda?»: answered directly, with the holder of the linked account (test agent B asked it
	// three times and the hotel kept repeating the offer: Oct 21, 07:04 UTC).
	if (/(a nombre de|titular|nombre del huesped|nombre de la reserva|quien (queda|figura)|a nombre)/.test(t) && !RESERVAR.test(t)) {
		const titular = actor.clienteId ? e.clientes.find((c) => c.id === actor.clienteId)?.nombre : undefined;
		return {
			...nada,
			text: titular
				? `La reserva queda a nombre de ${titular}, titular de la cuenta vinculada. Para reservar a nombre de otra persona, esa persona tiene que vincular su propia cuenta del ${e.nombre}.`
				: `La reserva queda a nombre del titular de la cuenta que se vincule: la persona se identifica con un código a su WhatsApp registrado en el ${e.nombre}. Para reservar a nombre de otra persona, esa persona tiene que vincular su propia cuenta.`,
		};
	}
	const servicios = `Servicios del hotel: ${h.servicios.map((x) => `${x.nombre} (${clp(x.precio)} ${x.unidad === "persona_noche" ? "por persona y noche" : x.unidad === "noche" ? "por noche" : "por trayecto"})`).join("; ")}. Paquete: ${h.paquetes.map((p) => `${p.nombre}, ${p.descuentoPct}% menos`).join("; ")}.`;
	if (it.noOfrecido && !mutado("servicio_inventado")) return { ...nada, text: `El hotel no ofrece ${it.noOfrecido}; no lo voy a cotizar ni prometer. ${servicios}` };

	const propuesta = (cap: string, inputs: Record<string, string>): Respuesta => {
		const r = nucleo.proponerOperacion(actor, caseId, cap, inputs, sesion, solicitud);
		const alcance = e.release.capacidades.find((c) => c.id === cap)!.alcance;
		if (!r.ok) {
			// Web ramp: the person approves exactly this on a hotel page, with a code sent to their WhatsApp.
			const enlace = nucleo.urlDe(e) ? AprobacionOperacion.enlace(nucleo.urlDe(e)!, e.slug, cap, inputs) : null;
			if (r.falta === "sign_in") return { ...nada, text: `Para eso, la persona tiene que autorizarlo.${enlace ? ` Puede aprobarlo directamente aquí: ${enlace} (ve los términos exactos y confirma con un código a su WhatsApp registrado en el ${e.nombre}).` : ""}`, necesita: { tipo: "sign_in", alcances: [alcance] }, ...(enlace ? { data: { aprobacion_url: enlace } } : {}) };
			if (Array.isArray(r.falta)) return { ...nada, text: "Para eso necesito un permiso que el usuario no ha dado.", necesita: { tipo: "scope", alcances: r.falta } };
			return { ...nada, text: motivo(r.falta) };
		}
		return { usados: [alcance], acciones: [{ tool: `${cap}.preparar`, argsHash: huellaJcs(solicitud) }], text: `Puedo hacerlo. ${r.operacion.summary} No queda hecho hasta que se confirme.`, operacion: r.operacion };
	};

	// On an existing booking: cancel, add a service or change dates.
	if (it.reserva) {
		if (CANCELAR.test(t)) {
			// Asking about the conditions does not require the cancel permission: with read access the policy and the
			// exact charge for THAT booking are answered; the cancel permission is requested only to execute (test agent B, Oct 21 11:11).
			const cancelar = nucleo.decidir(actor, { capability: "reserva.cancelar", inputs: { reserva: it.reserva }, reason: "El cliente pregunta por cancelar", expectedEffect: "write" });
			const leer = nucleo.decidir(actor, { capability: "reserva.consultar", inputs: {}, reason: "Condiciones de cancelación", expectedEffect: "read" });
			const erp = nucleo.erpDe(actor);
			const r = erp ? s.reservas.find((x) => x.id === it.reserva && x.huespedId === erp) : undefined;
			if (cancelar.decision !== "allow" && Array.isArray(cancelar.falta) && leer.decision === "allow" && r?.estado === "confirmada") {
				const cargo = cargoCancelacion(h, r, Date.now() + nucleo.desfaseMs);
				nucleo.evento(actor.tenantId, caseId, "policy.cancellation_terms_shown", { reserva: r.id, cargo });
				const condicion = cargo ? `cancelarla ahora tiene un cargo de ${clp(cargo)} (la primera noche), porque quedan menos de ${h.politica.cancelacionGratisHoras} horas para el check-in` : "cancelarla ahora no tiene cargo";
				return { usados: ["reservas:leer"], acciones: [{ tool: "reserva.consultar" }], text: `${r.id}: ${condicion}. ${textoCancelacion(h)} La política es la misma en cada pedido. Para cancelarla necesito el permiso de cancelar; antes de ejecutar te muestro el cargo exacto para aprobarlo.`, necesita: { tipo: "scope", alcances: cancelar.falta as string[] }, data: { reserva: r.id, cargo_cancelacion: cargo } };
			}
			return propuesta("reserva.cancelar", { reserva: it.reserva });
		}
		if (it.servicios.length && AGREGAR.test(t)) return propuesta("reserva.agregar_servicio", { reserva: it.reserva, servicio: it.servicios[0].codigo, ...(it.servicios[0].cantidad ? { cantidad: String(it.servicios[0].cantidad) } : {}) });
		if (CAMBIAR.test(t) && it.llegada && it.salida) return propuesta("reserva.modificar_fechas", { reserva: it.reserva, llegada: it.llegada, salida: it.salida });
		if (CAMBIAR.test(t)) return { ...nada, text: `¿A qué fechas? Por ejemplo: «${it.reserva} del ${masDias(isoDia(new Date()), 30)} al ${masDias(isoDia(new Date()), 32)}».` };
	}
	// «¿Quedó confirmada la reserva?» is also asking about a booking (external agent A, Oct 21 11:00: the chat replied with its introduction).
	if (it.reserva || /\b(mis reservas|mi reserva|estado de (la|mi) reserva)\b|reserva (esta|quedo|fue|ya esta|ya quedo) confirmada|(esta|quedo) confirmada (la|mi) reserva|confirmaron (la|mi) reserva/.test(t)) {
		const d = nucleo.decidir(actor, { capability: "reserva.consultar", inputs: {}, reason: "El cliente pregunta por sus reservas", expectedEffect: "read" });
		nucleo.evento(actor.tenantId, caseId, d.decision === "allow" ? "policy.allowed" : "policy.denied", d);
		if (d.decision !== "allow")
			return d.falta === "sign_in" || !d.falta
				? { ...nada, text: `Por privacidad, el estado de una reserva sólo se lo muestro a su titular identificado. Si la reserva se aprobó en la página del ${e.nombre}, ahí quedó su número y su constancia. Para consultarla desde aquí, el titular vincula su cuenta del ${e.nombre} con un código a su WhatsApp.`, necesita: { tipo: "sign_in", alcances: ["reservas:leer"] } } : { ...nada, text: "Para ver las reservas necesito un permiso que el usuario no ha dado.", necesita: { tipo: "scope", alcances: d.falta as string[] } };
		const erp = nucleo.erpDe(actor);
		const mias = erp ? s.reservas.filter((r) => r.huespedId === erp) : [];
		nucleo.evento(actor.tenantId, caseId, "tool.executed", { capability: "reserva.consultar", filas: mias.length });
		const lista = mias.map((r) => `${r.id}: ${h.tipos.find((x) => x.codigo === r.tipo)?.nombre}, ${r.llegada} → ${r.salida}, ${clp(r.total)}, ${r.estado}${r.servicios.length ? `, con ${r.servicios.map((l) => l.nombre.toLowerCase()).join(" y ")}` : ""}`).join("; ");
		return { usados: ["reservas:leer"], acciones: [{ tool: "reserva.consultar" }], text: mias.length ? `Reservas de la cuenta: ${lista}.` : "La cuenta vinculada no tiene reservas.", data: { reservas: mias.map(({ huespedId: _h, ...r }) => r) } };
	}

	const ultima = [...base.estadias.values()].filter((x) => x.caseId === caseId && x.estado === "abierta").at(-1);
	const abierta = ultima ? [...base.operaciones.values()].find((o) => o.state === "proposed" && o.interno.intent.inputs.estadia === ultima.id && o.interno.dueno.clientId === actor.clientId && o.interno.dueno.sub === actor.sub) : undefined;
	const pideDescuento = /(descuento|rebaja|dcto|mejor precio|mas barato|igual(an|en|ar)|booking|expedia|despegar|agencia|airbnb|trivago)/.test(t);
	const tieneFechas = !!(it.llegada && it.salida);

	// Book from the latest quote in this conversation.
	// «Resérvala» repeating the same quote data (dates, type, services) means booking THAT quote, not
	// quoting another (external agent A wrote «Resérvala: doble estándar con desayuno, del 14 al 16…» and the chat re-quoted: Oct 21, 06:45:40).
	const repiteLaCotizacion = !!ultima && (!tieneFechas || (it.llegada === ultima.llegada && it.salida === ultima.salida)) && (!it.tipo || it.tipo === ultima.tipo) && it.servicios.every((sv) => ultima.servicios.some((x) => x.codigo === sv.codigo));
	if (RESERVAR.test(t) && ultima && (repiteLaCotizacion || (!tieneFechas && !it.tipo))) return propuesta("reserva.crear", { estadia: ultima.id });

	// Changes to the open quote (without a complete set of new dates): type, services, package or discount.
	if (ultima && !tieneFechas && (it.tipo || it.servicios.length || it.paquete || pideDescuento || /\bsin (desayuno|estacionamiento|traslado)\b/.test(t))) {
		// Mutation: take the agent's word on a «de Booking» rate (which the policy forbids).
		if (mutado("tarifa_citada") && it.agenciaCitada) s.canal.push({ tipo: ultima.tipo, tarifa: Math.round(it.agenciaCitada / ultima.noches.length) });
		if (pideDescuento && !it.tipo && !it.servicios.length && !it.paquete && !mutado("tarifa_citada")) {
			const comp = ultima.comparacion.map((c) => `${c.agencia}: ${c.total === null ? "sin disponibilidad" : clp(c.total)}`).join("; ");
			const citada = it.agenciaCitada ? ` No tomamos una tarifa citada de un sitio externo (${clp(it.agenciaCitada)}): comparamos con lo que el hotel publica en agencias según su channel manager (simulado).` : "";
			// Firm and helpful (external agent A, Oct 21 11:00): insisting does not change the rule, but the data needed to verify
			// the agency is requested and real alternatives for the same dates are offered.
			const previas = base.eventos.filter((ev) => ev.caseId === caseId && ev.eventType === "negotiation.discount_declined").length;
			nucleo.evento(actor.tenantId, caseId, "negotiation.discount_declined", { estadia: ultima.id, citada: it.agenciaCitada ?? null, intento: previas + 1 });
			const insiste = previas ? "Te respondo lo mismo que antes, porque la regla es la misma para todos los clientes. " : "";
			const verificar = /(booking|expedia|despegar|agencia|airbnb|trivago)/.test(t) && !it.agenciaCitada ? " Si me dices en qué agencia y a qué precio lo viste para estas mismas noches y habitación, lo verifico contra lo que el hotel publica en esa agencia; si allí está más barato, igualo esa tarifa." : "";
			const habitacion = ultima.noches.reduce((n, x) => n + x.tarifa, 0);
			const alternativas = disponibilidad(h, s, ultima.llegada, ultima.salida, ultima.adultos).filter((x) => x.apta && x.libres > 0 && x.tipo !== ultima.tipo && x.directa < habitacion);
			const otra = alternativas.length ? ` Una alternativa más económica para las mismas fechas: ${alternativas.map((x) => `${x.nombre}, ${clp(x.directa)} la habitación`).join("; ")}.` : "";
			const noches = ultima.noches.length < 4 ? ` Desde 4 noches hay 10% automático.` : "";
			return { ...nada, text: `${insiste}${MOTIVOS.sin_descuento_adicional}${citada}${verificar} Publicado en agencias (simulado) por las noches: ${comp}. La cotización ${ultima.id} sigue igual: ${clp(ultima.total)}.${otra}${noches}` };
		}
		const quitar = [...t.matchAll(/\bsin (desayuno|estacionamiento|traslado)\b/g)].map((m) => ({ desayuno: "DESAYUNO", estacionamiento: "ESTAC", traslado: "TRASLADO" })[m[1] as "desayuno"]);
		const pide = { ...(it.tipo ? { tipo: it.tipo } : {}), ...(it.adultos ? { adultos: it.adultos } : {}), ...(it.paquete ? { paquete: it.paquete } : {}), agregar: it.servicios.filter((x) => !quitar.includes(x.codigo)), quitar };
		if (abierta) {
			const r = nucleo.contraproponerOperacion(actor, abierta, pide);
			if (!r.ok) return { ...nada, text: motivo(r.motivo) };
			return { usados: ["reservas:crear"], acciones: [{ tool: "reserva.crear.contrapropuesta", argsHash: huellaJcs(pide) }], text: `${r.notas.join(" ")} Nueva propuesta: ${r.operacion.summary}`.trim(), operacion: r.operacion };
		}
		const r = revisarEstadia(h, s, ultima, pide);
		if (r.contradiccion) nucleo.evento(actor.tenantId, caseId, "hotel.fuentes_contradictorias", { estadia: ultima.id, detalle: r.contradiccion });
		if (!r.ok) return { ...nada, text: `${r.notas.join(" ")} ${motivo(r.motivo)}`.trim() };
		base.estadias.set(r.est.id, r.est);
		nucleo.evento(actor.tenantId, caseId, "quote.revised", { estadia: r.est.id, revision: r.est.revision, total: r.est.total });
		return { ...nada, acciones: [{ tool: "estadia.revisar" }], text: `${r.notas.join(" ")} ${textoEstadia(r.est, e.nombre)} Si te sirve, dime «resérvala».`.trim(), data: { estadia: r.est } };
	}

	// Dates: a quote (with a type) or availability for all types (without a type).
	if (tieneFechas) {
		const adultos = it.adultos ?? 2;
		const tabla = disponibilidad(h, s, it.llegada!, it.salida!, adultos);
		const tipo = it.tipo ?? (it.paquete ? h.paquetes.find((p) => p.codigo === it.paquete)?.tipo : undefined) ?? tabla.filter((x) => x.apta && x.libres > 0).sort((a, b) => a.directa - b.directa)[0]?.tipo;
		if (!tipo) return { ...nada, acciones: [{ tool: "hotel.disponibilidad" }], text: `No tenemos habitaciones para ${adultos} persona${adultos === 1 ? "" : "s"} del ${it.llegada} al ${it.salida}.`, data: { disponibilidad: tabla } };
		const r = cotizarEstadia(h, s, { tipo, llegada: it.llegada!, salida: it.salida!, adultos, servicios: it.servicios, paquete: it.paquete ?? null }, { tenantId: actor.tenantId, caseId });
		if (r.contradiccion) nucleo.evento(actor.tenantId, caseId, "hotel.fuentes_contradictorias", { tipo, llegada: it.llegada, salida: it.salida, detalle: r.contradiccion });
		const resumen = tabla.filter((x) => x.apta).map((x) => `${x.nombre}: ${x.libres > 0 ? `${clp(x.directa)} directo (${x.libres} libre${x.libres === 1 ? "" : "s"})` : "sin disponibilidad"}`).join("; ");
		if (!r.ok) return { ...nada, acciones: [{ tool: "hotel.disponibilidad" }], text: `${r.notas.join(" ")} ${motivo(r.motivo)} Disponibilidad del ${it.llegada} al ${it.salida}: ${resumen}.`.trim(), data: { disponibilidad: tabla } };
		base.estadias.set(r.est.id, r.est);
		nucleo.evento(actor.tenantId, caseId, "quote.issued", { estadia: r.est.id, total: r.est.total });
		return { ...nada, acciones: [{ tool: "estadia.cotizar" }], text: `${r.notas.join(" ")} Disponibilidad: ${resumen}. ${textoEstadia(r.est, e.nombre)} Si te sirve, dime «resérvala».`.trim(), data: { estadia: r.est, disponibilidad: tabla } };
	}

	if (pideDescuento) return { ...nada, text: `${MOTIVOS.sin_descuento_adicional} Dime fechas y número de personas y te muestro la tarifa directa al lado de la publicada en agencias (comparación simulada).` };
	if (INFO.test(t) || /(precio|tarifa|cuanto|vale|disponib|habitacion|pieza)/.test(t))
		return { ...nada, acciones: [{ tool: "hotel.informacion" }], text: `${e.nombre} (${h.ubicacion}). Habitaciones: ${h.tipos.map((x) => `${x.nombre}, desde ${clp(x.tarifaBase)} la noche (viernes y sábado +${h.politica.recargoFinDeSemanaPct}%)`).join("; ")}. Tarifas en CLP con IVA incluido. ${servicios} ${textoCancelacion(h)} Check-in ${h.politica.checkIn}, check-out ${h.politica.checkOut}. ${h.politica.extranjeros} Dime fechas y número de personas y te cotizo.` };
	return { ...nada, text: `Hola, soy el agente del ${e.nombre}. Atendemos ${e.horario}. Puedo mostrarte disponibilidad y tarifas (con la comparación con agencias, simulada), cotizar, hacer reservas, cambiar fechas, agregar servicios y cancelar según la política.` };
}

export type { Estadia, Operacion };

// The company's agent, deterministic. In production this slot is filled by the company's real
// agent. Here it is enough for it to turn a message into ActionIntents on the core, because what
// is under test is the gateway:
// identity, delegation, Policy, operation, review, execution and verification.

import type { ActorExterno, Nucleo, Operacion } from "./nucleo.ts";
import { huellaJcs } from "./prueba.ts";
import { buscar, clp, cotizar, interpretar, negociar, textoCotizacion } from "./comercio.ts";
import { responderHotel } from "./agente-hotel.ts";
import { mutado } from "./mutar.ts";
import { conectorDe } from "./conectores.ts";

const titulo = (s: string) => s.replace(/(^|\s)(\p{L})/gu, (_m, a: string, b: string) => a + b.toUpperCase());

export type Respuesta = {
	text: string;
	data?: Record<string, unknown>;
	operacion?: Operacion;
	necesita?: { tipo: "sign_in" | "scope"; alcances: string[] };
	/** Scopes and tools used in this turn: they go into the signed receipt (PACT §5.6). */
	usados: string[];
	acciones: { tool: string; argsHash?: string }[];
};

const MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];

/**
 * The date to change to, not the first one that appears: «del 2026-10-24 al 2026-10-28» → 28;
 * also «al 28», «para el 28 de octubre», «28/10». If there are several, the one after «al/para/a» wins.
 */
export function fechaDestino(texto: string, hoy = new Date()): string | undefined {
	const t = texto.toLowerCase();
	const anio = hoy.getUTCFullYear();
	const mesHoy = hoy.getUTCMonth() + 1;
	const candidatas: { f: string; destino: boolean }[] = [];
	const marca = (i: number) => /(\bal|\bpara el|\bpara|\ba|\bhasta el|\bel)\s*$/.test(t.slice(Math.max(0, i - 12), i));
	for (const m of t.matchAll(/\b(20\d\d-\d\d-\d\d)\b/g)) candidatas.push({ f: m[1], destino: marca(m.index!) });
	for (const m of t.matchAll(/\b(\d{1,2})\s+de\s+([a-zé]+)(?:\s+de\s+(20\d\d))?/g)) {
		const mes = MESES.indexOf(m[2]) + 1;
		if (mes > 0) candidatas.push({ f: `${m[3] ?? anio}-${String(mes).padStart(2, "0")}-${m[1].padStart(2, "0")}`, destino: marca(m.index!) });
	}
	for (const m of t.matchAll(/\b(\d{1,2})\/(\d{1,2})(?:\/(20\d\d))?\b/g)) candidatas.push({ f: `${m[3] ?? anio}-${m[2].padStart(2, "0")}-${m[1].padStart(2, "0")}`, destino: marca(m.index!) });
	// «al 28» with no month: the current month (or the next one if that day already passed).
	for (const m of t.matchAll(/\b(?:al|para el)\s+(\d{1,2})\b(?!\s*(?:de|\/|-|\d))/g)) {
		const dia = Number(m[1]);
		const mes = dia >= hoy.getUTCDate() ? mesHoy : (mesHoy % 12) + 1;
		candidatas.push({ f: `${anio}-${String(mes).padStart(2, "0")}-${String(dia).padStart(2, "0")}`, destino: true });
	}
	const validas = candidatas.filter((c) => !Number.isNaN(Date.parse(c.f)));
	return (validas.filter((c) => c.destino).at(-1) ?? validas.at(-1))?.f;
}

const PEDIDO = /\b(P-\d{3,})\b/i;

export function responder(
	nucleo: Nucleo,
	actor: ActorExterno,
	caseId: string,
	texto: string,
	sesion: string | null,
): Respuesta {
	const empresa = nucleo.empresa(actor.tenantId);
	// Hospitality (stress-test sandbox): its own deterministic agent, on the same core.
	if (empresa.hotel) return responderHotel(nucleo, actor, caseId, texto, sesion);
	const t = texto.toLowerCase();

	// A message never approves anything, whatever it says: confirmation has its own endpoint.
	if (/\b(confirmo|apruebo|aprobado|autorizo|i approve|approved)\b/.test(t)) {
		nucleo.evento(actor.tenantId, caseId, "message.approval_text_ignored", {});
		return {
			usados: [],
			acciones: [],
			text: "Un mensaje no confirma cambios. Para ejecutar una operación, confírmala en el endpoint de operaciones con la revisión que aprobó el usuario.",
		};
	}

	// Commerce: catalog, quote, negotiation and new order, conversationally. It does not touch existing orders.
	const c = empresa.comercio;
	if (c && !PEDIDO.test(texto)) {
		const it = interpretar(c, texto);
		// The quote being discussed: the one named by its number, or the latest one from this conversation or from this same agent and user.
		const origen = `${actor.clientId}#${actor.sub}`;
		const nombrada = texto.match(/\bCOT-[A-Z0-9_-]{4,}/i)?.[0];
		const citada = nombrada ? [...nucleo.base(actor.tenantId).cotizaciones.values()].find((x) => x.id.toUpperCase() === nombrada.toUpperCase() && x.estado === "abierta") : undefined;
		const ultima = citada ?? nucleo.ultimaCotizacion(actor.tenantId, caseId, origen);
		const abierta = ultima ? [...nucleo.base(actor.tenantId).operaciones.values()].find((o) => o.state === "proposed" && o.interno.intent.inputs.cotizacion === ultima.id && o.interno.dueno.clientId === actor.clientId && o.interno.dueno.sub === actor.sub) : undefined;
		const quiereComprar = /(compr|haz(lo)? el pedido|hacer el pedido|haga el pedido|ordena|lo quiero|cerremos|cerrar|pedido nuevo|proced|adelante con|place the order|buy)/.test(t);
		const negocia = it.descuento !== undefined || ((it.fecha || it.antesDe) && it.items.length === 0);
		// Access ramp: the customer approves the exact quote on a company page, with a code sent to their
		// registered WhatsApp. This way an agent that only browses can get it ready without creating anything on its own.
		const enlaceAprobacion = (cot: { id: string; revision: number }) => (nucleo.urlDe(empresa) ? `${nucleo.urlDe(empresa)}/e/${empresa.slug}/aprobar?cot=${cot.id}&rev=${cot.revision}` : null);
		// Any request to hold it or about how to approve it, with a valid quote. (It used to require the exact phrase
		// «cotización lista»; external agent A wrote «la cotización COT-… (revisión 2) lista y reservada mientras mi cliente la
		// aprueba» and it was not recognized: Oct 21, 05:37:21.) The agent's «confirmo/apruebo» is ignored above.
		const enEspera = /(en espera|reserv|pendiente de|aprobaci|aprobarl|aprobar|apruebe|aprueba\b|lista para (que|mi|el|la)|dejarla lista|d[eé]jala lista)/.test(t);

		if (enEspera && ultima && !quiereComprar) {
			const url = enlaceAprobacion(ultima);
			nucleo.evento(actor.tenantId, caseId, "quote.held_for_customer_approval", { cotizacion: ultima.id, revision: ultima.revision });
			return {
				usados: [],
				acciones: [{ tool: "cotizacion.reservar" }],
				text: `La cotización ${ultima.id} (revisión ${ultima.revision}, total ${clp(ultima.total)}) queda reservada hasta ${ultima.vence.slice(0, 16).replace("T", " ")} UTC. No se crea ningún pedido hasta que el cliente la apruebe.${url ? ` Para aprobarla, el cliente abre ${url}: ve los términos exactos y confirma con un código que le llega al WhatsApp que tiene registrado en ${empresa.nombre}. Si actúas por el cliente, compártele ese enlace.` : ""}`,
				data: { cotizacion: ultima, ...(url ? { aprobacion_url: url } : {}) },
			};
		}

		if (quiereComprar && ultima && it.items.length === 0) {
			const solicitud = { binding: actor.protocolo === "pact" ? "pact.message" : actor.protocolo === "poppy" ? "poppy.message" : "web.message", text: texto };
			const r = nucleo.proponerCompra(actor, caseId, ultima.id, sesion, solicitud);
			if (!r.ok) {
				if (r.falta === "sign_in") {
					const url = enlaceAprobacion(ultima);
					return { usados: [], acciones: [], text: `Para hacer el pedido a nombre de alguien, esa persona tiene que autorizarlo. La cotización ${ultima.id} queda vigente.${url ? ` Puede aprobarla directamente aquí: ${url} (ve los términos exactos y confirma con un código a su WhatsApp registrado en ${empresa.nombre}).` : ""}`, necesita: { tipo: "sign_in", alcances: ["compras:crear"] }, data: url ? { aprobacion_url: url } : undefined };
				}
				if (r.falta === "cotizacion_vencida") return { usados: [], acciones: [], text: `La cotización ${ultima.id} venció. Te preparo una nueva si me repites qué necesitas.` };
				if (r.falta === "sin_vinculo") return { usados: [], acciones: [], text: `La cuenta vinculada no está asociada a un cliente en el sistema de ${empresa.nombre}; no puedo crear el pedido a su nombre.` };
				if (r.falta === "no_encontrado") return { usados: [], acciones: [], text: "No encuentro esa cotización." };
				return { usados: [], acciones: [], text: `Para hacer el pedido de la cotización ${ultima.id} (revisión ${ultima.revision}, ${clp(ultima.total)}) necesito que el usuario autorice «${r.falta.map((a) => empresa.alcances[a] ?? a).join(", ")}». La cotización queda vigente; cuando lo autorice, sigo desde aquí.`, necesita: { tipo: "scope", alcances: r.falta } };
			}
			return {
				usados: ["compras:crear"],
				acciones: [{ tool: "pedido.crear.preparar", argsHash: huellaJcs(solicitud) }],
				text: `Puedo hacerlo. ${r.operacion.summary} No queda hecho hasta que se confirme.`,
				operacion: r.operacion,
			};
		}

		if (negocia && ultima) {
			const pide = { ...(it.descuento !== undefined ? { descuento: it.descuento } : {}), ...(it.fecha ? { fecha: it.fecha } : {}), ...(it.antesDe ? { antesDe: it.antesDe } : {}) };
			const motivos: Record<string, string> = {
				tope_descuento_alcanzado: `Ya tiene el máximo descuento que podemos dar (${c.politica.topeDescuento}%).`,
				cotizacion_vencida: "La cotización venció; te preparo una nueva si me repites qué necesitas.",
				counter_rejected: "No puedo cambiar esa propuesta ahora.",
				negotiation_limit_exceeded: "Se alcanzó el máximo de revisiones de esta propuesta. No se hizo ningún cambio.",
			};
			if (abierta) {
				const r = nucleo.contraproponerCompra(actor, abierta, pide);
				if (!r.ok) return { usados: [], acciones: [], text: motivos[r.motivo] ?? (r.motivo.startsWith("ya_tiene_") ? `Ya tiene ${r.motivo.slice(9)}% de descuento.` : "No puedo mejorar esa propuesta.") };
				return { usados: ["compras:crear"], acciones: [{ tool: "pedido.crear.contrapropuesta", argsHash: huellaJcs(pide) }], text: `${r.notas.join(" ")} Nueva propuesta: ${r.operacion.summary}`.trim(), operacion: r.operacion };
			}
			const r = negociar(c, ultima, pide);
			if (!r.ok) return { usados: [], acciones: [], text: motivos[r.motivo] ?? (r.motivo.startsWith("ya_tiene_") ? `Esa cotización ya tiene ${r.motivo.slice(9)}% de descuento, que es lo que corresponde por volumen.` : "No puedo mejorar esa cotización.") };
			nucleo.guardarCotizacion(actor.tenantId, r.cot);
			nucleo.evento(actor.tenantId, caseId, "quote.revised", { cotizacion: r.cot.id, revision: r.cot.revision, total: r.cot.total });
			return { usados: [], acciones: [{ tool: "cotizacion.negociar" }], text: `${r.notas.join(" ")} ${textoCotizacion(r.cot, empresa.nombre)}`.trim(), data: { cotizacion: r.cot } };
		}

		// A price question («¿cuánto vale…?») without asking for delivery: catalog of what matches, not a quote.
		const preguntaPrecio = /(precio|cuanto|cuánto|vale|valor|cuestan|tienen)/.test(t) && !it.comuna && !/\d/.test(t);
		// Asking about a quote by its number: its state (valid, or already turned into an order).
		if (nombrada && !quiereComprar && !negocia && !enEspera && it.items.length === 0) {
			const cualquiera = [...nucleo.base(actor.tenantId).cotizaciones.values()].find((x) => x.id.toUpperCase() === nombrada.toUpperCase());
			if (!cualquiera) return { usados: [], acciones: [], text: `No encuentro la cotización ${nombrada}.` };
			if (cualquiera.estado === "usada") {
				const pedido = empresa.sistema.pedidos.find((p) => p.cotizacion === cualquiera.id && !p.anulado);
				return { usados: [], acciones: [], text: `La cotización ${cualquiera.id} ya se convirtió en el pedido ${pedido?.id ?? "(anulado)"}${pedido ? `, despacho el ${pedido.despacho}, ${pedido.pago}` : ""}.` };
			}
			const vence = Date.parse(cualquiera.vence) < Date.now() ? "venció" : `sigue vigente hasta ${cualquiera.vence.slice(0, 16).replace("T", " ")} UTC`;
			return { usados: [], acciones: [], text: `La cotización ${cualquiera.id} ${vence}. ${textoCotizacion(cualquiera, empresa.nombre)}`, data: { cotizacion: cualquiera } };
		}
		// Talking about the current quote is not asking for another: with no new comuna, keep the same one.
		if (ultima && it.items.length && !it.comuna && /(cotizaci[oó]n|COT-|esa|esta|la misma)/i.test(texto)) {
			return { usados: [], acciones: [], text: `${textoCotizacion(ultima, empresa.nombre)} ¿Quieres cambiar algo (cantidad, fecha o descuento) o la dejo reservada para que el cliente la apruebe?`, data: { cotizacion: ultima } };
		}
		if (it.items.length && !preguntaPrecio) {
			const comunas = Object.keys(c.politica.despacho.comunas).map(titulo).join(", ");
			if (!it.comuna) {
				const precios = it.items.map((x) => c.catalogo.find((p) => p.sku === x.sku)!).map((p) => `${p.nombre}: ${clp(p.precio)} (stock ${p.stock})`).join("; ");
				return { usados: [], acciones: [{ tool: "catalogo.consultar" }], text: `${precios}. ¿A qué dirección y comuna despachamos? Despachamos a ${comunas}.` };
			}
			const direccion = it.direccion ?? ultima?.despacho.direccion;
			if (!direccion) return { usados: [], acciones: [], text: `¿A qué dirección de ${it.comuna} despachamos?` };
			const r = cotizar(c, actor.tenantId, caseId, { items: it.items, comuna: it.comuna, direccion, fecha: it.fecha, antesDe: it.antesDe, descuento: it.descuento });
			if (!r.ok) {
				const [motivo, sku, stock] = r.motivo.split(":");
				if (motivo === "sin_stock") return { usados: [], acciones: [], text: `Del ${c.catalogo.find((p) => p.sku === sku)?.nombre} tenemos ${stock} en stock. ¿Te cotizo esa cantidad?` };
				return { usados: [], acciones: [], text: `No pude cotizar: ${motivo === "comuna_sin_despacho" ? `no despachamos a esa comuna (despachamos a ${comunas})` : motivo}.` };
			}
			r.cot.origen = origen;
			nucleo.guardarCotizacion(actor.tenantId, r.cot);
			nucleo.evento(actor.tenantId, caseId, "quote.issued", { cotizacion: r.cot.id, total: r.cot.total });
			return { usados: [], acciones: [{ tool: "cotizacion.preparar" }], text: `${r.notas.join(" ")} ${textoCotizacion(r.cot, empresa.nombre)} Si te sirve, dime «haz el pedido».`.trim(), data: { cotizacion: r.cot } };
		}

		if (/(catalog|precio|venden|tienen|productos|stock|price)/.test(t) || (/cotiz/.test(t) && !ultima)) {
			const hallados = buscar(c, texto);
			const lista = (hallados.length ? hallados : c.catalogo).map((p) => `${p.nombre} (${p.sku}): ${clp(p.precio)}, stock ${p.stock}`).join("; ");
			return { usados: [], acciones: [{ tool: "catalogo.consultar" }], text: `${lista}. Descuento por volumen: ${c.politica.descuentosVolumen.map((d) => `${d.pct}% desde ${d.desde} unidades`).join(", ")}. Despacho gratis sobre ${clp(c.politica.despacho.gratisDesde)}. Dime qué necesitas, cuántos y a qué comuna, y te cotizo.`, data: { catalogo: hallados.length ? hallados : c.catalogo } };
		}
	}

	const fecha = fechaDestino(texto);
	const pedidoId = texto.match(PEDIDO)?.[1]?.toUpperCase();
	// Return or voiding of an order (stress-test sandbox), if the company has it in its Release.
	if (pedidoId && conectorDe(empresa, "pedido.devolver") && /(devol|devuelv|reembols|anul|cancel)/.test(t)) {
		const solicitud = { binding: actor.protocolo === "pact" ? "pact.message" : actor.protocolo === "poppy" ? "poppy.message" : "web.message", text: texto };
		const r = nucleo.proponerOperacion(actor, caseId, "pedido.devolver", { pedidoId }, sesion, solicitud);
		if (!r.ok) {
			if (r.falta === "sign_in") return { usados: [], acciones: [], text: `Para devolver un pedido, el usuario tiene que vincular su cuenta de ${empresa.nombre}.`, necesita: { tipo: "sign_in", alcances: ["devoluciones:crear"] } };
			if (Array.isArray(r.falta)) return { usados: [], acciones: [], text: "Para devolver un pedido necesito un permiso que el usuario no ha dado.", necesita: { tipo: "scope", alcances: r.falta } };
			const motivos: Record<string, string> = {
				no_encontrado: `No encuentro el pedido ${pedidoId} en la cuenta vinculada.`,
				ya_devuelto_o_anulado: `El pedido ${pedidoId} ya está anulado o en devolución.`,
				en_ruta: `El pedido ${pedidoId} va en camino: cuando lo recibas puedes devolverlo dentro del plazo.`,
				en_curso: `Ya hay una gestión en curso sobre el pedido ${pedidoId}; no hice ningún cambio.`,
				limite_revisiones: `Se alcanzó el máximo de cambios a esta propuesta. No hice ningún cambio.`,
			};
			return { usados: [], acciones: [], text: motivos[r.falta] ?? (r.falta.startsWith("fuera_de_plazo") ? `El plazo para devolver es de ${r.falta.split(":")[1]} días desde la entrega, y ya pasó.` : `No pude preparar la devolución (${r.falta}).`) };
		}
		return { usados: ["devoluciones:crear"], acciones: [{ tool: "pedido.devolver.preparar", argsHash: huellaJcs(solicitud) }], text: `Puedo hacerlo. ${r.operacion.summary} No queda hecho hasta que se confirme.`, operacion: r.operacion };
	}
	// A «cambio» to the date it already has is not a change (test agent B got «del 24 al 24», Oct 21 05:59:35).
	const actual = pedidoId ? empresa.sistema.pedidos.find((p) => p.id === pedidoId) : undefined;
	if (fecha && actual && actual.despacho === fecha && /(reprogram|c[aá]mbi|mover|mueve|muév|posterg|adelant|reschedul|change)/.test(t) && !mutado("cambio_nulo"))
		return { usados: [], acciones: [], text: `El pedido ${pedidoId} ya está para el ${fecha}. No hay nada que cambiar.` };
	if (/(reprogram|c[aá]mbi|mover|mueve|muév|posterg|adelant|reschedul|change)/.test(t) && (fecha || pedidoId)) {
		if (!pedidoId || !fecha)
			return { usados: [], acciones: [], text: "¿Qué pedido y a qué fecha? Por ejemplo: «P-1042 al 2026-10-29»." };
		// The request enters the proof only as a digest (SPEC §9.4.1): `{binding, text}`.
		const solicitud = { binding: actor.protocolo === "pact" ? "pact.message" : "poppy.message", text: texto };
		const r = nucleo.proponerReprogramacion(actor, caseId, pedidoId, fecha, sesion, solicitud);
		if (!r.ok) {
			if (r.falta === "sign_in")
				return { usados: [], acciones: [], text: `Para cambiar un pedido necesito que el usuario vincule su cuenta de ${empresa.nombre}.`, necesita: { tipo: "sign_in", alcances: ["pedidos:modificar"] } };
			if (r.falta === "no_encontrado") return { usados: [], acciones: [], text: `No encuentro el pedido ${pedidoId} en la cuenta vinculada.` };
			// Round 3 (M3): only one operation in progress per order.
			if (r.falta === "en_curso")
				return { usados: [], acciones: [], text: `Ya hay un cambio en curso para el pedido ${pedidoId}. Cuando termine puedo proponer otro; no hice ningún cambio.` };
			if (r.falta === "limite_revisiones")
				return { usados: [], acciones: [], text: `Se alcanzó el máximo de cambios a esta propuesta para el pedido ${pedidoId}. No hice ningún cambio.` };
			return { usados: [], acciones: [], text: "Para cambiar un pedido necesito un permiso que el usuario no ha dado.", necesita: { tipo: "scope", alcances: r.falta } };
		}
		return {
			usados: ["pedidos:modificar"],
			// `argsHash` = JCS digest of what was requested in this turn (SPEC §12.2.4): a third party recomputes it from the text.
			acciones: [{ tool: "pedido.reprogramar_despacho.preparar", argsHash: huellaJcs(solicitud) }],
			text: `Puedo hacerlo. ${r.operacion.summary} No queda hecho hasta que se confirme.`,
			operacion: r.operacion,
		};
	}

	if (/(pedido|despacho|order|estado|dónde|donde)/.test(t)) {
		const r = nucleo.leerPedidos(actor, caseId);
		if (!r.ok) {
			if (r.falta === "sign_in")
				return { usados: [], acciones: [], text: `Puedo revisarlo si el usuario vincula su cuenta de ${empresa.nombre}.`, necesita: { tipo: "sign_in", alcances: ["pedidos:leer"] } };
			return { usados: [], acciones: [], text: "Para ver los pedidos necesito un permiso que el usuario no ha dado.", necesita: { tipo: "scope", alcances: r.falta } };
		}
		const usados = ["pedidos:leer"];
		const acciones = [{ tool: "pedido.consultar" }];
		if (r.pedidos.length === 0) return { usados, acciones, text: "La cuenta vinculada no tiene pedidos." };
		const lista = r.pedidos.map((p) => `${p.id}: ${p.producto}, despacho ${p.despacho}, ${p.estado.replace("_", " ")}`).join("; ");
		return {
			usados,
			acciones,
			text: `Pedidos de la cuenta: ${lista}.`,
			data: { pedidos: r.pedidos.map(({ clienteId: _c, ...p }) => p) },
		};
	}

	return {
		usados: [],
		acciones: [],
		text: `Hola, soy el agente de ${empresa.nombre}. Atendemos ${empresa.horario}. Puedo ${empresa.comercio ? "mostrarte el catálogo, cotizar, hacer pedidos, " : ""}revisar pedidos y cambiar fechas de despacho.`,
	};
}

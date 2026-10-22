// Connectors for the stress-test sandbox: each new capability with an effect (hospitality and returns)
// is described as a connector to the company's system. The core uses them along the SAME path that
// rescheduling and purchasing already follow: Policy (agente_personal) → frozen revision with digest and
// company signature → exact customer approval → [company review] → ONE execution with a precondition
// → read-back from the PMS/ERP and the payment provider → signed outcome (VXP Proof).
//
// A connector does NOT decide authorization or states: it only knows how to draft the terms under the
// company's policy, check the precondition, apply the effect once and read the system.

import type { Base, Efecto_, Empresa, Operacion, Pedido } from "./nucleo.ts";
import { type Estadia, type Hotel, type LineaServicio, type Noche, type SistemaHotel, clp, esFecha, horasHastaCheckIn, isoDia, libres, masDias, nochesEntre, recalcularServicios, revisarEstadia, tarifaNoche, textoCancelacion, textoEstadia } from "./hotel.ts";
import { type Pagos, consultar, mover, pagosVacios, saldo } from "./pagos.ts";
import { randomBytes } from "node:crypto";
import { mutado } from "./mutar.ts";

export type Ctx = { e: Empresa; base: Base; ahora: number; titular?: string };
export type Redaccion = { terms: Record<string, unknown>; summary: string; vence?: string; revision: string | null; monto: number; notas: string[] };
export type Ejecucion = { estado: "aplicado" | "rechazado" | "desconocido"; motivo?: string; efectos: Efecto_[] };

export type Conector = {
	capacidad: string;
	/** Name of the target in the native API (`target`). */
	objetivo: "reservation_ref" | "order_ref" | null;
	/** The resource it acts on (RAR identifier): an existing id or `nuevo`. */
	recurso(inputs: Record<string, string>): string;
	/** The customer in the company's system who owns the resource; null if it does not exist. */
	dueno(c: Ctx, recurso: string): string | null;
	redactar(c: Ctx, inputs: Record<string, string>): { ok: true; r: Redaccion } | { ok: false; motivo: string; notas?: string[] };
	precondicion(c: Ctx, op: Operacion): string | null;
	ejecutar(c: Ctx, op: Operacion, erp: string, falla: "definitiva" | "desconocida" | undefined): Ejecucion;
	leer(c: Ctx, op: Operacion): { observado: Record<string, unknown>; divulgacion?: Record<string, unknown> };
	exito(c: Ctx, op: Operacion): { summary: string; data: Record<string, unknown> };
	/** Agent counterproposal: new inputs for a new revision, or a refusal with its reason. */
	contraoferta?(c: Ctx, op: Operacion, pide: Record<string, unknown>): { ok: true; inputs: Record<string, string>; notas: string[] } | { ok: false; motivo: string };
};

const sal = () => randomBytes(16).toString("base64url");
const MEDIO_HOTEL = "tarjeta registrada (simulada) ****4242";
const hotelDe = (e: Empresa): { h: Hotel; s: SistemaHotel } => ({ h: e.hotel!, s: e.sistema.hotel! });
export const pagosDe = (e: Empresa): Pagos => (e.sistema.pagos ??= pagosVacios());
const reserva = (e: Empresa, id: string) => e.sistema.hotel?.reservas.find((r) => r.id === id);
const nombreTipo = (h: Hotel, t: string) => h.tipos.find((x) => x.codigo === t)?.nombre ?? t;

/** Payment movement with its result already translated into a declared effect. Reconciles if there was no response. */
function pagar(p: Pagos, m: { ref: string; tipo: "autorizacion" | "ajuste" | "captura" | "anulacion" | "reembolso"; monto: number; idem: string; medio: string }): { ok: boolean; efecto: Efecto_; conocido: boolean } {
	const r = mover(p, m);
	const cambio = `${m.tipo} ${clp(m.monto)} (${m.ref})`;
	if (r.estado === "aprobado") return { ok: true, conocido: true, efecto: { system: "payment", change: `${cambio}`, applied: true, status: "approved" } as Efecto_ };
	if (r.estado === "rechazado") return { ok: false, conocido: true, efecto: { system: "payment", change: `${cambio} rechazado`, applied: false, status: "declined" } as Efecto_ };
	if (r.estado === "caido") return { ok: false, conocido: true, efecto: { system: "payment", change: `${cambio} no enviado (proveedor sin conexión)`, applied: false, status: "not_sent" } as Efecto_ };
	// No response: QUERY by the idempotency key; never charge again.
	if (mutado("pago_sin_reconciliar")) return pagar(p, { ...m, idem: `${m.idem}:reintento` });
	const visto = consultar(p, m.idem);
	if (visto?.estado === "aprobado") return { ok: true, conocido: true, efecto: { system: "payment", change: `${cambio} (sin respuesta; confirmado consultando por idempotencia)`, applied: true, status: "reconciled" } as Efecto_ };
	if (visto) return { ok: false, conocido: true, efecto: { system: "payment", change: `${cambio} rechazado (confirmado consultando)`, applied: false, status: "declined" } as Efecto_ };
	return { ok: false, conocido: false, efecto: { system: "payment", change: `${cambio} sin respuesta y sin registro`, applied: false, status: "unknown" } as Efecto_ };
}

// ── Hotel: reserva.crear ─────────────────────────────────────────────────────────────────────────

const reservaCrear: Conector = {
	capacidad: "reserva.crear",
	objetivo: null,
	recurso: () => "nuevo",
	dueno: () => null,
	redactar(c, inputs) {
		const est = c.base.estadias.get(inputs.estadia ?? "");
		if (!est) return { ok: false, motivo: "no_encontrado" };
		if (est.estado !== "abierta") return { ok: false, motivo: `estadia_${est.estado}` };
		if (Date.parse(est.vence) < c.ahora) return { ok: false, motivo: "cotizacion_vencida" };
		const { h } = hotelDe(c.e);
		const revision = est.noches.length > h.politica.revisionSobreNoches
			? `estadía de ${est.noches.length} noches supera ${h.politica.revisionSobreNoches}`
			: est.total > h.politica.revisionSobreMonto
				? `reserva de ${est.total} CLP supera ${h.politica.revisionSobreMonto}`
				: null;
		return {
			ok: true,
			r: {
				terms: {
					estadia: est.id,
					revision_estadia: est.revision,
					tipo: est.tipo,
					llegada: est.llegada,
					salida: est.salida,
					adultos: est.adultos,
					noches: est.noches,
					servicios: est.servicios,
					descuento: est.descuento,
					tarifa_igualada: est.tarifa_igualada,
					neto: est.neto,
					iva: est.iva,
					total: est.total,
					moneda: "CLP",
					garantia: est.total,
					garantia_detalle: est.garantia,
					cancelacion: est.cancelacion,
					vxp_salt: sal(),
				},
				// The account holder is named: «a tu nombre» left test agent B unsure (Oct 21, 06:59).
				summary: `${c.titular ? `Reservar a nombre de ${c.titular} (titular de la cuenta vinculada)` : "Reservar a tu nombre"}: ${textoEstadia(est, c.e.nombre)}`,
				vence: est.vence,
				revision,
				monto: est.total,
				notas: [],
			},
		};
	},
	precondicion(c, op) {
		const est = c.base.estadias.get(String(op.terms.estadia));
		const { h, s } = hotelDe(c.e);
		if (!est || est.estado !== "abierta" || est.revision !== op.terms.revision_estadia) return "la cotización ya no está disponible";
		if (Date.parse(est.vence) < c.ahora) return "la cotización venció";
		if (libres(h, s, est.tipo, est.llegada, est.salida) < 1) return "ya no hay disponibilidad para esas fechas";
		const traslado = est.servicios.find((l) => l.codigo === "TRASLADO");
		const cupo = h.servicios.find((x) => x.codigo === "TRASLADO")?.cupoDiario;
		if (traslado && cupo !== undefined && (s.traslados[est.llegada] ?? 0) + traslado.cantidad > cupo) return "ya no hay cupo de traslado ese día";
		return null;
	},
	ejecutar(c, op, erp, falla) {
		const { s } = hotelDe(c.e);
		const est = c.base.estadias.get(String(op.terms.estadia))!;
		const id = `R-${4001 + s.reservas.filter((r) => r.estadia).length}`;
		const total = Number(op.terms.total);
		const p = pagar(pagosDe(c.e), { ref: id, tipo: "autorizacion", monto: total, idem: `${op.operation_id}:garantia`, medio: MEDIO_HOTEL });
		if (!p.conocido) return { estado: "desconocido", motivo: `Todavía no se sabe si el proveedor de pago pre-autorizó la garantía de ${clp(total)}: no respondió y no tiene registro. No se repite el cobro; se confirmará consultando.`, efectos: [p.efecto] };
		if (!p.ok) return { estado: "rechazado", motivo: `No se creó la reserva: ${p.efecto.status === "not_sent" ? "el proveedor de pago no estaba disponible" : "la tarjeta registrada rechazó la pre-autorización"}. No hubo cargo.`, efectos: [p.efecto] };
		if (falla === "definitiva") {
			const anula = pagar(pagosDe(c.e), { ref: id, tipo: "anulacion", monto: total, idem: `${op.operation_id}:anula`, medio: MEDIO_HOTEL });
			const efecto = { ...p.efecto, reverted: anula.ok };
			return { estado: "rechazado", motivo: `El sistema del hotel (PMS) rechazó la reserva. ${anula.ok ? "La pre-autorización se anuló: no queda cargo." : "La pre-autorización NO se pudo anular: lo revisa una persona."}`, efectos: [efecto, { system: "pms", change: `reserva ${id} no creada`, applied: false }, anula.efecto] };
		}
		s.reservas.push({ id, huespedId: erp, tipo: est.tipo, llegada: est.llegada, salida: est.salida, adultos: est.adultos, noches: est.noches.map((n) => ({ ...n })), servicios: est.servicios.map((l) => ({ ...l })), total, estado: "confirmada", estadia: est.id, historial: [{ at: new Date(c.ahora).toISOString(), cambio: `creada por operación ${op.operation_id}` }] });
		const traslado = est.servicios.find((l) => l.codigo === "TRASLADO");
		if (traslado) s.traslados[est.llegada] = (s.traslados[est.llegada] ?? 0) + traslado.cantidad;
		est.estado = "usada";
		const efectos = [p.efecto, { system: "pms" as const, change: `reserva ${id} creada (${est.tipo}, ${est.llegada} → ${est.salida})`, applied: true }];
		if (falla === "desconocida") return { estado: "desconocido", motivo: `Todavía no se sabe si el PMS de ${c.e.nombre} creó la reserva: no llegó su respuesta. No se repetirá; se confirmará leyendo el PMS.`, efectos };
		return { estado: "aplicado", efectos };
	},
	leer(c, op) {
		const r = c.e.sistema.hotel?.reservas.find((x) => x.estadia === op.terms.estadia && x.estado === "confirmada");
		if (!r) return { observado: { estadia: null } };
		return { observado: { estadia: r.estadia, tipo: r.tipo, llegada: r.llegada, salida: r.salida, total: r.total, garantia: saldo(pagosDe(c.e), r.id).garantia }, divulgacion: { reserva: r.id } };
	},
	exito(c, op) {
		const r = c.e.sistema.hotel!.reservas.find((x) => x.estadia === op.terms.estadia && x.estado === "confirmada")!;
		return {
			summary: `Listo: reserva ${r.id} confirmada en ${c.e.nombre}: ${nombreTipo(c.e.hotel!, r.tipo)}, llegada ${r.llegada} y salida ${r.salida}, total ${clp(r.total)} IVA incluido. Garantía pre-autorizada en la tarjeta registrada (simulada). Verificado en el sistema del hotel y en el proveedor de pago.`,
			data: { reserva: r.id, total: r.total, llegada: r.llegada, salida: r.salida, verificado: "lectura_del_sistema" },
		};
	},
	contraoferta(c, op, pide) {
		const est = c.base.estadias.get(String(op.terms.estadia));
		if (!est) return { ok: false, motivo: "counter_rejected" };
		const { h, s } = hotelDe(c.e);
		const agregar = Array.isArray(pide.agregar) ? (pide.agregar as { codigo?: unknown; cantidad?: unknown }[]).map((x) => ({ codigo: String(x?.codigo ?? ""), ...(typeof x?.cantidad === "number" ? { cantidad: x.cantidad } : {}) })) : [];
		const quitar = Array.isArray(pide.quitar) ? (pide.quitar as unknown[]).map(String) : [];
		const cambios = { ...(typeof pide.tipo === "string" ? { tipo: pide.tipo } : {}), ...(esFecha(pide.llegada) ? { llegada: pide.llegada } : {}), ...(esFecha(pide.salida) ? { salida: pide.salida } : {}), ...(typeof pide.adultos === "number" ? { adultos: pide.adultos } : {}), ...(pide.paquete === null || typeof pide.paquete === "string" ? { paquete: pide.paquete as string | null } : {}), agregar, quitar };
		const sinCambios = !agregar.length && !quitar.length && Object.keys(cambios).length === 2;
		if (sinCambios) return { ok: false, motivo: typeof pide.descuento === "number" ? "sin_descuento_adicional" : "counter_rejected" };
		const r = revisarEstadia(h, s, est, cambios, new Date(c.ahora));
		if (!r.ok) return { ok: false, motivo: r.motivo };
		c.base.estadias.set(r.est.id, r.est);
		return { ok: true, inputs: { estadia: r.est.id }, notas: r.notas };
	},
};

// ── Hotel: reserva.modificar_fechas ──────────────────────────────────────────────────────────────

function nochesDe(h: Hotel, s: SistemaHotel, tipo: string, llegada: string, salida: string): Noche[] {
	const out: Noche[] = [];
	for (let f = llegada; f < salida; f = masDias(f, 1)) out.push({ fecha: f, tarifa: tarifaNoche(h, s, tipo, f) });
	return out;
}

const reservaModificar: Conector = {
	capacidad: "reserva.modificar_fechas",
	objetivo: "reservation_ref",
	recurso: (i) => i.reserva ?? "",
	dueno: (c, id) => reserva(c.e, id)?.huespedId ?? null,
	redactar(c, inputs) {
		const { h, s } = hotelDe(c.e);
		const r = reserva(c.e, inputs.reserva ?? "");
		if (!r) return { ok: false, motivo: "no_encontrado" };
		if (r.estado !== "confirmada") return { ok: false, motivo: "reserva_cancelada" };
		const { llegada, salida } = inputs;
		if (!esFecha(llegada) || !esFecha(salida) || salida <= llegada) return { ok: false, motivo: "fechas_invalidas" };
		if (llegada < isoDia(new Date(c.ahora))) return { ok: false, motivo: "llegada_en_el_pasado" };
		if (llegada === r.llegada && salida === r.salida) return { ok: false, motivo: "mismas_fechas" };
		const n = nochesEntre(llegada, salida);
		if (n > h.politica.maxNoches) return { ok: false, motivo: "demasiadas_noches" };
		if (libres(h, s, r.tipo, llegada, salida, r.id) < 1) return { ok: false, motivo: "sin_disponibilidad" };
		const noches = nochesDe(h, s, r.tipo, llegada, salida);
		const servicios = recalcularServicios(h, r.servicios, r.adultos, n);
		const habit = noches.reduce((x, y) => x + y.tarifa, 0);
		const dto = n >= h.politica.estadiaLarga.desdeNoches ? Math.round((habit * h.politica.estadiaLarga.pct) / 100) : 0;
		const total = habit + servicios.reduce((x, y) => x + y.total, 0) - dto;
		const horas = horasHastaCheckIn(r.llegada, c.ahora, h.politica.checkIn);
		const revision = horas < h.politica.modificacionSinRevisionHoras ? `cambio a menos de ${h.politica.modificacionSinRevisionHoras} h de la llegada (${Math.max(0, Math.floor(horas))} h): lo decide una persona del hotel` : null;
		const diferencia = total - r.total;
		return {
			ok: true,
			r: {
				terms: { reserva: r.id, tipo: r.tipo, llegada_actual: r.llegada, salida_actual: r.salida, total_actual: r.total, llegada, salida, noches, servicios, descuento_estadia_larga: dto, total, diferencia, garantia: total, moneda: "CLP", vxp_salt: sal() },
				summary: `Cambiar la reserva ${r.id} (${nombreTipo(h, r.tipo)}) del ${r.llegada}–${r.salida} al ${llegada}–${salida} (${n} noche${n === 1 ? "" : "s"}). Total nuevo ${clp(total)} IVA incluido (antes ${clp(r.total)}; ${diferencia >= 0 ? `se pre-autorizan ${clp(diferencia)} más` : `se liberan ${clp(-diferencia)} de la garantía`}).${revision ? " Antes de aplicarse lo revisa una persona del hotel." : ""}`,
				revision,
				monto: Math.max(0, diferencia),
				notas: [],
			},
		};
	},
	precondicion(c, op) {
		const { h, s } = hotelDe(c.e);
		const r = reserva(c.e, String(op.terms.reserva));
		if (!r || r.estado !== "confirmada") return "la reserva ya no está confirmada";
		if (r.llegada !== op.terms.llegada_actual || r.salida !== op.terms.salida_actual || r.total !== op.terms.total_actual) return "la reserva cambió después de que se propuso este cambio";
		if (libres(h, s, r.tipo, String(op.terms.llegada), String(op.terms.salida), r.id) < 1) return "ya no hay disponibilidad para las fechas nuevas";
		return null;
	},
	ejecutar(c, op, _erp, falla) {
		const r = reserva(c.e, String(op.terms.reserva))!;
		const dif = Number(op.terms.diferencia);
		const efectos: Efecto_[] = [];
		if (falla === "definitiva") return { estado: "rechazado", motivo: "El sistema del hotel (PMS) rechazó el cambio. La reserva sigue en sus fechas originales; no se tocó la garantía.", efectos: [{ system: "pms", change: `cambio de ${r.id} no aplicado`, applied: false }] };
		if (dif !== 0) {
			const p = pagar(pagosDe(c.e), { ref: r.id, tipo: "ajuste", monto: dif, idem: `${op.operation_id}:ajuste`, medio: MEDIO_HOTEL });
			efectos.push(p.efecto);
			if (!p.conocido) return { estado: "desconocido", motivo: "Todavía no se sabe si el proveedor de pago ajustó la garantía. No se repite; se confirmará consultando.", efectos };
			if (!p.ok) return { estado: "rechazado", motivo: "No se cambió la reserva: la tarjeta registrada rechazó el ajuste de la garantía.", efectos };
		}
		const antes = `${r.llegada}–${r.salida}`;
		r.llegada = String(op.terms.llegada);
		r.salida = String(op.terms.salida);
		r.noches = (op.terms.noches as Noche[]).map((n) => ({ ...n }));
		r.servicios = (op.terms.servicios as LineaServicio[]).map((l) => ({ ...l }));
		r.total = Number(op.terms.total);
		r.historial.push({ at: new Date(c.ahora).toISOString(), cambio: `fechas ${antes} → ${r.llegada}–${r.salida} (operación ${op.operation_id})` });
		efectos.push({ system: "pms", change: `${r.id} ${antes} → ${r.llegada}–${r.salida}`, applied: true });
		if (falla === "desconocida") return { estado: "desconocido", motivo: `Todavía no se sabe si el PMS aplicó el cambio de ${r.id}: no llegó su respuesta. No se repetirá; se confirmará leyendo el PMS.`, efectos };
		return { estado: "aplicado", efectos };
	},
	leer(c, op) {
		const r = reserva(c.e, String(op.terms.reserva));
		if (!r) return { observado: { reserva: null } };
		return { observado: { reserva: r.id, llegada: r.llegada, salida: r.salida, total: r.total, garantia: saldo(pagosDe(c.e), r.id).garantia } };
	},
	exito(c, op) {
		const r = reserva(c.e, String(op.terms.reserva))!;
		return { summary: `Listo: la reserva ${r.id} quedó del ${r.llegada} al ${r.salida}, total ${clp(r.total)} IVA incluido. Verificado en el sistema del hotel y en el proveedor de pago.`, data: { reserva: r.id, llegada: r.llegada, salida: r.salida, total: r.total, verificado: "lectura_del_sistema" } };
	},
	contraoferta(c, op, pide) {
		if (!esFecha(pide.llegada) || !esFecha(pide.salida)) return { ok: false, motivo: "counter_rejected" };
		if (pide.llegada === op.terms.llegada && pide.salida === op.terms.salida) return { ok: false, motivo: "counter_rejected" };
		return { ok: true, inputs: { reserva: String(op.terms.reserva), llegada: pide.llegada, salida: pide.salida }, notas: [] };
	},
};

// ── Hotel: reserva.agregar_servicio ─────────────────────────────────────────────────────────────

const reservaServicio: Conector = {
	capacidad: "reserva.agregar_servicio",
	objetivo: "reservation_ref",
	recurso: (i) => i.reserva ?? "",
	dueno: (c, id) => reserva(c.e, id)?.huespedId ?? null,
	redactar(c, inputs) {
		const { h, s } = hotelDe(c.e);
		const r = reserva(c.e, inputs.reserva ?? "");
		if (!r) return { ok: false, motivo: "no_encontrado" };
		if (r.estado !== "confirmada") return { ok: false, motivo: "reserva_cancelada" };
		const sv = h.servicios.find((x) => x.codigo === inputs.servicio);
		if (!sv) return { ok: false, motivo: "servicio_no_ofrecido" };
		if (sv.unidad !== "trayecto" && r.servicios.some((l) => l.codigo === sv.codigo)) return { ok: false, motivo: "ya_incluido" };
		const n = r.noches.length;
		const cantidad = sv.unidad === "persona_noche" ? r.adultos * n : sv.unidad === "noche" ? n : Math.max(1, Math.min(Number(inputs.cantidad) || 1, 4));
		if (sv.cupoDiario !== undefined && (s.traslados[r.llegada] ?? 0) + cantidad > sv.cupoDiario) return { ok: false, motivo: "sin_cupo" };
		const linea: LineaServicio = { codigo: sv.codigo, nombre: sv.nombre, cantidad, precio_unitario: sv.precio, total: sv.precio * cantidad };
		const previo = r.servicios.find((l) => l.codigo === sv.codigo);
		const servicios = previo ? r.servicios.map((l) => (l.codigo === sv.codigo ? { ...l, cantidad: l.cantidad + cantidad, total: l.total + linea.total } : { ...l })) : [...r.servicios.map((l) => ({ ...l })), linea];
		const total = r.total + linea.total;
		return {
			ok: true,
			r: {
				terms: { reserva: r.id, servicio: sv.codigo, linea, servicios, total_actual: r.total, total, garantia: total, moneda: "CLP", vxp_salt: sal() },
				summary: `Agregar ${sv.nombre} × ${cantidad} (${clp(linea.total)}) a la reserva ${r.id} (${r.llegada}–${r.salida}). Total nuevo ${clp(total)} IVA incluido; se pre-autorizan ${clp(linea.total)} más en la tarjeta registrada (simulada).`,
				revision: null,
				monto: linea.total,
				notas: [],
			},
		};
	},
	precondicion(c, op) {
		const { h, s } = hotelDe(c.e);
		const r = reserva(c.e, String(op.terms.reserva));
		if (!r || r.estado !== "confirmada") return "la reserva ya no está confirmada";
		if (r.total !== op.terms.total_actual) return "la reserva cambió después de que se propuso este cambio";
		const l = op.terms.linea as LineaServicio;
		const cupo = h.servicios.find((x) => x.codigo === l.codigo)?.cupoDiario;
		if (cupo !== undefined && (s.traslados[r.llegada] ?? 0) + l.cantidad > cupo) return "ya no hay cupo de ese servicio";
		return null;
	},
	ejecutar(c, op, _erp, falla) {
		const r = reserva(c.e, String(op.terms.reserva))!;
		const { s } = hotelDe(c.e);
		const l = op.terms.linea as LineaServicio;
		if (falla === "definitiva") return { estado: "rechazado", motivo: "El sistema del hotel (PMS) rechazó agregar el servicio. La reserva sigue igual.", efectos: [{ system: "pms", change: `servicio en ${r.id} no aplicado`, applied: false }] };
		const p = pagar(pagosDe(c.e), { ref: r.id, tipo: "ajuste", monto: l.total, idem: `${op.operation_id}:ajuste`, medio: MEDIO_HOTEL });
		if (!p.conocido) return { estado: "desconocido", motivo: "Todavía no se sabe si el proveedor de pago ajustó la garantía. No se repite; se confirmará consultando.", efectos: [p.efecto] };
		if (!p.ok) return { estado: "rechazado", motivo: "No se agregó el servicio: la tarjeta registrada rechazó el ajuste de la garantía.", efectos: [p.efecto] };
		r.servicios = (op.terms.servicios as LineaServicio[]).map((x) => ({ ...x }));
		r.total = Number(op.terms.total);
		if (l.codigo === "TRASLADO") s.traslados[r.llegada] = (s.traslados[r.llegada] ?? 0) + l.cantidad;
		r.historial.push({ at: new Date(c.ahora).toISOString(), cambio: `servicio ${l.codigo} × ${l.cantidad} (operación ${op.operation_id})` });
		const efectos = [p.efecto, { system: "pms" as const, change: `${l.nombre} × ${l.cantidad} agregado a ${r.id}`, applied: true }];
		if (falla === "desconocida") return { estado: "desconocido", motivo: "Todavía no se sabe si el PMS registró el servicio. No se repetirá; se confirmará leyendo el PMS.", efectos };
		return { estado: "aplicado", efectos };
	},
	leer(c, op) {
		const r = reserva(c.e, String(op.terms.reserva));
		if (!r) return { observado: { reserva: null } };
		return { observado: { reserva: r.id, servicios: r.servicios, total: r.total, garantia: saldo(pagosDe(c.e), r.id).garantia } };
	},
	exito(c, op) {
		const r = reserva(c.e, String(op.terms.reserva))!;
		return { summary: `Listo: ${(op.terms.linea as LineaServicio).nombre} agregado a la reserva ${r.id}; total ${clp(r.total)} IVA incluido. Verificado en el sistema del hotel y en el proveedor de pago.`, data: { reserva: r.id, total: r.total, servicios: r.servicios, verificado: "lectura_del_sistema" } };
	},
};

// ── Hotel: reserva.cancelar ─────────────────────────────────────────────────────────────────────

export function cargoCancelacion(h: Hotel, r: { llegada: string; noches: Noche[] }, ahora: number): number {
	return horasHastaCheckIn(r.llegada, ahora, h.politica.checkIn) >= h.politica.cancelacionGratisHoras ? 0 : (r.noches[0]?.tarifa ?? 0);
}

const reservaCancelar: Conector = {
	capacidad: "reserva.cancelar",
	objetivo: "reservation_ref",
	recurso: (i) => i.reserva ?? "",
	dueno: (c, id) => reserva(c.e, id)?.huespedId ?? null,
	redactar(c, inputs) {
		const { h } = hotelDe(c.e);
		const r = reserva(c.e, inputs.reserva ?? "");
		if (!r) return { ok: false, motivo: "no_encontrado" };
		if (r.estado !== "confirmada") return { ok: false, motivo: "reserva_cancelada" };
		const cargo = cargoCancelacion(h, r, c.ahora);
		return {
			ok: true,
			r: {
				terms: { reserva: r.id, tipo: r.tipo, llegada: r.llegada, salida: r.salida, total_actual: r.total, estado: "cancelada", cargo, garantia: 0, politica: textoCancelacion(h), moneda: "CLP", vxp_salt: sal() },
				summary: `Cancelar la reserva ${r.id} (${nombreTipo(h, r.tipo)}, ${r.llegada}–${r.salida}, ${clp(r.total)}). ${cargo === 0 ? "Sin cargo: está dentro del plazo de cancelación gratuita; se libera toda la garantía." : `Se cobra la primera noche, ${clp(cargo)}, porque faltan menos de ${h.politica.cancelacionGratisHoras} horas para la llegada; se libera el resto de la garantía. Es un cobro (simulado) que no se revierte.`}`,
				revision: null,
				monto: cargo,
				notas: [],
			},
		};
	},
	precondicion(c, op) {
		const { h } = hotelDe(c.e);
		const r = reserva(c.e, String(op.terms.reserva));
		if (!r || r.estado !== "confirmada") return "la reserva ya no está confirmada";
		if (r.total !== op.terms.total_actual || r.llegada !== op.terms.llegada) return "la reserva cambió después de que se propuso cancelarla";
		// The approved charge must be the one that applies NOW: if the deadline passed, the approval no longer describes the truth.
		if (cargoCancelacion(h, r, c.ahora) !== op.terms.cargo && !mutado("cargo_vigente")) return "pasó el plazo de cancelación gratuita después de que se propuso; el cargo ya no es el aprobado";
		return null;
	},
	ejecutar(c, op, _erp, falla) {
		const r = reserva(c.e, String(op.terms.reserva))!;
		if (falla === "definitiva") return { estado: "rechazado", motivo: "El sistema del hotel (PMS) rechazó la cancelación. La reserva sigue confirmada; no se tocó la garantía.", efectos: [{ system: "pms", change: `cancelación de ${r.id} no aplicada`, applied: false }] };
		r.estado = "cancelada";
		r.cargoCancelacion = Number(op.terms.cargo);
		r.historial.push({ at: new Date(c.ahora).toISOString(), cambio: `cancelada (operación ${op.operation_id})` });
		const efectos: Efecto_[] = [{ system: "pms", change: `${r.id} cancelada`, applied: true }];
		const pagos = pagosDe(c.e);
		const cargo = Number(op.terms.cargo);
		if (cargo > 0) {
			const p = pagar(pagos, { ref: r.id, tipo: "captura", monto: cargo, idem: `${op.operation_id}:captura`, medio: MEDIO_HOTEL });
			efectos.push(p.efecto);
			if (!p.conocido) return { estado: "desconocido", motivo: "La reserva se canceló, pero no se sabe si el proveedor de pago cobró el cargo. No se repite; se confirmará consultando.", efectos };
		}
		const resto = saldo(pagos, r.id).garantia;
		if (resto > 0) {
			const p = pagar(pagos, { ref: r.id, tipo: "anulacion", monto: resto, idem: `${op.operation_id}:anula`, medio: MEDIO_HOTEL });
			efectos.push(p.efecto);
			if (!p.conocido) return { estado: "desconocido", motivo: "La reserva se canceló, pero no se sabe si el proveedor de pago liberó la garantía. No se repite; se confirmará consultando.", efectos };
		}
		if (falla === "desconocida") return { estado: "desconocido", motivo: `Todavía no se sabe si el PMS registró la cancelación de ${r.id}: no llegó su respuesta. Se confirmará leyendo el PMS.`, efectos };
		return { estado: "aplicado", efectos };
	},
	leer(c, op) {
		const r = reserva(c.e, String(op.terms.reserva));
		if (!r) return { observado: { reserva: null } };
		const sl = saldo(pagosDe(c.e), r.id);
		return { observado: { reserva: r.id, estado: r.estado, cargo: sl.capturado, garantia: sl.garantia } };
	},
	exito(c, op) {
		const cargo = Number(op.terms.cargo);
		return { summary: `Listo: la reserva ${op.terms.reserva} quedó cancelada. ${cargo ? `Se cobró la primera noche (${clp(cargo)}) y se liberó el resto de la garantía.` : "Sin cargo; se liberó toda la garantía."} Verificado en el sistema del hotel y en el proveedor de pago.`, data: { reserva: op.terms.reserva, cargo, verificado: "lectura_del_sistema" } };
	},
};

// ── Hardware store: pedido.devolver ─────────────────────────────────────────────────────────────

type Devolucion = { id: string; pedido: string; tipo: "devolucion" | "anulacion"; articulos: { sku: string; cantidad: number; precio_unitario: number }[]; reembolso: number; retiro: string | null; at: string };
const pedidoDe = (e: Empresa, id: string) => e.sistema.pedidos.find((p) => p.id === id);
const articulosDe = (p: Pedido) => (p.articulos ?? []).map((a) => ({ sku: a.sku, cantidad: a.cantidad, precio_unitario: a.precio_unitario }));

const pedidoDevolver: Conector = {
	capacidad: "pedido.devolver",
	objetivo: "order_ref",
	recurso: (i) => i.pedidoId ?? "",
	dueno: (c, id) => pedidoDe(c.e, id)?.clienteId ?? null,
	redactar(c, inputs) {
		const p = pedidoDe(c.e, inputs.pedidoId ?? "");
		const pol = c.e.politicaDevolucion ?? { diasDesdeEntrega: 10, despachoReembolsable: false, retiro: "retiro a domicilio" };
		if (!p) return { ok: false, motivo: "no_encontrado" };
		if ((p.anulado || p.estado === "anulado" || p.estado === "devolucion_en_curso") && !mutado("doble_devolucion")) return { ok: false, motivo: "ya_devuelto_o_anulado" };
		if (p.estado === "en_ruta") return { ok: false, motivo: "en_ruta" };
		const articulos = articulosDe(p);
		if (!articulos.length) return { ok: false, motivo: "sin_articulos_registrados" };
		const pagado = saldo(pagosDe(c.e), p.id).capturado;
		if (p.estado === "entregado") {
			const entregado = (p as Pedido & { entregadoEl?: string }).entregadoEl ?? p.despacho;
			const dias = Math.floor((c.ahora - Date.parse(`${entregado}T00:00:00Z`)) / 86_400_000);
			if (dias > pol.diasDesdeEntrega && !mutado("plazo_devolucion")) return { ok: false, motivo: `fuera_de_plazo:${pol.diasDesdeEntrega}` };
			const reembolso = Math.min(pagado, articulos.reduce((s, a) => s + a.precio_unitario * a.cantidad, 0));
			return {
				ok: true,
				r: {
					terms: { pedido: p.id, tipo: "devolucion", articulos, estado_pedido: "devolucion_en_curso", reembolso, retiro: pol.retiro, plazo_dias: pol.diasDesdeEntrega, moneda: "CLP", vxp_salt: sal() },
					summary: `Devolver el pedido ${p.id} (${p.producto}), entregado el ${entregado}: ${pol.retiro}; reembolso de ${clp(reembolso)} al medio de pago original (simulado)${pol.despachoReembolsable ? "" : "; el despacho no se reembolsa"}.`,
					revision: reembolso > 150_000 ? `reembolso de ${reembolso} CLP supera 150000` : null,
					monto: 0,
					notas: [],
				},
			};
		}
		return {
			ok: true,
			r: {
				terms: { pedido: p.id, tipo: "anulacion", articulos, estado_pedido: "anulado", reembolso: pagado, moneda: "CLP", vxp_salt: sal() },
				summary: `Anular el pedido ${p.id} (${p.producto}), que aún no sale: no se despacha${pagado ? ` y se reembolsan ${clp(pagado)} al medio de pago original (simulado)` : "; no hay nada pagado que reembolsar"}.`,
				revision: null,
				monto: 0,
				notas: [],
			},
		};
	},
	precondicion(c, op) {
		const p = pedidoDe(c.e, String(op.terms.pedido));
		if (!p || (p.anulado && !mutado("doble_devolucion"))) return "el pedido ya no está disponible";
		const esperado = op.terms.tipo === "devolucion" ? "entregado" : "preparando";
		if (p.estado !== esperado) return `el pedido cambió de estado (ahora ${p.estado.replace("_", " ")}) después de que se propuso`;
		return null;
	},
	ejecutar(c, op, _erp, falla) {
		const p = pedidoDe(c.e, String(op.terms.pedido))!;
		if (falla === "definitiva") return { estado: "rechazado", motivo: `El sistema de ${c.e.nombre} rechazó la devolución. El pedido sigue igual; no hubo reembolso.`, efectos: [{ system: "erp", change: `devolución de ${p.id} no registrada`, applied: false }] };
		const articulos = op.terms.articulos as Devolucion["articulos"];
		const dev: Devolucion = { id: `D-${601 + (c.e.sistema.devoluciones?.length ?? 0)}`, pedido: p.id, tipo: op.terms.tipo as Devolucion["tipo"], articulos, reembolso: Number(op.terms.reembolso), retiro: (op.terms.retiro as string | undefined) ?? null, at: new Date(c.ahora).toISOString() };
		(c.e.sistema.devoluciones ??= []).push(dev);
		p.estado = op.terms.estado_pedido as Pedido["estado"];
		if (dev.tipo === "anulacion") {
			p.anulado = true;
			for (const a of articulos) {
				const prod = c.e.comercio?.catalogo.find((x) => x.sku === a.sku);
				if (prod) prod.stock += a.cantidad;
			}
		}
		const efectos: Efecto_[] = [{ system: "erp", change: `${dev.id}: ${dev.tipo} del pedido ${p.id} registrada`, applied: true }];
		if (dev.reembolso > 0) {
			const r = pagar(pagosDe(c.e), { ref: p.id, tipo: "reembolso", monto: dev.reembolso, idem: `${op.operation_id}:reembolso`, medio: "medio de pago original (simulado)" });
			efectos.push(r.efecto);
			if (!r.conocido) return { estado: "desconocido", motivo: "La devolución quedó registrada, pero no se sabe si el reembolso salió. No se repite; se confirmará consultando.", efectos };
		}
		if (falla === "desconocida") return { estado: "desconocido", motivo: `Todavía no se sabe si el sistema de ${c.e.nombre} registró la devolución: no llegó su respuesta.`, efectos };
		return { estado: "aplicado", efectos };
	},
	leer(c, op) {
		const p = pedidoDe(c.e, String(op.terms.pedido));
		const dev = (c.e.sistema.devoluciones ?? []).filter((d: Devolucion) => d.pedido === op.terms.pedido).at(-1);
		if (!p) return { observado: { pedido: null } };
		return { observado: { pedido: p.id, estado_pedido: p.estado, reembolso: saldo(pagosDe(c.e), p.id).reembolsado, articulos: dev?.articulos ?? null } };
	},
	exito(c, op) {
		const dev = (c.e.sistema.devoluciones ?? []).filter((d: Devolucion) => d.pedido === op.terms.pedido).at(-1)!;
		return { summary: `Listo: ${dev.tipo === "anulacion" ? `pedido ${op.terms.pedido} anulado` : `devolución ${dev.id} del pedido ${op.terms.pedido} registrada (${dev.retiro})`}${dev.reembolso ? `; reembolso de ${clp(dev.reembolso)} enviado (simulado)` : ""}. Verificado en el sistema de ${c.e.nombre} y en el proveedor de pago.`, data: { pedido: op.terms.pedido, devolucion: dev.id, reembolso: dev.reembolso, verificado: "lectura_del_sistema" } };
	},
};

export const CONECTORES: Record<string, Conector> = Object.fromEntries([reservaCrear, reservaModificar, reservaServicio, reservaCancelar, pedidoDevolver].map((c) => [c.capacidad, c]));

/** The connector for a capability, only if the company has it in its Release. */
export function conectorDe(e: Empresa, capacidad: string): Conector | null {
	return e.release.capacidades.some((c) => c.id === capacidad) ? (CONECTORES[capacidad] ?? null) : null;
}

// ── What arrives over the API (native, Poppy extensions and PACT) ────────────────────────────────

const num = (v: unknown) => (typeof v === "number" && Number.isInteger(v) ? v : undefined);

/** Inputs of a native request on an existing resource, or null if the body is unusable. */
export function inputsDesdeApi(capacidad: string, target: Record<string, unknown>, p: Record<string, unknown>): Record<string, string> | null {
	const ref = (k: string) => (typeof target[k] === "string" && target[k] ? String(target[k]) : null);
	if (capacidad === "reserva.modificar_fechas") return ref("reservation_ref") && esFecha(p.check_in) && esFecha(p.check_out) ? { reserva: ref("reservation_ref")!, llegada: p.check_in, salida: p.check_out } : null;
	if (capacidad === "reserva.agregar_servicio") return ref("reservation_ref") && typeof p.service === "string" ? { reserva: ref("reservation_ref")!, servicio: p.service, ...(num(p.quantity) ? { cantidad: String(p.quantity) } : {}) } : null;
	if (capacidad === "reserva.cancelar") return ref("reservation_ref") ? { reserva: ref("reservation_ref")! } : null;
	if (capacidad === "pedido.devolver") return ref("order_ref") ? { pedidoId: ref("order_ref")! } : null;
	return null;
}

/** A counterproposal in API names, translated into what the connector understands. */
export function pideDesdeApi(capacidad: string, pt: Record<string, unknown>): Record<string, unknown> {
	if (capacidad === "reserva.modificar_fechas") return { llegada: pt.check_in, salida: pt.check_out };
	if (capacidad !== "reserva.crear") return {};
	const lista = (v: unknown) => (Array.isArray(v) ? (v as Record<string, unknown>[]) : null);
	return {
		...(lista(pt.add_services) ? { agregar: lista(pt.add_services)!.map((x) => ({ codigo: String(x?.code ?? ""), ...(num(x?.quantity) ? { cantidad: x.quantity } : {}) })) } : {}),
		...(lista(pt.remove_services) ? { quitar: lista(pt.remove_services)!.map(String) } : {}),
		...(typeof pt.room_type === "string" ? { tipo: pt.room_type } : {}),
		...(esFecha(pt.check_in) ? { llegada: pt.check_in } : {}),
		...(esFecha(pt.check_out) ? { salida: pt.check_out } : {}),
		...(num(pt.adults) ? { adultos: pt.adults } : {}),
		...(pt.package === null || typeof pt.package === "string" ? { paquete: pt.package } : {}),
		...(typeof pt.discount_pct === "number" ? { descuento: pt.discount_pct } : {}),
	};
}

/** What the person sees in «Vincular» for a capability `authorization_details`. */
export function textoRar(e: Empresa, x: { actions: string[]; identifier: string; limits?: { max_total_clp: number } }): string {
	const tope = x.limits ? ` por hasta ${clp(x.limits.max_total_clp)}` : "";
	if (x.identifier === "nuevo" && x.actions.includes("reserva.crear")) return `hacer una reserva nueva a tu nombre${tope}, con garantía en tu tarjeta registrada (simulada)`;
	if (x.identifier === "nuevo") return `hacer un pedido nuevo a tu nombre${tope}, sin pago en línea`;
	const desc = x.actions.map((a) => e.release.capacidades.find((c) => c.id === a)?.descripcion.toLowerCase() ?? a).join(" y ");
	const enHotel = x.actions.some((a) => CONECTORES[a]?.objetivo === "reservation_ref");
	return `${desc} ${enHotel ? "de la reserva" : "del pedido"} ${x.identifier}${tope ? `, con cargos${tope}` : ""}`;
}

/** Does the resource of an `authorization_details` belong to the linked customer? `nuevo` belongs to no one yet. */
export function rarPropio(e: Empresa, x: { actions: string[]; identifier: string }, erp: string | null, base: Base): boolean {
	if (erp === null) return false;
	if (x.identifier === "nuevo") return x.actions.every((a) => a === "pedido.crear" || a === "reserva.crear");
	const ctx = { e, base, ahora: Date.now() };
	return x.actions.every((a) => {
		const con = CONECTORES[a];
		if (con) return con.recurso(con.objetivo === "reservation_ref" ? { reserva: x.identifier } : { pedidoId: x.identifier }) !== "nuevo" && con.dueno(ctx, x.identifier) === erp;
		return e.sistema.pedidos.some((p) => p.id === x.identifier && p.clienteId === erp);
	});
}

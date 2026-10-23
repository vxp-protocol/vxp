// Hospitality in the stress-test sandbox: a FICTITIOUS hotel (Hotel Demo) on the same
// architecture as Ferretería Demo. This holds what, in production, would live in the hotel's systems:
//   - the PMS (inventory by type and date, reservations, blocks);
//   - the commercial policy (nightly rates with VAT included, weekend surcharge, long-stay
//     discount, a package the hotel DOES offer, real add-on services, cancellation and modification);
//   - the SIMULATED channel manager: the rate the hotel publishes on agencies, labeled «(simulada)».
//     No real site is queried or imitated; the names are «Agencia A (simulada)», etc.
// Negotiation never leaves the policy: anything beyond it gets the applicable rate or a no.

import { randomId } from "./jose.ts";
import { mutado } from "./mutar.ts";

export type TipoHabitacion = { codigo: string; nombre: string; capacidad: number; inventario: number; tarifaBase: number; palabras: string[] };
export type Servicio = { codigo: string; nombre: string; precio: number; unidad: "persona_noche" | "noche" | "trayecto"; palabras: string[]; cupoDiario?: number };
export type Paquete = { codigo: string; nombre: string; tipo: string; noches: number; servicios: string[]; descuentoPct: number; palabras: string[] };
export type Agencia = { nombre: string; ajustePct: number };

export type PoliticaHotel = {
	ivaPct: number;
	recargoFinDeSemanaPct: number;
	estadiaLarga: { desdeNoches: number; pct: number };
	cancelacionGratisHoras: number;
	modificacionSinRevisionHoras: number;
	revisionSobreNoches: number;
	revisionSobreMonto: number;
	maxNoches: number;
	checkIn: string;
	checkOut: string;
	/** Local hour (Chile) after which a guest who has not arrived on the arrival day counts as a late arrival. */
	llegadaTardiaDesde?: string;
	vigenciaMinutos: number;
	garantia: string;
	extranjeros: string;
};

export type Hotel = { tipos: TipoHabitacion[]; servicios: Servicio[]; paquetes: Paquete[]; politica: PoliticaHotel; agencias: Agencia[]; ubicacion: string };

export type LineaServicio = { codigo: string; nombre: string; cantidad: number; precio_unitario: number; total: number };
export type Noche = { fecha: string; tarifa: number };

export type Reserva = {
	id: string;
	/** The guest in the PMS (not the operator's canonical customer). */
	huespedId: string;
	tipo: string;
	llegada: string;
	salida: string;
	adultos: number;
	noches: Noche[];
	servicios: LineaServicio[];
	total: number;
	estado: "confirmada" | "cancelada";
	/** Stay quote it was born from (what the `reserva.crear` verification reads back). */
	estadia?: string;
	cargoCancelacion?: number;
	historial: { at: string; cambio: string }[];
};

export type OverrideCanal = { tipo: string; fecha?: string; agencia?: string; tarifa?: number; disponible?: boolean };

export type SistemaHotel = {
	reservas: Reserva[];
	bloqueos: { tipo: string; desde: string; hasta: string; unidades: number }[];
	/** Current base rate per type (changes via /interno/condiciones: «cambio de tarifa»). */
	tarifas: Record<string, number>;
	/** What the simulated channel manager publishes that differs from the computed value (contradictions). */
	canal: OverrideCanal[];
	/** Transfers already sold per day (quota). */
	traslados: Record<string, number>;
};

export type Estadia = {
	id: string;
	tenantId: string;
	caseId: string;
	revision: number;
	tipo: string;
	nombreTipo: string;
	llegada: string;
	salida: string;
	adultos: number;
	noches: Noche[];
	servicios: LineaServicio[];
	paquete: string | null;
	descuento: { motivo: string; pct: number; monto: number } | null;
	tarifa_igualada: { agencia: string; monto: number } | null;
	habitacion_total: number;
	neto: number;
	iva: number;
	total: number;
	moneda: "CLP";
	vence: string;
	cancelacion: string;
	garantia: string;
	comparacion: { agencia: string; total: number | null; disponible: boolean; simulada: true }[];
	historial: { revision: number; motivo: string; at: string }[];
	estado: "abierta" | "usada" | "vencida";
};

export const clp = (n: number) => `$${n.toLocaleString("es-CL")}`;
const norm = (s: string) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
export const isoDia = (d: Date) => d.toISOString().slice(0, 10);
export const masDias = (fecha: string, n: number) => {
	const d = new Date(`${fecha}T00:00:00Z`);
	d.setUTCDate(d.getUTCDate() + n);
	return isoDia(d);
};
const diaSemana = (fecha: string) => new Date(`${fecha}T00:00:00Z`).getUTCDay();
export const nochesEntre = (llegada: string, salida: string) => Math.round((Date.parse(`${salida}T00:00:00Z`) - Date.parse(`${llegada}T00:00:00Z`)) / 86_400_000);
const FECHA = /^\d{4}-\d{2}-\d{2}$/;
export const esFecha = (s: unknown): s is string => typeof s === "string" && FECHA.test(s) && !Number.isNaN(Date.parse(`${s}T00:00:00Z`));

/** Check-in instant (15:00, mainland Chile summer time: UTC−3). */
export const instanteCheckIn = (llegada: string, checkIn = "15:00") => Date.parse(`${llegada}T${checkIn}:00-03:00`);
export const horasHastaCheckIn = (llegada: string, ahora = Date.now(), checkIn = "15:00") => (instanteCheckIn(llegada, checkIn) - ahora) / 3_600_000;

/** Rate for one night: the type's current base, plus the Friday and Saturday surcharge. VAT included. */
export function tarifaNoche(h: Hotel, s: SistemaHotel, tipo: string, fecha: string): number {
	const t = h.tipos.find((x) => x.codigo === tipo)!;
	const base = s.tarifas[tipo] ?? t.tarifaBase;
	const finde = diaSemana(fecha) === 5 || diaSemana(fecha) === 6;
	return Math.round(base * (1 + (finde ? h.politica.recargoFinDeSemanaPct : 0) / 100));
}

/** Free rooms of a type on one night, per the PMS (the authoritative source). */
export function libresNoche(h: Hotel, s: SistemaHotel, tipo: string, fecha: string, excepto?: string): number {
	const t = h.tipos.find((x) => x.codigo === tipo);
	if (!t) return 0;
	const bloqueadas = s.bloqueos.filter((b) => b.tipo === tipo && b.desde <= fecha && fecha < b.hasta).reduce((n, b) => n + b.unidades, 0);
	const ocupadas = s.reservas.filter((r) => r.estado === "confirmada" && r.tipo === tipo && r.id !== excepto && r.llegada <= fecha && fecha < r.salida).length;
	return Math.max(0, t.inventario - bloqueadas - ocupadas);
}

export function libres(h: Hotel, s: SistemaHotel, tipo: string, llegada: string, salida: string, excepto?: string): number {
	let min = Number.POSITIVE_INFINITY;
	for (let f = llegada; f < salida; f = masDias(f, 1)) min = Math.min(min, libresNoche(h, s, tipo, f, excepto));
	return Number.isFinite(min) ? min : 0;
}

/**
 * What the SIMULATED channel manager publishes for each agency: the nights' total with its adjustment,
 * unless a test condition sets a different rate or availability (contradiction with the PMS).
 */
export function canalSimulado(h: Hotel, s: SistemaHotel, tipo: string, noches: Noche[], libresPms: number) {
	return h.agencias.map((a) => {
		const ov = s.canal.filter((o) => o.tipo === tipo && (!o.agencia || o.agencia === a.nombre));
		let total = 0;
		let disponible = libresPms > 0;
		for (const n of noches) {
			const o = ov.find((x) => !x.fecha || x.fecha === n.fecha);
			if (o?.disponible !== undefined) disponible = o.disponible;
			total += o?.tarifa !== undefined ? o.tarifa : Math.round(n.tarifa * (1 + a.ajustePct / 100));
		}
		return { agencia: a.nombre, total: disponible ? total : null, disponible, simulada: true as const };
	});
}

export type PedidoEstadia = { tipo: string; llegada: string; salida: string; adultos: number; servicios: { codigo: string; cantidad?: number }[]; paquete?: string | null };
export type ResultadoEstadia = { ok: true; est: Estadia; notas: string[]; contradiccion: string | null } | { ok: false; motivo: string; notas: string[]; contradiccion: string | null };

function lineaServicio(h: Hotel, codigo: string, cantidad: number | undefined, adultos: number, noches: number): LineaServicio | null {
	const sv = h.servicios.find((x) => x.codigo === codigo);
	if (!sv) return null;
	const n = sv.unidad === "persona_noche" ? adultos * noches : sv.unidad === "noche" ? noches : Math.max(1, Math.min(cantidad ?? 1, 4));
	return { codigo: sv.codigo, nombre: sv.nombre, cantidad: n, precio_unitario: sv.precio, total: sv.precio * n };
}

/** Recomputes per-night services when the dates change (the transfer does not depend on the nights). */
export function recalcularServicios(h: Hotel, servicios: LineaServicio[], adultos: number, noches: number): LineaServicio[] {
	return servicios.map((l) => lineaServicio(h, l.codigo, l.cantidad, adultos, noches)!).filter(Boolean);
}

export function textoCancelacion(h: Hotel): string {
	return `Cancelación sin cargo hasta ${h.politica.cancelacionGratisHoras} horas antes del check-in (${h.politica.checkIn}); después, se cobra la primera noche.`;
}

/** Quotes a stay under the hotel's policy, comparing against the simulated channel manager. */
export function cotizarEstadia(h: Hotel, s: SistemaHotel, p: PedidoEstadia, ctx: { tenantId: string; caseId: string; hoy?: Date }): ResultadoEstadia {
	const hoy = ctx.hoy ?? new Date();
	const notas: string[] = [];
	const t = h.tipos.find((x) => x.codigo === p.tipo);
	if (!t) return { ok: false, motivo: "tipo_desconocido", notas, contradiccion: null };
	if (!esFecha(p.llegada) || !esFecha(p.salida)) return { ok: false, motivo: "fechas_invalidas", notas, contradiccion: null };
	if (p.llegada < isoDia(hoy)) return { ok: false, motivo: "llegada_en_el_pasado", notas, contradiccion: null };
	const n = nochesEntre(p.llegada, p.salida);
	if (n < 1) return { ok: false, motivo: "salida_antes_de_llegada", notas, contradiccion: null };
	if (n > h.politica.maxNoches) return { ok: false, motivo: "demasiadas_noches", notas, contradiccion: null };
	if (p.adultos < 1 || p.adultos > t.capacidad) return { ok: false, motivo: `capacidad:${t.capacidad}`, notas, contradiccion: null };
	const paquete = p.paquete ? h.paquetes.find((x) => x.codigo === p.paquete) : null;
	if (p.paquete && !paquete) return { ok: false, motivo: "paquete_no_ofrecido", notas, contradiccion: null };
	if (paquete && (paquete.tipo !== p.tipo || paquete.noches !== n)) return { ok: false, motivo: `paquete_no_aplica:${paquete.tipo}:${paquete.noches}`, notas, contradiccion: null };
	const noches: Noche[] = [];
	for (let f = p.llegada; f < p.salida; f = masDias(f, 1)) noches.push({ fecha: f, tarifa: tarifaNoche(h, s, p.tipo, f) });
	const libresPms = libres(h, s, p.tipo, p.llegada, p.salida);
	const comparacion = canalSimulado(h, s, p.tipo, noches, libresPms);
	// Contradiction between systems: the channel manager says one thing and the PMS another. The PMS wins.
	const canalDice = comparacion.some((c) => c.disponible);
	const contradiccion = canalDice !== libresPms > 0 ? `El channel manager (simulado) muestra ${canalDice ? "disponibilidad" : "sin disponibilidad"} para ${t.nombre} y el sistema del hotel (PMS) ${libresPms > 0 ? `tiene ${libresPms} libre(s)` : "no tiene"}. Manda el PMS.` : null;
	if (contradiccion) notas.push(contradiccion);
	if (libresPms < 1 && !(mutado("canal_manda") && canalDice)) return { ok: false, motivo: "sin_disponibilidad", notas, contradiccion };
	const codigos = [...new Set([...(paquete?.servicios ?? []), ...p.servicios.map((x) => x.codigo)])];
	const servicios: LineaServicio[] = [];
	for (const c of codigos) {
		const l = lineaServicio(h, c, p.servicios.find((x) => x.codigo === c)?.cantidad, p.adultos, n);
		if (!l) return { ok: false, motivo: `servicio_no_ofrecido:${c}`, notas, contradiccion };
		const sv = h.servicios.find((x) => x.codigo === c)!;
		if (sv.cupoDiario !== undefined && (s.traslados[p.llegada] ?? 0) + l.cantidad > sv.cupoDiario) return { ok: false, motivo: `sin_cupo:${c}`, notas, contradiccion };
		servicios.push(l);
	}
	let habitacion = noches.reduce((x, y) => x + y.tarifa, 0);
	// Best direct rate: if a (simulated) agency publishes less for the same nights and the PMS has
	// the room, the hotel matches that rate. Nobody's word is taken: only what the channel publishes.
	let igualada: Estadia["tarifa_igualada"] = null;
	const menor = comparacion.filter((c) => c.total !== null).sort((a, b) => a.total! - b.total!)[0];
	if (menor && menor.total! < habitacion) {
		igualada = { agencia: menor.agencia, monto: habitacion - menor.total! };
		notas.push(`Igualamos la tarifa publicada en ${menor.agencia}: ${clp(menor.total!)} por las noches.`);
		habitacion = menor.total!;
	}
	const serviciosTotal = servicios.reduce((x, y) => x + y.total, 0);
	let descuento: Estadia["descuento"] = null;
	if (paquete) {
		const monto = Math.round(((habitacion + serviciosTotal) * paquete.descuentoPct) / 100);
		descuento = { motivo: `paquete ${paquete.nombre}`, pct: paquete.descuentoPct, monto };
	} else if (n >= h.politica.estadiaLarga.desdeNoches && !igualada) {
		const monto = Math.round((habitacion * h.politica.estadiaLarga.pct) / 100);
		descuento = { motivo: `estadía de ${h.politica.estadiaLarga.desdeNoches} noches o más`, pct: h.politica.estadiaLarga.pct, monto };
	}
	const total = habitacion + serviciosTotal - (descuento?.monto ?? 0);
	const neto = Math.round(total / (1 + h.politica.ivaPct / 100));
	const vence = new Date(hoy.getTime() + h.politica.vigenciaMinutos * 60_000).toISOString();
	const est: Estadia = {
		id: randomId("EST-", 5).toUpperCase(),
		tenantId: ctx.tenantId,
		caseId: ctx.caseId,
		revision: 1,
		tipo: t.codigo,
		nombreTipo: t.nombre,
		llegada: p.llegada,
		salida: p.salida,
		adultos: p.adultos,
		noches,
		servicios,
		paquete: paquete?.codigo ?? null,
		descuento,
		tarifa_igualada: igualada,
		habitacion_total: habitacion,
		neto,
		iva: total - neto,
		total,
		moneda: "CLP",
		vence,
		cancelacion: textoCancelacion(h),
		garantia: h.politica.garantia,
		comparacion,
		historial: [{ revision: 1, motivo: "cotizacion", at: hoy.toISOString() }],
		estado: "abierta",
	};
	return { ok: true, est, notas, contradiccion };
}

/** Revision of a stay (counterproposal): same id, new revision, within the policy. */
export function revisarEstadia(h: Hotel, s: SistemaHotel, est: Estadia, cambios: Partial<PedidoEstadia> & { agregar?: { codigo: string; cantidad?: number }[]; quitar?: string[] }, hoy = new Date()): ResultadoEstadia {
	if (est.estado !== "abierta") return { ok: false, motivo: `estadia_${est.estado}`, notas: [], contradiccion: null };
	if (Date.parse(est.vence) < hoy.getTime()) return { ok: false, motivo: "estadia_vencida", notas: [], contradiccion: null };
	const actuales = est.servicios.filter((l) => !(cambios.quitar ?? []).includes(l.codigo)).map((l) => ({ codigo: l.codigo, cantidad: h.servicios.find((x) => x.codigo === l.codigo)?.unidad === "trayecto" ? l.cantidad : undefined }));
	const servicios = [...actuales.filter((x) => !(cambios.agregar ?? []).some((a) => a.codigo === x.codigo)), ...(cambios.agregar ?? [])];
	const r = cotizarEstadia(h, s, { tipo: cambios.tipo ?? est.tipo, llegada: cambios.llegada ?? est.llegada, salida: cambios.salida ?? est.salida, adultos: cambios.adultos ?? est.adultos, servicios, paquete: cambios.paquete !== undefined ? cambios.paquete : est.paquete }, { tenantId: est.tenantId, caseId: est.caseId, hoy });
	if (!r.ok) return r;
	r.est.id = est.id;
	r.est.revision = est.revision + 1;
	r.est.historial = [...est.historial, { revision: est.revision + 1, motivo: "revision", at: hoy.toISOString() }];
	return r;
}

export function textoEstadia(est: Estadia, hotel: string): string {
	const sv = est.servicios.length ? ` Servicios: ${est.servicios.map((l) => `${l.nombre} × ${l.cantidad} = ${clp(l.total)}`).join("; ")}.` : "";
	const dto = est.descuento ? ` Descuento por ${est.descuento.motivo}: ${est.descuento.pct}% (−${clp(est.descuento.monto)}).` : "";
	const comp = est.comparacion.map((c) => `${c.agencia}: ${c.total === null ? "sin disponibilidad" : clp(c.total)}`).join("; ");
	return `Cotización ${est.id} (revisión ${est.revision}) de ${hotel}: ${est.nombreTipo}, ${est.adultos} adulto${est.adultos === 1 ? "" : "s"}, llegada ${est.llegada} y salida ${est.salida} (${est.noches.length} noche${est.noches.length === 1 ? "" : "s"}): habitación ${clp(est.habitacion_total)}.${sv}${dto} Total ${clp(est.total)} IVA incluido (neto ${clp(est.neto)} + IVA ${clp(est.iva)}). Tarifa directa vs. publicada en agencias (comparación simulada) por las noches: ${comp}. ${est.cancelacion} Garantía: ${est.garantia}. Válida hasta ${est.vence.slice(0, 16).replace("T", " ")} UTC.`;
}

/** Availability and rates of every type for given dates (public information). */
export function disponibilidad(h: Hotel, s: SistemaHotel, llegada: string, salida: string, adultos: number) {
	return h.tipos.map((t) => {
		const noches: Noche[] = [];
		for (let f = llegada; f < salida; f = masDias(f, 1)) noches.push({ fecha: f, tarifa: tarifaNoche(h, s, t.codigo, f) });
		const l = libres(h, s, t.codigo, llegada, salida);
		return { tipo: t.codigo, nombre: t.nombre, capacidad: t.capacidad, apta: adultos <= t.capacidad, libres: l, directa: noches.reduce((x, y) => x + y.tarifa, 0), por_noche: noches, agencias: canalSimulado(h, s, t.codigo, noches, l) };
	});
}

// ── Natural language: what the company's agent understands from a message about the hotel ────────

const MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];
const NUMEROS: Record<string, number> = { un: 1, una: 1, uno: 1, dos: 2, tres: 3, cuatro: 4, cinco: 5, seis: 6, siete: 7 };
export const NO_OFRECIDO = /\b(spa|masaje|masajes|cena|cenas|tour|tours|excursion|excursiones|termas|piscina temperada|room service|minibar|paquete romantico|luna de miel)\b/;

export type InterpretacionHotel = {
	llegada?: string;
	salida?: string;
	adultos?: number;
	tipo?: string;
	servicios: { codigo: string; cantidad?: number }[];
	paquete?: string;
	reserva?: string;
	noOfrecido?: string;
	agenciaCitada?: number;
};

function fechaDe(dia: number, mes: number, hoy: Date): string {
	let y = hoy.getUTCFullYear();
	const f = (yy: number) => `${yy}-${String(mes + 1).padStart(2, "0")}-${String(dia).padStart(2, "0")}`;
	if (f(y) < isoDia(hoy)) y += 1;
	return f(y);
}

export function interpretarHotel(h: Hotel, texto: string, hoy = new Date()): InterpretacionHotel {
	const t = norm(texto);
	const out: InterpretacionHotel = { servicios: [] };
	const isos = [...texto.matchAll(/\b(20\d\d-\d\d-\d\d)\b/g)].map((m) => m[1]);
	const meses = MESES.join("|");
	const delAl = t.match(new RegExp(`\\b(?:del?\\s+)?(\\d{1,2})(?:\\s+de\\s+(${meses}))?\\s+(?:al|hasta el|-)\\s+(\\d{1,2})\\s+de\\s+(${meses})`));
	const barras = [...texto.matchAll(/\b(\d{1,2})\/(\d{1,2})(?:\/(20\d\d))?\b/g)];
	const diasMes = [...t.matchAll(new RegExp(`\\b(\\d{1,2})\\s+de\\s+(${meses})\\b`, "g"))];
	if (isos.length >= 2) [out.llegada, out.salida] = isos;
	else if (delAl) {
		const m2 = MESES.indexOf(delAl[4]);
		const m1 = delAl[2] ? MESES.indexOf(delAl[2]) : m2;
		out.llegada = fechaDe(Number(delAl[1]), m1, hoy);
		out.salida = fechaDe(Number(delAl[3]), m2, hoy);
		if (out.salida < out.llegada) out.salida = fechaDe(Number(delAl[3]), m2, new Date(Date.parse(`${out.llegada}T00:00:00Z`)));
	} else if (diasMes.length >= 2) {
		// «check-in sábado 14 de noviembre y check-out lunes 16 de noviembre»: two separate dates (external agent A, Oct 21).
		out.llegada = fechaDe(Number(diasMes[0][1]), MESES.indexOf(diasMes[0][2]), hoy);
		out.salida = fechaDe(Number(diasMes[1][1]), MESES.indexOf(diasMes[1][2]), hoy);
		if (out.salida < out.llegada) out.salida = fechaDe(Number(diasMes[1][1]), MESES.indexOf(diasMes[1][2]), new Date(Date.parse(`${out.llegada}T00:00:00Z`)));
	} else if (barras.length >= 2) {
		const f =(m: RegExpMatchArray) => (m[3] ? `${m[3]}-${m[2].padStart(2, "0")}-${m[1].padStart(2, "0")}` : fechaDe(Number(m[1]), Number(m[2]) - 1, hoy));
		out.llegada = f(barras[0]);
		out.salida = f(barras[1]);
	} else if (isos.length === 1) out.llegada = isos[0];
	const noches = t.match(/\b(\d+|una|dos|tres|cuatro|cinco|seis|siete)\s+noches?\b/);
	if (out.llegada && !out.salida && noches) out.salida = masDias(out.llegada, Number(noches[1]) || NUMEROS[noches[1]] || 1);
	const ad = t.match(/\b(\d+|un|una|dos|tres|cuatro|cinco)\s+(adultos?|personas?|huespedes?)\b/);
	if (ad) out.adultos = Number(ad[1]) || NUMEROS[ad[1]];
	else if (/\b(para dos|pareja|mi senora y yo|mi esposa y yo|mi esposo y yo)\b/.test(t)) out.adultos = 2;
	else if (/\b(para mi|solo yo|una persona)\b/.test(t)) out.adultos = 1;
	for (const tp of h.tipos) if (tp.palabras.some((w) => new RegExp(`\\b${norm(w)}\\b`).test(t))) out.tipo = tp.codigo;
	for (const sv of h.servicios) {
		if (!sv.palabras.some((w) => new RegExp(`\\b${norm(w)}\\b`).test(t))) continue;
		out.servicios.push({ codigo: sv.codigo, ...(sv.unidad === "trayecto" ? { cantidad: /ida y vuelta|ambos|los dos trayectos/.test(t) ? 2 : 1 } : {}) });
	}
	for (const pq of h.paquetes) if (pq.palabras.some((w) => new RegExp(`\\b${norm(w)}\\b`).test(t))) out.paquete = pq.codigo;
	out.reserva = texto.match(/\b(R-\d{4})\b/i)?.[1]?.toUpperCase();
	out.noOfrecido = t.match(NO_OFRECIDO)?.[1];
	const citada = t.match(/(?:a|en|por)\s*\$?\s*(\d{1,3}(?:[.\s]\d{3})+|\d{4,7})\b/);
	if (citada && /(booking|expedia|despegar|agencia|airbnb|trivago|en otra|mas barato|más barato)/.test(t)) out.agenciaCitada = Number(citada[1].replace(/[.\s]/g, ""));
	return out;
}

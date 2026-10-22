// The company's commerce: catalog, quoting and negotiation under the company's real commercial
// policy (volume discounts, negotiable cap, shipping costs and lead times per comuna, validity).
// Negotiation never leaves the policy: anything beyond it gets a counteroffer within it, or a no.
// In production this knowledge lives in the company's system (ERP/e-commerce); here, in `Empresa.comercio`.

import { randomId } from "./jose.ts";

export type Producto = { sku: string; nombre: string; palabras: string[]; precio: number; stock: number; unidad: string };
export type Politica = {
	descuentosVolumen: { desde: number; pct: number }[];
	topeDescuento: number;
	despacho: { comunas: Record<string, { costo: number; diasHabiles: number }>; gratisDesde: number };
	vigenciaHoras: number;
	revisionSobre: number;
	topePermanente?: number;
	pago: string;
};
export type Comercio = { catalogo: Producto[]; politica: Politica };

export type Linea = { sku: string; nombre: string; cantidad: number; precio_unitario: number; descuento_pct: number; subtotal: number };
export type Cotizacion = {
	id: string;
	tenantId: string;
	/** Case (conversation) where it was created: the «esta cotización» of later messages. */
	caseId: string;
	/** Who requested it (the agent's `client_id#sub`, or the channel): to resume it from another conversation. */
	origen?: string;
	revision: number;
	lineas: Linea[];
	despacho: { comuna: string; direccion: string; fecha: string; costo: number };
	neto_productos: number;
	total: number;
	moneda: "CLP";
	vence: string;
	pago: string;
	historial: { revision: number; motivo: string; at: string }[];
	estado: "abierta" | "usada" | "vencida";
};

const norm = (s: string) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
const NUMEROS: Record<string, number> = { un: 1, una: 1, uno: 1, dos: 2, tres: 3, cuatro: 4, cinco: 5, seis: 6, siete: 7, ocho: 8, nueve: 9, diez: 10, once: 11, doce: 12, quince: 15, veinte: 20 };
const DIAS = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"];
/** A catalog word in singular or plural («sierra»/«sierras», «circular»/«circulares»). */
const palabra = (w: string) => new RegExp(`\\b${w}(s|es)?\\b`);
export const clp = (n: number) => `$${n.toLocaleString("es-CL")}`;
const iso = (d: Date) => d.toISOString().slice(0, 10);

/** The business day (Monday to Friday) `n` business days after `desde`. */
export function sumarHabiles(desde: Date, n: number): Date {
	const d = new Date(Date.UTC(desde.getUTCFullYear(), desde.getUTCMonth(), desde.getUTCDate()));
	let k = 0;
	while (k < n) {
		d.setUTCDate(d.getUTCDate() + 1);
		if (d.getUTCDay() !== 0 && d.getUTCDay() !== 6) k++;
	}
	return d;
}

export function buscar(c: Comercio, texto: string): Producto[] {
	const t = norm(texto);
	return c.catalogo.filter((p) => p.palabras.some((w) => palabra(norm(w)).test(t)));
}

export type Interpretacion = { items: { sku: string; cantidad: number }[]; comuna?: string; direccion?: string; fecha?: string; antesDe?: string; descuento?: number };

/** Parses a natural-language message: items and quantities, comuna/address, date and requested discount. */
export function interpretar(c: Comercio, texto: string, hoy = new Date()): Interpretacion {
	const t = norm(texto);
	const out: Interpretacion = { items: [] };
	for (const p of c.catalogo) {
		const w = p.palabras.map(norm).find((x) => palabra(x).test(t));
		if (!w) continue;
		// If a more specific item also matches (cordless drill), the generic one is not added.
		if (p.sku === "TAL-800" && /inalambric|bateria/.test(t)) continue;
		if (p.sku === "TAL-INA-18" && !/inalambric|bateria/.test(t)) continue;
		const antes = t.slice(Math.max(0, t.search(palabra(w)) - 24), t.search(palabra(w)));
		const m = antes.match(/(\d+)\s*(x|unidades|u\.?|sets?|pares?)?\s*(de\s+)?([a-z]+\s+)?$/) ?? antes.match(new RegExp(`\\b(${Object.keys(NUMEROS).join("|")})\\b\\s*(de\\s+)?([a-z]+\\s+)?$`));
		const cantidad = m ? (Number(m[1]) || NUMEROS[m[1]] || 1) : 1;
		out.items.push({ sku: p.sku, cantidad: Math.max(1, Math.min(cantidad, 999)) });
	}
	// If more than one comuna matches («La Reina (Santiago)»), the most specific wins: «santiago» as a city is the
	// last resort. Found by an external agent on Oct 21 (it quoted «Santiago» instead of La Reina).
	const calzan = Object.keys(c.politica.despacho.comunas).filter((comuna) => new RegExp(`\\b${norm(comuna)}\\b`).test(t));
	if (calzan.length) out.comuna = calzan.find((x) => x !== "santiago") ?? calzan[0];
	const dir = texto.match(/\b((?:av\.?|avenida|calle|pasaje|los|las)\s+[A-Za-zÁÉÍÓÚÑáéíóúñ .]+?\s+\d{1,5})\b/i);
	if (dir) out.direccion = dir[1].trim();
	const isoF = texto.match(/\b(20\d\d-\d\d-\d\d)\b/)?.[1];
	const dm = texto.match(/\b(\d{1,2})\/(\d{1,2})(?:\/(20\d\d))?\b/);
	if (isoF) out.fecha = isoF;
	else if (dm) out.fecha = `${dm[3] ?? hoy.getUTCFullYear()}-${dm[2].padStart(2, "0")}-${dm[1].padStart(2, "0")}`;
	const dia = DIAS.findIndex((d) => new RegExp(`\\b${d}\\b`).test(t));
	if (!out.fecha && dia >= 0) {
		const d = new Date(Date.UTC(hoy.getUTCFullYear(), hoy.getUTCMonth(), hoy.getUTCDate()));
		do d.setUTCDate(d.getUTCDate() + 1);
		while (d.getUTCDay() !== dia);
		if (/\bantes del?\b/.test(t)) out.antesDe = iso(d);
		else out.fecha = iso(d);
	}
	const pct = t.match(/(\d{1,2})\s*%/);
	if (pct && /(descuento|rebaja|dcto|baj|precio)/.test(t)) out.descuento = Number(pct[1]);
	else if (/(descuento|rebaja|mejor precio|dcto)/.test(t)) out.descuento = -1; // asks for a discount without a figure
	return out;
}

/** Discount allowed by policy: volume, plus what was requested, never above the cap. */
function descuentoLinea(pol: Politica, cantidad: number, pedido: number | undefined): { pct: number; tope: number } {
	const volumen = pol.descuentosVolumen.filter((d) => cantidad >= d.desde).reduce((m, d) => Math.max(m, d.pct), 0);
	// The published discount is the volume discount. On top of it, a negotiated commercial discount: requested
	// without a figure, one 2-point step; with a figure, up to the amount requested. Never above the cap. (Before,
	// asking without a figure granted the cap at once; found by an external agent on Oct 21.)
	const extra = pedido === undefined ? volumen : pedido < 0 ? volumen + 2 : Math.max(volumen, pedido);
	return { pct: Math.min(Math.max(volumen, extra), pol.topeDescuento), tope: pol.topeDescuento };
}

export type ResultadoCotizacion = { ok: true; cot: Cotizacion; notas: string[] } | { ok: false; motivo: string };

export function cotizar(
	c: Comercio,
	tenantId: string,
	caseId: string,
	pedido: { items: { sku: string; cantidad: number }[]; comuna: string; direccion: string; fecha?: string; antesDe?: string; descuento?: number },
	hoy = new Date(),
): ResultadoCotizacion {
	const pol = c.politica;
	const notas: string[] = [];
	if (pedido.items.length === 0) return { ok: false, motivo: "sin_articulos" };
	const zona = pol.despacho.comunas[pedido.comuna];
	if (!zona) return { ok: false, motivo: "comuna_sin_despacho" };
	const lineas: Linea[] = [];
	for (const it of pedido.items) {
		const p = c.catalogo.find((x) => x.sku === it.sku);
		if (!p) return { ok: false, motivo: `sku_desconocido:${it.sku}` };
		if (p.stock < it.cantidad) return { ok: false, motivo: `sin_stock:${p.sku}:${p.stock}` };
		const d = descuentoLinea(pol, it.cantidad, pedido.descuento);
		if (pedido.descuento !== undefined && pedido.descuento > d.tope) notas.push(`El máximo que podemos ofrecer es ${d.tope}% de descuento; lo aplicamos.`);
		const unit = Math.round(p.precio * (1 - d.pct / 100));
		lineas.push({ sku: p.sku, nombre: p.nombre, cantidad: it.cantidad, precio_unitario: unit, descuento_pct: d.pct, subtotal: unit * it.cantidad });
	}
	const minimo = iso(sumarHabiles(hoy, zona.diasHabiles));
	let fecha = pedido.fecha ?? minimo;
	if (fecha < minimo) {
		notas.push(`La fecha más próxima de despacho a ${pedido.comuna} es el ${minimo}.`);
		fecha = minimo;
	}
	if (pedido.antesDe && minimo > pedido.antesDe) notas.push(`No alcanzamos a despachar antes del ${pedido.antesDe}: lo más pronto es el ${minimo}.`);
	else if (pedido.antesDe && minimo === pedido.antesDe) notas.push(`Antes del ${pedido.antesDe} no alcanzamos; lo más pronto es ese mismo día, el ${minimo}.`);
	if (pedido.antesDe && !pedido.fecha && minimo < pedido.antesDe) fecha = minimo;
	const neto = lineas.reduce((s, l) => s + l.subtotal, 0);
	const costo = neto >= pol.despacho.gratisDesde ? 0 : zona.costo;
	const cot: Cotizacion = {
		id: randomId("COT-", 5).toUpperCase(),
		tenantId,
		caseId,
		revision: 1,
		lineas,
		despacho: { comuna: pedido.comuna, direccion: pedido.direccion, fecha, costo },
		neto_productos: neto,
		total: neto + costo,
		moneda: "CLP",
		vence: new Date(hoy.getTime() + pol.vigenciaHoras * 3_600_000).toISOString(),
		pago: pol.pago,
		historial: [{ revision: 1, motivo: "cotizacion", at: hoy.toISOString() }],
		estado: "abierta",
	};
	return { ok: true, cot, notas };
}

/** Negotiates on a quote: a new revision within policy, or a no with its reason. */
export function negociar(c: Comercio, cot: Cotizacion, pide: { descuento?: number; fecha?: string; antesDe?: string; cantidades?: { sku: string; cantidad: number }[] }, hoy = new Date()): ResultadoCotizacion {
	if (cot.estado !== "abierta") return { ok: false, motivo: `cotizacion_${cot.estado}` };
	if (Date.parse(cot.vence) < hoy.getTime()) return { ok: false, motivo: "cotizacion_vencida" };
	const actualPct = Math.max(...cot.lineas.map((l) => l.descuento_pct));
	if (pide.descuento !== undefined && pide.descuento >= 0 && pide.descuento <= actualPct && !pide.fecha && !pide.antesDe && !pide.cantidades)
		return { ok: false, motivo: `ya_tiene_${actualPct}` };
	if (pide.descuento !== undefined && actualPct >= c.politica.topeDescuento && !pide.fecha && !pide.antesDe && !pide.cantidades)
		return { ok: false, motivo: "tope_descuento_alcanzado" };
	const items = pide.cantidades ?? cot.lineas.map((l) => ({ sku: l.sku, cantidad: l.cantidad }));
	// Asking for «más descuento» without a figure goes up one step over the current one; it never jumps to the cap.
	const descuento = pide.descuento === -1 ? Math.min(actualPct + 2, c.politica.topeDescuento) : (pide.descuento ?? actualPct);
	const r = cotizar(c, cot.tenantId, cot.caseId, { items, comuna: cot.despacho.comuna, direccion: cot.despacho.direccion, fecha: pide.fecha ?? cot.despacho.fecha, antesDe: pide.antesDe, descuento }, hoy);
	if (!r.ok) return r;
	// States where the discount comes from: the published volume discount and the negotiated commercial one, with its cap.
	const volumen = Math.max(0, ...c.politica.descuentosVolumen.filter((d) => r.cot.lineas.every((l) => l.cantidad >= d.desde)).map((d) => d.pct));
	const nuevo = Math.max(...r.cot.lineas.map((l) => l.descuento_pct));
	if (pide.descuento !== undefined && nuevo > volumen)
		r.notas.push(`Te damos ${nuevo}%: ${volumen}% por volumen (publicado) + ${nuevo - volumen}% de descuento comercial negociado. El máximo negociable es ${c.politica.topeDescuento}%.`);
	r.cot.id = cot.id;
	r.cot.origen = cot.origen;
	r.cot.revision = cot.revision + 1;
	r.cot.historial = [...cot.historial, { revision: cot.revision + 1, motivo: "negociacion", at: hoy.toISOString() }];
	return r;
}

export function textoCotizacion(cot: Cotizacion, empresa: string): string {
	const lineas = cot.lineas.map((l) => `${l.cantidad} × ${l.nombre} a ${clp(l.precio_unitario)}${l.descuento_pct ? ` (${l.descuento_pct}% dcto.)` : ""} = ${clp(l.subtotal)}`).join("; ");
	const comuna = cot.despacho.comuna.replace(/(^|\s)(\p{L})/gu, (_m, a: string, b: string) => a + b.toUpperCase());
	const despacho = cot.despacho.costo ? `despacho a ${cot.despacho.direccion}, ${comuna}, el ${cot.despacho.fecha}: ${clp(cot.despacho.costo)}` : `despacho gratis a ${cot.despacho.direccion}, ${comuna}, el ${cot.despacho.fecha}`;
	return `Cotización ${cot.id} (revisión ${cot.revision}) de ${empresa}: ${lineas}; ${despacho}. Total ${clp(cot.total)} IVA incluido. Válida hasta ${cot.vence.slice(0, 16).replace("T", " ")} UTC. ${cot.pago}`;
}

// Hotel Demo: a FICTITIOUS company of the stress-test sandbox (a different tenant and domain from
// Ferretería Demo). Its test customers are Cliente de prueba A and Cliente de prueba B, with the same WhatsApp as in
// the hardware store: this proves that an account, a delegation or a booking of one company does not
// exist for the other. Dates are set relative to the day the server starts.
//
// It also adds to Ferretería Demo what the return flow needs: an order DELIVERED and PAID by
// bank transfer (the refund is simulated, like every payment in the sandbox).

import type { Capacidad, Empresa } from "./nucleo.ts";
import { type Hotel, type Reserva, type SistemaHotel, isoDia, masDias, recalcularServicios, tarifaNoche } from "./hotel.ts";
import { pagosVacios } from "./pagos.ts";

export const T_HOTEL = "t_hotel_demo";

export const hotelDemo = (): Hotel => ({
	ubicacion: "Cajón del Maipo, Región Metropolitana (ficticio)",
	tipos: [
		{ codigo: "DBL-EST", nombre: "Doble estándar", capacidad: 2, inventario: 6, tarifaBase: 78000, palabras: ["doble estandar", "estandar", "matrimonial", "doble"] },
		{ codigo: "DBL-VIS", nombre: "Doble con vista a la montaña", capacidad: 2, inventario: 4, tarifaBase: 98000, palabras: ["vista", "vista a la montaña", "con vista"] },
		{ codigo: "FAM", nombre: "Familiar (hasta 4 personas)", capacidad: 4, inventario: 2, tarifaBase: 132000, palabras: ["familiar", "familia", "ninos"] },
		{ codigo: "SUI", nombre: "Suite montaña", capacidad: 2, inventario: 1, tarifaBase: 165000, palabras: ["suite"] },
	],
	servicios: [
		{ codigo: "DESAYUNO", nombre: "Desayuno buffet", precio: 12000, unidad: "persona_noche", palabras: ["desayuno", "desayunos"] },
		{ codigo: "ESTAC", nombre: "Estacionamiento", precio: 6000, unidad: "noche", palabras: ["estacionamiento", "parking", "auto", "auto propio"] },
		{ codigo: "TRASLADO", nombre: "Traslado aeropuerto de Santiago ↔ hotel", precio: 45000, unidad: "trayecto", palabras: ["traslado", "transfer", "aeropuerto"], cupoDiario: 4 },
	],
	// The only package the hotel offers. Any other (spa, dinner, tour) does not exist and is not invented.
	paquetes: [{ codigo: "ESCAPADA", nombre: "Escapada Demo (2 noches en doble con vista, desayuno y estacionamiento)", tipo: "DBL-VIS", noches: 2, servicios: ["DESAYUNO", "ESTAC"], descuentoPct: 10, palabras: ["escapada", "escapada demo"] }],
	politica: {
		ivaPct: 19,
		recargoFinDeSemanaPct: 15,
		estadiaLarga: { desdeNoches: 4, pct: 10 },
		cancelacionGratisHoras: 72,
		modificacionSinRevisionHoras: 72,
		revisionSobreNoches: 7,
		revisionSobreMonto: 1_000_000,
		maxNoches: 14,
		checkIn: "15:00",
		checkOut: "12:00",
		vigenciaMinutos: 60,
		garantia: "pre-autorización del total en la tarjeta registrada en tu cuenta (simulada en este entorno: no hay cobros reales)",
		extranjeros: "Tarifas en CLP con IVA (19%) incluido. Los huéspedes extranjeros no residentes que pagan en divisas pueden quedar exentos de IVA; en este entorno de prueba se cobra siempre en CLP con IVA.",
	},
	// SIMULATED channel manager: it does not represent any real agency.
	agencias: [
		{ nombre: "Agencia A (simulada)", ajustePct: 10 },
		{ nombre: "Agencia B (simulada)", ajustePct: 4 },
	],
});

const capacidadesHotel: Capacidad[] = [
	{ id: "hotel.disponibilidad", efecto: "read", alcance: "publico", descripcion: "Consultar disponibilidad, tarifas y servicios del hotel" },
	{ id: "reserva.consultar", efecto: "read", alcance: "reservas:leer", descripcion: "Ver tus reservas" },
	{ id: "reserva.crear", efecto: "write", alcance: "reservas:crear", descripcion: "Hacer una reserva a tu nombre",
		// The read-back confirms each of these terms in the PMS and with the payment provider.
		lecturaDeVuelta: { estadia: "pms.reserva.estadia", tipo: "pms.reserva.tipo", llegada: "pms.reserva.llegada", salida: "pms.reserva.salida", total: "pms.reserva.total", garantia: "pago.garantia_vigente" },
	},
	{ id: "reserva.modificar_fechas", efecto: "write", alcance: "reservas:modificar", descripcion: "Cambiar las fechas de tu reserva",
		lecturaDeVuelta: { reserva: "pms.reserva.id", llegada: "pms.reserva.llegada", salida: "pms.reserva.salida", total: "pms.reserva.total", garantia: "pago.garantia_vigente" },
	},
	{ id: "reserva.agregar_servicio", efecto: "write", alcance: "reservas:modificar", descripcion: "Agregar un servicio del hotel a tu reserva",
		lecturaDeVuelta: { reserva: "pms.reserva.id", servicios: "pms.reserva.servicios", total: "pms.reserva.total", garantia: "pago.garantia_vigente" },
	},
	{ id: "reserva.cancelar", efecto: "write", alcance: "reservas:cancelar", descripcion: "Cancelar tu reserva según la política",
		lecturaDeVuelta: { reserva: "pms.reserva.id", estado: "pms.reserva.estado", cargo: "pago.capturado", garantia: "pago.garantia_vigente" },
	},
];

const alcancesHotel = {
	"reservas:leer": "Ver tus reservas en el Hotel Demo",
	"reservas:crear": "Hacer reservas a tu nombre hasta el monto que apruebes, con garantía en tu tarjeta registrada",
	"reservas:modificar": "Cambiar fechas o agregar servicios a una reserva tuya (puede cambiar el total)",
	"reservas:cancelar": "Cancelar una reserva tuya según la política (puede tener cargo)",
};

const haceUnaHora = () => new Date(Date.now() - 3_600_000).toISOString();
const linea = () => ({ ultimaEntrada: haceUnaHora(), consentimientoServicio: "inbound_message" as const });

function reservaInicial(h: Hotel, s: SistemaHotel, id: string, huespedId: string, tipo: string, llegada: string, noches: number, adultos: number, servicios: string[]): Reserva {
	const salida = masDias(llegada, noches);
	const ns = Array.from({ length: noches }, (_, i) => ({ fecha: masDias(llegada, i), tarifa: tarifaNoche(h, s, tipo, masDias(llegada, i)) }));
	const lineas = recalcularServicios(h, servicios.map((c) => ({ codigo: c, nombre: "", cantidad: 1, precio_unitario: 0, total: 0 })), adultos, noches);
	const total = ns.reduce((x, y) => x + y.tarifa, 0) + lineas.reduce((x, y) => x + y.total, 0);
	return { id, huespedId, tipo, llegada, salida, adultos, noches: ns, servicios: lineas, total, estado: "confirmada", historial: [{ at: new Date().toISOString(), cambio: "reserva previa (datos de prueba)" }] };
}

export function hotelDePrueba(dominio: string, hoy = new Date()): Empresa {
	const h = hotelDemo();
	const sis: SistemaHotel = { reservas: [], bloqueos: [], tarifas: {}, canal: [], traslados: {} };
	const base = isoDia(hoy);
	// R-3001: Ana, in 3 weeks (outside the 72 h window). R-3002: Bruno. R-3003: Ana,
	// tomorrow (inside the window: cancelling charges the first night; a person reviews any modification).
	sis.reservas.push(reservaInicial(h, sis, "R-3001", "HC-H-0193", "DBL-VIS", masDias(base, 21), 2, 2, ["DESAYUNO"]));
	sis.reservas.push(reservaInicial(h, sis, "R-3002", "HC-H-0457", "FAM", masDias(base, 30), 3, 3, []));
	sis.reservas.push(reservaInicial(h, sis, "R-3003", "HC-H-0193", "DBL-EST", masDias(base, 1), 1, 2, []));
	const pagos = pagosVacios();
	for (const r of sis.reservas)
		pagos.movimientos.push({ id: `pay_ini_${r.id}`, ref: r.id, tipo: "autorizacion", monto: r.total, estado: "aprobado", idem: `ini:${r.id}`, medio: "tarjeta registrada (simulada) ****4242", at: new Date().toISOString() });
	return {
		tenantId: T_HOTEL,
		slug: "hotel-demo",
		nombre: "Hotel Demo",
		dominio,
		descripcion: "Hotel (ficticio) en el Cajón del Maipo: disponibilidad, tarifas, reservas, cambios de fecha, servicios y cancelaciones.",
		alcances: alcancesHotel,
		release: { version: "rel-2026-10-21.h1", capacidades: capacidadesHotel },
		hotel: h,
		agentesPersonales: { modo: "abierto", permitidos: [] },
		diasSinRevision: 7,
		reglaRevisionAgentes: "regla_de_la_empresa",
		plantillasWhatsApp: { autenticacion: true, aprobacion: false },
		horario: "todos los días, de 8:00 a 22:00 (recepción 24 h)",
		clientes: [
			{ id: "cli_a_hotel", nombre: "Cliente de prueba A", telefono: "+56 9 0000 0101", erp: { id: "HC-H-0193", evidencia: "telefono_registrado_en_ficha_pms" }, whatsapp: linea() },
			{ id: "cli_b_hotel", nombre: "Cliente de prueba B", telefono: "+56 9 0000 0202", erp: { id: "HC-H-0457", evidencia: "telefono_registrado_en_ficha_pms" }, whatsapp: linea() },
		],
		sistema: { pedidos: [], hotel: sis, pagos },
	} as Empresa;
}

/** What the return flow needs in Ferretería Demo: a delivered and paid order, and its payment ledger. */
export function prepararDevoluciones(ferreteria: Empresa, hoy = new Date()): void {
	const entregado = isoDia(new Date(hoy.getTime() - 3 * 86_400_000));
	ferreteria.sistema.pedidos.push({
		id: "P-1044",
		clienteId: "ERP-C-0193",
		producto: "2 × Lijadora orbital 240 W",
		despacho: entregado,
		direccion: "Calle Ejemplo 100, Santiago",
		estado: "entregado",
		articulos: [{ sku: "LIJ-ORB", cantidad: 2, precio_unitario: 39990, descuento_pct: 0 }],
		total: 79980,
		pago: "pagado por transferencia (simulada)",
		entregadoEl: entregado,
	} as never);
	ferreteria.sistema.pagos ??= pagosVacios();
	ferreteria.sistema.pagos.movimientos.push({ id: "pay_ini_P-1044", ref: "P-1044", tipo: "captura", monto: 79980, estado: "aprobado", idem: "ini:P-1044", medio: "transferencia (simulada)", at: new Date().toISOString() });
	ferreteria.sistema.devoluciones ??= [];
	ferreteria.politicaDevolucion = { diasDesdeEntrega: 10, despachoReembolsable: false, retiro: "retiro a domicilio sin costo dentro de 3 días hábiles" };
	// New return capability in the Demo Release: it does not change any existing capability.
	ferreteria.alcances["devoluciones:crear"] = "Pedir la devolución o anulación de un pedido tuyo, con reembolso al medio de pago original";
	ferreteria.release.capacidades.push({ id: "pedido.devolver", efecto: "write", alcance: "devoluciones:crear", descripcion: "Pedir la devolución o anulación de un pedido",
		lecturaDeVuelta: { pedido: "erp.pedido.id", estado_pedido: "erp.pedido.estado", reembolso: "pago.reembolsado", articulos: "erp.devolucion.articulos" },
	});
}

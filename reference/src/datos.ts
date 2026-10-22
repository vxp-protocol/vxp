// Two fictitious companies. Cliente de prueba A is a customer of both with the same WhatsApp: this
// proves that a delegation, a session or an order of one company does not exist for the other.

import type { Capacidad, Empresa } from "./nucleo.ts";

const capacidades: Capacidad[] = [
	{ id: "pedido.consultar", efecto: "read", alcance: "pedidos:leer", descripcion: "Leer los pedidos del cliente" },
	{ id: "pedido.reprogramar_despacho", efecto: "write", alcance: "pedidos:modificar", descripcion: "Cambiar la fecha de despacho",
		// The read-back confirms these terms against these system fields (SPEC §9.4.7).
		lecturaDeVuelta: { pedido: "id", despacho_nuevo: "despacho" },
	},
];

const alcances = {
	"pedidos:leer": "Ver tus pedidos y sus fechas de despacho",
	"pedidos:modificar": "Cambiar la fecha de despacho de un pedido que aún no sale",
};

// Ferretería Demo sells: public catalog, quote and new order (no online payment: paid on
// delivery or by bank transfer). Creating an order is reversible: it can be voided before shipping.
const capacidadesFerreteria: Capacidad[] = [
	...capacidades,
	{ id: "catalogo.consultar", efecto: "read", alcance: "publico", descripcion: "Consultar el catálogo, precios y stock" },
	{ id: "pedido.crear", efecto: "write", alcance: "compras:crear", descripcion: "Hacer un pedido nuevo a tu nombre (sin pago en línea)",
		// The read-back confirms the created order has the approved quote, items and total.
		lecturaDeVuelta: { cotizacion: "cotizacion", articulos: "articulos", total: "total" },
	},
];

const alcancesFerreteria = {
	...alcances,
	"compras:crear": "Hacer pedidos a tu nombre hasta el monto que apruebes (pagas al recibir o por transferencia)",
	// Standing permission: the agent closes orders without asking you each time, within the company's cap.
	"compras:sin_confirmar": "Hacer pedidos sin preguntarte cada vez, hasta $200.000 por pedido (durante 30 días; lo puedes revocar)",
};

/** Catalog and commercial policy of Ferretería Demo. Prices in CLP, VAT included. */
export const comercioFerreteria = () => ({
	catalogo: [
		{ sku: "TAL-800", nombre: "Taladro percutor 800 W", palabras: ["taladro", "percutor", "taladros"], precio: 54990, stock: 14, unidad: "unidad" },
		{ sku: "TAL-INA-18", nombre: "Taladro inalámbrico 18 V con 2 baterías", palabras: ["taladro", "taladros", "inalambrico", "inalámbrico", "bateria", "batería"], precio: 89990, stock: 6, unidad: "unidad" },
		{ sku: "ESC-AL-6", nombre: "Escalera de aluminio 6 peldaños", palabras: ["escalera", "escaleras"], precio: 64990, stock: 9, unidad: "unidad" },
		{ sku: "BRO-SET-15", nombre: "Set de brocas para concreto y metal, 15 piezas", palabras: ["broca", "brocas"], precio: 12990, stock: 40, unidad: "set" },
		{ sku: "LLA-ALLEN", nombre: "Set de llaves Allen, 9 piezas", palabras: ["allen", "llaves"], precio: 7990, stock: 25, unidad: "set" },
		{ sku: "MAR-16", nombre: "Martillo carpintero 16 oz", palabras: ["martillo", "martillos"], precio: 9990, stock: 30, unidad: "unidad" },
		{ sku: "SIE-CIR-1400", nombre: "Sierra circular 1400 W", palabras: ["sierra", "circular"], precio: 79990, stock: 4, unidad: "unidad" },
		{ sku: "LIJ-ORB", nombre: "Lijadora orbital 240 W", palabras: ["lijadora", "lijar"], precio: 39990, stock: 8, unidad: "unidad" },
		{ sku: "CAS-SEG", nombre: "Casco de seguridad", palabras: ["casco", "cascos"], precio: 6990, stock: 50, unidad: "unidad" },
		{ sku: "GUA-NIT", nombre: "Guantes de nitrilo reforzados (par)", palabras: ["guante", "guantes"], precio: 3490, stock: 120, unidad: "par" },
	],
	politica: {
		/** Automatic discount by number of units of the same item. */
		descuentosVolumen: [
			{ desde: 3, pct: 5 },
			{ desde: 10, pct: 10 },
		],
		/** The most a salesperson can negotiate off the list price, per line. */
		topeDescuento: 8,
		despacho: {
			comunas: {
				"la reina": { costo: 4990, diasHabiles: 2 },
				"providencia": { costo: 4990, diasHabiles: 2 },
				"santiago": { costo: 4990, diasHabiles: 2 },
				"las condes": { costo: 5990, diasHabiles: 2 },
				"la florida": { costo: 5990, diasHabiles: 3 },
				"maipú": { costo: 6990, diasHabiles: 3 },
				"puente alto": { costo: 6990, diasHabiles: 3 },
			} as Record<string, { costo: number; diasHabiles: number }>,
			gratisDesde: 150000,
		},
		vigenciaHoras: 48,
		/** Above this total, a person at the company reviews the order before it is created. */
		revisionSobre: 500000,
		/** With standing permission, the agent confirms without asking up to this total per order. */
		topePermanente: 200000,
		pago: "Pagas al recibir o por transferencia. No se cobra nada en línea.",
	},
});

// Round 4 (M5): the test customers wrote to the company an hour ago (Meta's 24 h window open,
// service consent via inbound message). The closed-window tests change this.
const haceUnaHora = () => new Date(Date.now() - 3_600_000).toISOString();
const linea = () => ({ ultimaEntrada: haceUnaHora(), consentimientoServicio: "inbound_message" as const });
// Round 4 (M6): the link between the canonical customer and the ERP customer, with its evidence. ERP
// orders name the ERP customer, not the operator's.
const vinculo = (id: string) => ({ id, evidencia: "telefono_registrado_en_ficha_erp" });

export function empresasDePrueba(dominios: { ferreteria: string; libreria: string }): Empresa[] {
	return [
		{
			tenantId: "t_ferreteria_demo",
			slug: "ferreteria-demo",
			nombre: "Ferretería Demo",
			dominio: dominios.ferreteria,
			descripcion: "Ferretería: catálogo, cotizaciones, pedidos y despachos.",
			alcances: alcancesFerreteria,
			release: { version: "rel-2026-10-21.1", capacidades: capacidadesFerreteria },
			comercio: comercioFerreteria(),
			agentesPersonales: { modo: "abierto", permitidos: [] },
			diasSinRevision: 7,
			reglaRevisionAgentes: "regla_de_la_empresa",
			plantillasWhatsApp: { autenticacion: true, aprobacion: false },
			horario: "de lunes a sábado, de 9:00 a 19:00",
			clientes: [
				{ id: "cli_a_ferreteria", nombre: "Cliente de prueba A", telefono: "+56 9 0000 0101", erp: vinculo("ERP-C-0193"), whatsapp: linea() },
				{ id: "cli_b_ferreteria", nombre: "Cliente de prueba B", telefono: "+56 9 0000 0202", erp: vinculo("ERP-C-0457"), whatsapp: linea() },
			],
			sistema: {
				pedidos: [
					{ id: "P-1042", clienteId: "ERP-C-0193", producto: "Taladro percutor 800 W", despacho: "2026-10-24", direccion: "Calle Ejemplo 100, Santiago", estado: "preparando" },
					{ id: "P-1043", clienteId: "ERP-C-0193", producto: "Escalera de aluminio 6 peldaños", despacho: "2026-10-27", direccion: "Calle Ejemplo 100, Santiago", estado: "preparando" },
					{ id: "P-2001", clienteId: "ERP-C-0457", producto: "Set de llaves Allen", despacho: "2026-10-23", direccion: "Calle Ejemplo 200, Concepción", estado: "en_ruta" },
				],
			},
		},
		{
			tenantId: "t_libreria_demo",
			slug: "libreria-demo",
			nombre: "Librería Demo",
			dominio: dominios.libreria,
			descripcion: "Pedidos de Librería Demo.",
			alcances,
			release: { version: "rel-2026-10-18.3", capacidades },
			agentesPersonales: { modo: "abierto", permitidos: [] },
			diasSinRevision: 7,
			reglaRevisionAgentes: "regla_de_la_empresa",
			plantillasWhatsApp: { autenticacion: true, aprobacion: false },
			horario: "de lunes a viernes, de 10:00 a 18:00",
			clientes: [{ id: "cli_a_libreria", nombre: "Cliente de prueba A", telefono: "+56 9 0000 0101", erp: vinculo("AUS-0012"), whatsapp: linea() }],
			sistema: {
				pedidos: [
					{ id: "P-7001", clienteId: "AUS-0012", producto: "Atlas de Chile", despacho: "2026-10-25", direccion: "Calle Ejemplo 100, Santiago", estado: "preparando" },
				],
			},
		},
	];
}

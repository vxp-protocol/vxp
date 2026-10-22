// Condition simulator for the stress-test sandbox (only /interno, with the internal key). It changes
// the companies' world between a quote and its acceptance, or during execution, to prove that
// SOVRAS keeps control: stock and availability, price and rate, a PMS/ERP that loses the response,
// a channel manager that contradicts the PMS, a payment that fails or that the ledger does not show,
// human review, expired approvals and passes, revocation and a dropped connection with the agent.
//
// Everything is reversible: `reiniciar` restores the systems to the snapshot taken at server start, so
// both agents run under the same conditions. What already happened (operations, VXP Proof chains,
// access log) is NOT erased: it is evidence; open proposals expire with their signed outcome.

import type { Delegaciones } from "./identidad.ts";
import type { Empresa, Nucleo } from "./nucleo.ts";
import type { FallaPago } from "./pagos.ts";
import { pagosVacios } from "./pagos.ts";

type Foto = Pick<Empresa, "sistema" | "comercio" | "hotel" | "clientes" | "limites" | "reglaRevisionAgentes">;
const foto = (e: Empresa): string => JSON.stringify({ sistema: e.sistema, comercio: e.comercio ?? null, hotel: e.hotel ?? null, clientes: e.clientes, limites: e.limites ?? null, reglaRevisionAgentes: e.reglaRevisionAgentes });

export type CambioCondicion = { at: string; tenant: string; cambio: Record<string, unknown> };

export class Simulador {
	private readonly nucleo: Nucleo;
	private readonly del: Delegaciones;
	private readonly fotos = new Map<string, string>();
	private readonly vencerPases: (tenantId: string) => number;
	/** Next N write responses that are lost AFTER being processed (dropped connection). */
	cortarRespuestas = 0;
	readonly historial: CambioCondicion[] = [];

	constructor(nucleo: Nucleo, del: Delegaciones, vencerPases: (tenantId: string) => number) {
		this.nucleo = nucleo;
		this.del = del;
		this.vencerPases = vencerPases;
		for (const e of nucleo.empresas.values()) this.fotos.set(e.tenantId, foto(e));
	}

	/** Applies conditions to a company. Returns what was applied (or the error). */
	aplicar(tenantId: string, b: Record<string, unknown>): { aplicado: Record<string, unknown> } | { error: string } {
		const e = this.nucleo.empresa(tenantId);
		const hecho: Record<string, unknown> = {};
		const obj = (v: unknown) => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
		if (obj(b.stock) || obj(b.precio)) {
			if (!e.comercio) return { error: "la empresa no vende productos" };
			for (const [sku, n] of Object.entries(obj(b.stock) ?? {})) {
				const p = e.comercio.catalogo.find((x) => x.sku === sku);
				if (!p || !Number.isInteger(n)) return { error: `stock: ${sku}` };
				p.stock = Number(n);
			}
			for (const [sku, n] of Object.entries(obj(b.precio) ?? {})) {
				const p = e.comercio.catalogo.find((x) => x.sku === sku);
				if (!p || !Number.isInteger(n)) return { error: `precio: ${sku}` };
				p.precio = Number(n);
			}
			if (b.stock) hecho.stock = b.stock;
			if (b.precio) hecho.precio = b.precio;
		}
		if (obj(b.tarifa) || b.bloqueo || b.canal !== undefined) {
			const s = e.sistema.hotel;
			if (!s || !e.hotel) return { error: "la empresa no es un hotel" };
			for (const [tipo, n] of Object.entries(obj(b.tarifa) ?? {})) {
				if (!e.hotel.tipos.some((t) => t.codigo === tipo) || !Number.isInteger(n)) return { error: `tarifa: ${tipo}` };
				s.tarifas[tipo] = Number(n);
			}
			const bl = obj(b.bloqueo);
			if (bl) s.bloqueos.push({ tipo: String(bl.tipo), desde: String(bl.desde), hasta: String(bl.hasta), unidades: Number(bl.unidades ?? 99) });
			if (Array.isArray(b.canal) && b.canal.length === 0) s.canal = [];
			else if (obj(b.canal)) s.canal.push(b.canal as never);
			if (b.tarifa) hecho.tarifa = b.tarifa;
			if (bl) hecho.bloqueo = bl;
			if (b.canal !== undefined) hecho.canal = b.canal;
		}
		if (b.sistema === "definitiva" || b.sistema === "desconocida") hecho.sistema = e.sistema.proximaFalla = b.sistema;
		if (["rechaza", "caido", "sin_respuesta"].includes(String(b.pago))) hecho.pago = (e.sistema.pagos ??= pagosVacios()).proxima = b.pago as FallaPago;
		if (b.pago_contradictorio === true) hecho.pago_contradictorio = (e.sistema.pagos ??= pagosVacios()).ocultarProximo = true;
		if (typeof b.revision_humana === "boolean") {
			e.reglaRevisionAgentes = b.revision_humana ? "toda_escritura" : "regla_de_la_empresa";
			hecho.revision_humana = b.revision_humana;
		}
		if (obj(b.limites)) hecho.limites = e.limites = { ...this.nucleo.limites(tenantId), ...(b.limites as object) };
		if (typeof b.entregar === "string") {
			const p = e.sistema.pedidos.find((x) => x.id === b.entregar);
			if (!p) return { error: "entregar: pedido" };
			p.estado = "entregado";
			(p as typeof p & { entregadoEl?: string }).entregadoEl = new Date().toISOString().slice(0, 10);
			hecho.entregar = p.id;
		}
		if (b.vencer === true) {
			// Expired approval: this company's open proposals, device codes and native passes.
			const pasado = new Date(Date.now() - 1000).toISOString();
			let ops = 0;
			for (const op of this.nucleo.base(tenantId).operaciones.values())
				if (op.state === "proposed") {
					op.expires_at = pasado;
					ops++;
				}
			let codigos = 0;
			for (const d of this.del.dispositivos.values())
				if (d.tenantId === tenantId && d.estado === "pendiente") {
					d.expira = Math.floor(Date.now() / 1000) - 1;
					codigos++;
				}
			hecho.vencer = { propuestas: ops, codigos_de_dispositivo: codigos, pases_nativos: this.vencerPases(tenantId) };
		}
		if (typeof b.revocar_cliente === "string") {
			let n = 0;
			for (const g of this.del.grants.values())
				if (g.tenantId === tenantId && g.clienteId === b.revocar_cliente && !g.revocado) {
					g.revocado = true;
					n++;
				}
			this.nucleo.evento(tenantId, "-", "delegation.revoked_by_customer", { cliente: b.revocar_cliente, grants: n });
			hecho.revocar_cliente = { cliente: b.revocar_cliente, delegaciones: n };
		}
		if (typeof b.adelantar_horas === "number" && Number.isFinite(b.adelantar_horas)) {
			// The policy clock (cancellation and modification deadlines), not the token or signature clock.
			this.nucleo.desfaseMs = b.adelantar_horas * 3_600_000;
			hecho.adelantar_horas = b.adelantar_horas;
		}
		if (Number.isInteger(b.cortar_respuestas)) hecho.cortar_respuestas = this.cortarRespuestas = Math.max(0, Number(b.cortar_respuestas));
		if (!Object.keys(hecho).length) return { error: "sin condiciones reconocidas" };
		this.historial.push({ at: new Date().toISOString(), tenant: tenantId, cambio: hecho });
		this.nucleo.evento(tenantId, "-", "sandbox.condition_applied", hecho);
		return { aplicado: hecho };
	}

	/** What is currently active in a company (for the script and the evidence). */
	estado(tenantId: string) {
		const e = this.nucleo.empresa(tenantId);
		return {
			proxima_falla_sistema: e.sistema.proximaFalla ?? null,
			proxima_falla_pago: e.sistema.pagos?.proxima ?? null,
			pago_contradictorio: !!e.sistema.pagos?.ocultarProximo,
			movimientos_ocultos: e.sistema.pagos?.ocultos ?? [],
			revision_humana: e.reglaRevisionAgentes === "toda_escritura",
			limites: this.nucleo.limites(tenantId),
			cortar_respuestas: this.cortarRespuestas,
			reloj_politica_adelanto_horas: this.nucleo.desfaseMs / 3_600_000,
			...(e.sistema.hotel ? { tarifas: e.sistema.hotel.tarifas, bloqueos: e.sistema.hotel.bloqueos, canal: e.sistema.hotel.canal } : {}),
			historial: this.historial.filter((h) => h.tenant === tenantId),
		};
	}

	/**
	 * Restores a company (or all of them) to the initial snapshot. Open proposals expire with their signed
	 * outcome; with `revocar_delegaciones`, live delegations are also revoked (start from scratch).
	 */
	reiniciar(tenantId: string | null, revocarDelegaciones = false): { reiniciadas: string[]; propuestas_vencidas: number; delegaciones_revocadas: number } {
		const ids = tenantId ? [tenantId] : [...this.fotos.keys()];
		let vencidas = 0;
		let revocadas = 0;
		for (const id of ids) {
			const e = this.nucleo.empresa(id);
			const f = JSON.parse(this.fotos.get(id)!) as Foto;
			e.sistema = f.sistema;
			if (f.comercio) e.comercio = f.comercio;
			if (f.hotel) e.hotel = f.hotel;
			const haceUnaHora = new Date(Date.now() - 3_600_000).toISOString();
			e.clientes = f.clientes.map((c) => ({ ...c, whatsapp: { ...c.whatsapp, ultimaEntrada: haceUnaHora } }));
			e.limites = f.limites ?? undefined;
			e.reglaRevisionAgentes = f.reglaRevisionAgentes;
			vencidas += this.nucleo.vencerPropuestas(id, "sandbox_reset");
			this.nucleo.base(id).cotizaciones.clear();
			this.nucleo.base(id).estadias.clear();
			if (revocarDelegaciones)
				for (const g of this.del.grants.values())
					if (g.tenantId === id && !g.revocado) {
						g.revocado = true;
						revocadas++;
					}
			this.nucleo.evento(id, "-", "sandbox.reset", { revocar_delegaciones: revocarDelegaciones });
		}
		this.nucleo.carriles?.reiniciar();
		this.nucleo.desfaseMs = 0;
		this.cortarRespuestas = 0;
		this.historial.push({ at: new Date().toISOString(), tenant: tenantId ?? "*", cambio: { reset: true, revocar_delegaciones: revocarDelegaciones } });
		return { reiniciadas: ids, propuestas_vencidas: vencidas, delegaciones_revocadas: revocadas };
	}
}

// SIMULATED payment provider (stress-test sandbox). It never moves money: it keeps a ledger of entries
// that the company reconciles. The customer's card or account is registered with the company (in
// SOVRAS, tokenized by its provider): the personal agent never sees or sends payment data.
//
// - Each entry carries its idempotency key: the same key never charges twice, and the company
//   can QUERY by that key when it did not get the response (reconciliation without repeating the charge).
// - Failures are set from /interno/condiciones for the next call:
//   `rechaza` (declined, no effect), `caido` (no connection: nothing was applied),
//   `sin_respuesta` (applied, but the response was lost).
// - `ocultar` simulates contradictory information between systems: the ledger stops showing an entry
//   that did happen (the read-back must notice it and not declare success).

import { randomId } from "./jose.ts";

export type TipoMovimiento = "autorizacion" | "ajuste" | "captura" | "anulacion" | "reembolso";

export type Movimiento = {
	id: string;
	/** Booking or order it belongs to. */
	ref: string;
	tipo: TipoMovimiento;
	/** CLP, integer. An `ajuste` may be negative (releases part of the hold). */
	monto: number;
	estado: "aprobado" | "rechazado";
	idem: string;
	medio: string;
	at: string;
};

export type FallaPago = "rechaza" | "caido" | "sin_respuesta";

export type Pagos = {
	movimientos: Movimiento[];
	/** Failure for the next call with effect (consumed when used). */
	proxima?: FallaPago;
	/** Ids the ledger does not show (contradiction between systems). */
	ocultos?: string[];
	/** The next ledger read hides the latest entry for this reference. */
	ocultarProximo?: boolean;
	llamadas: number;
	consultas: number;
};

export const pagosVacios = (): Pagos => ({ movimientos: [], llamadas: 0, consultas: 0 });

export type ResultadoPago =
	| { estado: "aprobado"; mov: Movimiento }
	| { estado: "rechazado"; mov: Movimiento }
	| { estado: "caido" }
	| { estado: "sin_respuesta" };

/** A call with effect to the provider. The same `idem` returns the entry already made, without repeating it. */
export function mover(p: Pagos, m: { ref: string; tipo: TipoMovimiento; monto: number; idem: string; medio: string }): ResultadoPago {
	p.llamadas += 1;
	const previo = p.movimientos.find((x) => x.idem === m.idem);
	const falla = p.proxima;
	p.proxima = undefined;
	if (falla === "caido") return { estado: "caido" };
	if (previo) return { estado: previo.estado, mov: previo } as ResultadoPago;
	const mov: Movimiento = { id: randomId("pay_", 9), ref: m.ref, tipo: m.tipo, monto: m.monto, estado: falla === "rechaza" ? "rechazado" : "aprobado", idem: m.idem, medio: m.medio, at: new Date().toISOString() };
	p.movimientos.push(mov);
	if (p.ocultarProximo) {
		p.ocultos = [...(p.ocultos ?? []), mov.id];
		p.ocultarProximo = false;
	}
	if (falla === "sin_respuesta") return { estado: "sin_respuesta" };
	return mov.estado === "aprobado" ? { estado: "aprobado", mov } : { estado: "rechazado", mov };
}

/** Query by idempotency key (no effect): what the provider has on record. */
export function consultar(p: Pagos, idem: string): Movimiento | null {
	p.consultas += 1;
	return visibles(p).find((x) => x.idem === idem) ?? null;
}

const visibles = (p: Pagos) => p.movimientos.filter((x) => !(p.ocultos ?? []).includes(x.id));

/** Reconciliation of one reference: current hold, captured and refunded, per the visible ledger. */
export function saldo(p: Pagos, ref: string): { garantia: number; capturado: number; reembolsado: number; movimientos: number } {
	const ms = visibles(p).filter((x) => x.ref === ref && x.estado === "aprobado");
	const suma = (t: TipoMovimiento) => ms.filter((x) => x.tipo === t).reduce((s, x) => s + x.monto, 0);
	const capturado = suma("captura");
	return {
		garantia: suma("autorizacion") + suma("ajuste") - suma("anulacion") - capturado,
		capturado,
		reembolsado: suma("reembolso"),
		movimientos: ms.length,
	};
}

/** Full ledger reconciliation, per reference. What the evidence collector exports. */
export function conciliacion(p: Pagos): Record<string, ReturnType<typeof saldo>> {
	const refs = [...new Set(p.movimientos.map((x) => x.ref))];
	return Object.fromEntries(refs.map((r) => [r, saldo(p, r)]));
}

// Lanes: how much traffic the gateway admits based on what the caller can prove.
//
// - credencial: carries a Poppy, PACT or VXP token (agent identity + customer approval).
// - agente_verificado: verified Web Bot Auth signature (we know which operator it is, not who it acts for).
// - anonimo: nothing verified (browser, unsigned bot, agent pretending to be a person).
//
// A persistent agent breaks nothing: at 3 a.m. or at 4, the lane and its quota are the
// same, and anything beyond receives 429 with Retry-After. Actions with a cost (sending a code over
// WhatsApp) also have their own per-recipient cap.

import { mutado } from "./mutar.ts";

export type Carril = "credencial" | "agente_verificado" | "anonimo";

export const CUPOS: Record<Carril, { capacidad: number; porSegundo: number }> = {
	credencial: { capacidad: 600, porSegundo: 10 },
	agente_verificado: { capacidad: 60, porSegundo: 1 },
	anonimo: { capacidad: 12, porSegundo: 0.2 },
};

/** WhatsApp codes to the same number: a cap within a window (anti-abuse against persistent agents). */
export const TOPE_OTP = { maximo: 3, ventanaMs: 10 * 60_000 };

type Balde = { fichas: number; t: number };

export class Carriles {
	private readonly baldes = new Map<string, Balde>();
	private readonly otp = new Map<string, number[]>();
	readonly rechazos: { at: string; clave: string; carril: Carril }[] = [];

	/** Stress-test sandbox: resets quotas to zero to compare two agents under the same conditions. */
	reiniciar(): void {
		this.baldes.clear();
		this.otp.clear();
	}
	private readonly reloj: () => number;

	constructor(reloj: () => number = () => Date.now()) {
		this.reloj = reloj;
	}

	/** `null` if allowed; otherwise, the seconds to wait. */
	tomar(carril: Carril, clave: string): number | null {
		if (mutado("sin_carriles")) return null;
		const cupo = CUPOS[carril];
		const ahora = this.reloj();
		const k = `${carril}|${clave}`;
		const b = this.baldes.get(k) ?? { fichas: cupo.capacidad, t: ahora };
		b.fichas = Math.min(cupo.capacidad, b.fichas + ((ahora - b.t) / 1000) * cupo.porSegundo);
		b.t = ahora;
		this.baldes.set(k, b);
		if (b.fichas >= 1) {
			b.fichas -= 1;
			return null;
		}
		this.rechazos.push({ at: new Date(ahora).toISOString(), clave: k, carril });
		return Math.ceil((1 - b.fichas) / cupo.porSegundo);
	}

	/** Can another code be sent to this number now? Records the send if so. */
	enviarOtp(telefono: string): boolean {
		if (mutado("sin_tope_otp")) return true;
		const ahora = this.reloj();
		const previos = (this.otp.get(telefono) ?? []).filter((t) => t > ahora - TOPE_OTP.ventanaMs);
		if (previos.length >= TOPE_OTP.maximo) {
			this.otp.set(telefono, previos);
			return false;
		}
		previos.push(ahora);
		this.otp.set(telefono, previos);
		return true;
	}
}

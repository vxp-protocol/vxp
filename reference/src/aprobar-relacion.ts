// VXP Relationship for a present-day Poppy agent: the agent requests it in its conversation («avísame si pasa
// algo, para confirmar o bloquear») and the person approves it on a company page. Same pattern as
// /aprobar, /cambiar and /autorizar: the link reveals nothing until the person identifies with a
// code sent to their registered WhatsApp, and only the customer of the account the agent already has
// linked can approve it. Only then do they see the agreement in business language (actions, cap and validity) and approve it.
// The relationship is bound to the client_id, sub and delegation of that Poppy session, and the company writes to the
// agent inside its conversation (finding with test agent B, Oct 21 06:28: it had no way to discover it).

import { randomInt } from "node:crypto";
import { randomId, sha256 } from "./jose.ts";
import type { CaraNativa } from "./nativo.ts";
import type { Empresa, Nucleo } from "./nucleo.ts";
import { type DetalleRelacion, RAR_RELACION, type Relacion, Relaciones } from "./relacion.ts";

const SEGURIDAD = {
	"content-type": "text/html; charset=utf-8",
	"cache-control": "no-store",
	"content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
	"x-frame-options": "DENY",
	"referrer-policy": "no-referrer",
};
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const norm = (t: string) => t.replace(/[^\d+]/g, "");

function pagina(titulo: string, cuerpo: string, status = 200): Response {
	return new Response(
		`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title>` +
			`<body style="font:16px system-ui;max-width:30rem;margin:2.5rem auto;padding:0 1rem;color:#111">${cuerpo}</body></html>`,
		{ status, headers: SEGURIDAD },
	);
}

/** What the agent requested in its conversation, awaiting the person's approval. */
export type OfertaRelacion = {
	id: string;
	tenantId: string;
	clientId: string;
	agente: string;
	sub: string;
	clienteId: string;
	grantId: string;
	convId: string;
	detalle: DetalleRelacion;
	otpHash: string | null;
	intentos: number;
	estado: "nuevo" | "codigo" | "verificado" | "listo";
	vence: number;
};

export class AprobacionRelacion {
	private readonly nucleo: Nucleo;
	private readonly nativo: CaraNativa;
	readonly ofertas = new Map<string, OfertaRelacion>();
	/** Notifies the agent, in its conversation, that the relationship was created (wired by the gateway). */
	alAprobar: ((o: OfertaRelacion, r: Relacion, acuerdo: string) => void) | null = null;
	/** Whether the session's delegation is still valid (wired by the gateway). */
	grantVigente: (grantId: string) => boolean = () => false;

	constructor(nucleo: Nucleo, nativo: CaraNativa) {
		this.nucleo = nucleo;
		this.nativo = nativo;
	}

	/** The agent requested it: stores the offer and returns the link for the person. */
	ofrecer(e: Empresa, o: Omit<OfertaRelacion, "id" | "detalle" | "otpHash" | "intentos" | "estado" | "vence">, pedidas: string[] = []): { oferta: OfertaRelacion; enlace: string | null } {
		// Only what was requested that the company offers; if the agent named nothing specific, its industry's closed question.
		const ofrecidas = this.nativo.accionesEmpresa(e);
		const calzan = pedidas.filter((a) => ofrecidas.includes(a));
		const acciones = calzan.length ? calzan : ofrecidas.filter((a) => a.startsWith("alerta."));
		const detalle = Relaciones.validar({ type: RAR_RELACION, identifier: "relationship", actions: acciones, limits: { max_per_day: 3, duration_seconds: 30 * 86_400 } }, acciones)!;
		const oferta: OfertaRelacion = { ...o, id: randomId("ofr_", 12), detalle, otpHash: null, intentos: 0, estado: "nuevo", vence: Date.now() + 15 * 60_000 };
		this.ofertas.set(oferta.id, oferta);
		const base = this.nucleo.urlDe(e);
		return { oferta, enlace: base ? `${base}/e/${e.slug}/relacion?o=${oferta.id}` : null };
	}

	async atender(req: Request, e: Empresa, paso: string): Promise<Response> {
		const url = new URL(req.url);
		const titulo = `<h1 style="font-size:1.3rem">${esc(e.nombre)} · acuerdo con tu asistente</h1>`;
		const casillaTelefono = (id: string) =>
			`<form method="post" action="/e/${e.slug}/relacion/telefono"><input type="hidden" name="o" value="${esc(id)}"><label>Tu número de WhatsApp<br><input name="telefono" inputmode="tel" required></label> <button>Enviarme un código</button></form>`;
		if (req.method === "GET" && paso === "") {
			const o = this.ofertas.get(url.searchParams.get("o") ?? "");
			if (!o || o.tenantId !== e.tenantId || o.vence < Date.now()) return pagina("Enlace no válido", "<p>El enlace venció o no es válido. Pídele a tu asistente uno nuevo.</p>", 400);
			return pagina("Acuerdo", `${titulo}<p>Tu asistente pidió un acuerdo para que ${esc(e.nombre)} pueda contactarlo. Para verlo y aprobarlo, confirma que eres tú con un código a tu WhatsApp registrado. Abrir este enlace no aprueba nada.</p>${casillaTelefono(o.id)}`);
		}
		const form = new URLSearchParams(await req.text());
		const o = this.ofertas.get(form.get("o") ?? "");
		if (!o || o.tenantId !== e.tenantId || o.vence < Date.now()) return pagina("Enlace vencido", "<p>Este enlace venció o no es válido. Pídele a tu asistente uno nuevo.</p>", 400);
		const casillaCodigo = `<form method="post" action="/e/${e.slug}/relacion/codigo"><input type="hidden" name="o" value="${esc(o.id)}"><label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>`;

		if (paso === "telefono") {
			const telefono = norm(form.get("telefono") ?? "");
			// Only the customer of the account the agent already has linked can approve its agreement.
			const cliente = e.clientes.find((c) => norm(c.telefono) === telefono && c.id === o.clienteId);
			const tope = cliente && this.nucleo.carriles && !this.nucleo.carriles.enviarOtp(telefono);
			if (cliente && !tope) {
				const otp = String(randomInt(0, 1_000_000)).padStart(6, "0");
				o.otpHash = sha256(`${o.id}:${otp}`);
				o.estado = "codigo";
				this.nucleo.enviarWhatsApp(e.tenantId, cliente, {
					proposito: "autenticacion",
					texto: `${e.nombre}: tu código es ${otp}. Es para ver y aprobar el acuerdo que pidió tu asistente. Si no lo pediste tú, ignóralo.`,
					textoPlantilla: `[plantilla de autenticación] ${otp} es tu código de verificación. Por tu seguridad, no lo compartas.`,
				});
			}
			return pagina("Código enviado", `${titulo}<p>Si ese número es el de la cuenta vinculada a tu asistente, le llegó un código por WhatsApp.</p>${casillaCodigo}`);
		}

		if (paso === "codigo") {
			o.intentos += 1;
			const ok = o.otpHash !== null && o.intentos <= 5 && sha256(`${o.id}:${form.get("codigo") ?? ""}`) === o.otpHash;
			if (!ok) {
				const quedan = Math.max(0, 5 - o.intentos);
				return pagina("Código incorrecto", `${titulo}<p>El código no coincide.${quedan ? ` Te quedan ${quedan} intento${quedan === 1 ? "" : "s"}.` : " Ya no quedan intentos."}</p>${quedan && o.otpHash ? casillaCodigo : ""}`, 400);
			}
			o.otpHash = null;
			o.estado = "verificado";
			const terminos = Relaciones.texto(o.detalle, e.nombre, Boolean(e.hotel));
			return pagina("Acuerdo", `${titulo}<p style="background:#f4f4f4;padding:.6rem;border-radius:.4rem">Asistente: <b>${esc(o.agente)}</b>.<br>Acuerdo: ${esc(terminos)}.<br>Tu asistente sólo puede responder con las opciones que te pregunten; nada más. Puedes revocarlo cuando quieras.</p><p><b>¿Apruebas este acuerdo?</b></p>` +
				`<form method="post" action="/e/${e.slug}/relacion/decision"><input type="hidden" name="o" value="${esc(o.id)}"><button name="decision" value="aprobar">Aprobar</button> <button name="decision" value="rechazar">No</button></form>`);
		}

		if (paso === "decision") {
			if (o.estado === "listo") return pagina("Listo", `${titulo}<p>Ya respondiste esto.</p>`, 409);
			if (o.estado !== "verificado") return pagina("Falta verificar", "<p>Primero verifica tu número.</p>", 400);
			o.estado = "listo";
			if (form.get("decision") !== "aprobar") return pagina("No aprobado", `${titulo}<p>No aprobaste. No se creó ningún acuerdo.</p>`);
			if (!this.grantVigente(o.grantId)) return pagina("Cuenta desconectada", `${titulo}<p>Tu asistente ya no tiene la cuenta vinculada. No se creó ningún acuerdo.</p>`, 409);
			const { relacion, acuerdo } = this.nativo.crearRelacionEnConversacion(e, { clientId: o.clientId, sub: o.sub, clienteId: o.clienteId, grantId: o.grantId }, o.detalle);
			this.alAprobar?.(o, relacion, acuerdo);
			return pagina("Listo", `${titulo}<p>Acuerdo aprobado. ${esc(e.nombre)} sólo podrá contactar a tu asistente para lo que aprobaste, hasta el ${new Date(relacion.expira * 1000).toLocaleDateString("es-CL")}.</p><p style="color:#555">Constancia del acuerdo: ${esc(relacion.id)}. Ya puedes volver a tu asistente.</p>`);
		}
		return pagina("No encontrado", "<p>No encontrado.</p>", 404);
	}
}

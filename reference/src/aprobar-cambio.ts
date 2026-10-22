// Web ramp for changes to an existing order (requested by external agent A on Oct 21: «con la cotización el chat entrega un
// enlace; con el cambio de fecha sólo se niega»).
//
// The link reveals nothing about the order: first the person identifies with a code sent to their registered WhatsApp;
// only then is it checked that the order is theirs and the EXACT terms of the change are shown (the same
// operation with revision and digest that Poppy, PACT and VXP use). They approve or reject; it executes only once.

import { randomInt } from "node:crypto";
import { randomId, sha256 } from "./jose.ts";
import type { ActorExterno, Empresa, Nucleo } from "./nucleo.ts";
import { codigoVisible } from "./prueba.ts";

const SEGURIDAD = {
	"content-type": "text/html; charset=utf-8",
	"cache-control": "no-store",
	"content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
	"x-frame-options": "DENY",
	"referrer-policy": "no-referrer",
};
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const norm = (t: string) => t.replace(/[^\d+]/g, "");
const FECHA = /^\d{4}-\d{2}-\d{2}$/;

function pagina(titulo: string, cuerpo: string, status = 200): Response {
	return new Response(
		`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title>` +
			`<body style="font:16px system-ui;max-width:30rem;margin:2.5rem auto;padding:0 1rem;color:#111">${cuerpo}</body></html>`,
		{ status, headers: SEGURIDAD },
	);
}

type Flujo = { id: string; tenantId: string; pedido: string; fecha: string; clienteId: string | null; otpHash: string | null; intentos: number; estado: "nuevo" | "codigo" | "verificado" | "listo"; vence: number; operacion?: string };

export class AprobacionCambio {
	private readonly nucleo: Nucleo;
	readonly flujos = new Map<string, Flujo>();

	constructor(nucleo: Nucleo) {
		this.nucleo = nucleo;
	}

	/** The link the chat hands out: it reveals nothing about the order. */
	static enlace(urlBase: string, slug: string, pedido: string, fecha: string): string {
		return `${urlBase}/e/${slug}/cambiar?pedido=${encodeURIComponent(pedido)}&fecha=${encodeURIComponent(fecha)}`;
	}

	private actor(e: Empresa, f: Flujo): ActorExterno {
		return { tenantId: e.tenantId, via: "agente_personal", protocolo: "vxp", clientId: "web:aprobacion-cliente", sub: f.clienteId!, clienteId: f.clienteId, alcances: ["pedidos:modificar"], grantId: null };
	}

	async atender(req: Request, e: Empresa, paso: string): Promise<Response> {
		const url = new URL(req.url);
		const titulo = `<h1 style="font-size:1.3rem">${esc(e.nombre)} · aprobar un cambio de tu pedido</h1>`;
		if (req.method === "GET" && paso === "") {
			const pedido = (url.searchParams.get("pedido") ?? "").toUpperCase();
			const fecha = url.searchParams.get("fecha") ?? "";
			if (!/^P-\d{3,}$/.test(pedido) || !FECHA.test(fecha)) return pagina("Enlace no válido", "<p>El enlace no es válido.</p>", 400);
			const f: Flujo = { id: randomId("cam_", 12), tenantId: e.tenantId, pedido, fecha, clienteId: null, otpHash: null, intentos: 0, estado: "nuevo", vence: Date.now() + 15 * 60_000 };
			this.flujos.set(f.id, f);
			return pagina("Aprobar cambio", `${titulo}<p>Para ver y aprobar el cambio de tu pedido, confirma que eres tú con un código que te llega al WhatsApp registrado en ${esc(e.nombre)}. Abrir este enlace no aprueba nada.</p>` +
				`<form method="post" action="/e/${e.slug}/cambiar/telefono"><input type="hidden" name="f" value="${esc(f.id)}"><label>Tu número de WhatsApp<br><input name="telefono" inputmode="tel" required></label> <button>Enviarme un código</button></form>`);
		}
		const form = new URLSearchParams(await req.text());
		const f = this.flujos.get(form.get("f") ?? "");
		if (!f || f.tenantId !== e.tenantId || f.vence < Date.now()) return pagina("Enlace vencido", "<p>Este enlace venció o no es válido. Pídele a tu asistente uno nuevo.</p>", 400);
		const casillaCodigo = `<form method="post" action="/e/${e.slug}/cambiar/codigo"><input type="hidden" name="f" value="${esc(f.id)}"><label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>`;

		if (paso === "telefono") {
			const telefono = norm(form.get("telefono") ?? "");
			const coinciden = e.clientes.filter((c) => norm(c.telefono) === telefono && c.erp);
			const cliente = coinciden.length === 1 ? coinciden[0] : undefined;
			const tope = cliente && this.nucleo.carriles && !this.nucleo.carriles.enviarOtp(telefono);
			if (cliente && !tope) {
				const otp = String(randomInt(0, 1_000_000)).padStart(6, "0");
				f.clienteId = cliente.id;
				f.otpHash = sha256(`${f.id}:${otp}`);
				f.estado = "codigo";
				this.nucleo.enviarWhatsApp(e.tenantId, cliente, {
					proposito: "autenticacion",
					texto: `${e.nombre}: tu código es ${otp}. Es para ver y aprobar un cambio en tu pedido. Si no lo pediste tú, ignóralo.`,
					textoPlantilla: `[plantilla de autenticación] ${otp} es tu código de verificación. Por tu seguridad, no lo compartas.`,
				});
			}
			return pagina("Código enviado", `${titulo}<p>Si ese número es de un cliente de ${esc(e.nombre)}, le llegó un código por WhatsApp.</p>${casillaCodigo}`);
		}

		if (paso === "codigo") {
			f.intentos += 1;
			const ok = f.otpHash !== null && f.intentos <= 5 && sha256(`${f.id}:${form.get("codigo") ?? ""}`) === f.otpHash;
			if (!ok) {
				const quedan = Math.max(0, 5 - f.intentos);
				return pagina("Código incorrecto", `${titulo}<p>El código no coincide.${quedan ? ` Te quedan ${quedan} intento${quedan === 1 ? "" : "s"}.` : " Ya no quedan intentos."}</p>${quedan && f.otpHash ? casillaCodigo : ""}`, 400);
			}
			f.otpHash = null;
			f.estado = "verificado";
			// Only now: does the order belong to this person? The same operation (revision + digest) as through any other path.
			const caso = this.nucleo.abrirCaso(e.tenantId, { clientId: "web:aprobacion-cliente", sub: f.clienteId! });
			const r = this.nucleo.proponerReprogramacion(this.actor(e, f), caso.id, f.pedido, f.fecha, f.id, { binding: "web.customer_change", pedido: f.pedido, fecha: f.fecha });
			if (!r.ok) {
				const motivo = r.falta === "no_encontrado" ? `No encontramos el pedido ${esc(f.pedido)} en tu cuenta.` : r.falta === "en_curso" ? `Ya hay un cambio en curso para el pedido ${esc(f.pedido)}.` : "No se puede proponer ese cambio.";
				f.estado = "listo";
				return pagina("No se puede", `${titulo}<p>${motivo} No se cambió nada.</p>`, 409);
			}
			f.operacion = r.operacion.operation_id;
			return pagina("Aprobar cambio", `${titulo}<p style="background:#f4f4f4;padding:.6rem;border-radius:.4rem">${esc(r.operacion.summary)}</p><p><b>¿Apruebas exactamente este cambio?</b></p>` +
				`<form method="post" action="/e/${e.slug}/cambiar/decision"><input type="hidden" name="f" value="${esc(f.id)}"><button name="decision" value="aprobar">Aprobar el cambio</button> <button name="decision" value="rechazar">No</button></form>`);
		}

		if (paso === "decision") {
			if (f.estado === "listo") return pagina("Listo", `${titulo}<p>Ya respondiste este cambio.</p>`, 409);
			if (f.estado !== "verificado" || !f.operacion) return pagina("Falta verificar", "<p>Primero verifica tu número.</p>", 400);
			f.estado = "listo";
			const op = this.nucleo.base(e.tenantId).operaciones.get(f.operacion)!;
			if (form.get("decision") !== "aprobar") {
				this.nucleo.cancelar(e.tenantId, op);
				return pagina("No aprobado", `${titulo}<p>No aprobaste. No se cambió nada.</p>`);
			}
			await this.nucleo.confirmar(this.actor(e, f), op, op.revision, "user", { canal: "whatsapp", display_code: codigoVisible(op.interno.termsDigest), inbound_text: "código verificado en la página de aprobación de la empresa", provider_message_id: f.id });
			this.nucleo.evento(e.tenantId, op.interno.caseId, "change.customer_approved", { operation_id: op.operation_id, pedido: f.pedido, via: "pagina_de_aprobacion" });
			const fin = op.result?.summary ?? (op.interno.revisionEmpresa ? "Lo revisa una persona de la empresa antes de aplicarlo." : "Listo.");
			return pagina("Listo", `${titulo}<p>${esc(fin)}</p><p style="color:#555">Constancia de la operación: ${esc(op.operation_id)}. Ya puedes volver a tu asistente.</p>`);
		}
		return pagina("No encontrado", "<p>No encontrado.</p>", 404);
	}
}

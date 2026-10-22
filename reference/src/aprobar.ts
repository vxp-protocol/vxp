// Web access ramp: the customer approves an EXACT quote on a company page.
//
// For agents that only browse (they speak neither Poppy, PACT nor VXP): the chat hands them this link and the
// customer opens it. They see the exact terms, identify with a code sent to the WhatsApp the
// company already has on file, and approve or reject. Only then is the order created, with its evidence:
// the approval is recorded as `company_channel` (whoever controls the linked number answered) and bound to
// the terms digest via `display_code`. The agent never receives a permission: only the outcome.

import { randomInt } from "node:crypto";
import { clp, textoCotizacion } from "./comercio.ts";
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

function pagina(titulo: string, cuerpo: string, status = 200): Response {
	return new Response(
		`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title>` +
			`<body style="font:16px system-ui;max-width:30rem;margin:2.5rem auto;padding:0 1rem;color:#111">${cuerpo}</body></html>`,
		{ status, headers: SEGURIDAD },
	);
}

type Flujo = { id: string; tenantId: string; cot: string; rev: number; clienteId: string | null; otpHash: string | null; intentos: number; estado: "nuevo" | "codigo" | "verificado" | "listo"; vence: number; operacion?: string; pedido?: string };

export class AprobacionWeb {
	private readonly nucleo: Nucleo;
	readonly flujos = new Map<string, Flujo>();

	constructor(nucleo: Nucleo) {
		this.nucleo = nucleo;
	}

	async atender(req: Request, e: Empresa, paso: string): Promise<Response> {
		const url = new URL(req.url);
		const form = req.method === "POST" ? new URLSearchParams(await req.text()) : url.searchParams;
		if (req.method === "GET" && paso === "") return this.inicio(e, url.searchParams.get("cot") ?? "", Number(url.searchParams.get("rev")));
		const f = this.flujos.get(form.get("f") ?? "");
		if (!f || f.tenantId !== e.tenantId || f.vence < Date.now()) return pagina("Enlace vencido", "<p>Este enlace venció o no es válido. Pídele a tu asistente o a la empresa una cotización nueva.</p>", 400);
		const cot = this.nucleo.cotizacionDe(e.tenantId, f.cot);
		if (!cot) return pagina("No encontrado", "<p>No encontramos esa cotización.</p>", 404);
		const encabezado = `<h1 style="font-size:1.3rem">${esc(e.nombre)} · aprobar cotización</h1><p style="background:#f4f4f4;padding:.6rem;border-radius:.4rem">${esc(textoCotizacion(cot, e.nombre))}</p>`;

		if (req.method === "POST" && paso === "telefono") {
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
					texto: `${e.nombre}: tu código es ${otp}. Es para aprobar la cotización ${cot.id} por ${clp(cot.total)}. Si no lo pediste tú, ignóralo.`,
					textoPlantilla: `[plantilla de autenticación] ${otp} es tu código de verificación. Por tu seguridad, no lo compartas.`,
				});
			}
			// Same response whether or not the number exists: who is a customer is not revealed.
			return pagina("Código enviado", `${encabezado}<p>Si ese número es de un cliente de ${esc(e.nombre)}, le llegó un código por WhatsApp.</p>` +
				`<form method="post" action="/e/${e.slug}/aprobar/codigo"><input type="hidden" name="f" value="${esc(f.id)}"><label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>`);
		}

		if (req.method === "POST" && paso === "codigo") {
			f.intentos += 1;
			const ok = f.otpHash !== null && f.intentos <= 5 && sha256(`${f.id}:${form.get("codigo") ?? ""}`) === f.otpHash;
			// A mistyped code does not leave the person stuck: they see the input box again and how many attempts remain.
			if (!ok) {
				const quedan = Math.max(0, 5 - f.intentos);
				return pagina("Código incorrecto", `${encabezado}<p>El código no coincide.${quedan ? ` Te quedan ${quedan} intento${quedan === 1 ? "" : "s"}.` : " Ya no quedan intentos: pide un enlace nuevo."}</p>` +
					(quedan && f.otpHash ? `<form method="post" action="/e/${e.slug}/aprobar/codigo"><input type="hidden" name="f" value="${esc(f.id)}"><label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>` : ""), 400);
			}
			f.otpHash = null;
			f.estado = "verificado";
			return pagina("Aprobar", `${encabezado}<p><b>¿Apruebas exactamente estos términos?</b> Al aprobar se crea el pedido a tu nombre. No se cobra nada en línea.</p>` +
				`<form method="post" action="/e/${e.slug}/aprobar/decision"><input type="hidden" name="f" value="${esc(f.id)}">` +
				`<button name="decision" value="aprobar">Aprobar y hacer el pedido</button> <button name="decision" value="rechazar">No</button></form>`);
		}

		if (req.method === "POST" && paso === "decision") {
			if (f.estado === "listo") return pagina("Listo", `${encabezado}<p>Ya respondiste esta aprobación${f.pedido ? `: pedido ${esc(f.pedido)}` : ""}.</p>`, 409);
			if (f.estado !== "verificado" || !f.clienteId) return pagina("Falta verificar", "<p>Primero verifica tu número.</p>", 400);
			f.estado = "listo";
			if (form.get("decision") !== "aprobar") {
				this.nucleo.evento(e.tenantId, cot.caseId, "quote.customer_declined", { cotizacion: cot.id, revision: cot.revision });
				return pagina("No aprobado", `${encabezado}<p>No aprobaste. No se creó ningún pedido.</p>`);
			}
			// The approved terms are those of the revision the person saw on this page.
			if (cot.revision !== f.rev) return pagina("La cotización cambió", `${encabezado}<p>La cotización cambió desde que se te envió el enlace. Pide el enlace nuevo; no se creó nada.</p>`, 409);
			const actor: ActorExterno = { tenantId: e.tenantId, via: "agente_personal", protocolo: "vxp", clientId: "web:aprobacion-cliente", sub: f.clienteId, clienteId: f.clienteId, alcances: ["compras:crear"], grantId: null };
			const r = this.nucleo.proponerCompra(actor, cot.caseId, cot.id, f.id, { binding: "web.customer_approval", cotizacion: cot.id, revision: cot.revision });
			if (!r.ok) return pagina("No se pudo", `${encabezado}<p>No se pudo crear el pedido (${esc(String(r.falta))}). No se creó nada.</p>`, 409);
			const op = r.operacion;
			// The approval came through the channel the company already authenticates: the code reached the registered WhatsApp.
			await this.nucleo.confirmar(actor, op, op.revision, "user", { canal: "whatsapp", display_code: codigoVisible(op.interno.termsDigest), inbound_text: "código verificado en la página de aprobación de la empresa", provider_message_id: f.id });
			f.operacion = op.operation_id;
			f.pedido = (op.result?.data as { pedido?: string } | undefined)?.pedido;
			this.nucleo.evento(e.tenantId, cot.caseId, "quote.customer_approved", { cotizacion: cot.id, revision: cot.revision, operation_id: op.operation_id, pedido: f.pedido ?? null, via: "pagina_de_aprobacion" });
			return pagina("Listo", `${encabezado}<p>${esc(op.result?.summary ?? "Listo.")}</p><p style="color:#555">Constancia de la operación: ${esc(op.operation_id)}. Ya puedes volver a tu asistente.</p>`);
		}
		return pagina("No encontrado", "<p>No encontrado.</p>", 404);
	}

	private inicio(e: Empresa, cotId: string, rev: number): Response {
		const cot = this.nucleo.cotizacionDe(e.tenantId, cotId);
		if (!cot || cot.estado !== "abierta" || Date.parse(cot.vence) < Date.now()) return pagina("No disponible", "<p>Esa cotización no existe, venció o ya se usó.</p>", 404);
		const vigente = Number.isInteger(rev) && rev === cot.revision ? rev : cot.revision;
		const f: Flujo = { id: randomId("apr_", 12), tenantId: e.tenantId, cot: cot.id, rev: vigente, clienteId: null, otpHash: null, intentos: 0, estado: "nuevo", vence: Date.now() + 15 * 60_000 };
		this.flujos.set(f.id, f);
		const aviso = rev && rev !== cot.revision ? `<p style="color:#a33">La cotización cambió: ésta es la revisión ${cot.revision}.</p>` : "";
		return pagina("Aprobar cotización", `<h1 style="font-size:1.3rem">${esc(e.nombre)} · aprobar cotización</h1>${aviso}<p style="background:#f4f4f4;padding:.6rem;border-radius:.4rem">${esc(textoCotizacion(cot, e.nombre))}</p>` +
			`<p>Para aprobarla, confirma que eres tú con un código que te llega al WhatsApp registrado en ${esc(e.nombre)}. Abrir este enlace no aprueba nada.</p>` +
			`<form method="post" action="/e/${e.slug}/aprobar/telefono"><input type="hidden" name="f" value="${esc(f.id)}"><label>Tu número de WhatsApp<br><input name="telefono" inputmode="tel" required></label> <button>Enviarme un código</button></form>`);
	}
}

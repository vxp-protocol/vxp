// Generic web ramp: the person approves an exact hotel operation (book, change dates, cancel,
// add a service) on a company page. Same pattern validated live in commerce
// (/aprobar and /cambiar, Oct 21): the link reveals nothing until the person identifies with a code sent to their
// registered WhatsApp; only then is the operation prepared IN THEIR NAME (revision + digest), the exact terms
// are shown, and they approve or reject. The approval is recorded as `company_channel`. A single execution.

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

/** Which operations can be approved this way and which inputs they accept (nothing else travels in the link). */
const PERMITIDAS: Record<string, string[]> = {
	"reserva.crear": ["estadia"],
	"reserva.modificar_fechas": ["reserva", "llegada", "salida"],
	"reserva.cancelar": ["reserva"],
	"reserva.agregar_servicio": ["reserva", "servicio", "cantidad"],
};

function pagina(titulo: string, cuerpo: string, status = 200): Response {
	return new Response(
		`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title>` +
			`<body style="font:16px system-ui;max-width:30rem;margin:2.5rem auto;padding:0 1rem;color:#111">${cuerpo}</body></html>`,
		{ status, headers: SEGURIDAD },
	);
}

type Flujo = { id: string; tenantId: string; cap: string; inputs: Record<string, string>; clienteId: string | null; otpHash: string | null; intentos: number; estado: "nuevo" | "codigo" | "verificado" | "listo"; vence: number; operacion?: string };

export class AprobacionOperacion {
	private readonly nucleo: Nucleo;
	readonly flujos = new Map<string, Flujo>();

	constructor(nucleo: Nucleo) {
		this.nucleo = nucleo;
	}

	/** The link the chat hands out. It only carries the capability and its allowed inputs. */
	static enlace(urlBase: string, slug: string, cap: string, inputs: Record<string, string>): string | null {
		const claves = PERMITIDAS[cap];
		if (!claves) return null;
		const q = new URLSearchParams({ cap });
		for (const k of claves) if (inputs[k] !== undefined) q.set(k, inputs[k]);
		return `${urlBase}/e/${slug}/autorizar?${q.toString()}`;
	}

	private actor(e: Empresa, f: Flujo): ActorExterno {
		const alcance = e.release.capacidades.find((c) => c.id === f.cap)?.alcance ?? "";
		return { tenantId: e.tenantId, via: "agente_personal", protocolo: "vxp", clientId: "web:aprobacion-cliente", sub: f.clienteId!, clienteId: f.clienteId, alcances: [alcance], grantId: null };
	}

	async atender(req: Request, e: Empresa, paso: string): Promise<Response> {
		const url = new URL(req.url);
		const titulo = `<h1 style="font-size:1.3rem">${esc(e.nombre)} · aprobar</h1>`;
		if (req.method === "GET" && paso === "") {
			const cap = url.searchParams.get("cap") ?? "";
			const claves = PERMITIDAS[cap];
			if (!claves || !e.release.capacidades.some((c) => c.id === cap)) return pagina("Enlace no válido", "<p>El enlace no es válido.</p>", 400);
			const inputs: Record<string, string> = {};
			for (const k of claves) {
				const v = url.searchParams.get(k);
				if (v !== null) inputs[k] = v.slice(0, 40);
			}
			const f: Flujo = { id: randomId("aut_", 12), tenantId: e.tenantId, cap, inputs, clienteId: null, otpHash: null, intentos: 0, estado: "nuevo", vence: Date.now() + 15 * 60_000 };
			this.flujos.set(f.id, f);
			return pagina("Aprobar", `${titulo}<p>Para ver y aprobar lo que pidió tu asistente, confirma que eres tú con un código que te llega al WhatsApp registrado en ${esc(e.nombre)}. Abrir este enlace no aprueba nada.</p>` +
				`<form method="post" action="/e/${e.slug}/autorizar/telefono"><input type="hidden" name="f" value="${esc(f.id)}"><label>Tu número de WhatsApp<br><input name="telefono" inputmode="tel" required></label> <button>Enviarme un código</button></form>`);
		}
		const form = new URLSearchParams(await req.text());
		const f = this.flujos.get(form.get("f") ?? "");
		if (!f || f.tenantId !== e.tenantId || f.vence < Date.now()) return pagina("Enlace vencido", "<p>Este enlace venció o no es válido. Pídele a tu asistente uno nuevo.</p>", 400);
		const casillaCodigo = `<form method="post" action="/e/${e.slug}/autorizar/codigo"><input type="hidden" name="f" value="${esc(f.id)}"><label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>`;

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
					texto: `${e.nombre}: tu código es ${otp}. Es para ver y aprobar lo que pidió tu asistente. Si no lo pediste tú, ignóralo.`,
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
			const caso = this.nucleo.abrirCaso(e.tenantId, { clientId: "web:aprobacion-cliente", sub: f.clienteId! });
			const r = this.nucleo.proponerOperacion(this.actor(e, f), caso.id, f.cap, f.inputs, f.id, { binding: "web.customer_approval", cap: f.cap, inputs: f.inputs });
			if (!r.ok) {
				f.estado = "listo";
				const falta = Array.isArray(r.falta) ? r.falta.join(", ") : r.falta;
				const legible: Record<string, string> = { no_encontrado: "No encontramos eso en tu cuenta.", en_curso: "Ya hay un cambio en curso para esa reserva.", estadia_usada: "Esa cotización ya se usó.", mismas_fechas: "Esas ya son las fechas de la reserva.", reserva_cancelada: "Esa reserva está cancelada." };
				return pagina("No se puede", `${titulo}<p>${esc(legible[falta] ?? `No se puede preparar (${falta}).`)} No se hizo nada.</p>`, 409);
			}
			f.operacion = r.operacion.operation_id;
			return pagina("Aprobar", `${titulo}<p style="background:#f4f4f4;padding:.6rem;border-radius:.4rem">${esc(r.operacion.summary)}</p><p><b>¿Apruebas exactamente esto?</b></p>` +
				`<form method="post" action="/e/${e.slug}/autorizar/decision"><input type="hidden" name="f" value="${esc(f.id)}"><button name="decision" value="aprobar">Aprobar</button> <button name="decision" value="rechazar">No</button></form>`);
		}

		if (paso === "decision") {
			if (f.estado === "listo") return pagina("Listo", `${titulo}<p>Ya respondiste esto.</p>`, 409);
			if (f.estado !== "verificado" || !f.operacion) return pagina("Falta verificar", "<p>Primero verifica tu número.</p>", 400);
			f.estado = "listo";
			const op = this.nucleo.base(e.tenantId).operaciones.get(f.operacion)!;
			if (form.get("decision") !== "aprobar") {
				this.nucleo.cancelar(e.tenantId, op);
				return pagina("No aprobado", `${titulo}<p>No aprobaste. No se hizo nada.</p>`);
			}
			await this.nucleo.confirmar(this.actor(e, f), op, op.revision, "user", { canal: "whatsapp", display_code: codigoVisible(op.interno.termsDigest), inbound_text: "código verificado en la página de aprobación de la empresa", provider_message_id: f.id });
			this.nucleo.evento(e.tenantId, op.interno.caseId, "operation.customer_approved_web", { operation_id: op.operation_id, capability: f.cap, via: "pagina_de_aprobacion" });
			const fin = op.result?.summary ?? (op.interno.revisionEmpresa ? "Lo revisa una persona del hotel antes de aplicarlo." : "Listo.");
			return pagina("Listo", `${titulo}<p>${esc(fin)}</p><p style="color:#555">Constancia de la operación: ${esc(op.operation_id)}. Ya puedes volver a tu asistente.</p>`);
		}
		return pagina("No encontrado", "<p>No encontrado.</p>", 404);
	}
}

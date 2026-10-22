// «Vincular con WhatsApp»: the sign-in step that both protocols leave to the company
// (Poppy 4.6 Device Sign-In; PACT §5.3 «the login step is the Brand's own login»).
//
// The typical Chilean SMB has no identity provider for its customers; what it does have, and the
// operator already runs, is the WhatsApp line where the customer is identified by their number
// (contact identity → canonical customer). Proving that the user controls that number is the
// sign-in. The code is sent over the company's line, never through the personal agent.

import { randomInt } from "node:crypto";
import type { Delegaciones, Dispositivo } from "./identidad.ts";
import { ahora, sha256 } from "./jose.ts";
import { mutado } from "./mutar.ts";
import type { Empresa, Nucleo } from "./nucleo.ts";
import { ALCANCE_RELACION, ETIQUETA_RELACION } from "./relacion.ts";

const SEGURIDAD = {
	"content-type": "text/html; charset=utf-8",
	"cache-control": "no-store",
	"content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
	"x-frame-options": "DENY",
	"referrer-policy": "no-referrer",
};

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function pagina(titulo: string, cuerpo: string, status = 200): Response {
	return new Response(
		`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title>` +
			`<body style="font:16px system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#111">${cuerpo}</body></html>`,
		{ status, headers: SEGURIDAD },
	);
}

const normalizar = (tel: string) => tel.replace(/[^\d+]/g, "");

export async function vincular(nucleo: Nucleo, del: Delegaciones, req: Request, empresa: Empresa, paso: string): Promise<Response> {
	const url = new URL(req.url);
	const form = req.method === "POST" ? new URLSearchParams(await req.text()) : url.searchParams;
	const userCode = (form.get("user_code") ?? "").toUpperCase();
	const d = del.porUserCode(userCode);
	// A code from another company does not exist for this one.
	if (!d || d.tenantId !== empresa.tenantId) return pagina("Código no válido", "<p>El código no es válido o ya venció. Vuelve a tu asistente y pide uno nuevo.</p>", 400);
	if (d.estado !== "pendiente") return pagina("Listo", "<p>Esta solicitud ya fue respondida.</p>", 409);
	const encabezado = `<p><b>${esc(d.clientName)}</b> pide acceso a tu cuenta de <b>${esc(empresa.nombre)}</b>.</p>` +
		(d.detalles ? `<p>Sólo para: ${d.detalles.texto.map(esc).join("; ")}.</p>` : "") +
		`<p style="color:#555">Sigue sólo si tú le pediste a tu asistente que hiciera algo con ${esc(empresa.nombre)}. Código: <b>${esc(d.userCode)}</b></p>`;

	if (req.method === "GET" && paso === "")
		// Opening the link approves nothing (Poppy 4.6).
		return pagina("Vincular cuenta", `${encabezado}<form method="post" action="/e/${empresa.slug}/vincular/telefono">` +
			`<input type="hidden" name="user_code" value="${esc(d.userCode)}"><label>Tu número de WhatsApp<br><input name="telefono" inputmode="tel" required></label> ` +
			`<button>Enviarme un código</button></form>`);

	if (req.method === "POST" && paso === "telefono") {
		const telefono = normalizar(form.get("telefono") ?? "");
		// Do not merge people by coincidence (design 0.1 §5): if two customers share the number,
		// the number alone does not say who it is, and neither is linked this way.
		const coinciden = empresa.clientes.filter((c) => normalizar(c.telefono) === telefono);
		const cliente = coinciden.length === 1 || mutado("telefono_ambiguo") ? coinciden[0] : undefined;
		if (coinciden.length > 1) nucleo.evento(empresa.tenantId, "vincular", "link.ambiguous_identifier", { clientes: coinciden.length });
		// A persistent agent cannot use the page to flood a person with codes: there is a per-number cap.
		// The response is the same (it reveals nothing); the event is logged.
		const tope = cliente && nucleo.carriles && !nucleo.carriles.enviarOtp(telefono);
		if (tope) nucleo.evento(empresa.tenantId, "vincular", "link.otp_rate_limited", { motivo: "tope_por_numero" });
		if (cliente && !tope) {
			const otp = String(randomInt(0, 1_000_000)).padStart(6, "0");
			d.telefono = telefono;
			d.otpHash = sha256(`${d.deviceCode}:${otp}`);
			d.clienteId = cliente.id;
			// The message names the agent and what it asks for: approval happens on a channel the
			// customer already recognizes as the company's (defense against device-code phishing).
			// Round 4 (M5): inside the 24 h window, the text naming the agent is sent; outside it, only
			// Meta's fixed-text authentication template (it names neither the agent nor the permissions: this
			// page shows those before and after the code). Meta sets its actual text; this one is an example.
			// If it cannot be delivered, the response is the same: who is a customer is not revealed.
			nucleo.enviarWhatsApp(empresa.tenantId, cliente, {
				proposito: "autenticacion",
				texto: `${empresa.nombre}: tu código es ${otp}. Es para que ${d.clientName} pueda ${d.detalles ? d.detalles.texto.join("; ") : d.alcancesPedidos.map((a) => empresa.alcances[a] ?? a).join(" y ").toLowerCase()}. Si no lo pediste tú, ignóralo.`,
				textoPlantilla: `[plantilla de autenticación] ${otp} es tu código de verificación. Por tu seguridad, no lo compartas.`,
			});
		}
		// Same response whether or not the number exists: who is a customer is not revealed.
		return pagina("Código enviado", `${encabezado}<p>Si ese número es de un cliente de ${esc(empresa.nombre)}, le llegó un código por WhatsApp.</p>` +
			`<form method="post" action="/e/${empresa.slug}/vincular/codigo"><input type="hidden" name="user_code" value="${esc(d.userCode)}">` +
			`<label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>`);
	}

	if (req.method === "POST" && paso === "codigo") {
		d.intentos += 1;
		const ok = d.otpHash !== null && d.intentos <= 5 && sha256(`${d.deviceCode}:${form.get("codigo") ?? ""}`) === d.otpHash;
		if (!ok) {
			if (d.intentos >= 5) d.estado = "denegado";
			// A mistyped code does not leave the person stuck (found in a live manual test, Oct 21).
			const quedan = Math.max(0, 5 - d.intentos);
			return pagina("Código incorrecto", `${encabezado}<p>El código no coincide.${quedan ? ` Te quedan ${quedan} intento${quedan === 1 ? "" : "s"}.` : " Ya no quedan intentos: pídele a tu asistente un código de vinculación nuevo."}</p>` +
				(quedan && d.otpHash ? `<form method="post" action="/e/${empresa.slug}/vincular/codigo"><input type="hidden" name="user_code" value="${esc(d.userCode)}"><label>Código<br><input name="codigo" inputmode="numeric" required></label> <button>Seguir</button></form>` : ""), 400);
		}
		d.otpHash = null;
		const casillas = d.alcancesPedidos
			.map((a) => `<label style="display:block;margin:.4rem 0"><input type="checkbox" name="scope" value="${esc(a)}" checked> ${esc(a === ALCANCE_RELACION ? ETIQUETA_RELACION : (empresa.alcances[a] ?? a))}</label>`)
			.join("");
		return pagina("Dar acceso", `${encabezado}<form method="post" action="/e/${empresa.slug}/vincular/decision">` +
			`<input type="hidden" name="user_code" value="${esc(d.userCode)}">${casillas}` +
			`<button name="decision" value="allow">Permitir</button> <button name="decision" value="deny">No permitir</button></form>`);
	}

	if (req.method === "POST" && paso === "decision") {
		if (!d.clienteId || d.otpHash !== null) return pagina("Falta verificar", "<p>Primero verifica tu número.</p>", 400);
		if (form.get("decision") !== "allow") {
			d.estado = "denegado";
			return Response.redirect(`${url.origin}/e/${empresa.slug}/vinculado?status=denied`, 303);
		}
		// The boxes the user left checked, never more than what was requested.
		d.alcancesAprobados = form.getAll("scope").filter((a) => d.alcancesPedidos.includes(a));
		if (d.alcancesAprobados.length === 0) {
			d.estado = "denegado";
			return Response.redirect(`${url.origin}/e/${empresa.slug}/vinculado?status=denied`, 303);
		}
		d.estado = "aprobado";
		// Round 4 (M5): linking records the WhatsApp service consent (`communication_consent`,
		// via `form`), with evidence of which agent and which permissions. It is what backs approving
		// terms over the line; it does not back `marketing`.
		nucleo.registrarConsentimientoServicio(empresa.tenantId, d.clienteId, `vinculó ${d.clientName} con ${d.alcancesAprobados.join(" ")}`);
		return Response.redirect(`${url.origin}/e/${empresa.slug}/vinculado?status=approved`, 303);
	}
	return pagina("No encontrado", "<p>No encontrado.</p>", 404);
}

export function vinculado(url: URL): Response {
	const ok = url.searchParams.get("status") === "approved";
	return pagina("Vincular cuenta", ok ? "<p>Listo. Ya puedes volver a tu asistente.</p>" : "<p>No diste acceso. Tu asistente no podrá usar tu cuenta.</p>");
}

/** Device state for token endpoint polling (RFC 8628 §3.5). */
export function sondeo(d: Dispositivo): "authorization_pending" | "slow_down" | "access_denied" | "expired_token" | "listo" {
	const t = ahora();
	if (d.estado === "consumido") return "expired_token";
	if (d.expira < t) return "expired_token";
	if (d.estado === "denegado") return "access_denied";
	if (d.estado === "pendiente") {
		const rapido = t - d.ultimoPoll < d.intervalo - 1;
		d.ultimoPoll = t;
		return rapido ? "slow_down" : "authorization_pending";
	}
	return "listo";
}

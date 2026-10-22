// Agent access over traditional channels (VXP, a SOVRAS-specific capability): WhatsApp, web chat
// and voice. It is not a third protocol: it is what SOVRAS does when an agent arrives the way
// people do.
//
// - Detect: signals that an agent may be writing. A signal NEVER proves identity: there is no
//   verified signature here (the Web Bot Auth header is reported as present, not as valid).
// - Offer the move to a structured, authenticated connection: poppy.json, PACT Agent Card and,
//   experimentally, vxp.json, all on the company's domain. To operate on an account, the
//   customer links it and authorizes specific actions through that path.
// - If the agent does not support it, stay in the channel, limited to what that channel already authorizes: on
//   WhatsApp, the number's identity for reading only, and only if the number belongs to
//   ONE customer; on web chat and voice, public information only. A write requested by a suspected
//   agent is never executed in the channel: it is redirected to the structured connection.
// - With no signals, the message goes to the company's agent like any conversation.

import type { Empresa, Nucleo } from "./nucleo.ts";
import { mutado } from "./mutar.ts";
import type { ResultadoWba } from "./webbotauth.ts";
import { fechaDestino, responder } from "./agente.ts";
import { AprobacionCambio } from "./aprobar-cambio.ts";
import { randomId } from "./jose.ts";
import { clp, disponibilidad, esFecha, textoCancelacion } from "./hotel.ts";

export type Canal = "whatsapp" | "chat_web" | "voz";

export type Entrada = {
	canal: Canal;
	/** WhatsApp: the number. Voice: the calling number (spoofable). Web chat: none. */
	remitente?: string;
	texto: string;
	/** Web chat conversation (the same case across messages). */
	sesion?: string;
	metadatos?: { user_agent?: string; signature_agent?: string; latencia_ms?: number; voz_sintetica?: boolean; web_bot_auth?: ResultadoWba | null };
};

export type Senal = { tipo: string; peso: "fuerte" | "debil"; detalle: string };
export type Deteccion = { probable_agente: boolean; senales: Senal[]; prueba_identidad: false };

const AUTODECLARACION = /\b(soy|habla|le escribe|te escribe)\s+(un|una|el|la|tu|su)?\s*(asistente|agente)\b|\ben (nombre|representaci[oó]n) de\b|\bon behalf of\b|\bAI (assistant|agent)\b|\basistente (de IA|virtual|personal)\b/i;
const PROTOCOLO = /poppy\.json|agent-card|\bA2A\b|\bPACT\b|sovras\.json|\bMCP\b|\bPoppy\b/i;
const UA_AUTOMATIZADO = /bot|agent|headless|python-requests|curl|openai|chatgpt|meta-externalagent|perplexity/i;
// Write on the account = a change verb ON an existing order. Quoting or ordering something new is not one.
const ESCRITURA = /\b(c[aá]mbi|reprogram|cancel|anul|modific|mu[eé]v|mover|posterg|adelant|devol|devuelv|reembols|agreg|añad|anad)/i;
const SOBRE_PEDIDO = /(P-\d{3,}|mi pedido|mis pedidos|mi compra|mi despacho|del pedido|despacho del|R-\d{4}|mi reserva|mis reservas|la reserva|de la reserva)/i;
const LECTURA = /(P-\d{3,}|mi pedido|mis pedidos|estado de|cu[aá]ndo llega|despacho de mi|R-\d{4}|mi reserva|mis reservas)/i;

const norm = (t: string) => t.replace(/[^\d+]/g, "");

export class Canales {
	private readonly nucleo: Nucleo;
	private readonly esquema: string;
	/** Channel conversations: session → case and history (to resume where it left off). */
	readonly sesiones = new Map<string, { tenantId: string; caseId: string; agente?: boolean; turnos: { de: "visita" | "empresa"; texto: string; at: string }[] }>();

	constructor(nucleo: Nucleo, authOrigin: string, _providerOrigin: string) {
		this.nucleo = nucleo;
		this.esquema = new URL(authOrigin).protocol;
	}

	disponibles(e: Empresa): Record<Canal, boolean> {
		return { whatsapp: true, chat_web: true, voz: true, ...(e.canales ?? {}) };
	}

	detectar(m: Entrada): Deteccion {
		const s: Senal[] = [];
		const md = m.metadatos ?? {};
		if (AUTODECLARACION.test(m.texto)) s.push({ tipo: "autodeclaracion", peso: "fuerte", detalle: "el mensaje dice actuar como asistente o en nombre de otro" });
		if (PROTOCOLO.test(m.texto)) s.push({ tipo: "mencion_de_protocolo", peso: "fuerte", detalle: "menciona un protocolo de agentes" });
		// Web Bot Auth: verified = the agent's operator is cryptographically proven (RFC 9421).
		// Even when verified, it identifies the agent's OPERATOR (e.g. chatgpt.com), not the person.
		if (md.web_bot_auth?.verificada) s.push({ tipo: "web_bot_auth_verificada", peso: "fuerte", detalle: `firma RFC 9421 verificada de ${md.web_bot_auth.operador} (llave ${md.web_bot_auth.keyid})` });
		else if (md.signature_agent || md.web_bot_auth) s.push({ tipo: "web_bot_auth_presente", peso: "fuerte", detalle: `cabecera Signature-Agent presente; firma NO verificada${md.web_bot_auth && !md.web_bot_auth.verificada ? ` (${md.web_bot_auth.motivo})` : ""}` });
		if (md.user_agent && UA_AUTOMATIZADO.test(md.user_agent)) s.push({ tipo: "user_agent_automatizado", peso: "debil", detalle: md.user_agent.slice(0, 80) });
		if (typeof md.latencia_ms === "number" && md.latencia_ms < 1500 && m.texto.length > 200) s.push({ tipo: "respuesta_instantanea", peso: "debil", detalle: `${md.latencia_ms} ms para ${m.texto.length} caracteres` });
		if (/^\s*[{[]/.test(m.texto) || m.texto.includes("```")) s.push({ tipo: "formato_estructurado", peso: "debil", detalle: "el mensaje trae datos estructurados" });
		if (md.voz_sintetica) s.push({ tipo: "voz_sintetica_reportada", peso: "debil", detalle: "el proveedor de voz la clasificó como sintética" });
		const fuertes = s.filter((x) => x.peso === "fuerte").length;
		const debiles = s.length - fuertes;
		return { probable_agente: fuertes > 0 || debiles >= 2, senales: s, prueba_identidad: false };
	}

	/** Where to connect in a structured way, on the company's domain. */
	oferta(e: Empresa) {
		const base = `${this.esquema}//${e.dominio}`;
		return {
			poppy: `${base}/.well-known/poppy.json`,
			pact_agent_card: `${base}/.well-known/agent-card.json`,
			vxp_experimental: `${base}/.well-known/vxp.json`,
			account_linking: this.disponibles(e).whatsapp ? "device_authorization_with_whatsapp" : "pending_company_login",
		};
	}

	entrante(e: Empresa, m: Entrada) {
		if (!["whatsapp", "chat_web", "voz"].includes(m.canal) || typeof m.texto !== "string") return { error: "invalid_request" };
		if (!this.disponibles(e)[m.canal]) return { error: "canal_no_disponible" };
		// Insistence: the same sender (or web visitor) has a quota; at 3 or 4 a.m., the same.
		// (Web chat already goes through the gateway lanes, by IP; WhatsApp and voice go here, by sender.)
		const espera = m.canal === "chat_web" ? null : (this.nucleo.carriles?.tomar("anonimo", `${m.canal}:${m.remitente ?? "sin_remitente"}`) ?? null);
		if (espera !== null) return { error: "rate_limited", retry_after: espera };
		const d = this.detectar(m);
		const escritura = ESCRITURA.test(m.texto) && SOBRE_PEDIDO.test(m.texto);
		const lectura = !escritura && LECTURA.test(m.texto);
		this.nucleo.evento(e.tenantId, "-", "channel.message", { canal: m.canal, probable_agente: d.probable_agente, senales: d.senales.map((x) => x.tipo), user_agent: (m.metadatos?.user_agent ?? "").slice(0, 160) });
		// The conversation: same session = same case (quotes and proposals are still there on resume).
		const sesion = m.sesion && this.sesiones.get(m.sesion)?.tenantId === e.tenantId ? m.sesion : randomId("ses_", 12);
		if (!this.sesiones.has(sesion)) this.sesiones.set(sesion, { tenantId: e.tenantId, caseId: this.nucleo.abrirCaso(e.tenantId, { clientId: `canal:${m.canal}`, sub: sesion }).id, turnos: [] });
		const conv = this.sesiones.get(sesion)!;
		// Whoever declared themselves an assistant in this conversation remains one even if the next message does not repeat it.
		if (d.probable_agente) conv.agente = true;
		else if (conv.agente) d.senales.push({ tipo: "sesion_de_agente", peso: "fuerte", detalle: "en esta conversación ya se identificó como asistente" });
		const probable = d.probable_agente || !!conv.agente;
		d.probable_agente = probable;
		conv.turnos.push({ de: "visita", texto: m.texto.slice(0, 2000), at: new Date().toISOString() });
		const empresaDice = (texto: string) => {
			conv.turnos.push({ de: "empresa", texto, at: new Date().toISOString() });
			return texto;
		};
		// The company's agent replies (catalog, quote, negotiation). There is no linked account in the channel:
		// anything that requires an account is requested over the structured connection.
		const anonimo = { tenantId: e.tenantId, via: "agente_personal" as const, protocolo: "vxp" as const, clientId: `canal:${m.canal}`, sub: sesion, clienteId: null, alcances: [], grantId: null };
		if (!d.probable_agente) {
			// There is always a reply: the company's agent says what requires an account (and explains how to authorize).
			// Before, an account query without identifying as an assistant got NO reply (external agent A,
			// hotel, Oct 21 06:48:17: «el chat se quedó pegado»).
			const r = mutado("chat_sin_respuesta") && (escritura || lectura) ? null : responder(this.nucleo, anonimo, conv.caseId, m.texto, sesion);
			return { deteccion: d, derivar: "agente_de_la_empresa", sesion, ...(r ? { respuesta: empresaDice(r.text), datos: r.data ?? null } : {}) };
		}

		const oferta = this.oferta(e);
		const conectar = `Si eres un asistente que actúa por un cliente de ${e.nombre}, conéctate de forma estructurada: ${oferta.poppy} (Poppy) o ${oferta.pact_agent_card} (PACT). Para actuar sobre una cuenta, el cliente debe vincularla y autorizar acciones específicas por esa vía.`;
		// Channel identity: WhatsApp only, and only if the number belongs to ONE customer (no merging by number).
		const clientes = m.canal === "whatsapp" && m.remitente ? e.clientes.filter((c) => norm(c.telefono) === norm(m.remitente!)) : [];
		const identidadCanal = clientes.length === 1 || (mutado("telefono_ambiguo") && clientes.length > 0) ? clientes[0] : null;

		if (escritura && !mutado("escritura_en_canal") && !e.hotel) {
			this.nucleo.evento(e.tenantId, "-", "channel.write_deferred_to_structured", { canal: m.canal });
			// Ramp: as with a quote, the person approves the exact change on a company page
			// (requested by external agent A, Oct 21). The link reveals nothing about the order until the person identifies.
			const pedido = m.texto.match(/\bP-\d{3,}\b/i)?.[0]?.toUpperCase();
			const fecha = fechaDestino(m.texto);
			const enlace = pedido && fecha && this.nucleo.urlDe(e) ? AprobacionCambio.enlace(this.nucleo.urlDe(e)!, e.slug, pedido, fecha) : null;
			const rampa = enlace
				? ` Para que la clienta apruebe el cambio de ${pedido} al ${fecha}, compártele este enlace: ${enlace}. Ahí se identifica con un código a su WhatsApp registrado y ve el cambio exacto antes de aprobarlo. Se puede reprogramar a días hábiles desde el próximo; un corrimiento de más de ${e.diasSinRevision} días lo revisa una persona de la empresa.`
				: pedido ? " Dime a qué fecha quieres cambiarlo (por ejemplo «al 2026-10-28») y te doy un enlace para que la clienta lo apruebe." : "";
			return { deteccion: d, oferta, sesion, en_canal: { lectura: false, escritura: false }, respuesta: empresaDice(`No hago cambios por este canal cuando escribe un asistente.${rampa} ${conectar}`), ...(enlace ? { datos: { aprobacion_url: enlace } } : {}) };
		}
		if (lectura) {
			const erp = identidadCanal?.erp?.id ?? null;
			if (m.canal === "whatsapp" && erp) {
				const pedidos = e.hotel
					? (e.sistema.hotel?.reservas ?? []).filter((x) => x.huespedId === erp).map((x) => `${x.id}: ${x.llegada} → ${x.salida}, ${x.estado}`)
					: e.sistema.pedidos.filter((p) => p.clienteId === erp).map((p) => `${p.id}: despacho ${p.despacho}`);
				return { deteccion: d, oferta, sesion, en_canal: { lectura: true, escritura: false, identidad: "numero_de_whatsapp" }, respuesta: empresaDice(`${pedidos.join("; ") || "No hay pedidos."} ${conectar}`) };
			}
			return { deteccion: d, oferta, sesion, en_canal: { lectura: false, escritura: false }, respuesta: empresaDice(`Por este canal no puedo dar datos de una cuenta a un asistente. ${conectar}`) };
		}
		const r = responder(this.nucleo, anonimo, conv.caseId, m.texto, sesion);
		// Public matters (catalog, quote, negotiation) are answered here; what requires an account, via the structured path.
		const general = !r.data && !r.necesita && /^Hola, soy el agente/.test(r.text);
		const texto = general ? `${e.nombre} atiende ${e.horario}. ${conectar}` : r.necesita ? `${r.text} ${conectar}` : r.text;
		return { deteccion: d, oferta, sesion, en_canal: { lectura: false, escritura: false, cotizacion: !!r.data?.cotizacion }, respuesta: empresaDice(texto), datos: r.data ?? null };
	}

	/** The company's public web chat: the same criteria, with HTTP headers as signals. */
	async chatWeb(req: Request, e: Empresa, wba: ResultadoWba | null = null): Promise<Response> {
		let body: Record<string, unknown> = {};
		const tipo = req.headers.get("content-type") ?? "";
		const crudo = await req.text();
		try {
			body = tipo.includes("application/x-www-form-urlencoded") ? Object.fromEntries(new URLSearchParams(crudo)) : JSON.parse(crudo || "{}");
		} catch {
			body = {};
		}
		const r = this.entrante(e, {
			canal: "chat_web",
			texto: String(body.texto ?? ""),
			sesion: typeof body.sesion === "string" ? body.sesion : undefined,
			metadatos: { user_agent: req.headers.get("user-agent") ?? undefined, signature_agent: req.headers.get("signature-agent") ?? undefined, web_bot_auth: wba },
		});
		// The chat session also goes in a header: the access log uses it to attribute without reading the body.
		const sesionCab: Record<string, string> = "sesion" in r && typeof r.sesion === "string" ? { "x-sovras-sesion": r.sesion } : {};
		if (!tipo.includes("application/json")) {
			const h = this.html(e, r);
			return new Response(h.body, { status: h.status, headers: { ...Object.fromEntries(h.headers), ...sesionCab } });
		}
		return new Response(JSON.stringify(r), { status: "error" in r ? (r.error === "rate_limited" ? 429 : 400) : 200, headers: { "content-type": "application/json", "cache-control": "no-store", ...sesionCab } });
	}

	/**
	 * The hotel's public rates (stress-test sandbox): rooms, services, package and policy; with
	 * `?llegada=AAAA-MM-DD&salida=AAAA-MM-DD&adultos=N`, PMS availability and the direct rate next to
	 * the agency-published one per the SIMULATED channel manager. HTML or JSON (Accept: application/json).
	 */
	paginaTarifas(req: Request, e: Empresa): Response {
		const h = e.hotel;
		if (!h) return new Response(null, { status: 404 });
		const u = new URL(req.url);
		const llegada = u.searchParams.get("llegada");
		const salida = u.searchParams.get("salida");
		const adultos = Math.max(1, Math.min(Number(u.searchParams.get("adultos") ?? 2) || 2, 6));
		const fechas = esFecha(llegada) && esFecha(salida) && salida > llegada;
		const tabla = fechas ? disponibilidad(h, e.sistema.hotel!, llegada, salida, adultos) : null;
		const datos = {
			empresa: e.nombre,
			ficticia: true,
			moneda: "CLP",
			iva_incluido: true,
			habitaciones: h.tipos.map(({ palabras: _p, ...t }) => t),
			servicios: h.servicios.map(({ palabras: _p, ...x }) => x),
			paquetes: h.paquetes.map(({ palabras: _p, ...x }) => x),
			politica: { cancelacion: textoCancelacion(h), recargo_fin_de_semana_pct: h.politica.recargoFinDeSemanaPct, estadia_larga: h.politica.estadiaLarga, check_in: h.politica.checkIn, check_out: h.politica.checkOut, garantia: h.politica.garantia, extranjeros: h.politica.extranjeros },
			agencias: "comparación SIMULADA (channel manager de prueba); no representa a ninguna agencia real",
			...(tabla ? { llegada, salida, adultos, disponibilidad: tabla } : {}),
			reservar: "Escribe en el chat las fechas, cuántas personas y qué habitación; para reservar a nombre de un cliente, el cliente autoriza por la conexión estructurada.",
		};
		this.nucleo.evento(e.tenantId, "-", "channel.rates_view", { con_fechas: !!tabla, user_agent: (req.headers.get("user-agent") ?? "").slice(0, 160) });
		if ((req.headers.get("accept") ?? "").includes("application/json")) return new Response(JSON.stringify(datos), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
		const esc = (s: string) => s.replace(/[&<>"']/g, (x) => `&#${x.charCodeAt(0)};`);
		const filas = h.tipos.map((t) => `<tr><td>${esc(t.nombre)}</td><td style="text-align:right">${t.capacidad}</td><td style="text-align:right">${clp(t.tarifaBase)}</td></tr>`).join("");
		const disp = tabla
			? `<h2>Del ${esc(String(llegada))} al ${esc(String(salida))}, ${adultos} adulto(s)</h2><table style="border-collapse:collapse;width:100%"><tr><th>Habitación</th><th>Libres</th><th>Directo</th>${h.agencias.map((a) => `<th>${esc(a.nombre)}</th>`).join("")}</tr>` +
				tabla.filter((x) => x.apta).map((x) => `<tr><td>${esc(x.nombre)}</td><td style="text-align:right">${x.libres}</td><td style="text-align:right">${x.libres ? clp(x.directa) : "—"}</td>${x.agencias.map((a) => `<td style="text-align:right">${a.total === null ? "—" : clp(a.total)}</td>`).join("")}</tr>`).join("") +
				`</table><p style="color:#555">Las columnas de agencias son una comparación SIMULADA del channel manager de prueba.</p>`
			: `<form method="get"><label>Llegada <input name="llegada" type="date" required></label> <label>Salida <input name="salida" type="date" required></label> <label>Adultos <input name="adultos" type="number" min="1" max="4" value="2"></label> <button>Ver disponibilidad</button></form>`;
		const cuerpo = `<h1>${esc(e.nombre)} · tarifas</h1><p>${esc(h.ubicacion)}. Empresa ficticia de prueba.</p><table style="border-collapse:collapse;width:100%"><tr><th>Habitación</th><th>Personas</th><th>Desde, por noche (IVA incl.)</th></tr>${filas}</table>` +
			`<p>Viernes y sábado +${h.politica.recargoFinDeSemanaPct}%. Estadías de ${h.politica.estadiaLarga.desdeNoches} noches o más: ${h.politica.estadiaLarga.pct}% menos.</p><p>Servicios: ${h.servicios.map((x) => `${esc(x.nombre)} ${clp(x.precio)}`).join("; ")}. Paquete: ${h.paquetes.map((p) => esc(p.nombre)).join("; ")}.</p><p>${esc(textoCancelacion(h))}</p>${disp}<p><a href="chat">Cotizar o reservar en el chat</a></p>`;
		return new Response(`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(e.nombre)} · tarifas</title><body style="font:16px system-ui;max-width:44rem;margin:2rem auto;padding:0 1rem">${cuerpo}</body></html>`, {
			headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" },
		});
	}

	/** Public catalog (HTML for browsers; JSON with Accept: application/json). */
	paginaCatalogo(req: Request, e: Empresa): Response {
		const c = e.comercio;
		if (!c) return new Response(null, { status: 404 });
		const datos = {
			empresa: e.nombre,
			moneda: "CLP",
			iva_incluido: true,
			productos: c.catalogo.map(({ palabras: _p, ...x }) => x),
			descuentos_por_volumen: c.politica.descuentosVolumen,
			despacho: { comunas: c.politica.despacho.comunas, gratis_desde: c.politica.despacho.gratisDesde, dias: "hábiles, de lunes a viernes" },
			pago: c.politica.pago,
			cotizar: "Escribe en el chat qué necesitas, cuántos y a qué dirección y comuna.",
		};
		if ((req.headers.get("accept") ?? "").includes("application/json")) return new Response(JSON.stringify(datos), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
		const esc = (s: string) => s.replace(/[&<>"']/g, (x) => `&#${x.charCodeAt(0)};`);
		const filas = datos.productos.map((p) => `<tr><td>${esc(p.sku)}</td><td>${esc(p.nombre)}</td><td style="text-align:right">$${p.precio.toLocaleString("es-CL")}</td><td style="text-align:right">${p.stock}</td></tr>`).join("");
		const comunas = Object.entries(c.politica.despacho.comunas).map(([k, v]) => `${esc(k)}: $${v.costo.toLocaleString("es-CL")}, ${v.diasHabiles} días hábiles`).join("; ");
		const cuerpo = `<h1>${esc(e.nombre)} · catálogo</h1><table style="border-collapse:collapse;width:100%"><tr><th>SKU</th><th>Producto</th><th>Precio (IVA incl.)</th><th>Stock</th></tr>${filas}</table>` +
			`<p>Descuento por volumen: ${c.politica.descuentosVolumen.map((d) => `${d.pct}% desde ${d.desde} unidades`).join(", ")}.</p><p>Despacho: ${comunas}. Gratis sobre $${c.politica.despacho.gratisDesde.toLocaleString("es-CL")}.</p><p>${esc(c.politica.pago)}</p><p><a href="chat">Cotizar en el chat</a></p>`;
		return new Response(`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(e.nombre)} · catálogo</title><body style="font:16px system-ui;max-width:40rem;margin:2rem auto;padding:0 1rem">${cuerpo}</body></html>`, {
			headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'" },
		});
	}

	/** The chat when the lane throttles: a chat message, the conversation intact and the input box to continue. 429 + Retry-After. */
	paginaEspera(e: Empresa, segundos: number, sesion: string): Response {
		const s = this.sesiones.get(sesion)?.tenantId === e.tenantId ? sesion : undefined;
		const r = this.html(e, { sesion: s, respuesta: `Vas muy rápido. Espera ${segundos} segundo${segundos === 1 ? "" : "s"} y vuelve a escribir; no se perdió nada de la conversación.` }, `Vas muy rápido. Espera ${segundos} segundo${segundos === 1 ? "" : "s"} y vuelve a escribir; no se perdió nada de la conversación.`);
		return new Response(r.body, { status: 429, headers: { ...Object.fromEntries(r.headers), "retry-after": String(segundos) } });
	}

	/** The web chat page (GET): what a browsing person or agent sees. */
	paginaChat(req: Request, e: Empresa, wba: ResultadoWba | null = null): Response {
		const d = this.detectar({ canal: "chat_web", texto: "", metadatos: { user_agent: req.headers.get("user-agent") ?? undefined, signature_agent: req.headers.get("signature-agent") ?? undefined, web_bot_auth: wba } });
		this.nucleo.evento(e.tenantId, "-", "channel.page_view", { canal: "chat_web", probable_agente: d.probable_agente, senales: d.senales.map((x) => x.tipo), user_agent: (req.headers.get("user-agent") ?? "").slice(0, 160) });
		return this.html(e, d.probable_agente ? { deteccion: d, oferta: this.oferta(e), respuesta: `Hola. Si eres un asistente que actúa por un cliente de ${e.nombre}, conéctate de forma estructurada (abajo).` } : { deteccion: d, respuesta: `Hola, ¿en qué te ayudamos?` });
	}

	private html(e: Empresa, r: Record<string, any>, aviso?: string): Response {
		const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
		const senales = (r.deteccion?.senales ?? []).map((s: Senal) => `<li><code>${esc(s.tipo)}</code> — ${esc(s.detalle)}</li>`).join("");
		const oferta = r.oferta ? `<p>Conexión estructurada:</p><ul><li><a href="${esc(r.oferta.poppy)}">poppy.json</a></li><li><a href="${esc(r.oferta.pact_agent_card)}">Agent Card (PACT)</a></li><li><a href="${esc(r.oferta.vxp_experimental)}">vxp.json (VXP, experimental)</a></li></ul>` : "";
		// The conversation is shown in full, both ways: every visitor message and every reply.
		const turnos = r.sesion ? (this.sesiones.get(r.sesion)?.turnos ?? []) : [];
		const burbuja = (de: string, texto: string, fondo: string) => `<p style="background:${fondo};padding:.5rem;border-radius:.4rem"><b>${esc(de)}:</b> ${esc(texto)}</p>`;
		const conversacion = turnos.length
			? turnos.slice(-30).map((t) => burbuja(t.de === "visita" ? "Tú" : e.nombre, t.texto, t.de === "visita" ? "#eef" : "#f4f4f4")).join("")
			: burbuja(e.nombre, String(r.respuesta ?? r.error ?? ""), "#f4f4f4");
		const cuerpo = `<h1>${esc(e.nombre)} · chat</h1>${conversacion}${aviso && turnos.length ? burbuja(e.nombre, aviso, "#fff4e0") : ""}${oferta}` +
			`<form method="post"><input type="hidden" name="sesion" value="${esc(String(r.sesion ?? ""))}"><label>Mensaje<br><input name="texto" required style="width:100%"></label> <button>Enviar</button></form>` +
			(e.hotel ? `<p style="color:#555;font-size:.9rem">Tarifas: <a href="tarifas">ver habitaciones, tarifas y disponibilidad</a></p>` : `<p style="color:#555;font-size:.9rem">Catálogo: <a href="catalogo">ver productos y precios</a></p>`) +
			(senales ? `<details><summary>Lo que vimos de esta visita</summary><ul>${senales}</ul><p>Detectar no prueba identidad.</p></details>` : "");
		return new Response(`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(e.nombre)} · chat</title><body style="font:16px system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem">${cuerpo}</body></html>`, {
			headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" },
		});
	}
}

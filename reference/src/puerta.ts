// The agent gateway: one core, two protocol faces and the «Vincular con WhatsApp» step.
// `crearPuerta` returns a handler (Request → Response) to run under node:http or in process.

import { randomBytes } from "node:crypto";
import { Delegaciones, Directorio, type FetchLike, type PlataformaPact } from "./identidad.ts";
import { type Empresa, Nucleo } from "./nucleo.ts";
import { CaraNativa } from "./nativo.ts";
import { CaraPact } from "./pact.ts";
import { CaraPoppy } from "./poppy.ts";
import { EmisorPruebas } from "./prueba.ts";
import { Canales } from "./canales.ts";
import { RAR_RELACION, Relaciones } from "./relacion.ts";
import { WebBotAuth } from "./webbotauth.ts";
import { AprobacionWeb } from "./aprobar.ts";
import { AprobacionCambio } from "./aprobar-cambio.ts";
import { AprobacionOperacion } from "./aprobar-operacion.ts";
import { AprobacionRelacion } from "./aprobar-relacion.ts";
import { conectarRelacionPoppy } from "./relacion-poppy.ts";
import { type Carril, Carriles } from "./carriles.ts";
import { createHash } from "node:crypto";
import { vincular, vinculado } from "./vincular.ts";
import { Simulador } from "./simulador.ts";
import type { ResultadoWba } from "./webbotauth.ts";
import { conciliacion } from "./pagos.ts";
import { libresNoche, masDias } from "./hotel.ts";
import { mutado } from "./mutar.ts";

/** One request in the access log (sandbox observability; never stores tokens, codes or bodies). */
export type Acceso = {
	seq: number;
	at: string;
	metodo: string;
	ruta: string;
	estado: number | "corte";
	latencia_ms: number;
	ua: string | null;
	ip: string | null;
	carril: Carril | null;
	protocolo: string | null;
	client_id: string | null;
	sub: string | null;
	sesion_chat: string | null;
	wba: { operador: string | null; verificada: boolean; motivo?: string } | null;
	tenant: string | null;
};

export type Config = {
	/** Origin of the authorization server and of the Poppy endpoints (issuer = `${authOrigin}/e/<slug>`). */
	authOrigin: string;
	/** Origin of the PACT Provider (`${providerOrigin}/a2a/<brandId>`). */
	providerOrigin: string;
	empresas: Empresa[];
	/** Companies that offer delegated authority over PACT (PACT Delegated profile). */
	pactDelegada: string[];
	plataformasPact: PlataformaPact[];
	fetch?: FetchLike;
	origenesLocales?: string[];
	/** Lanes and anti-insistence caps. Enabled in production; the contract suites turn them off. */
	carriles?: Carriles | null;
	/** Lifetime of the native pass in seconds (access ramp). */
	ttlPase?: number;
};

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

export function crearPuerta(cfg: Config) {
	// Outcome proof (SPEC §9): one operator key per environment, one per company and one for the
	// log. Each company's issuer is the same one its poppy.json publishes.
	const pruebas = new EmisorPruebas(`${cfg.authOrigin}/sovras/operador`, `${new URL(cfg.authOrigin).host}/sovras/log/v0`);
	// Bindings the company declares in its metadata (SPEC §9.9.1): its brand domain and, if it offers
	// PACT delegation, the interface and authorization server that may cite its block.
	for (const e of cfg.empresas) {
		const iface = `${cfg.providerOrigin}/a2a/${e.tenantId}`;
		pruebas.registrarEmpresa(e.tenantId, `${cfg.authOrigin}/e/${e.slug}`, {
			domains: [e.dominio],
			pact: cfg.pactDelegada.includes(e.tenantId) ? [{ interface: iface, authorization_server: `${iface}/oauth` }] : [],
		});
	}
	const nucleo = new Nucleo(cfg.empresas, pruebas);
	nucleo.carriles = cfg.carriles ?? null;
	nucleo.urlBase = cfg.authOrigin;
	const dir = new Directorio({ fetch: cfg.fetch ?? ((u, i) => fetch(u, i)), origenesLocales: cfg.origenesLocales ?? [] });
	const del = new Delegaciones();
	const poppy = new CaraPoppy(nucleo, dir, del, cfg.authOrigin);
	const salidaHttp = cfg.fetch ?? ((u: string, i?: RequestInit) => fetch(u, i));
	const nativo = new CaraNativa(nucleo, dir, del, cfg.authOrigin, new Relaciones(), salidaHttp, cfg.ttlPase ?? 3600);
	/** Traditional channels (WhatsApp, web chat, voice): detection, structured connection offer and limits. */
	const canales = new Canales(nucleo, cfg.authOrigin, cfg.providerOrigin);
	/** Web Bot Auth (RFC 9421): verifies the signature of agents that identify themselves on the web (e.g. ChatGPT agent). */
	const wba = new WebBotAuth(salidaHttp);
	const aprobacionWeb = new AprobacionWeb(nucleo);
	const aprobacionCambio = new AprobacionCambio(nucleo);
	const aprobacionOperacion = new AprobacionOperacion(nucleo);
	// VXP Relationship for Poppy agents without an inbox: requested and answered in the Poppy conversation.
	const aprobacionRelacion = new AprobacionRelacion(nucleo, nativo);
	aprobacionRelacion.grantVigente = (id) => {
		const g = del.grants.get(id);
		return Boolean(g && !g.revocado && g.expira > Math.floor(Date.now() / 1000));
	};
	conectarRelacionPoppy(nucleo, poppy, nativo, aprobacionRelacion);
	const pact = new CaraPact(nucleo, dir, del, cfg.plataformasPact, cfg.providerOrigin, cfg.authOrigin, new Set(cfg.pactDelegada));
	/** Key for the simulated internal endpoints: only whoever started the test knows it. */
	const llaveInterna = randomBytes(18).toString("base64url");
	/** Condition simulator for the stress-test sandbox (/interno/condiciones and /interno/reset). */
	const simulador = new Simulador(nucleo, del, (t) => nativo.vencerPases(t));
	/** Per-request access log: who (by their credential), through which route, with what result and how fast. */
	const accesos: Acceso[] = [];
	let seqAcceso = 0;
	const meta = new WeakMap<Request, { carril: Carril; wba: ResultadoWba | null }>();

	/** Final state of a company's systems: what the evidence collector exports. */
	function estadoSistemas(tenant: string) {
		const e = nucleo.empresa(tenant);
		const base = nucleo.base(tenant);
		const h = e.hotel;
		const sh = e.sistema.hotel;
		const hoy = new Date().toISOString().slice(0, 10);
		return {
			tenant,
			slug: e.slug,
			nombre: e.nombre,
			dominio: e.dominio,
			issuer: `${cfg.authOrigin}/e/${e.slug}`,
			pedidos: e.sistema.pedidos,
			stock: e.comercio?.catalogo.map((x) => ({ sku: x.sku, nombre: x.nombre, precio: x.precio, stock: x.stock })) ?? null,
			reservas: sh?.reservas ?? null,
			// PMS occupancy over the next 60 days: only nights with rooms taken or blocked.
			inventario: h && sh ? h.tipos.map((t) => ({ tipo: t.codigo, inventario: t.inventario, noches: Array.from({ length: 60 }, (_, i) => masDias(hoy, i)).map((f) => ({ fecha: f, libres: libresNoche(h, sh, t.codigo, f) })).filter((x) => x.libres < t.inventario) })) : null,
			pagos: e.sistema.pagos ? { movimientos: e.sistema.pagos.movimientos, conciliacion: conciliacion(e.sistema.pagos), llamadas: e.sistema.pagos.llamadas, consultas: e.sistema.pagos.consultas } : null,
			devoluciones: e.sistema.devoluciones ?? null,
			cotizaciones: [...base.cotizaciones.values()],
			estadias: [...base.estadias.values()],
			operaciones: [...base.operaciones.values()].map((op) => ({
				operation_id: op.operation_id,
				capability: op.interno.intent.capability,
				inputs: op.interno.intent.inputs,
				state: op.state,
				nativo: op.interno.nativo.estado,
				motivo: op.interno.nativo.motivoFinal,
				revision: op.revision,
				dueno: op.interno.dueno,
				caseId: op.interno.caseId,
				ejecutada: op.interno.ejecutada,
				revision_empresa: op.interno.revisionEmpresa,
				metodo_aprobacion: op.interno.metodoAprobacion,
				efectos: op.interno.nativo.efectos,
				eventos: op.interno.nativo.eventos,
				relacion: op.interno.relacionId ?? null,
				visible: nucleo.visible(op),
			})),
			delegaciones: [...del.grants.values()].filter((g) => g.tenantId === tenant).map((g) => ({ id: g.id, protocolo: g.protocolo, client_id: g.clientId, sub: g.sub, cliente: g.clienteId, alcances: g.alcances, revocado: g.revocado, expira: new Date(g.expira * 1000).toISOString() })),
			relaciones: [...nativo.relaciones.todas.values()].filter((r) => r.tenantId === tenant).map((r) => ({ id: r.id, client_id: r.clientId, sub: r.sub, cliente: r.clienteId, acciones: r.acciones, limites: r.limites, expira: new Date(r.expira * 1000).toISOString(), revocada: r.revocada })),
			condiciones: simulador.estado(tenant),
		};
	}

	async function interno(req: Request, ruta: string[]): Promise<Response> {
		if (req.headers.get("x-sovras-prueba") !== llaveInterna) return new Response(null, { status: 404 });
		const url = new URL(req.url);
		const body = req.method === "POST" ? JSON.parse((await req.text()) || "{}") : {};
		// Stress-test sandbox: access log, companies, conditions and reset (global).
		if (ruta[0] === "accesos") {
			const desde = Number(url.searchParams.get("desde") ?? 0);
			return json(200, { total: accesos.length, accesos: accesos.filter((a) => a.seq > desde) });
		}
		if (ruta[0] === "tenants") return json(200, { tenants: [...nucleo.empresas.values()].map((e) => ({ tenantId: e.tenantId, slug: e.slug, nombre: e.nombre, dominio: e.dominio, issuer: `${cfg.authOrigin}/e/${e.slug}` })) });
		if (ruta[0] === "reset" && req.method === "POST") {
			const t = typeof body.tenant === "string" && body.tenant ? body.tenant : null;
			if (t && !nucleo.empresas.has(t)) return json(404, { error: "tenant" });
			return json(200, simulador.reiniciar(t, body.revocar_delegaciones === true));
		}
		const tenant = String(url.searchParams.get("tenant") ?? body.tenant ?? "");
		if (!nucleo.empresas.has(tenant)) return json(404, { error: "tenant" });
		const base = nucleo.base(tenant);
		// The company's WhatsApp line (simulated): what went out and what the customer replies.
		if (ruta[0] === "whatsapp" && ruta[1] === "salida") return json(200, base.whatsappSalida);
		if (ruta[0] === "whatsapp" && ruta[1] === "entrada") return json(200, { aceptado: await pact.whatsappEntrante(tenant, body.telefono, body.texto) });
		// The company's review inbox (Human Review).
		if (ruta[0] === "revisiones") {
			const pendientes = [...base.operaciones.values()].filter((o) => o.interno.revisionEmpresa?.estado === "pendiente");
			if (req.method === "GET") return json(200, pendientes.map((o) => ({ review_id: o.interno.revisionEmpresa!.id, summary: o.summary, huella: o.interno.huella })));
			const op = await nucleo.decidirRevision(tenant, String(ruta[1]), body.decision);
			return op ? json(200, nucleo.visible(op)) : json(404, { error: "review" });
		}
		if (ruta[0] === "casos") return json(200, { casos: [...base.casos.values()], eventos: base.eventos });
		// The simulated carrier: set its response, later change what it confirms, or read its calls.
		if (ruta[0] === "transportista") {
			const s = nucleo.empresa(tenant).sistema;
			s.transportista ??= { respuesta: {}, confirmado: {}, solicitudes: [], consultas: 0 };
			if (req.method === "POST") {
				if (body.respuesta) Object.assign(s.transportista.respuesta, body.respuesta);
				if (body.confirmado) Object.assign(s.transportista.confirmado, body.confirmado);
			}
			return json(200, s.transportista);
		}
		if (ruta[0] === "limites" && req.method === "POST") {
			nucleo.empresa(tenant).limites = { ...nucleo.limites(tenant), ...body.limites };
			return json(200, nucleo.limites(tenant));
		}
		if (ruta[0] === "pedidos" && req.method === "POST") {
			nucleo.empresa(tenant).sistema.pedidos.push(body.pedido);
			if (body.cliente) nucleo.empresa(tenant).clientes.push(body.cliente);
			return json(200, nucleo.empresa(tenant).sistema.pedidos);
		}
		if (ruta[0] === "feedback") return json(200, base.feedback);
		// VXP Relationship, company side: start an action, revoke (by the person or the
		// company) and view the signed outbox.
		if (ruta[0] === "relaciones") {
			const e = nucleo.empresa(tenant);
			if (ruta[1] === "iniciar" && req.method === "POST") {
				const r = await nativo.iniciarPorEmpresa(e, String(body.relationship_id), String(body.action), body.params ?? {});
				return json(r.status, r.body);
			}
			if (ruta[1] === "revocar" && req.method === "POST") {
				const por = body.by === "empresa" ? "empresa" : "usuario";
				const r = nativo.relaciones.revocar(String(body.relationship_id), por);
				if (r) nucleo.evento(tenant, "-", "relationship.revoked", { relationship: r.id, by: por });
				return r && r.tenantId === tenant ? json(200, { revoked: true }) : json(404, { error: "relationship_not_found" });
			}
			if (ruta[1] === "salida") return json(200, nativo.relaciones.salida.filter((s) => s.tenantId === tenant));
		}
		// Traditional channels: an inbound WhatsApp message or a transcribed call.
		if (ruta[0] === "canal" && ruta[1] === "entrada" && req.method === "POST") return json(200, canales.entrante(nucleo.empresa(tenant), body));
		if (ruta[0] === "webbotauth") return json(200, wba.registro);
		// Test reversibility: the company voids an order born from a purchase (restores stock).
		if (ruta[0] === "anular" && req.method === "POST") {
			const p = nucleo.anularPedido(tenant, String(body.pedido));
			return p ? json(200, { anulado: p.id }) : json(404, { error: "pedido_no_anulable" });
		}
		if (ruta[0] === "catalogo") return json(200, nucleo.empresa(tenant).comercio?.catalogo ?? []);
		// Evidence: an operation's VXP Proof package and its state, to keep it outside the process.
		if (ruta[0] === "prueba") {
			const id = String(url.searchParams.get("op") ?? "");
			const op = nucleo.base(tenant).operaciones.get(id);
			if (!op || !pruebas.tiene(tenant, id)) return json(404, { error: "operacion" });
			return json(200, { operacion: nucleo.visible(op), paquete: pruebas.paquete(tenant, id) });
		}
		if (ruta[0] === "operaciones") return json(200, [...nucleo.base(tenant).operaciones.values()].map((o) => ({ ...nucleo.visible(o), capability: o.interno.intent.capability, dueno: o.interno.dueno, estado_nativo: o.interno.nativo.estado, aprobacion: o.interno.metodoAprobacion })));
		if (ruta[0] === "cotizaciones") return json(200, [...nucleo.base(tenant).cotizaciones.values()]);
		if (ruta[0] === "chat") return json(200, [...canales.sesiones.entries()].filter(([, v]) => v.tenantId === tenant).map(([k, v]) => ({ sesion: k, ...v })));
		if (ruta[0] === "condiciones") {
			if (req.method !== "POST") return json(200, simulador.estado(tenant));
			const r = simulador.aplicar(tenant, body);
			return json("error" in r ? 400 : 200, { ...r, estado: simulador.estado(tenant) });
		}
		if (ruta[0] === "estado") return json(200, estadoSistemas(tenant));
		if (ruta[0] === "paquete") {
			const op = String(url.searchParams.get("op") ?? "");
			return nucleo.pruebas?.tiene(tenant, op) ? json(200, nucleo.pruebas.paquete(tenant, op)) : json(404, { error: "operation_not_found" });
		}
		if (ruta[0] === "sistema") {
			const e = nucleo.empresa(tenant);
			if (req.method === "POST") e.sistema.proximaFalla = body.proximaFalla;
			return json(200, e.sistema.pedidos);
		}
		return new Response(null, { status: 404 });
	}

	/** Which agent the request's credential belongs to, using only what the server already knows (never the body, except the OAuth form's `client_id`). */
	async function quien(req: Request, partes: string[]): Promise<{ protocolo: string; clientId: string | null; sub: string | null } | null> {
		const auth = req.headers.get("authorization") ?? "";
		const [esquema, valor] = auth.split(" ");
		if (esquema === "DPoP" && valor) {
			const n = nativo.quienToken(valor);
			if (n) return { protocolo: "vxp_nativo", ...n };
			const p = poppy.quienToken(valor);
			return p ? { protocolo: "poppy", ...p } : { protocolo: "dpop_token_desconocido", clientId: null, sub: null };
		}
		if (partes[0] === "a2a") {
			const j = pact.quienJwt(auth);
			if (j) return { protocolo: "pact", ...j };
		}
		if (req.method === "POST" && partes[0] === "e" && partes[2] === "oauth") {
			const f = new URLSearchParams(await req.clone().text());
			const c = f.get("client_id");
			if (c) return { protocolo: f.get("resource") ? "vxp_nativo" : "poppy", clientId: c, sub: null };
		}
		return null;
	}

	async function handler(req: Request): Promise<Response> {
		const t0 = performance.now();
		const url = new URL(req.url);
		const partes = url.pathname.split("/").filter(Boolean);
		if (partes[0] === "interno") return atender(req);
		const id = await quien(req, partes).catch(() => null);
		const sesionForm = req.method === "POST" && partes[2] === "chat" ? await req.clone().text().then((t) => (t.trim().startsWith("{") ? String(JSON.parse(t).sesion ?? "") : new URLSearchParams(t).get("sesion") ?? "")).catch(() => "") : "";
		let res = await atender(req);
		// Simulated connection drop: the write was processed, but the response never reaches the agent.
		const escritura = req.method === "POST" && ((partes[0] === "e" && (partes[2] === "v1" || partes[2] === "poppy")) || (partes[0] === "a2a" && url.pathname.endsWith("message:send")));
		let corte = false;
		if (escritura && simulador.cortarRespuestas > 0) {
			simulador.cortarRespuestas -= 1;
			corte = true;
			res = new Response(null, { status: 502, headers: { "x-sovras-corte": "1" } });
		}
		if (!mutado("acceso_sin_registro")) {
			const m = meta.get(req);
			const e = partes[0] === "e" ? nucleo.porSlug(partes[1] ?? "") : partes[0] === "a2a" ? nucleo.empresas.get(decodeURIComponent(partes[1] ?? "")) : [...nucleo.empresas.values()].find((x) => x.dominio.toLowerCase() === url.host.toLowerCase());
			accesos.push({
				seq: ++seqAcceso,
				at: new Date().toISOString(),
				metodo: req.method,
				ruta: url.pathname,
				estado: corte ? "corte" : res.status,
				latencia_ms: Math.round(performance.now() - t0),
				ua: req.headers.get("user-agent")?.slice(0, 200) ?? null,
				ip: req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? null,
				carril: m?.carril ?? null,
				protocolo: id?.protocolo ?? (partes[2] === "chat" ? "chat_web" : null),
				client_id: id?.clientId ?? null,
				sub: id?.sub ?? null,
				sesion_chat: res.headers.get("x-sovras-sesion") ?? (sesionForm || null),
				wba: m?.wba ? { operador: m.wba.operador ?? null, verificada: m.wba.verificada, ...(m.wba.verificada ? {} : { motivo: m.wba.motivo }) } : null,
				tenant: e?.tenantId ?? null,
			});
			if (accesos.length > 50_000) accesos.splice(0, accesos.length - 50_000);
		}
		return res;
	}

	async function atender(req: Request): Promise<Response> {
		const url = new URL(req.url);
		const partes = url.pathname.split("/").filter(Boolean);
		try {
			// Every request carrying a Web Bot Auth signature is verified and logged.
			const firmaAgente = partes[0] === "interno" ? null : await wba.observar(req);
			{
				const cred = req.headers.get("authorization") ?? req.headers.get("x-a2a-user-delegation");
				meta.set(req, { carril: cred ? "credencial" : firmaAgente?.verificada ? "agente_verificado" : "anonimo", wba: firmaAgente });
			}
			// Lanes: whoever presents credentials (token) takes the fast lane; an agent with a verified signature,
			// the middle one; anonymous traffic, the slow one. Same rule at 3 a.m. as at 3 p.m.
			const publica = partes[0] === "a2a" || (partes[0] === "e" && ["chat", "catalogo", "tarifas", "aprobar", "cambiar", "autorizar", "relacion", "vincular", "v1", "poppy", "oauth"].includes(partes[2] ?? ""));
			if (cfg.carriles && publica) {
				const cred = req.headers.get("authorization") ?? req.headers.get("x-a2a-user-delegation");
				const carril: Carril = cred ? "credencial" : firmaAgente?.verificada ? "agente_verificado" : "anonimo";
				const ip = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "local";
				// A verified operator shares one bucket across IPs only if it was explicitly allowed; anyone can publish
				// a key directory, so for the rest the bucket is per operator and IP.
				const clave = carril === "credencial" ? createHash("sha256").update(cred!).digest("base64url").slice(0, 22) : carril === "agente_verificado" && firmaAgente?.verificada ? (wba.confiable(firmaAgente.operador) ? firmaAgente.operador : `${firmaAgente.operador}|${ip}`) : ip;
				const espera = cfg.carriles.tomar(carril, clave);
				if (espera !== null) {
					// In the web chat (form), the writer sees a chat message and keeps their input box and
					// conversation (found by external agent A: before, they saw raw JSON and lost the box). The API gets JSON.
					const enChat = partes[2] === "chat" && req.method === "POST" && !(req.headers.get("content-type") ?? "").includes("application/json");
					if (enChat) {
						const e = nucleo.porSlug(partes[1] ?? "");
						const sesion = new URLSearchParams(await req.text()).get("sesion") ?? "";
						if (e) return canales.paginaEspera(e, espera, sesion);
					}
					return json(429, { error: "rate_limited", lane: carril, retry_after: espera }, { "retry-after": String(espera) });
				}
			}
			// poppy.json is served on the company's subdomain (CNAME to SOVRAS).
			if (url.pathname === "/.well-known/poppy.json") {
				const e = [...nucleo.empresas.values()].find((x) => x.dominio.toLowerCase() === url.host.toLowerCase());
				return e ? json(200, poppy.poppyJson(e), { "cache-control": "max-age=300" }) : new Response(null, { status: 404 });
			}
			// PACT §2.1: the standard location of the Agent Card is the brand domain, which serves it or redirects
			// to the provider URL. This is what anchors the proof under PACT (SPEC §9.9.1, brand anchor).
			// Native VXP profile (design 0.1 §3.A), on the same company domain.
			if (url.pathname === "/.well-known/vxp.json") {
				const e = [...nucleo.empresas.values()].find((x) => x.dominio.toLowerCase() === url.host.toLowerCase());
				return e ? json(200, nativo.sovrasJson(e), { "cache-control": "max-age=300" }) : new Response(null, { status: 404 });
			}
			if (url.pathname === "/.well-known/agent-card.json") {
				const e = [...nucleo.empresas.values()].find((x) => x.dominio.toLowerCase() === url.host.toLowerCase());
				return e ? new Response(null, { status: 302, headers: { location: `${cfg.providerOrigin}/a2a/${e.tenantId}/.well-known/agent-card.json` } }) : new Response(null, { status: 404 });
			}
			// RFC 8414 §3.1 for each brand's PACT authorization server (issuer `{iface}/oauth`).
			if (url.pathname.startsWith("/.well-known/oauth-authorization-server/a2a/")) {
				const e = nucleo.empresas.get(decodeURIComponent(partes[3] ?? ""));
				return e && partes.length === 5 && partes[4] === "oauth" ? pact.metadataAs(e) : new Response(null, { status: 404 });
			}
			// RFC 8414 §3.1: the issuer path goes after the well-known segment.
			if (url.pathname.startsWith("/.well-known/oauth-authorization-server/e/")) {
				const e = nucleo.porSlug(partes[3]);
				if (!e || partes.length !== 4) return new Response(null, { status: 404 });
				const m = poppy.metadata(e);
				// VXP Relationship: the relationship's RAR type and the key the company signs what it initiates with,
				// anchored to the issuer just like the proof (RFC 8414 §2, additional parameters).
				return json(200, {
					...m,
					authorization_details_types_supported: [...m.authorization_details_types_supported, RAR_RELACION],
					vxp_relationship: { version: "0.1", jwks_uri: `${m.issuer}/vxp/relationship-jwks.json`, company_initiated_actions: nativo.accionesEmpresa(e) },
				});
			}
			// Public proof material: operator and log JWKS, checkpoint and consistency.
			if (partes[0] === "sovras" && req.method === "GET") {
				const ruta = partes.slice(1).join("/");
				if (ruta === "operador/proof-jwks.json") return json(200, pruebas.jwksOperador(), { "cache-control": "max-age=300" });
				if (ruta === "log/jwks.json") return json(200, pruebas.jwksRegistro(), { "cache-control": "max-age=300" });
				if (ruta === "log/checkpoint") return new Response(pruebas.checkpoint(), { headers: { "content-type": "application/jwt", "cache-control": "no-store" } });
				if (ruta === "log/consistency") {
					const first = Number(url.searchParams.get("first"));
					const second = Number(url.searchParams.get("second"));
					const path = pruebas.consistencia(first, second);
					return path ? json(200, { first, second, path }) : json(400, { error: "invalid_request" });
				}
				return new Response(null, { status: 404 });
			}
			if (partes[0] === "e") {
				const e = nucleo.porSlug(partes[1] ?? "");
				if (!e) return json(404, { error: "not_found" });
				const [zona, recurso, ...resto] = partes.slice(2);
				if (zona === "vincular" && recurso === "inicio")
					return new Response(`<!doctype html><meta charset="utf-8"><p>Para vincular tu cuenta de ${e.nombre}, pídele a tu asistente el código de vinculación.</p>`, {
						headers: { "content-type": "text/html; charset=utf-8", "x-frame-options": "DENY" },
					});
				if (zona === "vincular") return vincular(nucleo, del, req, e, recurso ?? "");
				if (zona === "vinculado") return vinculado(url);
				if (zona === "oauth" && req.method === "POST") {
					// A single authorization server per issuer (RFC 8414). Native mode is distinguished by
					// `resource` = its endpoint (RFC 8707); everything else is still Poppy, unchanged.
					if (recurso === "token" || recurso === "device") {
						const texto = await req.text();
						const form = new URLSearchParams(texto);
						const copia = new Request(req.url, { method: "POST", headers: req.headers, body: texto });
						if (form.get("resource") === nativo.endpoint(e)) return recurso === "token" ? nativo.token(copia, e, form) : nativo.device(e, form);
						if (recurso === "token") return poppy.token(copia, e);
						return poppy.device(copia, e);
					}
					if (recurso === "revoke") return poppy.revoke(req, e);
				}
				if (zona === "v1") return nativo.atender(req, e, [recurso ?? "", ...resto].filter(Boolean));
				if (zona === "poppy" && recurso === "conversaciones") return poppy.conversaciones(req, e, resto);
				if (zona === "poppy" && recurso === "operaciones") return poppy.operaciones(req, e, resto);
				if (zona === "poppy" && recurso === "feedback" && req.method === "POST") return poppy.feedback(req, e);
				if (zona === "sovras" && recurso === "proof-jwks.json" && req.method === "GET")
					return json(200, pruebas.jwksEmpresa(e.tenantId), { "cache-control": "max-age=300" });
				if (zona === "sovras" && recurso === "proof") return poppy.prueba(req, e, resto);
				if (zona === "vxp" && recurso === "relationship-jwks.json" && req.method === "GET")
					return json(200, nativo.relaciones.jwks(e.tenantId), { "cache-control": "max-age=300" });
				// The company's web chat (traditional channel): usable by a person or an agent.
				if (zona === "chat" && req.method === "POST") return canales.chatWeb(req, e, firmaAgente);
				if (zona === "chat" && req.method === "GET") return canales.paginaChat(req, e, firmaAgente);
				if (zona === "catalogo" && req.method === "GET") return canales.paginaCatalogo(req, e);
				// Web ramp: the customer approves an exact quote (code sent to their registered WhatsApp).
				if (zona === "aprobar") return aprobacionWeb.atender(req, e, recurso ?? "");
				if (zona === "cambiar") return aprobacionCambio.atender(req, e, recurso ?? "");
				if (zona === "autorizar") return aprobacionOperacion.atender(req, e, recurso ?? "");
				if (zona === "relacion") return aprobacionRelacion.atender(req, e, recurso ?? "");
				if (zona === "tarifas" && req.method === "GET") return canales.paginaTarifas(req, e);
				return json(404, { error: "not_found" });
			}
			if (partes[0] === "a2a" && partes[1]) {
				const e = nucleo.empresas.get(decodeURIComponent(partes[1]));
				const ruta = url.pathname.split("/").slice(3).join("/");
				return pact.atender(req, e, ruta);
			}
			if (partes[0] === "interno") return interno(req, partes.slice(1));
			return new Response(null, { status: 404 });
		} catch (err) {
			console.error("[puerta]", err);
			return json(500, { error: "server_error" });
		}
	}

	return { handler, nucleo, del, pact, poppy, nativo, canales, wba, carriles: cfg.carriles ?? null, pruebas, llaveInterna, simulador, accesos };
}

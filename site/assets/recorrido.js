// Walkthrough of one VXP operation in seven steps. The objects come from recorrido-data.js (a real capture of
// the native profile); this file only decides what is drawn and which field is highlighted in each step.
// Each step is told first in plain language; the technical messages and objects open only when the visitor
// asks. Visible texts live in TEXTOS, one set per language, chosen by <html lang>.
// Captured objects are not translated.
import { RECORRIDO } from "./recorrido-data.js";

const ACTORES = { person: { x: 70 }, agent: { x: 290 }, company: { x: 510 }, system: { x: 700 } };
const LINKS = ["request", "terms", "user_approval", "execution", "read_back", "outcome"];
const step = (id) => RECORRIDO.steps.find((s) => s.id === id);

// Structure of each step, shared by all languages. flows: [from, to, return]; paths: [path, state].
// State per entry path, from 02-ARQUITECTURA-EDITORIAL.md §3.
const PASOS = [
	{
		id: "discover",
		flows: [["agent", "company"], ["company", "agent", true]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "suite"]],
		value: () => step("discover").response,
		keys: ["protocol", "issuer", "endpoint", "id", "commitment_modes", "outcome_proof", "status"],
	},
	{
		id: "identify",
		flows: [["agent", "company"], ["company", "agent", true]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "suite"]],
		value: () => ({ request: step("identify").form, headers: step("identify").headers, response: step("identify").response }),
		keys: ["grant_type", "client_assertion_type", "DPoP", "token_type"],
	},
	{
		id: "authority",
		flows: [["agent", "company"], ["company", "agent", true], ["company", "person"], ["person", "company"], ["company", "agent", true]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "own"]],
		value: () => ({ request: step("authority").body, response: step("authority").response, token: { authorization_details: step("authority").token.authorization_details } }),
		keys: ["state", "error", "identifier", "authorization_details", "device_authorization_endpoint", "type"],
	},
	{
		id: "context",
		flows: [["agent", "company"], ["company", "agent", true]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "suite"]],
		value: () => step("context").response,
		keys: ["request_id", "state", "poppy", "a2a"],
	},
	{
		id: "operate",
		flows: [["company", "agent", true], ["agent", "person"], ["person", "agent"], ["agent", "company"], ["company", "system"]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "own"]],
		value: () => ({ proposal: step("operate").proposal, accept: step("operate").body }),
		keys: ["revision", "despacho_nuevo", "commitment", "mode", "user_approval_required", "approved_by"],
		chain: 3,
	},
	{
		id: "prove",
		flows: [["company", "system"], ["system", "company", true], ["company", "agent", true]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "own"]],
		value: () => ({ response: step("prove").response, verdict: step("prove").verdict }),
		keys: ["state", "reason", "applied", "valid", "final_state", "approval", "single_root", "logged"],
		chain: 6,
	},
	{
		id: "relate",
		flows: [["company", "agent"], ["agent", "person"], ["person", "agent"], ["agent", "company"]],
		paths: [["native", "tested"], ["poppy", "live"], ["pact", "pending"]],
		value: () => ({ relationship: step("relate").relationship, delivery: step("relate").outbox, after_accept: step("relate").accepted }),
		keys: ["relationship_id", "actions", "max_per_day", "expires_at", "agreement", "delivery", "state", "reason"],
		chain: 6,
	},
];

// Per step: title; say and flows in plain language (always shown); tech and wire with the real messages
// (shown on request); detail for each path (in the order of paths, empty if none) and the object's title.
const TEXTOS = {
	en: {
		actors: { person: "Person", agent: "Personal agent", company: "Company", system: "Company system" },
		ways: { native: "Native", poppy: "Poppy draft 0.2", pact: "PACT 1.0" },
		states: { tested: "tested", live: "live agent", suite: "official suite", own: "own test", pending: "pending" },
		pause: "Pause", play: "Play", first: "first", none: "—",
		techOpen: "Show the messages and objects", techClose: "Hide the messages and objects",
		pathsLabel: "Status of this step by entry path",
		statements: (n) => `${n} signed statements`,
		attempt: (n) => `attempt ${n}`,
		matches: "matches", mismatch: "mismatch", valid: "Valid", invalid: "Invalid",
		steps: {
			discover: {
				title: "Discover",
				say: "The agent finds the company on the company's own website and reads what it offers: which requests it takes from agents, which ones need the person's permission, and which ones leave a signed record.",
				flows: ["what do you offer?", "operations and their rules"],
				tech: "The agent reads /.well-known/vxp.json on the company's domain: the issuer, the endpoint, each capability with its access and admission, and whether it leaves proof.",
				wire: ["GET /.well-known/vxp.json", "capabilities, issuer, endpoint"],
				extras: ["", "poppy.json", "Agent Card"],
				obj: "GET /.well-known/vxp.json",
			},
			identify: {
				title: "Identify",
				say: "The agent shows who it is, with a key only it holds. The company now knows which agent is asking, but not yet what that agent may do.",
				flows: ["this is me, signed", "a session tied to my key"],
				tech: "The agent signs in with its own key (private_key_jwt over its client metadata) and binds the token to a key only it holds (DPoP). Identity says who the agent is, nothing yet about what it may do.",
				wire: ["token request · signed assertion + DPoP", "token_type: DPoP"],
				extras: [],
				obj: "POST …/oauth/token",
			},
			authority: {
				title: "Authority",
				say: "The agent asks to move the delivery of order P-1042. The company answers that it needs the person's permission for that order. On the company's page, the person links their account with a code the company sends to their phone, and allows that one order.",
				flows: ["move the delivery of P-1042", "needs the person's permission", "code to link the account", "allows order P-1042", "permission for P-1042"],
				tech: "Asking without permission returns authorization_required with the exact authorization_details missing. The agent starts a device authorization (RFC 8628). On the company's linking page the person confirms with a code sent to the phone linked at the company, and grants the order and, in the same consent, the relationship of step 7. The token comes back with the details granted.",
				wire: ["POST /v1/requests", "202 authorization_required", "linking page · code to the phone", "allow · per-order RAR", "token · authorization_details"],
				extras: ["per-order RAR", "scopes", "delegated grant"],
				obj: "POST …/v1/requests → 202, then the token",
			},
			context: {
				title: "Context",
				say: "With permission in hand, the agent asks again. The company recognizes the same request and continues it, instead of starting a new one.",
				flows: ["the same request, again", "same request, continued"],
				tech: "The agent repeats the same request with the same Idempotency-Key. The company re-evaluates it with the new token and continues the same request_id, now proposed.",
				wire: ["same request · same Idempotency-Key", "same request_id, now proposed"],
				extras: ["request_id + events", "conversation", "contextId"],
				obj: "POST …/v1/requests → 201",
			},
			operate: {
				title: "Operate",
				say: "The company proposes exact terms: delivery on 28 October instead of 24, at no cost. The agent accepts them and tells the company the person agrees; the record notes that it was the agent who said so. Then the change runs once.",
				flows: ["exact terms, revision 1", "here are the terms", "agreed", "accept revision 1", "change it, once"],
				tech: "The company signs revision 1 with the exact terms and a firm commitment. The agent accepts it with approved_by: user, and the proof records that approval as agent_asserted: the agent's statement, not a confirmation through the company's channel. It runs once, under the company's own rules and the operation requirements O1 to O7.",
				wire: ["signed proposal, revision 1", "exact terms", "approve", "accept revision 1", "execute once"],
				extras: ["", "Operations", "A2A task"],
				obj: "Proposal, then POST …/proposals/{id}/accept",
			},
			prove: {
				title: "Proof",
				say: "After the change, the company reads its own system. Only if what it reads matches what was agreed does the operation count as done. The agent receives a signed record of every step.",
				flows: ["read it back", "P-1042 ships on 28 Oct", "result + signed record"],
				tech: "Only a read-back that matches the approved terms yields succeeded (P5). The signed chain of six statements goes to the agent, and a verifier that shares no code with the issuer checks it.",
				wire: ["read back", "P-1042 ships 2026-10-28", "result + signed chain"],
				extras: ["", "proof in the operation", "proof next to pact.receipt"],
				obj: "Result and the verifier's verdict",
			},
			relate: {
				title: "Relationship",
				say: "Because the person also allowed it, the company can now come to the agent: it proposes moving another order, within the actions, the daily limit and the time the person agreed to. The agent answers within that.",
				flows: ["company proposes a change", "proposed change", "agreed", "accept"],
				tech: "With the relationship granted in the same consent, the company signs a request (vxp-company-request+jwt) and delivers it to the agent's HTTP inbox; the proposal is a normal operation with its own proof. Revoking the delegation ends the relationship.",
				wire: ["company request (signed)", "proposed change", "approve", "accept"],
				extras: ["HTTP inbox, experimental", "in the conversation"],
				obj: "Relationship from the token, then the company's request",
			},
		},
	},
	es: {
		actors: { person: "Persona", agent: "Agente personal", company: "Empresa", system: "Sistema interno" },
		ways: { native: "Nativo", poppy: "Poppy draft 0.2", pact: "PACT 1.0" },
		states: { tested: "probado", live: "agente en vivo", suite: "suite oficial", own: "prueba propia", pending: "pendiente" },
		pause: "Pausa", play: "Reproducir", first: "primera", none: "–",
		techOpen: "Ver los mensajes y objetos", techClose: "Ocultar los mensajes y objetos",
		pathsLabel: "Estado de este paso por vía de entrada",
		statements: (n) => `${n} declaraciones firmadas`,
		attempt: (n) => `intento ${n}`,
		matches: "calza", mismatch: "no calza", valid: "Válida", invalid: "No válida",
		steps: {
			discover: {
				title: "Descubrir",
				say: "El agente encuentra a la empresa en su propio sitio y lee lo que ofrece: qué solicitudes recibe de agentes, cuáles requieren el permiso de la persona y cuáles dejan un registro firmado.",
				flows: ["¿qué ofreces?", "operaciones y sus reglas"],
				tech: "El agente lee /.well-known/vxp.json en el dominio de la empresa: el issuer, el endpoint, cada capacidad con su acceso y admisión, y si deja constancia.",
				wire: ["GET /.well-known/vxp.json", "capabilities, issuer, endpoint"],
				extras: ["", "poppy.json", "Agent Card"],
				obj: "GET /.well-known/vxp.json",
			},
			identify: {
				title: "Identificarse",
				say: "El agente muestra quién es, con una llave que sólo él tiene. La empresa ya sabe qué agente pregunta, pero todavía no qué puede hacer.",
				flows: ["soy yo, firmado", "sesión amarrada a mi llave"],
				tech: "El agente se autentica con su propia llave (private_key_jwt sobre sus metadatos de cliente) y amarra el token a una llave que sólo él tiene (DPoP). La identidad dice quién es el agente; todavía no dice qué puede hacer.",
				wire: ["pide token · aserción firmada + DPoP", "token_type: DPoP"],
				extras: [],
				obj: "POST …/oauth/token",
			},
			authority: {
				title: "Autoridad",
				say: "El agente pide cambiar el despacho del pedido P-1042. La empresa responde que necesita el permiso de la persona para ese pedido. En la página de la empresa, la persona vincula su cuenta con un código que la empresa le envía al teléfono, y permite ese pedido puntual.",
				flows: ["cambiar el despacho de P-1042", "falta el permiso de la persona", "código para vincular la cuenta", "permite el pedido P-1042", "permiso para P-1042"],
				tech: "Si pide sin permiso, recibe authorization_required con el authorization_details exacto que le falta. El agente inicia una autorización de dispositivo (RFC 8628). En la página de vinculación de la empresa, la persona confirma con un código enviado al teléfono vinculado en la empresa, y otorga el pedido y, en el mismo consentimiento, la relación del paso 7. El token vuelve con lo otorgado.",
				wire: ["POST /v1/requests", "202 authorization_required", "página de vinculación · código al teléfono", "permite · RAR por pedido", "token · authorization_details"],
				extras: ["RAR por pedido", "scopes", "grant delegado"],
				obj: "POST …/v1/requests → 202, y luego el token",
			},
			context: {
				title: "Contexto",
				say: "Con el permiso, el agente vuelve a pedir. La empresa reconoce la misma solicitud y la continúa, en vez de abrir una nueva.",
				flows: ["la misma solicitud, otra vez", "misma solicitud, continúa"],
				tech: "El agente repite la misma solicitud con la misma Idempotency-Key. La empresa la reevalúa con el token nuevo y continúa el mismo request_id, ahora proposed.",
				wire: ["misma solicitud · misma Idempotency-Key", "mismo request_id, ahora proposed"],
				extras: ["request_id + eventos", "conversación", "contextId"],
				obj: "POST …/v1/requests → 201",
			},
			operate: {
				title: "Operar",
				say: "La empresa propone términos exactos: despacho el 28 de octubre en vez del 24, sin costo. El agente los acepta y le dice a la empresa que la persona está de acuerdo; el registro anota que fue el agente quien lo dijo. Entonces el cambio se ejecuta una sola vez.",
				flows: ["términos exactos, revisión 1", "estos son los términos", "de acuerdo", "acepta la revisión 1", "cámbialo, una vez"],
				tech: "La empresa firma la revisión 1 con los términos exactos y un compromiso firm. El agente la acepta con approved_by: user, y la constancia registra esa aprobación como agent_asserted: lo afirma el agente, no es una confirmación por el canal de la empresa. Se ejecuta una sola vez, con las reglas de la propia empresa y los requisitos de operación O1 a O7.",
				wire: ["propuesta firmada, revisión 1", "términos exactos", "aprueba", "acepta la revisión 1", "ejecuta una vez"],
				extras: ["", "Operations", "tarea A2A"],
				obj: "Propuesta, y luego POST …/proposals/{id}/accept",
			},
			prove: {
				title: "Proof",
				say: "Después del cambio, la empresa lee su propio sistema. Sólo si lo que lee calza con lo acordado, la operación cuenta como hecha. El agente recibe un registro firmado de cada paso.",
				flows: ["vuelve a leer", "P-1042 sale el 28 oct", "resultado + registro firmado"],
				tech: "Sólo una relectura que calza con los términos aprobados da succeeded (P5). La cadena firmada de seis declaraciones llega al agente, y la revisa un verificador que no comparte código con el emisor.",
				wire: ["relectura", "P-1042 sale el 2026-10-28", "resultado + cadena firmada"],
				extras: ["", "constancia en la operación", "constancia junto a pact.receipt"],
				obj: "Resultado y veredicto del verificador",
			},
			relate: {
				title: "Relationship",
				say: "Como la persona también lo permitió, ahora la empresa puede ir al agente: propone cambiar otro pedido, dentro de las acciones, el límite diario y el plazo que la persona aceptó. El agente responde dentro de eso.",
				flows: ["la empresa propone un cambio", "cambio propuesto", "de acuerdo", "acepta"],
				tech: "Con la relación otorgada en el mismo consentimiento, la empresa firma una solicitud (vxp-company-request+jwt) y la entrega en el inbox HTTP del agente; la propuesta es una operación normal con su propia constancia. Si se revoca la delegación, la relación termina.",
				wire: ["solicitud de la empresa (firmada)", "cambio propuesto", "aprueba", "acepta"],
				extras: ["inbox HTTP, experimental", "en la conversación"],
				obj: "Relación desde el token, y luego la solicitud de la empresa",
			},
		},
	},
};
const T = TEXTOS[document.documentElement.lang.toLowerCase().startsWith("es") ? "es" : "en"];

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);

export function jsonHtml(value, keys = []) {
	const marca = new Set(keys);
	const lineas = JSON.stringify(value, null, 2).split("\n");
	return lineas
		.map((l) => {
			const m = l.match(/^(\s*)"([^"]+)":(.*)$/);
			let html = m ? `${m[1]}<span class="k">"${esc(m[2])}"</span>:${esc(m[3]).replace(/"([^"]*)"/g, '<span class="s">"$1"</span>')}` : esc(l).replace(/"([^"]*)"/g, '<span class="s">"$1"</span>');
			return m && marca.has(m[2]) ? `<span class="hl">${html}</span>` : html;
		})
		.join("\n");
}

const NS = "http://www.w3.org/2000/svg";
function el(tag, attrs, parent) {
	const n = document.createElementNS(NS, tag);
	for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
	parent?.appendChild(n);
	return n;
}

function dibujarActores(svg, alto) {
	const g = el("g", { "data-actors": "" }, svg);
	const Y = 26;
	for (const [id, a] of Object.entries(ACTORES)) {
		const c = el("g", { "data-actor": id, opacity: "0.45" }, g);
		el("line", { x1: a.x, y1: Y + 22, x2: a.x, y2: alto - 6, stroke: "var(--line-deep)", "stroke-dasharray": "2 5" }, c);
		if (id === "person") el("circle", { cx: a.x, cy: Y, r: 13, fill: "none", stroke: "var(--person)", "stroke-width": 2 }, c);
		if (id === "agent") el("rect", { x: a.x - 10, y: Y - 10, width: 20, height: 20, transform: `rotate(45 ${a.x} ${Y})`, fill: "var(--agent)", rx: 2 }, c);
		if (id === "company") el("rect", { x: a.x - 13, y: Y - 13, width: 26, height: 26, fill: "var(--company)", rx: 3 }, c);
		if (id === "system") for (let i = 0; i < 3; i++) el("rect", { x: a.x - 15, y: Y - 11 + i * 8.5, width: 30, height: 5, fill: "none", stroke: "var(--on-deep-soft)", "stroke-width": 1.3, rx: 1 }, c);
		const t = el("text", { x: a.x, y: Y + 34, "text-anchor": "middle", fill: "currentColor", "font-family": "var(--mono)", "font-size": 12 }, c);
		t.textContent = T.actors[id];
	}
	return g;
}

export function montar(raiz) {
	const lista = raiz.querySelector(".run__steps");
	const svg = raiz.querySelector(".stage svg");
	const say = raiz.querySelector(".stage__say");
	const paths = raiz.querySelector(".paths");
	const objTitle = raiz.querySelector(".obj__title");
	const pre = raiz.querySelector(".obj pre");
	const chain = raiz.querySelector(".chain");
	const btnPlay = raiz.querySelector("[data-play]");
	const btnTech = raiz.querySelector("[data-tech]");
	const panelTech = raiz.querySelector(".run__tech");
	const techSay = raiz.querySelector(".run__techsay");
	const wire = raiz.querySelector(".wire");
	const quieto = matchMedia("(prefers-reduced-motion: reduce)").matches;

	const ALTO = 250;
	dibujarActores(svg, ALTO);
	const flujos = el("g", {}, svg);
	const defs = el("defs", {}, svg);
	const flecha = el("marker", { id: "vxp-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
	el("path", { d: "M0,0 L10,5 L0,10 z", fill: "currentColor" }, flecha);

	const prueba = step("prove").chain;
	chain.innerHTML = LINKS.map((k) => {
		const s = prueba.find((x) => x.kind === k);
		const dig = s?.prev ? s.prev.replace("sha-256:", "").slice(0, 10) + "…" : T.first;
		return `<div class="link" data-kind="${k}" data-signer="${s?.signer ?? ""}"><b>${k}</b><span>seq ${s?.seq ?? "–"} · ${s?.signer ?? ""}</span><span class="p">prev ${dig}</span></div>`;
	}).join("");

	lista.innerHTML = PASOS.map((p, i) => `<li><button type="button" data-i="${i}"><span class="run__n">${i + 1}</span><span class="run__t">${T.steps[p.id].title}</span><span class="run__bar"><i></i></span></button></li>`).join("");
	const botones = [...lista.querySelectorAll("button")];
	paths.setAttribute("aria-label", T.pathsLabel);

	let actual = 0;
	let reproduciendo = !quieto;
	let t0 = 0;
	const DUR = 11000;

	function mostrar(i) {
		actual = i;
		const p = PASOS[i];
		const tx = T.steps[p.id];
		botones.forEach((b, j) => (j === i ? b.setAttribute("aria-current", "step") : b.removeAttribute("aria-current")));
		say.textContent = tx.say;
		techSay.textContent = tx.tech;
		wire.innerHTML = p.flows.map(([de, a, v], k) => `<li${v ? ' class="back"' : ""}><span>${T.actors[de]} → ${T.actors[a]}</span><code>${esc(tx.wire[k])}</code></li>`).join("");
		paths.innerHTML = p.paths.map(([v, s], k) => { const extra = tx.extras[k]; return `<span class="path" data-s="${s}"><b>${T.ways[v]}</b> · ${T.states[s]}${extra ? " · " + esc(extra) : ""}</span>`; }).join("");
		objTitle.textContent = tx.obj;
		pre.innerHTML = jsonHtml(p.value(), p.keys);
		const primera = pre.querySelector(".hl");
		pre.scrollTop = 0;
		if (primera && !panelTech.hidden) pre.scrollTop = Math.max(0, primera.getBoundingClientRect().top - pre.getBoundingClientRect().top - 40);

		const activos = new Set(p.flows.flatMap(([a, b]) => [a, b]));
		svg.querySelectorAll("[data-actor]").forEach((g) => g.setAttribute("opacity", activos.has(g.dataset.actor) ? "1" : "0.32"));
		flujos.innerHTML = "";
		p.flows.forEach(([de, a, vuelta], k) => {
			const rotulo = tx.flows[k];
			const x1 = ACTORES[de].x, x2 = ACTORES[a].x;
			const dir = Math.sign(x2 - x1);
			const y = 92 + k * 34;
			const d = `M${x1 + dir * 6},${y} H${x2 - dir * 8}`;
			const g = el("g", { color: vuelta ? "var(--on-deep-soft)" : "var(--on-deep)" }, flujos);
			el("circle", { cx: x1, cy: y, r: 3, fill: "currentColor" }, g);
			const path = el("path", { d, fill: "none", stroke: "currentColor", "stroke-width": 1.3, "stroke-dasharray": vuelta ? "4 4" : "none", "marker-end": "url(#vxp-arrow)" }, g);
			const texto = el("text", { x: (x1 + x2) / 2, y: y - 8, "text-anchor": "middle", fill: "currentColor", "font-family": "var(--sans)", "font-size": 12.5 }, g);
			texto.textContent = rotulo;
			if (!quieto) {
				const largo = path.getTotalLength();
				if (!vuelta) {
					path.style.strokeDasharray = `${largo}`;
					path.animate([{ strokeDashoffset: largo }, { strokeDashoffset: 0 }], { duration: 600, delay: k * 480, easing: "cubic-bezier(.22,1,.36,1)", fill: "backwards" });
				}
				g.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 360, delay: k * 480, fill: "backwards" });
			}
		});
		raiz.querySelector(".flows-list").innerHTML = p.flows.map(([de, a, v], k) => `<li${v ? ' class="back"' : ""}><span>${T.actors[de]} → ${T.actors[a]}</span>${esc(tx.flows[k])}</li>`).join("");
		const n = p.chain ?? 0;
		chain.querySelectorAll(".link").forEach((l, j) => l.classList.toggle("on", j < n));
		t0 = performance.now();
	}

	function tick(ahora) {
		const barra = botones[actual].querySelector(".run__bar i");
		if (reproduciendo) {
			const f = Math.min(1, (ahora - t0) / DUR);
			barra.style.width = `${f * 100}%`;
			if (f >= 1) {
				barra.style.width = "0";
				mostrar((actual + 1) % PASOS.length);
			}
		}
		requestAnimationFrame(tick);
	}

	function pausar(p) {
		reproduciendo = !p;
		btnPlay.textContent = reproduciendo ? T.pause : T.play;
		btnPlay.setAttribute("aria-pressed", String(!reproduciendo));
		if (reproduciendo) t0 = performance.now() - parseFloat(botones[actual].querySelector(".run__bar i").style.width || "0") / 100 * DUR;
	}

	// Optional technical inspection: opening it pauses playback so it can be read.
	btnTech.textContent = T.techOpen;
	btnTech.addEventListener("click", () => {
		const abrir = panelTech.hidden;
		panelTech.hidden = !abrir;
		btnTech.setAttribute("aria-expanded", String(abrir));
		btnTech.textContent = abrir ? T.techClose : T.techOpen;
		if (abrir) { pausar(true); mostrar(actual); }
	});

	botones.forEach((b) => b.addEventListener("click", () => { botones[actual].querySelector(".run__bar i").style.width = "0"; mostrar(Number(b.dataset.i)); pausar(true); }));
	raiz.querySelector("[data-prev]").addEventListener("click", () => { botones[actual].querySelector(".run__bar i").style.width = "0"; mostrar((actual + PASOS.length - 1) % PASOS.length); pausar(true); });
	raiz.querySelector("[data-next]").addEventListener("click", () => { botones[actual].querySelector(".run__bar i").style.width = "0"; mostrar((actual + 1) % PASOS.length); pausar(true); });
	btnPlay.addEventListener("click", () => pausar(reproduciendo));
	document.addEventListener("visibilitychange", () => { if (document.hidden && reproduciendo) pausar(true); });

	mostrar(0);
	pausar(!reproduciendo);
	if (!quieto) {
		// Starts playing when the walkthrough scrolls into view.
		pausar(true);
		new IntersectionObserver((e, o) => { if (e[0].isIntersecting) { pausar(false); o.disconnect(); } }, { threshold: 0.35 }).observe(raiz);
	}
	requestAnimationFrame(tick);
}

// Summarized proof: the real chain of the walkthrough's operation, with the verifier's verdict.
const RESUMEN = {
	request: (b) => b.channel,
	terms: (b) => `rev ${b.revision} · ${b.commitment?.mode}`,
	user_approval: (b) => b.method,
	execution: (b) => T.attempt(b.attempt),
	read_back: (b) => (b.matches_terms ? T.matches : T.mismatch),
	outcome: (b) => b.state,
};
export function recibo(raiz) {
	const p = step("prove");
	raiz.querySelector(".receipt__op").textContent = T.statements(p.chain.length);
	raiz.querySelector(".receipt__rows").innerHTML = p.chain
		.map((s) => `<li><span class="r-seq">${s.seq}</span><span class="r-kind">${s.kind}</span><span class="r-sum">${esc((RESUMEN[s.kind] ?? (() => ""))(s.body))}</span><span class="r-by" data-signer="${s.signer}">${s.signer}</span><span class="r-prev">${s.prev ? s.prev.replace("sha-256:", "").slice(0, 6) : T.none}</span></li>`)
		.join("");
	const v = p.verdict;
	raiz.querySelector(".receipt__verdict").innerHTML = `<b>${v.valid ? T.valid : T.invalid}</b> · approval <code>${v.approval}</code> · single_root <code>${v.single_root}</code> · logged <code>${v.logged}</code>`;
}

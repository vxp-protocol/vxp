// VXP Relationship from the inside: the agreement the person authorized in the walkthrough's native run
// (recorrido-data.js, steps "authority" and "relate") and the request the company started within it.
// The "what if" rejections are the ones specification §7 requires (R6, R9); they are not part of the capture.
import { RECORRIDO } from "./recorrido-data.js";
import { jsonHtml } from "./recorrido.js";

const step = (id) => RECORRIDO.steps.find((s) => s.id === id);
const REL = step("relate");
const PEDIDO = JSON.parse(step("authority").device.authorization_details).find((d) => d.type.endsWith("/relationship"));
const DESCUBRIR = step("discover").response;

const TEXTOS = {
	en: {
		agreement: "The agreement",
		signedAs: "Signed by the company as",
		rows: {
			parties: ["Between", `${DESCUBRIR.organization.name} (${DESCUBRIR.organization.domain}) and the person's agent (agent.example)`],
			actions: ["The company may", "propose a delivery change to the agent"],
			limit: ["Limit", (n) => `at most ${n} per day`],
			validity: ["Valid until", (t) => `${t} UTC, one hour after the consent`],
			revoke: ["Revocation", "the person, the company or the agent can end it; revoking the delegation ends it too"],
		},
		inspectAgreement: "Show the agreement objects", hideAgreement: "Hide the agreement objects",
		stepsLabel: "The request the company started",
		steps: [
			["The company checks the agreement", "Before signing or sending anything, the company checks that the request fits what the person authorized."],
			["It signs and sends the request", "The store proposes moving another order. The request is signed with the company's key and delivered to the agent's inbox."],
			["The agent answers within the agreement", "The agent checks the signature against the company it knows, and that the action is one the person allowed. It accepts the proposal; as in step 5, the approval is the agent's statement (agent_asserted)."],
			["The company runs it once and reads it back", "The change runs once under the company's own rules, and its own proof records it like any other operation."],
		],
		checks: ["The agreement is in force", "The person's delegation is still in force", "The action is in the agreement", "Under the daily limit", "The order belongs to that customer"],
		delivered: (h) => `Delivered to the agent's inbox · HTTP ${h}`,
		proposal: "Proposal from the store",
		accepted: "Accepted · ran once",
		readBack: "Read back from the system",
		prev: "Previous", next: "Next",
		stepN: (i, n) => `Step ${i} of ${n}`,
		whatIfLegend: "What if the company tried this?",
		whatIf: {
			ok: ["The request above", null, "It fits the agreement, so it goes through."],
			limit: ["A third request on the same day", "relationship_limit_exceeded", "The person allowed two per day. The company must reject it before signing or sending anything."],
			action: ["Notifying an incident (incidencia.avisar): the store offers it, but the person did not include it", "action_not_authorized", "Only the actions in the agreement can be started. Anything else needs a new consent."],
			revoked: ["The same request after the person revoked", "relationship_revoked", "Once revoked, nothing goes through. Accepting an earlier proposal is checked again too, and has no effect."],
			expired: ["The same request after the agreement expired", "relationship_expired", "The agreement lasted one hour. After that, the company cannot start anything."],
		},
		rule: "Required by specification §7, rules R6 and R9.",
		inspect: "Show the request and the result", hide: "Hide the request and the result",
		captured: "Captured from the native run of 22 October 2026. In that run, a test triggered the store's request through the operator's internal route; signing, delivery, acceptance and read-back are the real ones.",
	},
	es: {
		agreement: "El acuerdo",
		signedAs: "Lo firma la empresa como",
		rows: {
			parties: ["Entre", `${DESCUBRIR.organization.name} (${DESCUBRIR.organization.domain}) y el agente de la persona (agent.example)`],
			actions: ["La empresa puede", "proponerle al agente un cambio de despacho"],
			limit: ["Límite", (n) => `como máximo ${n} por día`],
			validity: ["Vigente hasta", (t) => `${t} UTC, una hora después del consentimiento`],
			revoke: ["Revocación", "la persona, la empresa o el agente pueden terminarlo; revocar la delegación también lo termina"],
		},
		inspectAgreement: "Ver los objetos del acuerdo", hideAgreement: "Ocultar los objetos del acuerdo",
		stepsLabel: "La gestión que inició la empresa",
		steps: [
			["La empresa revisa el acuerdo", "Antes de firmar o enviar nada, la empresa comprueba que la solicitud cabe en lo que la persona autorizó."],
			["Firma y envía la solicitud", "La ferretería propone cambiar otro pedido. La solicitud va firmada con la llave de la empresa y llega al inbox del agente."],
			["El agente responde dentro del acuerdo", "El agente revisa la firma contra la empresa que conoce, y que la acción sea una que la persona permitió. Acepta la propuesta; como en el paso 5, la aprobación la afirma el agente (agent_asserted)."],
			["La empresa la ejecuta una vez y la relee", "El cambio se ejecuta una sola vez con las reglas de la propia empresa, y su propia constancia lo registra como cualquier otra operación."],
		],
		checks: ["El acuerdo está vigente", "La delegación de la persona sigue vigente", "La acción está en el acuerdo", "Bajo el límite diario", "El pedido es de ese cliente"],
		delivered: (h) => `Entregada en el inbox del agente · HTTP ${h}`,
		proposal: "Propuesta de la ferretería",
		accepted: "Aceptada · se ejecutó una vez",
		readBack: "Releído en el sistema",
		prev: "Anterior", next: "Siguiente",
		stepN: (i, n) => `Paso ${i} de ${n}`,
		whatIfLegend: "¿Y si la empresa intentara esto?",
		whatIf: {
			ok: ["La solicitud de arriba", null, "Cabe en el acuerdo, así que pasa."],
			limit: ["Una tercera solicitud el mismo día", "relationship_limit_exceeded", "La persona permitió dos por día. La empresa debe rechazarla antes de firmar o enviar nada."],
			action: ["Avisar una incidencia (incidencia.avisar): la ferretería la ofrece, pero la persona no la incluyó", "action_not_authorized", "Sólo se pueden iniciar las acciones del acuerdo. Cualquier otra requiere un consentimiento nuevo."],
			revoked: ["La misma solicitud después de que la persona revocó", "relationship_revoked", "Revocado, no pasa nada. Aceptar una propuesta anterior también se vuelve a revisar, y no tiene efecto."],
			expired: ["La misma solicitud después de que venció el acuerdo", "relationship_expired", "El acuerdo duraba una hora. Después, la empresa no puede iniciar nada."],
		},
		rule: "Lo exige la especificación §7, reglas R6 y R9.",
		inspect: "Ver la solicitud y el resultado", hide: "Ocultar la solicitud y el resultado",
		captured: "Capturado de la corrida nativa del 22 de octubre de 2026. En esa corrida, una prueba disparó la solicitud de la ferretería por la ruta interna del operador; la firma, la entrega, la aceptación y la relectura son las reales.",
	},
};
const T = TEXTOS[document.documentElement.lang.toLowerCase().startsWith("es") ? "es" : "en"];
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);

function desplegable(boton, panel, abrir, cerrar) {
	boton.addEventListener("click", () => {
		const a = panel.hidden;
		panel.hidden = !a;
		boton.setAttribute("aria-expanded", String(a));
		boton.textContent = a ? cerrar : abrir;
	});
}

export function montarRelationship(raiz) {
	const r = REL.relationship;
	const vence = r.expires_at.replace("T", " ").replace(/:\d\d\.\d+Z$/, "");
	const efecto = REL.accepted.effects[0];
	const n = T.steps.length;
	let actual = 0;

	raiz.innerHTML = `
		<article class="rl__deal" aria-labelledby="rl-deal-h">
			<p class="rl__id"><code>${esc(r.relationship_id)}</code><span class="rl__state">${esc(r.state)}</span></p>
			<h3 id="rl-deal-h">${T.agreement}</h3>
			<dl>
				<div><dt>${T.rows.parties[0]}</dt><dd>${esc(T.rows.parties[1])}</dd></div>
				<div><dt>${T.rows.actions[0]}</dt><dd>${T.rows.actions[1]} <code>${esc(r.actions.join(", "))}</code></dd></div>
				<div><dt>${T.rows.limit[0]}</dt><dd>${T.rows.limit[1](r.limits.max_per_day)}</dd></div>
				<div><dt>${T.rows.validity[0]}</dt><dd>${T.rows.validity[1](esc(vence))}</dd></div>
				<div><dt>${T.rows.revoke[0]}</dt><dd>${T.rows.revoke[1]}</dd></div>
			</dl>
			<p class="rl__sig">${T.signedAs} <code>vxp-relationship+jwt</code></p>
			<button type="button" class="pl__toggle" aria-expanded="false" aria-controls="rl-deal-json">${T.inspectAgreement}</button>
			<pre id="rl-deal-json" class="pl__json" tabindex="0" hidden>${jsonHtml({ requested_in_consent: PEDIDO, granted_in_token: r }, ["actions", "max_per_day", "duration_seconds", "expires_at", "agreement"])}</pre>
		</article>
		<div class="rl__flow">
			<ol class="rl__steps" aria-label="${T.stepsLabel}">${T.steps.map((s, i) => `<li><button type="button" data-i="${i}"><span>${i + 1}</span>${s[0]}</button></li>`).join("")}</ol>
			<div class="rl__stage">
				<p class="rl__count" aria-live="polite"></p>
				<h3 class="rl__title"></h3>
				<p class="rl__say"></p>
				<div class="rl__scene"></div>
				<div class="rl__nav"><button type="button" data-prev>${T.prev}</button><button type="button" data-next>${T.next}</button></div>
			</div>
			<fieldset class="rl__whatif">
				<legend>${T.whatIfLegend}</legend>
				${Object.entries(T.whatIf).map(([k, w]) => `<label><input type="radio" name="rl-if" value="${k}"${k === "ok" ? " checked" : ""}> <span>${w[0]}</span></label>`).join("")}
				<p class="rl__answer" aria-live="polite"></p>
			</fieldset>
			<button type="button" class="pl__toggle" aria-expanded="false" aria-controls="rl-json">${T.inspect}</button>
			<div id="rl-json" hidden>
				<p class="small">${T.captured}</p>
				<pre class="pl__json" tabindex="0">${jsonHtml({ delivery: REL.outbox, after_accept: REL.accepted }, ["delivery", "http", "summary", "terms_digest", "state", "reason", "change"])}</pre>
			</div>
		</div>`;

	const botones = [...raiz.querySelectorAll(".rl__steps button")];
	const escena = raiz.querySelector(".rl__scene");

	const ESCENAS = [
		() => `<ul class="rl__checks">${T.checks.map((c) => `<li>${c}</li>`).join("")}</ul>`,
		() => `<div class="rl__msg rl__msg--company"><p class="rl__from">${T.proposal} · <code>vxp-company-request+jwt</code></p><p lang="es">${esc(REL.outbox.content.summary)}</p><p class="rl__foot">${T.delivered(REL.outbox.http)}</p></div>`,
		() => `<div class="rl__msg rl__msg--agent"><p class="rl__from"><code>POST …/proposals/${esc(REL.outbox.content.proposal_id)}/accept</code></p><p><code>approved_by: user</code> → <code>agent_asserted</code></p></div>`,
		() => `<div class="rl__msg rl__msg--done"><p class="rl__from">${T.accepted} · <code>${esc(REL.accepted.state)}</code></p><p><code>${esc(efecto.system)}</code> ${esc(efecto.change)}</p><p class="rl__foot">${T.readBack} · <code>${esc(REL.accepted.reason)}</code></p></div>`,
	];

	function mostrar(i) {
		actual = i;
		botones.forEach((b, j) => (j === i ? b.setAttribute("aria-current", "step") : b.removeAttribute("aria-current")));
		raiz.querySelector(".rl__count").textContent = T.stepN(i + 1, n);
		raiz.querySelector(".rl__title").textContent = T.steps[i][0];
		raiz.querySelector(".rl__say").textContent = T.steps[i][1];
		escena.innerHTML = ESCENAS[i]();
	}

	function responder(k) {
		const [, codigo, texto] = T.whatIf[k];
		const caja = raiz.querySelector(".rl__answer");
		caja.dataset.ok = String(!codigo);
		caja.innerHTML = codigo ? `<b><code>${codigo}</code></b> ${texto} <span class="small">${T.rule}</span>` : `<b>✓</b> ${texto}`;
	}

	botones.forEach((b) => b.addEventListener("click", () => mostrar(Number(b.dataset.i))));
	raiz.querySelector("[data-prev]").addEventListener("click", () => mostrar((actual + n - 1) % n));
	raiz.querySelector("[data-next]").addEventListener("click", () => mostrar((actual + 1) % n));
	raiz.querySelectorAll('input[name="rl-if"]').forEach((x) => x.addEventListener("change", () => responder(x.value)));
	const [b1, b2] = raiz.querySelectorAll(".pl__toggle");
	desplegable(b1, raiz.querySelector("#rl-deal-json"), T.inspectAgreement, T.hideAgreement);
	desplegable(b2, raiz.querySelector("#rl-json"), T.inspect, T.hide);
	mostrar(0);
	responder("ok");
}

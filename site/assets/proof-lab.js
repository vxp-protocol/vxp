// VXP Proof from the inside: the real chain of the walkthrough's operation (recorrido-data.js, step "prove"),
// link by link, with who signs each one and what it points to. Tampering is a simulation of the rules of
// specification §6 and of the verifier (same error codes); the real verification is at /verify/.
import { RECORRIDO } from "./recorrido-data.js";
import { jsonHtml } from "./recorrido.js";

const PRUEBA = RECORRIDO.steps.find((s) => s.id === "prove");
const CADENA = PRUEBA.chain;
const VEREDICTO = PRUEBA.verdict;

// Which value is altered in each link for the simulation: [path inside body, new value].
const ALTERA = {
	request: [["client_id"], "https://other-agent.example/agent.json"],
	terms: [["expires_at"], "2026-10-23T22:45:29.356Z"],
	user_approval: [["revision"], 2],
	execution: [["attempt"], 2],
	read_back: [["observed", "despacho_nuevo"], "2026-10-29"],
	outcome: [["state"], "failed"],
};

const TEXTOS = {
	en: {
		chainLabel: "The six signed statements of the operation",
		signer: { company: "signed by the company", operator: "signed by the operator" },
		role: { company: "The company", operator: "The operator" },
		first: "First link: it points to nothing before it.",
		prev: (k, d) => `Points to statement ${k} by its digest: ${d}`,
		seq: "Position", signedBy: "Signed by", points: "Points to", digest: "Digest it names",
		showJson: "Show the signed content", hideJson: "Hide the signed content",
		tamperLegend: (k) => `What if someone alters statement ${k}?`,
		modes: {
			intact: "Leave it intact",
			edit: "Change a value without signing again",
			resign: "Change a value and sign it again with the same key",
			remove: "Remove it from the chain",
		},
		changed: (campo, de, a) => `Changed: ${campo} from ${de} to ${a}`,
		removed: "Removed from the chain",
		verdictIntact: "Verdict on the intact chain",
		verdictSim: "What the verifier answers",
		simNote: "Simulated in this page from the rules of specification §6. The verifier runs the real checks on this proof, intact or altered.",
		openVerifier: "Open the verifier",
		valid: "valid", invalid: "not valid",
		intactSay: "Every signature checks against the keys the company publishes, every statement points to the one before, and the system read-back matches the approved terms. It is an attestation signed by the operator: there are no external witnesses yet, and the verdict says so.",
		results: {
			edit: (k) => `The content of statement ${k} no longer matches its signature. The verifier stops at the first failure.`,
			resign: (k) => `Statement ${k} now has another digest, so statement ${k + 1}, which still names the old one, no longer points to it. The chain breaks at ${k + 1}.`,
			resignApproval: "Signed again, the approval now names revision 2, but the company only offered revision 1. The verifier rejects it at this statement.",
			resignLast: "Whoever holds the company's key, and also rewrites the operator's own log, can sign a different last statement and the chain alone still checks. An agent that kept the operation it saw catches it, because the state no longer matches. A public log with outside witnesses would also catch it; it is not in place yet, which is why the verdict says logged: false.",
			remove: (k) => `Statement ${k + 1} now sits in position ${k}. Positions must have no gaps, so the chain is rejected there.`,
			removeLast: "Without a final statement, the result cannot be read as done: the verifier treats it as unknown.",
		},
		kinds: {
			request: ["What the agent asked", "Received from the agent: the channel, the agent's identity and a digest of what it asked for."],
			terms: ["The exact terms, revision 1", "The company's offer: a digest of the exact terms, a firm commitment, when it expires, and which terms it will read back in its system."],
			user_approval: ["The approval, and how it was given", "The approval of revision 1, with its method: agent_asserted. The agent stated that the person approved; this record shows that, and no more."],
			execution: ["One execution", "The operation ran once, attempt 1, on the approved revision and the same terms digest."],
			read_back: ["What the system showed afterwards", "After running, the company's system was read: order P-1042, delivery on 2026-10-28. It matches the terms."],
			outcome: ["The declared result", "The company declares succeeded, bound to the same terms digest and to a digest of the result it reported."],
		},
	},
	es: {
		chainLabel: "Las seis declaraciones firmadas de la operación",
		signer: { company: "firma la empresa", operator: "firma el operador" },
		role: { company: "La empresa", operator: "El operador" },
		first: "Primer eslabón: no apunta a nada anterior.",
		prev: (k, d) => `Apunta a la declaración ${k} por su huella: ${d}`,
		seq: "Posición", signedBy: "Firma", points: "Apunta a", digest: "Huella que nombra",
		showJson: "Ver el contenido firmado", hideJson: "Ocultar el contenido firmado",
		tamperLegend: (k) => `¿Y si alguien altera la declaración ${k}?`,
		modes: {
			intact: "Dejarla intacta",
			edit: "Cambiar un valor sin volver a firmar",
			resign: "Cambiar un valor y volver a firmarla con la misma llave",
			remove: "Sacarla de la cadena",
		},
		changed: (campo, de, a) => `Cambiado: ${campo} de ${de} a ${a}`,
		removed: "Sacada de la cadena",
		verdictIntact: "Veredicto sobre la cadena intacta",
		verdictSim: "Lo que responde el verificador",
		simNote: "Simulado en esta página con las reglas de la especificación §6. El verificador hace las comprobaciones reales sobre esta constancia, intacta o alterada.",
		openVerifier: "Abrir el verificador",
		valid: "válida", invalid: "no válida",
		intactSay: "Cada firma calza con las llaves que publica la empresa, cada declaración apunta a la anterior y la relectura del sistema calza con los términos aprobados. Es una atestación firmada por el operador: todavía no hay testigos externos, y el veredicto lo dice.",
		results: {
			edit: (k) => `El contenido de la declaración ${k} ya no calza con su firma. El verificador se detiene en la primera falla.`,
			resign: (k) => `La declaración ${k} tiene ahora otra huella, así que la ${k + 1}, que sigue nombrando la anterior, ya no apunta a ella. La cadena se corta en la ${k + 1}.`,
			resignApproval: "Firmada de nuevo, la aprobación nombra ahora la revisión 2, pero la empresa sólo ofreció la revisión 1. El verificador la rechaza en esta declaración.",
			resignLast: "Quien tiene la llave de la empresa, y además reescribe el registro del propio operador, puede firmar otra última declaración y la cadena sola sigue cuadrando. Un agente que guardó la operación que vio lo detecta, porque el estado ya no calza. Un registro público con testigos externos también lo detectaría; todavía no existe, y por eso el veredicto dice logged: false.",
			remove: (k) => `La declaración ${k + 1} queda en la posición ${k}. Las posiciones no pueden tener huecos, así que la cadena se rechaza ahí.`,
			removeLast: "Sin una declaración final, el resultado no se puede leer como hecho: el verificador lo trata como desconocido.",
		},
		kinds: {
			request: ["Lo que pidió el agente", "Recibido del agente: el canal, la identidad del agente y una huella de lo que pidió."],
			terms: ["Los términos exactos, revisión 1", "La oferta de la empresa: la huella de los términos exactos, un compromiso firm, cuándo vence y qué términos volverá a leer en su sistema."],
			user_approval: ["La aprobación, y cómo se dio", "La aprobación de la revisión 1, con su método: agent_asserted. El agente afirmó que la persona aprobó; este registro muestra eso, y nada más."],
			execution: ["Una ejecución", "La operación se ejecutó una vez, intento 1, sobre la revisión aprobada y la misma huella de términos."],
			read_back: ["Lo que mostró el sistema después", "Después de ejecutar, se leyó el sistema de la empresa: pedido P-1042, despacho el 2026-10-28. Calza con los términos."],
			outcome: ["El resultado declarado", "La empresa declara succeeded, amarrado a la misma huella de términos y a la huella del resultado que informó."],
		},
	},
};
const T = TEXTOS[document.documentElement.lang.toLowerCase().startsWith("es") ? "es" : "en"];
const corto = (d) => (d ? d.replace("sha-256:", "").slice(0, 12) + "…" : "—");

export function montarProof(raiz, verificar = "verify/") {
	let sel = 3;
	let modo = "intact";

	raiz.innerHTML = `
		<ol class="pl__chain" aria-label="${T.chainLabel}">${CADENA.map((s, i) => `
			<li class="pl__item" data-i="${i}">
				<span class="pl__con" aria-hidden="true"><i></i><code>prev ${corto(s.prev)}</code></span>
				<button type="button" class="pl__link" data-signer="${s.signer}" aria-pressed="false">
					<span class="pl__seq">${s.seq}</span>
					<span class="pl__txt"><b>${T.kinds[s.kind][0]}</b><code>${s.kind}</code></span>
					<span class="pl__by">${T.signer[s.signer]}</span>
				</button>
			</li>`).join("")}
		</ol>
		<div class="pl__panel">
			<div class="pl__insp">
				<p class="pl__kicker"></p>
				<h3 class="pl__title"></h3>
				<p class="pl__say"></p>
				<dl class="pl__meta"></dl>
				<p class="pl__change" aria-live="polite"></p>
				<button type="button" class="pl__toggle" aria-expanded="false" aria-controls="pl-json">${T.showJson}</button>
				<pre id="pl-json" class="pl__json" tabindex="0" hidden></pre>
			</div>
			<fieldset class="pl__tamper">
				<legend></legend>
				${Object.entries(T.modes).map(([v, t]) => `<label><input type="radio" name="pl-mode" value="${v}"${v === "intact" ? " checked" : ""}> <span>${t}</span></label>`).join("")}
			</fieldset>
			<div class="pl__verdict" aria-live="polite"></div>
		</div>`;

	const items = [...raiz.querySelectorAll(".pl__item")];
	const botones = [...raiz.querySelectorAll(".pl__link")];
	const kicker = raiz.querySelector(".pl__kicker");
	const titulo = raiz.querySelector(".pl__title");
	const say = raiz.querySelector(".pl__say");
	const meta = raiz.querySelector(".pl__meta");
	const cambio = raiz.querySelector(".pl__change");
	const toggle = raiz.querySelector(".pl__toggle");
	const pre = raiz.querySelector(".pl__json");
	const leyenda = raiz.querySelector(".pl__tamper legend");
	const veredicto = raiz.querySelector(".pl__verdict");

	function cuerpoAlterado(s) {
		const body = structuredClone(s.body);
		const [ruta, nuevo] = ALTERA[s.kind];
		let o = body;
		for (const k of ruta.slice(0, -1)) o = o[k];
		const viejo = o[ruta.at(-1)];
		o[ruta.at(-1)] = nuevo;
		return { body, campo: ruta.join("."), viejo, nuevo };
	}

	// Verifier result for the chosen alteration, with the codes of verify/vxp-verify.js.
	function resultado() {
		const ultimo = sel === CADENA.length - 1;
		if (modo === "edit") return { valid: false, error: "signature_invalid", seq: sel, say: T.results.edit(sel), bad: [sel] };
		if (modo === "resign") {
			if (ultimo) return { valid: false, error: "operation_state_mismatch", say: T.results.resignLast, chainOk: true, bad: [sel] };
			// An approval re-signed with another revision no longer matches the latest revision offered.
			if (CADENA[sel].kind === "user_approval") return { valid: false, error: "approval_not_latest_revision", seq: sel, say: T.results.resignApproval, bad: [sel] };
			return { valid: false, error: "chain_broken", seq: sel + 1, say: T.results.resign(sel), bad: [sel], broken: sel + 1 };
		}
		if (modo === "remove") {
			if (ultimo) return { valid: false, error: "no_outcome", final_state: "unknown", say: T.results.removeLast, gone: sel };
			return { valid: false, error: "seq_error", seq: sel, say: T.results.remove(sel), gone: sel, broken: sel + 1 };
		}
		return null;
	}

	function pintar() {
		const s = CADENA[sel];
		const r = resultado();
		botones.forEach((b, i) => b.setAttribute("aria-pressed", String(i === sel)));
		items.forEach((li, i) => {
			li.classList.toggle("is-sel", i === sel);
			li.classList.toggle("is-bad", !!r?.bad?.includes(i));
			li.classList.toggle("is-gone", r?.gone === i);
			li.classList.toggle("is-broken", r?.broken === i);
			li.classList.toggle("is-after", !!r && !r.chainOk && i > (r.gone ?? r.seq ?? sel));
		});
		kicker.textContent = `seq ${s.seq} · ${s.kind}`;
		titulo.textContent = T.kinds[s.kind][0];
		say.textContent = T.kinds[s.kind][1];
		const siguiente = CADENA[sel + 1];
		meta.innerHTML = `
			<div><dt>${T.signedBy}</dt><dd>${T.role[s.signer]} <code>${s.signer}</code></dd></div>
			<div><dt>${T.points}</dt><dd>${s.prev ? T.prev(s.seq - 1, `<code>${corto(s.prev)}</code>`) : T.first}</dd></div>
			${siguiente ? `<div><dt>${T.digest}</dt><dd><code>${corto(siguiente.prev)}</code> · seq ${siguiente.seq}</dd></div>` : ""}`;

		let body = s.body;
		cambio.textContent = "";
		if (modo === "edit" || modo === "resign") {
			const a = cuerpoAlterado(s);
			body = a.body;
			cambio.textContent = T.changed(a.campo, JSON.stringify(a.viejo), JSON.stringify(a.nuevo));
		} else if (modo === "remove") cambio.textContent = T.removed;
		const campoAlterado = modo === "edit" || modo === "resign" ? [ALTERA[s.kind][0].at(-1)] : [];
		pre.innerHTML = jsonHtml({ seq: s.seq, kind: s.kind, signer: s.signer, prev: s.prev, body }, campoAlterado);
		leyenda.textContent = T.tamperLegend(s.seq);

		if (!r) {
			const v = VEREDICTO;
			veredicto.dataset.ok = "true";
			veredicto.innerHTML = `
				<p class="pl__vh">${T.verdictIntact}</p>
				<p class="pl__vbig"><b>${T.valid}</b> · <code>final_state: ${v.final_state}</code> · <code>approval: ${v.approval}</code></p>
				<p>${T.intactSay}</p>
				<p class="pl__vcodes"><code>single_root: ${v.single_root}</code> <code>logged: ${v.logged}</code> <code>derived_assurance: ${v.derived_assurance.length}</code></p>
				<a class="btn btn--ghost" href="${verificar}">${T.openVerifier}</a>`;
		} else {
			veredicto.dataset.ok = "false";
			const codigo = [`valid: false`, `error: ${r.error}`, r.seq !== undefined ? `seq: ${r.seq}` : "", r.final_state ? `final_state: ${r.final_state}` : ""].filter(Boolean);
			veredicto.innerHTML = `
				<p class="pl__vh">${T.verdictSim}</p>
				<p class="pl__vbig"><b>${T.invalid}</b> · ${codigo.map((c) => `<code>${c}</code>`).join(" ")}</p>
				<p>${r.say}</p>
				<p class="small">${T.simNote}</p>
				<a class="btn btn--ghost" href="${verificar}">${T.openVerifier}</a>`;
		}
	}

	// On narrow screens the panel sits below the chain: bring it into view when a link is chosen.
	const angosto = matchMedia("(max-width: 900px)");
	const quieto = matchMedia("(prefers-reduced-motion: reduce)").matches;
	botones.forEach((b, i) => b.addEventListener("click", () => {
		sel = i;
		pintar();
		if (angosto.matches) raiz.querySelector(".pl__insp").scrollIntoView({ behavior: quieto ? "auto" : "smooth", block: "start" });
	}));
	raiz.querySelectorAll('input[name="pl-mode"]').forEach((r) => r.addEventListener("change", () => { modo = r.value; pintar(); }));
	toggle.addEventListener("click", () => {
		const abrir = pre.hidden;
		pre.hidden = !abrir;
		toggle.setAttribute("aria-expanded", String(abrir));
		toggle.textContent = abrir ? T.hideJson : T.showJson;
	});
	pintar();
}

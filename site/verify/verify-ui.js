// Verifier interface: loads the examples published in /downloads, applies the chosen alteration and
// shows the verdict of vxp-verify.js with the explanation of each check.
import { explain, verdictJson, verifyPackage, verifyVectors } from "./vxp-verify.js";

const EJEMPLOS = {
	native: { dir: "../downloads/native-run-2026-10-22-evening/", pkg: "paquete-op_XzdILOmlgiae.json", mat: "material-op_XzdILOmlgiae.json", op: "operacion-op_XzdILOmlgiae.json", naming: "vxp", campo: "despacho_nuevo" },
	channel: { dir: "../downloads/pact-run-2026-10-22-evening/", pkg: "pact-op_R6F-x006Gxsg.json", mat: "pact-op_R6F-x006Gxsg.material.json", op: null, naming: "vxp", campo: null },
};
const $ = (s) => document.querySelector(s);
const valor = (n) => document.querySelector(`input[name="${n}"]:checked`).value;
const texto = (url) => fetch(url).then((r) => {
	if (!r.ok) throw new Error(`${url}: ${r.status}`);
	return r.text();
});

const b64u = {
	dec: (s) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0))),
	enc: (t) => btoa(String.fromCharCode(...new TextEncoder().encode(t))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
};

// Alterations are made on the example's text, as someone trying to fool the verifier would.
function alterar(tipo, pkgText, opText, campo) {
	if (tipo === "none" || tipo === "aud") return { pkgText, opText };
	const pkg = JSON.parse(pkgText);
	if (tipo === "outcome") {
		const i = pkg.statements.findIndex((s) => JSON.parse(b64u.dec(s.split("~")[0].split(".")[1])).kind === "outcome");
		const [jwt, ...resto] = pkg.statements[i].split("~");
		const [h, p, sig] = jwt.split(".");
		const cuerpo = b64u.dec(p).replace('"state":"succeeded"', '"state":"failed"');
		pkg.statements[i] = [[h, b64u.enc(cuerpo), sig].join("."), ...resto].join("~");
	}
	if (tipo === "swap") [pkg.statements[2], pkg.statements[3]] = [pkg.statements[3], pkg.statements[2]];
	if (tipo === "term" && opText) {
		const op = JSON.parse(opText);
		const terms = op.terms ?? op.proposal?.terms;
		if (terms && campo in terms) terms[campo] = "2026-11-15";
		return { pkgText, opText: JSON.stringify(op) };
	}
	return { pkgText: JSON.stringify(pkg), opText };
}

// Text masked on display (the verified package is not touched). Published proofs use neutral data: empty.
const TAPAR = [];
const tapar = (t) => TAPAR.reduce((x, [a, b]) => x.split(a).join(b), String(t));

const ETIQUETA = { pass: "Pass", fail: "Fail", info: "Note", not_reached: "Not reached" };

function pintar(veredicto) {
	const caja = $(".vverdict");
	caja.dataset.state = veredicto.valid ? "valid" : "invalid";
	$(".vverdict__big").textContent = veredicto.valid ? `Valid · ${veredicto.final_state}` : `Invalid · ${veredicto.error}`;
	$(".vverdict__sub").textContent = veredicto.valid
		? `Approval ${veredicto.approval} · single_root ${veredicto.single_root} · logged ${veredicto.logged} · ${veredicto.statements} statements`
		: String(veredicto.error).startsWith("operation_") ? "The signed chain checks out; the operation shown to the agent does not match what was signed."
		: veredicto.seq === null || veredicto.seq === undefined ? "Stopped before reading the statements." : `Stopped at statement seq ${veredicto.seq}.`;
	resumen(veredicto);
	const lista = $(".vchecks");
	lista.replaceChildren(
		...explain(veredicto).map((c) => {
			const li = document.createElement("li");
			li.dataset.status = c.status;
			const t = document.createElement("span");
			t.className = "vchecks__s";
			t.textContent = ETIQUETA[c.status] ?? c.status;
			const n = document.createElement("b");
			n.textContent = c.title;
			const p = document.createElement("span");
			p.textContent = tapar(c.text);
			li.append(t, n, p);
			return li;
		}),
	);
	$(".vraw pre").textContent = tapar(verdictJson(veredicto));
}

// Five questions a verdict answers, kept apart (spec §10, Reading a verdict): a valid signature, the
// operator's testimony and an independent confirmation are different things.
function resumen(v) {
	let dl = $(".vsum");
	if (!dl) {
		dl = document.createElement("dl");
		dl.className = "vsum";
		$(".vverdict").append(dl);
	}
	const filas = [["Integrity", v.valid ? "Intact, complete and ordered: no statement changed, missing or out of place." : `Broken: ${v.error}${v.seq === null || v.seq === undefined ? "" : ` at seq ${v.seq}`}.`]];
	if (v.valid) {
		filas.push(
			["Provenance", `${v.company} · anchored by ${v.anchor} · keys from ${v.key_source}.`],
			["Authority", `Revision ${v.revision} approved · method ${v.approval}.`],
			["Declared result", `${v.final_state}, as the company asserts it.`],
			["Corroboration", `${(v.derived_assurance ?? []).join(", ") || "none"} · single_root ${v.single_root} · logged ${v.logged}.${v.single_root === "operator" ? " No independent confirmation: every signature traces back to the operator." : ""}`],
		);
	}
	dl.replaceChildren(...filas.flatMap(([k, t]) => {
		const dt = document.createElement("dt");
		dt.textContent = k;
		const dd = document.createElement("dd");
		dd.textContent = tapar(t);
		return [dt, dd];
	}));
}

async function verificar() {
	const boton = $("#run");
	boton.disabled = true;
	$(".vverdict__big").textContent = "Verifying…";
	try {
		const ej = valor("ex");
		let pkgText, matText, opText, naming;
		if (ej === "own") {
			pkgText = $("#in-pkg").value.trim();
			matText = $("#in-mat").value.trim();
			opText = $("#in-op").value.trim() || null;
			naming = $("#in-legacy").checked ? "legacy-0.1" : "vxp";
			if (!pkgText || !matText) throw new Error("Paste the package and the public material first.");
		} else {
			const e = EJEMPLOS[ej];
			[pkgText, matText, opText] = await Promise.all([texto(e.dir + e.pkg), texto(e.dir + e.mat), e.op ? texto(e.dir + e.op) : null]);
			naming = e.naming;
			({ pkgText, opText } = alterar(valor("tm"), pkgText, opText, e.campo));
		}
		const aud = valor("tm") === "aud" ? "https://another-agent.example/agent.json" : null;
		pintar(await verifyPackage({ package: pkgText, material: matText, operation: opText, aud, naming }));
	} catch (err) {
		const caja = $(".vverdict");
		caja.dataset.state = "invalid";
		$(".vverdict__big").textContent = "Could not verify";
		$(".vverdict__sub").textContent = String(err.message ?? err);
		$(".vchecks").replaceChildren();
	} finally {
		boton.disabled = false;
	}
}

document.querySelectorAll('input[name="ex"]').forEach((r) =>
	r.addEventListener("change", () => {
		const propio = valor("ex") === "own";
		const sinOperacion = !propio && !EJEMPLOS[valor("ex")].op;
		$(".vown").hidden = !propio;
		document.querySelectorAll('input[name="tm"]').forEach((t) => (t.disabled = (propio && t.value !== "none" && t.value !== "aud") || (sinOperacion && t.value === "term")));
		const marcado = document.querySelector('input[name="tm"]:checked');
		if (marcado.disabled) document.querySelector('input[name="tm"][value="none"]').checked = true;
	}),
);
$("#run").addEventListener("click", verificar);
$("#vectors").addEventListener("click", async () => {
	const out = $("#vectors-out");
	out.textContent = " running…";
	try {
		const r = await verifyVectors(await texto("../downloads/vectors/vectores-0.1.json"));
		out.textContent = ` ${r.total} checks, ${r.failures} failures.`;
	} catch (e) {
		out.textContent = " " + (e.message ?? e);
	}
});

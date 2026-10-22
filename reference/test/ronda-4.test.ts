// Review round 4: what the implementation did not model about a production operator, now in
// code and with tests that fail if it is removed.
//
// - M1: the `agente_personal` authority has its review rule written down and returns `review`; the
//   customer's decision and the company's are two, over the same digest, each with its principal.
// - M3: the truth of an operation comes from its execution (`tool.verified`), not from closing the case.
// - M5: WhatsApp approval honors the 24 h window, templates and consent;
//   if it is not delivered, the operation stays `proposed` and is not executed.
// - M6: the resource owner comes from the canonical customer ↔ ERP customer link and from a prior
//   read; Policy does not read the ERP.

import assert from "node:assert/strict";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import type { ActorExterno, Operacion } from "../src/nucleo.ts";
import { codigoVisible } from "../src/prueba.ts";
import { crearPuerta } from "../src/puerta.ts";

const T = "t_ferreteria_demo";
const puerta = crearPuerta({
	authOrigin: "https://auth.sovras.test",
	providerOrigin: "https://provider.sovras.test",
	empresas: empresasDePrueba({ ferreteria: "agentes.ferreteria-demo.test", libreria: "agentes.libreria-demo.test" }),
	pactDelegada: [T],
	plataformasPact: [],
	fetch: (input, init) => puerta.handler(new Request(input, init)),
});
const nucleo = puerta.nucleo;
const ferreteria = nucleo.empresa(T);
const ana = ferreteria.clientes.find((c) => c.id === "cli_a_ferreteria")!;
const ANA_TEL = "+56 9 0000 0101";

// This suite's own orders, belonging to Ana's ERP customer.
for (const id of ["P-4001", "P-4002", "P-4003", "P-4004", "P-4005", "P-4006"])
	ferreteria.sistema.pedidos.push({ id, clienteId: "ERP-C-0193", producto: "Caja de tornillos", despacho: "2026-10-24", direccion: "Calle Ejemplo 100, Santiago", estado: "preparando" });
// An order whose ERP owner has the SAME id as Ana's canonical customer at the operator: it is not
// hers. If the filter compared against the operator's id instead of the link, she would see it (M6).
ferreteria.sistema.pedidos.push({ id: "P-4099", clienteId: "cli_a_ferreteria", producto: "Pedido de otro", despacho: "2026-10-24", direccion: "Otra dirección", estado: "preparando" });

let n = 0;
function actorPact(clienteId = "cli_a_ferreteria"): ActorExterno {
	const grantId = `grant_r4_${++n}`;
	puerta.del.grants.set(grantId, {
		id: grantId,
		tenantId: T,
		protocolo: "pact",
		clientId: "https://pa-pact.test",
		sub: `pact-user-r4-${n}`,
		clienteId,
		alcances: ["pedidos:leer", "pedidos:modificar"],
		expira: Math.floor(Date.now() / 1000) + 3600,
		revocado: false,
		refreshVigente: "x",
		refreshUsados: new Set(),
	});
	return { tenantId: T, via: "agente_personal", protocolo: "pact", clientId: "https://pa-pact.test", sub: `pact-user-r4-${n}`, clienteId, alcances: ["pedidos:leer", "pedidos:modificar"], grantId };
}

function proponer(actor: ActorExterno, pedido: string, fecha: string, caseId = nucleo.abrirCaso(T, actor).id): Operacion {
	const r = nucleo.proponerReprogramacion(actor, caseId, pedido, fecha, null, { binding: "pact.message", text: `${pedido} al ${fecha}` });
	assert.ok(r.ok, JSON.stringify(r));
	return r.operacion;
}

const pedirAprobacion = (actor: ActorExterno, op: Operacion): string =>
	(Reflect.get(puerta.pact, "pedirAprobacion") as (...a: unknown[]) => string).call(puerta.pact, ferreteria, actor, op);
const eventos = (caseId: string) => nucleo.base(T).eventos.filter((e) => e.caseId === caseId);
const kinds = (op: Operacion) => nucleo.pruebas!.declaraciones(T, op.operation_id).map((d) => d.kind);

test("M1: con `toda_escritura`, Policy (agente_personal) pide revisión y hay dos decisiones sobre la misma huella", async () => {
	ferreteria.reglaRevisionAgentes = "toda_escritura";
	try {
		const actor = actorPact();
		// A one-day shift: the threshold rule does not require it; the authority rule does.
		const decision = nucleo.decidir(actor, { capability: "pedido.reprogramar_despacho", inputs: { pedidoId: "P-4001", nuevaFecha: "2026-10-25" }, reason: "x", expectedEffect: "write" });
		assert.equal(decision.decision, "review");
		assert.equal(decision.basis, "personal_agent_write_requires_company_review");
		const op = proponer(actor, "P-4001", "2026-10-25");
		const r = await nucleo.confirmar(actor, op, op.revision, "user");
		assert.equal(r.status, 200);
		assert.equal(op.state, "in_progress", "la aprobación del cliente no ejecuta: falta la de la empresa");
		assert.equal(nucleo.base(T).casos.get(op.interno.caseId)!.estado, "waiting_review");
		await nucleo.decidirRevision(T, op.interno.revisionEmpresa!.id, "aprobada");
		assert.equal(op.state, "succeeded");
		const ev = eventos(op.interno.caseId);
		const cliente = ev.find((e) => e.eventType === "customer.approved")!;
		const empresa = ev.find((e) => e.eventType === "review.decided")!;
		assert.equal((cliente.payload.principal as { tipo: string }).tipo, "cliente");
		assert.equal((empresa.payload.principal as { tipo: string }).tipo, "miembro_empresa");
		assert.equal(cliente.payload.huella, empresa.payload.huella, "las dos decisiones son sobre la misma huella");
		assert.ok(ev.findIndex((e) => e.eventType === "customer.approved") < ev.findIndex((e) => e.eventType === "review.decided"), "primero el cliente, después la empresa");
		const k = kinds(op);
		assert.ok(k.indexOf("user_approval") < k.indexOf("company_review") && k.indexOf("company_review") < k.indexOf("execution"));
	} finally {
		ferreteria.reglaRevisionAgentes = "regla_de_la_empresa";
	}
});

test("M1: con `regla_de_la_empresa`, la escritura queda sujeta sólo a la aprobación exacta del cliente", async () => {
	const actor = actorPact();
	const decision = nucleo.decidir(actor, { capability: "pedido.reprogramar_despacho", inputs: { pedidoId: "P-4002", nuevaFecha: "2026-10-25" }, reason: "x", expectedEffect: "write" });
	assert.equal(decision.decision, "allow");
	assert.equal(decision.basis, "delegated_scope_release_and_exact_customer_approval");
	const op = proponer(actor, "P-4002", "2026-10-25");
	assert.equal(op.state, "proposed", "proponer no ejecuta");
	assert.equal(op.user_approval_required, true);
	assert.equal(op.interno.revisionEmpresa, null);
	// A 20-day shift does trigger the company's rule, now decided by Policy.
	const larga = nucleo.decidir(actor, { capability: "pedido.reprogramar_despacho", inputs: { pedidoId: "P-4002", nuevaFecha: "2026-11-13" }, reason: "x", expectedEffect: "write" });
	assert.equal(larga.decision, "review");
	assert.equal(larga.basis, "company_rule_requires_review");
	nucleo.cancelar(T, op);
});

test("M3: dos operaciones en un mismo Case dan dos verificaciones y dos resultados, uno por ejecución", async () => {
	const actor = actorPact();
	const caso = nucleo.abrirCaso(T, actor);
	const a = proponer(actor, "P-4003", "2026-10-25", caso.id);
	const b = proponer(actor, "P-4004", "2026-10-26", caso.id);
	await nucleo.confirmar(actor, a, a.revision, "user");
	await nucleo.confirmar(actor, b, b.revision, "user");
	assert.equal(a.state, "succeeded");
	assert.equal(b.state, "succeeded");
	const verificadas = eventos(caso.id).filter((e) => e.eventType === "tool.verified").map((e) => e.payload.operation_id);
	assert.deepEqual(verificadas.sort(), [a.operation_id, b.operation_id].sort());
	assert.equal(eventos(caso.id).filter((e) => e.eventType === "outcome.verified").length, 0, "el cierre del Case no es la verdad de una operación");
	for (const op of [a, b]) assert.equal(kinds(op).filter((x) => x === "outcome").length, 1);
});

test("M5: fuera de la ventana de 24 h y sin plantilla, la aprobación no se entrega y la operación no se ejecuta", async () => {
	const antes = { ...ana.whatsapp };
	try {
		ana.whatsapp.ultimaEntrada = new Date(Date.now() - 25 * 3_600_000).toISOString();
		const actor = actorPact();
		const op = proponer(actor, "P-4005", "2026-10-25");
		const salidaAntes = nucleo.base(T).whatsappSalida.length;
		const texto = pedirAprobacion(actor, op);
		assert.match(texto, /últimas 24 horas/);
		assert.equal(nucleo.base(T).whatsappSalida.length, salidaAntes, "no salió ningún mensaje");
		assert.ok(eventos(op.interno.caseId).some((e) => e.eventType === "approval.not_delivered" && e.payload.motivo === "ventana_cerrada_sin_plantilla"));
		// A code that was never sent approves nothing.
		assert.equal(await puerta.pact.whatsappEntrante(T, ANA_TEL, `APROBAR ${codigoVisible(op.interno.termsDigest)}`), false);
		assert.equal(op.state, "proposed");
		// That message from Ana opened the window: the agent asks again and now it is delivered, as free text.
		pedirAprobacion(actor, op);
		const ultimo = nucleo.base(T).whatsappSalida.at(-1)!;
		assert.equal(ultimo.via, "ventana_de_servicio");
		assert.equal(await puerta.pact.whatsappEntrante(T, ANA_TEL, `APROBAR ${codigoVisible(op.interno.termsDigest)}`), true);
		assert.equal(op.state, "succeeded");
	} finally {
		Object.assign(ana.whatsapp, antes);
	}
});

test("M5: fuera de la ventana, con plantilla aprobada sale la plantilla; sin consentimiento de servicio no sale nada", () => {
	const antes = { ...ana.whatsapp };
	try {
		ana.whatsapp.ultimaEntrada = null;
		ferreteria.plantillasWhatsApp.aprobacion = true;
		const actor = actorPact();
		const op = proponer(actor, "P-4006", "2026-10-25");
		pedirAprobacion(actor, op);
		const ultimo = nucleo.base(T).whatsappSalida.at(-1)!;
		assert.equal(ultimo.via, "plantilla");
		assert.equal(ultimo.proposito, "aprobacion");
		assert.match(ultimo.texto, new RegExp(`APROBAR ${codigoVisible(op.interno.termsDigest)}`));
		// Outside the window, the linking code can only go in the authentication template,
		// which has fixed text: it does not name the agent.
		const otp = nucleo.enviarWhatsApp(T, ana, { proposito: "autenticacion", texto: "con agente", textoPlantilla: "123456 es tu código de verificación." });
		assert.deepEqual(otp, { entregado: true, via: "plantilla" });
		assert.doesNotMatch(nucleo.base(T).whatsappSalida.at(-1)!.texto, /agente/);
		// Without service consent, not even with the window open.
		ana.whatsapp.consentimientoServicio = null;
		ana.whatsapp.ultimaEntrada = new Date().toISOString();
		assert.deepEqual(nucleo.enviarWhatsApp(T, ana, { proposito: "aprobacion", texto: "x", textoPlantilla: "x" }), { entregado: false, motivo: "sin_consentimiento" });
		nucleo.cancelar(T, op);
	} finally {
		ferreteria.plantillasWhatsApp.aprobacion = false;
		Object.assign(ana.whatsapp, antes);
	}
});

test("M6: el dueño sale del vínculo con el ERP; sin vínculo, nada; lo ajeno y lo inexistente responden igual", () => {
	const actor = actorPact();
	const caso = nucleo.abrirCaso(T, actor);
	const leidos = nucleo.leerPedidos(actor, caso.id);
	assert.ok(leidos.ok);
	assert.ok(leidos.pedidos.some((p) => p.id === "P-1042"));
	assert.ok(!leidos.pedidos.some((p) => p.id === "P-4099"), "el filtro usa el cliente del ERP, no el id del operador");
	const ajeno = nucleo.proponerReprogramacion(actor, caso.id, "P-4099", "2026-10-25", null);
	const inexistente = nucleo.proponerReprogramacion(actor, caso.id, "P-0000", "2026-10-25", null);
	assert.deepEqual(ajeno, { ok: false, falta: "no_encontrado" });
	assert.deepEqual(inexistente, ajeno);
	// Without an ERP link: it neither reads nor writes, and externally responds the same as for a foreign resource.
	const vinculo = ana.erp;
	try {
		ana.erp = null;
		const sinVinculo = nucleo.leerPedidos(actor, caso.id);
		assert.ok(sinVinculo.ok);
		assert.equal(sinVinculo.pedidos.length, 0);
		assert.deepEqual(nucleo.proponerReprogramacion(actor, caso.id, "P-1042", "2026-10-25", null), ajeno);
		assert.equal(nucleo.decidir(actor, { capability: "pedido.reprogramar_despacho", inputs: { pedidoId: "P-1042", nuevaFecha: "2026-10-25" }, reason: "x", expectedEffect: "write" }).basis, "customer_not_linked_to_company_system");
	} finally {
		ana.erp = vinculo;
	}
});

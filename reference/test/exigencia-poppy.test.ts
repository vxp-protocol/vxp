// Stress sandbox: the SAME official Poppy validator (unmodified kit) against Hotel
// Demo and against Ferretería Demo with returns, on the gateway with all three companies. Copy of
// test/poppy-validador.test.ts, which keeps running unchanged over the usual companies. In-process. The https://*.test hosts resolve to the
// gateway and https://agent.test serves the identity of the test agent the validator generates.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { empresasDePrueba } from "../src/datos.ts";
import { hotelDePrueba, prepararDevoluciones } from "../src/datos-hotel.ts";
import { crearPuerta } from "../src/puerta.ts";
import { newContext } from "../vendor/poppy-kit/validate/checks/types.ts";
import { createHttp } from "../vendor/poppy-kit/validate/http.ts";
import { keygen } from "../vendor/poppy-kit/validate/identity.ts";
import { parseMilestones, runChecks } from "../vendor/poppy-kit/validate/run.ts";

const cwd = mkdtempSync(join(tmpdir(), "puerta-poppy-"));
await keygen("https://agent.test", { cwd });

function montar() {
	let puerta: ReturnType<typeof crearPuerta>;
	const red = async (input: string, init: RequestInit = {}): Promise<Response> => {
		const url = new URL(input);
		if (url.origin === "https://agent.test") {
			return new Response(readFileSync(join(cwd, ".poppy", url.pathname.slice(1)), "utf8"), {
				headers: { "content-type": "application/json" },
			});
		}
		return puerta.handler(new Request(input, init));
	};
	puerta = crearPuerta({
		authOrigin: "https://auth.sovras.test",
		providerOrigin: "https://provider.sovras.test",
		empresas: (() => {
			const e = empresasDePrueba({ ferreteria: "agentes.ferreteria-demo.test", libreria: "agentes.libreria-demo.test" });
			prepararDevoluciones(e[0]);
			return [...e, hotelDePrueba("reservas.hotel-demo.test")];
		})(),
		pactDelegada: [],
		plataformasPact: [],
		fetch: red,
	});
	return { puerta, red };
}

test("S2 · el validador oficial de Poppy pasa los hitos foundation + interfaces en el Hotel Demo", async () => {
	const { red } = montar();
	const http = createHttp({ fetch: red });
	const ctx = newContext(http, { milestones: parseMilestones("interfaces")! }, "https://reservas.hotel-demo.test");
	const results = await runChecks(ctx, { cwd });
	const resumen: Record<string, number> = {};
	for (const r of results) resumen[r.status] = (resumen[r.status] ?? 0) + 1;
	console.log("Poppy validator:", JSON.stringify(resumen));
	for (const r of results) if (r.status !== "pass") console.log(`  ${r.status.padEnd(4)} ${r.id}: ${r.got ?? ""} ${r.cause ?? ""}`.slice(0, 400));
	for (const n of ctx.notes) console.log("  nota:", n);
	const fallas = results.filter((r) => r.status === "fail");
	assert.deepEqual(fallas.map((r) => r.id), []);
	assert.ok(results.filter((r) => r.status === "pass").length >= 40);
});
test("S2 · el validador oficial de Poppy pasa los hitos foundation + interfaces en Ferretería Demo con devoluciones", async () => {
	const { red } = montar();
	const http = createHttp({ fetch: red });
	const ctx = newContext(http, { milestones: parseMilestones("interfaces")! }, "https://agentes.ferreteria-demo.test");
	const results = await runChecks(ctx, { cwd });
	const resumen: Record<string, number> = {};
	for (const r of results) resumen[r.status] = (resumen[r.status] ?? 0) + 1;
	console.log("Poppy validator:", JSON.stringify(resumen));
	for (const r of results) if (r.status !== "pass") console.log(`  ${r.status.padEnd(4)} ${r.id}: ${r.got ?? ""} ${r.cause ?? ""}`.slice(0, 400));
	for (const n of ctx.notes) console.log("  nota:", n);
	const fallas = results.filter((r) => r.status === "fail");
	assert.deepEqual(fallas.map((r) => r.id), []);
	assert.ok(results.filter((r) => r.status === "pass").length >= 40);
});

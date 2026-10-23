// Runs the conformance validator against the reference implementation, started here as a native-only gateway
// (no Poppy, no PACT) with persistent keys in a temporary directory.
// Usage, from the repository root: node conformance/reference/run.ts [--report <out.json>]

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const RAIZ = join(import.meta.dirname, "..", "..");
const PUERTO = 3740;
const AGENTE = 3890;
const tmp = mkdtempSync(join(tmpdir(), "vxp-conformance-"));
const origen = `http://localhost:${PUERTO}`;

const servidor = spawn(process.execPath, ["src/main.ts"], {
	cwd: join(RAIZ, "reference"),
	env: { ...process.env, PORT: String(PUERTO), PA_PORT: String(PUERTO + 2), ORIGENES_LOCALES: `http://localhost:${AGENTE}`, VXP_ADAPTERS: "none", VXP_KEYS_DIR: join(tmp, "keys"), VXP_DATOS_NEUTROS: "1" },
});
const llave = await new Promise<string>((ok, mal) => {
	const t = setTimeout(() => mal(new Error("the reference gateway did not start")), 20_000);
	servidor.stdout!.on("data", (d) => {
		const m = String(d).match(/llave interna: (\S+)/);
		if (m) {
			clearTimeout(t);
			ok(m[1]);
		}
	});
});

const config = {
	domain: `localhost:${PUERTO}`,
	scheme: "http",
	agentOrigin: `http://localhost:${AGENTE}`,
	agentPort: AGENTE,
	operation: { operation: "pedido.reprogramar_despacho", target: { order_ref: "P-1042" }, parameters: { delivery_date: "2026-10-28" } },
	counter: { proposed_terms: { delivery_date: "2026-10-29" }, note: "One day later works too." },
	relationship: { actions: ["despacho.proponer_cambio", "alerta.confirmar_o_bloquear"], limits: { max_per_day: 3, duration_seconds: 3600 } },
	approve: { command: `node "${join(RAIZ, "conformance", "reference", "approve.mjs")}"` },
	companyRequest: { command: `node "${join(RAIZ, "conformance", "reference", "company-request.mjs")}"`, proposalAction: "despacho.proponer_cambio", questionAction: "alerta.confirmar_o_bloquear" },
};
const cfgPath = join(tmp, "config.json");
writeFileSync(cfgPath, JSON.stringify(config, null, 2));
const args = [join(RAIZ, "conformance", "validate.ts"), cfgPath, ...process.argv.slice(2)];
const r = spawnSync(process.execPath, args, {
	stdio: "inherit",
	env: {
		...process.env,
		REF_ORIGIN: origen,
		REF_INTERNAL_KEY: llave,
		REF_TENANT: "t_ferreteria_demo",
		REF_PHONE: "+56 9 0000 0101",
		REF_PROPOSAL_PARAMS: JSON.stringify({ order_ref: "P-1043", delivery_date: "2026-10-30" }),
		REF_QUESTION_PARAMS: JSON.stringify({ order_ref: "P-1043", summary: "An unusual delivery change was requested for this order. Confirm or block it." }),
	},
});
servidor.kill();
process.exit(r.status ?? 1);

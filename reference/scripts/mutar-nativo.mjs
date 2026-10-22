// Design 0.1 mutations: turns off ONE protection at a time (src/mutar.ts) and requires
// test/nativo.test.ts to fail. Without a mutation, it must pass in full. Usage: node scripts/mutar-nativo.mjs
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const raiz = join(dirname(fileURLToPath(import.meta.url)), "..");
const MUTACIONES = [
	["condicion", "1a: la condición carrier_acceptance se da por cumplida sin preguntar"],
	["efectos_parciales", "1b: el rechazo del transportista no declara ni compensa el efecto en el ERP"],
	["limite_revisiones", "2: sin máximo de revisiones"],
	["vigencia", "2: una propuesta vencida se puede aceptar"],
	["intentos", "2: sin límite de intentos de aceptación"],
	["cancelacion_honesta", "3: cancelar durante la ejecución marca `cancelled` y promete «sin cambios»"],
	["separar_protocolos", "4: el dueño de una operación no incluye el protocolo"],
	["telefono_ambiguo", "4b: un número compartido vincula al primer cliente que coincide"],
	["rar_por_pedido", "5: el grant RFC 9396 se revisa por acción, no por pedido"],
	["reverificar_al_aceptar", "5: accept no vuelve a verificar el grant"],
	["sin_reintento", "6: leer vuelve a pedirle el cambio al transportista"],
	["no_failed_incierto", "6: sin respuesta del transportista → failed"],
	["idempotencia", "7: se ignora Idempotency-Key"],
	["transiciones_legales", "8: cualquier transición es legal"],
	["proyeccion", "9: la proyección filtra el valor nativo a Poppy/A2A"],
];

const correr = (mut) =>
	spawnSync(process.execPath, ["--test", "test/nativo.test.ts"], { cwd: raiz, encoding: "utf8", env: { ...process.env, SOVRAS_MUTAR: mut } });

const base = correr("");
const resumen = (out) => (out.match(/^# (pass|fail) \d+/gm) ?? []).join(", ");
console.log(`sin mutación: exit ${base.status} (${resumen(base.stdout)})`);
if (base.status !== 0) process.exit(1);
let detectadas = 0;
for (const [m, que] of MUTACIONES) {
	const r = correr(m);
	const fallan = (r.stdout.match(/^not ok \d+ - (.*)$/gm) ?? []).map((l) => l.replace(/^not ok \d+ - /, "").slice(0, 60));
	const ok = r.status !== 0;
	if (ok) detectadas++;
	console.log(`${ok ? "DETECTADA" : "NO DETECTADA"}  ${m.padEnd(24)} ${que}\n    fallan: ${fallan.join(" | ") || "—"}`);
}
console.log(`\nmutaciones detectadas: ${detectadas}/${MUTACIONES.length}`);
process.exit(detectadas === MUTACIONES.length ? 0 : 1);

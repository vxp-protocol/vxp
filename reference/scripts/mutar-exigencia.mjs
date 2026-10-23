// Stress-sandbox mutations: turns off ONE new protection at a time (src/mutar.ts) and requires
// test/exigencia.test.ts to fail. Without a mutation, it must pass in full. Usage: node scripts/mutar-exigencia.mjs
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const raiz = join(dirname(fileURLToPath(import.meta.url)), "..");
const MUTACIONES = [
	["precondicion_conector", "HO-C2: se reserva aunque el PMS ya no tenga la habitación"],
	["tope_conector", "B-H: se acepta sobre el monto que autorizó el cliente (sin ampliación)"],
	["ampliacion_nueva_solicitud", "B-H/HO-N3: tras el permiso nuevo se abre otra solicitud en vez de seguir la misma"],
	["aceptar_con_permiso_del_llamador", "B-H: la propuesta de la relación se evalúa con el permiso del token y no con el de la relación"],
	["pago_sin_reconciliar", "HO-C4: sin respuesta del pago, se vuelve a cobrar en vez de consultar"],
	["lectura_pago_ignorada", "HO-A2: la lectura de vuelta no mira el libro de pagos"],
	["cargo_vigente", "HO-A3: se cancela con el cargo aprobado aunque ya no sea el que corresponde"],
	["revision_conector", "HO-A4: un cambio a menos de 72 h no espera a una persona del hotel"],
	["canal_manda", "HO-C5: el channel manager manda sobre el PMS"],
	["tarifa_citada", "HO-A1: se iguala una tarifa que sólo dice el agente"],
	["servicio_inventado", "HO-A1: se responde como si el hotel ofreciera spa"],
	["doble_devolucion", "CO-A: un pedido ya devuelto se devuelve otra vez"],
	["plazo_devolucion", "CO-A: se devuelve fuera de plazo"],
	["relacion_recurso_ajeno", "RE-A: la empresa escribe al agente sobre la reserva de otro cliente"],
	["acceso_sin_registro", "B-H/S1/HO-A6: sin registro de accesos no hay atribución"],
	["permanente_conector_sin_tope", "NH-P: con permiso de antemano, una revisión sobre el tope se acepta sin preguntar"],
	["chat_sin_respuesta", "NH-C: una consulta de cuenta en el chat se queda sin respuesta"],
	// relacion_otra_identidad is a second layer behind the client_id + sub lookup of the proposal (NH-I): no API path reaches it alone.
];

const correr = (mut) => spawnSync(process.execPath, ["--test", "test/exigencia.test.ts"], { cwd: raiz, encoding: "utf8", env: { ...process.env, SOVRAS_MUTAR: mut } });
const resumen = (out) => (out.match(/^# (pass|fail) \d+/gm) ?? []).join(", ");
const base = correr("");
console.log(`sin mutación: exit ${base.status} (${resumen(base.stdout)})`);
if (base.status !== 0) process.exit(1);
let detectadas = 0;
for (const [m, que] of MUTACIONES) {
	const r = correr(m);
	const fallan = (r.stdout.match(/^not ok \d+ - (.*)$/gm) ?? []).map((l) => l.replace(/^not ok \d+ - /, "").slice(0, 40));
	const ok = r.status !== 0;
	if (ok) detectadas++;
	console.log(`${ok ? "DETECTADA" : "NO DETECTADA"}  ${m.padEnd(34)} ${que}\n    fallan: ${fallan.join(" | ") || "—"}`);
}
console.log(`\nmutaciones detectadas: ${detectadas}/${MUTACIONES.length}`);
process.exit(detectadas === MUTACIONES.length ? 0 : 1);

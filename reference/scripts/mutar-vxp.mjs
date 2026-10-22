// VXP mutations: turns off ONE protection at a time (src/mutar.ts) and requires test/vxp.test.ts
// to fail. Without a mutation, it must pass in full. Usage: node scripts/mutar-vxp.mjs
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const raiz = join(dirname(fileURLToPath(import.meta.url)), "..");
const MUTACIONES = [
	["sin_lectura_succeeded", "C3: una capacidad sin lectura de vuelta se trata como si pudiera comprobarse"],
	["contradiccion_es_exito", "C2: una lectura que contradice lo aprobado se da por éxito"],
	["no_failed_incierto", "C1: sin respuesta del transportista → failed"],
	["escritura_en_canal", "D1: un asistente sospechado puede pedir escrituras por el canal"],
	["telefono_ambiguo", "D2: un número compartido identifica al primer cliente"],
	["relacion_revocada", "E4/E5: una relación revocada sigue valiendo"],
	["relacion_vencida", "E5: una relación vencida sigue valiendo"],
	["accion_relacion", "E3: la empresa inicia acciones que la relación no incluye"],
	["limite_relacion", "E3: sin tope por día"],
	["relacion_sin_grant", "E5: la relación sobrevive a la revocación de la delegación"],
	["sin_carriles", "F1/F1b: sin cupos, un agente insistente no tiene techo"],
	["sin_tope_otp", "F2: un agente puede bombardear a una persona con códigos"],
	["alerta_opcion_libre", "F5: el agente responde algo distinto de confirmar o bloquear"],
	["alerta_dos_respuestas", "F5: una alerta se responde dos veces"],
	["alerta_vencida", "F5: una alerta vencida se puede responder"],
	["tope_compra", "G3: se acepta una compra sobre el monto que aprobó el cliente"],
	["precondicion_compra", "G3: se crea el pedido aunque ya no haya stock"],
	["permanente_sin_tope", "H4: el permiso permanente cierra pedidos sobre el tope"],
	["permisos_suman", "H3: ampliar un permiso concede más de lo pedido (Poppy §4.4)"],
	["cotizacion_por_conversacion", "H2: al reconectarse se pierde la cotización y se cotiza de cero"],
	["cambio_nulo", "H1d: se propone «cambiar» a la fecha que ya tiene"],
	// `reverificar_al_aceptar` and `separar_protocolos` are covered by scripts/mutar-nativo.mjs (test/nativo.test.ts).
];

const correr = (mut) =>
	spawnSync(process.execPath, ["--test", "test/vxp.test.ts"], { cwd: raiz, encoding: "utf8", env: { ...process.env, SOVRAS_MUTAR: mut } });

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

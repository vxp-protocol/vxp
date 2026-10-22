// Evidence collector for a run with real agents against the stress sandbox.
//
// Exports, into a dated folder, everything the SERVER recorded (never what an agent said):
//   accesses (method, path, status, user-agent, lane, client_id, latency), case events, chat
//   sessions, Web Bot Auth signatures, simulated WhatsApp output, VXP Relationship output, final
//   state of the systems (orders, bookings, payments and their reconciliation, inventory), every VXP
//   Proof package verified with verifier/verificar_paquete.py, the log checkpoint and,
//   optionally, an RFC 3161 timestamp of the checkpoint (--sello; FreeTSA by default).
//
// Attribution comes from the log: the token's client_id (Poppy, PACT, native), the chat session,
// the verified Web Bot Auth operator and the user-agent. Whatever carries no credential stays «sin credencial»:
// it is never attributed to an agent by guesswork.
//
// Usage: node scripts/recolectar-evidencia.mjs --base http://localhost:3600 --llave <internal key>
//        [--salida evidencia] [--etiqueta corrida-1] [--sello] [--tsa https://freetsa.org/tsr]
//      (the internal key comes from the «llave interna:» line of the server log)

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERIFICADOR = join(RAIZ, "..", "verifier", "verificar_paquete.py");
const arg = (n, def) => {
	const i = process.argv.indexOf(`--${n}`);
	return i >= 0 ? (process.argv[i + 1] ?? true) : def;
};
const BASE = String(arg("base", "http://localhost:3600")).replace(/\/$/, "");
const LLAVE = String(arg("llave", process.env.LLAVE_INTERNA ?? ""));
const SELLO = process.argv.includes("--sello");
const TSA = String(arg("tsa", "https://freetsa.org/tsr"));
if (!LLAVE) {
	console.error("falta --llave (la llave interna del servidor)");
	process.exit(2);
}
const sello = new Date().toISOString().replace(/[:.]/g, "-");
const DIR = join(String(arg("salida", join(RAIZ, "evidencia"))), `${sello}${arg("etiqueta") ? `-${arg("etiqueta")}` : ""}`);
mkdirSync(join(DIR, "paquetes"), { recursive: true });

const interno = async (ruta) => {
	const r = await fetch(`${BASE}/interno/${ruta}`, { headers: { "x-sovras-prueba": LLAVE } });
	if (!r.ok) throw new Error(`/interno/${ruta} → ${r.status}`);
	return r.json();
};
const guardar = (nombre, valor) => writeFileSync(join(DIR, nombre), typeof valor === "string" ? valor : JSON.stringify(valor, null, 2));

const { tenants } = await interno("tenants");
const accesos = await interno("accesos");
guardar("accesos.json", accesos);
const csv = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
guardar("accesos.csv", ["seq,at,metodo,ruta,estado,latencia_ms,carril,protocolo,client_id,sub,sesion_chat,wba_operador,wba_verificada,ip,user_agent", ...accesos.accesos.map((a) => [a.seq, a.at, a.metodo, a.ruta, a.estado, a.latencia_ms, a.carril, a.protocolo, a.client_id, a.sub, a.sesion_chat, a.wba?.operador, a.wba?.verificada, a.ip, a.ua].map(csv).join(","))].join("\n"));

const resultados = [];
for (const t of tenants) {
	const q = `tenant=${t.tenantId}`;
	const estado = await interno(`estado?${q}`);
	guardar(`${t.slug}-estado.json`, estado);
	guardar(`${t.slug}-casos.json`, await interno(`casos?${q}`));
	guardar(`${t.slug}-chat.json`, await interno(`chat?${q}`));
	guardar(`${t.slug}-whatsapp-salida.json`, await interno(`whatsapp/salida?${q}`));
	guardar(`${t.slug}-relaciones-salida.json`, await interno(`relaciones/salida?${q}`));
	guardar(`${t.slug}-feedback.json`, await interno(`feedback?${q}`));
	for (const op of estado.operaciones) {
		const paquete = await interno(`paquete?${q}&op=${op.operation_id}`).catch(() => null);
		if (!paquete) continue;
		const f = join(DIR, "paquetes", `${t.slug}-${op.operation_id}.json`);
		writeFileSync(f, JSON.stringify(paquete, null, 2));
		const opf = join(DIR, "paquetes", `${t.slug}-${op.operation_id}.op.json`);
		writeFileSync(opf, JSON.stringify(op.visible));
		const args = [VERIFICADOR, "vivo", "--issuer", estado.issuer, "--paquete", f, "--aud", op.dueno.clientId, "--operacion", opf];
		if (estado.issuer.startsWith("http://")) args.splice(2, 0, "--http-local");
		const v = spawnSync("python", args, { encoding: "utf8" });
		let veredicto;
		try {
			veredicto = JSON.parse(v.stdout.trim().split("\n").at(-1));
		} catch {
			veredicto = { valid: false, error: "verificador_sin_salida", stderr: v.stderr.slice(0, 500) };
		}
		resultados.push({ tenant: t.slug, operation_id: op.operation_id, capability: op.capability, estado_nativo: op.nativo, protocolo: op.dueno.protocolo, client_id: op.dueno.clientId, sub: op.dueno.sub, veredicto });
	}
	guardar("webbotauth.json", await interno(`webbotauth?${q}`));
}
guardar("verificacion-paquetes.json", resultados);

// Attribution: only from what the server saw.
const actores = new Map();
for (const a of accesos.accesos) {
	const clave = a.client_id ? `client_id:${a.client_id}${a.sub ? `#${a.sub}` : ""}` : a.wba?.verificada ? `web_bot_auth:${a.wba.operador}` : a.sesion_chat ? `chat:${a.sesion_chat}` : `sin_credencial:${a.ua ?? "-"}|${a.ip ?? "-"}`;
	const x = actores.get(clave) ?? { actor: clave, peticiones: 0, primera: a.at, ultima: a.at, rutas: {}, estados: {}, carriles: {}, user_agents: new Set(), latencia_total_ms: 0 };
	x.peticiones += 1;
	x.ultima = a.at;
	const ruta = `${a.metodo} ${a.ruta.replace(/(op|req|cnv|rel|prop|ses)_[A-Za-z0-9_-]+/g, "$1_…")}`;
	x.rutas[ruta] = (x.rutas[ruta] ?? 0) + 1;
	x.estados[a.estado] = (x.estados[a.estado] ?? 0) + 1;
	if (a.carril) x.carriles[a.carril] = (x.carriles[a.carril] ?? 0) + 1;
	if (a.ua) x.user_agents.add(a.ua);
	x.latencia_total_ms += a.latencia_ms ?? 0;
	actores.set(clave, x);
}
const atribucion = [...actores.values()].map((x) => ({ ...x, user_agents: [...x.user_agents], operaciones: resultados.filter((r) => x.actor.startsWith(`client_id:${r.client_id}`)).map((r) => `${r.tenant}/${r.operation_id} ${r.capability} → ${r.estado_nativo} (verificador: ${r.veredicto.valid ? `válido, ${r.veredicto.final_state}` : `NO válido: ${r.veredicto.error}`})`) }));
guardar("atribucion.json", atribucion);

// Log checkpoint and, if requested, an RFC 3161 timestamp.
const cp = await fetch(`${BASE}/vxp/log/checkpoint`).then((r) => r.text());
guardar("checkpoint.jwt", cp);
let selloInfo = "no pedido";
if (SELLO) {
	const q = spawnSync("openssl", ["ts", "-query", "-data", join(DIR, "checkpoint.jwt"), "-sha256", "-cert", "-out", join(DIR, "checkpoint.tsq")], { encoding: "utf8" });
	if (q.status !== 0) selloInfo = `openssl no generó la consulta: ${q.stderr.slice(0, 200)}`;
	else {
		const r = await fetch(TSA, { method: "POST", headers: { "content-type": "application/timestamp-query" }, body: readFileSync(join(DIR, "checkpoint.tsq")) }).catch((e) => ({ ok: false, status: String(e) }));
		if (!r.ok) selloInfo = `la TSA respondió ${r.status}`;
		else {
			writeFileSync(join(DIR, "checkpoint.tsr"), Buffer.from(await r.arrayBuffer()));
			const txt = spawnSync("openssl", ["ts", "-reply", "-in", join(DIR, "checkpoint.tsr"), "-text"], { encoding: "utf8" });
			guardar("checkpoint.tsr.txt", txt.stdout);
			selloInfo = `${TSA}: ${(txt.stdout.match(/Time stamp: (.*)/) ?? [])[1] ?? "respuesta guardada"}`;
		}
	}
}

// Readable summary and manifest with digests.
const filas = atribucion.sort((a, b) => b.peticiones - a.peticiones).map((x) => `| ${x.actor.slice(0, 90)} | ${x.peticiones} | ${x.primera.slice(11, 19)}–${x.ultima.slice(11, 19)} | ${Object.entries(x.estados).map(([k, v]) => `${k}×${v}`).join(" ")} | ${Object.entries(x.carriles).map(([k, v]) => `${k}×${v}`).join(" ")} | ${x.operaciones.length} |`);
const ops = resultados.map((r) => `| ${r.tenant} | ${r.operation_id} | ${r.capability} | ${r.protocolo} | ${r.client_id.slice(0, 60)} | ${r.estado_nativo} | ${r.veredicto.valid ? `válido (${r.veredicto.final_state})` : `NO: ${r.veredicto.error}`} |`);
guardar("RESUMEN.md", `# Evidencia ${sello}\n\nBase: ${BASE}. Todo sale del registro del servidor; lo que no trae credencial no se atribuye a ningún agente.\n\n## Actores (por credencial, sesión de chat, Web Bot Auth o user-agent)\n\n| Actor | Peticiones | Ventana (UTC) | Estados HTTP | Carriles | Operaciones |\n|---|---|---|---|---|---|\n${filas.join("\n")}\n\n## Operaciones y verificación independiente\n\n| Empresa | Operación | Capacidad | Protocolo | client_id | Estado | Verificador |\n|---|---|---|---|---|---|---|\n${ops.join("\n") || "| — | — | — | — | — | — | — |"}\n\n## Checkpoint\n\nSello RFC 3161: ${selloInfo}\n`);
const manifiesto = {};
const recorrer = (d, pre = "") => {
	for (const n of readdirSync(d, { withFileTypes: true })) {
		if (n.isDirectory()) recorrer(join(d, n.name), `${pre}${n.name}/`);
		else manifiesto[`${pre}${n.name}`] = `sha-256:${createHash("sha256").update(readFileSync(join(d, n.name))).digest("base64url")}`;
	}
};
recorrer(DIR);
guardar("MANIFIESTO.json", manifiesto);
const malos = resultados.filter((r) => !r.veredicto.valid).length;
console.log(`evidencia en ${DIR}\n  accesos: ${accesos.accesos.length}  actores: ${atribucion.length}  paquetes: ${resultados.length} (no válidos: ${malos})  sello: ${selloInfo}`);

// Starts the gateway on node:http (local development) and, if requested, a test personal agent
// that only publishes its JWKS. Variables: PORT, PA_PORT, PA_PUBLIC_JWK (JSON).
//
// Stress-test sandbox: besides Ferretería Demo (with returns) it serves Hotel Demo
// (fictitious) on ANOTHER domain. HOTEL_ORIGIN is the hotel's public origin (e.g. a second https
// tunnel to the SAME port); by default, http://127.0.0.1:<PORT>. The gateway routes by the Host header.

import { createServer, type IncomingMessage } from "node:http";
import { empresasDePrueba } from "./datos.ts";
import { T_HOTEL, hotelDePrueba, prepararDevoluciones } from "./datos-hotel.ts";
import { crearPuerta } from "./puerta.ts";
import { Carriles } from "./carriles.ts";

const port = Number(process.env.PORT ?? 3100);
const paPort = Number(process.env.PA_PORT ?? 3102);
// PUBLIC_ORIGIN: public origin (e.g. an https tunnel) when the sandbox is exposed to external validators.
const origen = process.env.PUBLIC_ORIGIN ?? `http://localhost:${port}`;
const paIssuer = `http://localhost:${paPort}`;
const origenHotel = process.env.HOTEL_ORIGIN ?? `http://127.0.0.1:${port}`;
let empresas = empresasDePrueba({ ferreteria: new URL(origen).host, libreria: "libreria-demo.localhost" });
prepararDevoluciones(empresas[0]);
empresas.push(hotelDePrueba(new URL(origenHotel).host));
let delegadas = ["t_ferreteria_demo", T_HOTEL];

// VXP_DATOS_NEUTROS=1: the same test companies with neutral names, customers and addresses, for
// screenshots published signed (Oct 22). The tests do not use it and keep the usual data.
if (process.env.VXP_DATOS_NEUTROS === "1") {
	const NEUTROS: [string, string][] = [
		["t_ferreteria_demo", "t_ferreteria_demo"], ["t_hotel_demo", "t_hotel_demo"], ["t_libreria_demo", "t_libreria_demo"],
		["ferreteria-demo", "ferreteria-demo"], ["hotel-demo", "hotel-demo"], ["libreria-demo", "libreria-demo"],
		["Ferretería Demo", "Ferretería Demo"], ["Hotel Demo", "Hotel Demo"], ["Librería Demo", "Librería Demo"],
		["Cliente de prueba A", "Cliente de prueba A"], ["Cliente de prueba B", "Cliente de prueba B"],
		["cli_a_ferreteria", "cli_a_ferreteria"], ["cli_b_ferreteria", "cli_b_ferreteria"], ["cli_a_hotel", "cli_a_hotel"], ["cli_b_hotel", "cli_b_hotel"], ["cli_a_libreria", "cli_a_libreria"],
		["Calle Ejemplo 100, Santiago", "Calle Ejemplo 100, Santiago"], ["Calle Ejemplo 200, Concepción", "Calle Ejemplo 200, Concepción"],
	];
	const neutro = (s: string) => NEUTROS.reduce((x, [a, b]) => x.split(a).join(b), s);
	const recorrer = (v: unknown): unknown => {
		if (typeof v === "string") return neutro(v);
		if (Array.isArray(v)) return v.map(recorrer);
		if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
			for (const k of Object.keys(v)) (v as Record<string, unknown>)[k] = recorrer((v as Record<string, unknown>)[k]);
		}
		return v;
	};
	empresas = recorrer(empresas) as typeof empresas;
	delegadas = delegadas.map(neutro);
}

const puerta = crearPuerta({
	authOrigin: origen,
	providerOrigin: origen,
	empresas,
	pactDelegada: delegadas,
	plataformasPact: [
		{ nombre: "pa-de-prueba", issuer: paIssuer, jwksUri: `${paIssuer}/jwks.json`, enabled: true },
		{ nombre: "pa-deshabilitado", issuer: `${paIssuer}/disabled-pa`, jwksUri: `${paIssuer}/jwks.json`, enabled: false },
	],
	// ORIGENES_LOCALES: http:// origins of test agents (comma-separated), e.g. the one for the VXP network walkthrough.
	origenesLocales: [paIssuer, origen, origenHotel, ...(process.env.ORIGENES_LOCALES ?? "").split(",").filter(Boolean)],
	// VXP_CARRILES=1: lanes and anti-persistence caps active (public sandbox). The Poppy and PACT contract
	// suites run without them because they repeat linkings of the same number within seconds.
	carriles: process.env.VXP_CARRILES === "1" ? new Carriles() : null,
	// Persistent proof keys: with VXP_KEYS_DIR, the operator, log and company keys survive restarts and rotations keep earlier public keys published.
	dirLlaves: process.env.VXP_KEYS_DIR ?? null,
	// VXP_ADAPTERS=none serves the native profile only (no poppy.json, Agent Card, A2A or Poppy endpoints); "poppy" or "pact" keeps just that one.
	adaptadores: process.env.VXP_ADAPTERS === undefined ? undefined : { poppy: /poppy/.test(process.env.VXP_ADAPTERS), pact: /pact/.test(process.env.VXP_ADAPTERS) },
});

async function leer(req: IncomingMessage): Promise<Buffer> {
	const chunks: Buffer[] = [];
	for await (const c of req) chunks.push(c as Buffer);
	return Buffer.concat(chunks);
}

createServer(async (req, res) => {
	const body = req.method === "GET" || req.method === "HEAD" ? undefined : await leer(req);
	const headers = new Headers();
	for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
	// The origin comes from the Host header only if it is one of the known public ones (the hotel); otherwise, the default.
	const base = (req.headers.host ?? "").toLowerCase() === new URL(origenHotel).host.toLowerCase() ? origenHotel : origen;
	const response = await puerta.handler(new Request(`${base}${req.url}`, { method: req.method, headers, body }));
	// Simulated dropped connection (/interno/condiciones `cortar_respuestas`): the socket is cut without responding.
	if (response.headers.get("x-sovras-corte")) {
		req.socket.destroy();
		return;
	}
	res.writeHead(response.status, Object.fromEntries(response.headers));
	res.end(Buffer.from(await response.arrayBuffer()));
}).listen(port, () => console.log(`[puerta] ${origen}  hotel: ${origenHotel}  llave interna: ${puerta.llaveInterna}`));

if (process.env.PA_PUBLIC_JWK) {
	const jwk = JSON.parse(process.env.PA_PUBLIC_JWK);
	createServer((req, res) => {
		res.writeHead(req.url === "/jwks.json" ? 200 : 404, { "content-type": "application/json" });
		res.end(req.url === "/jwks.json" ? JSON.stringify({ keys: [jwk] }) : "{}");
	}).listen(paPort, () => console.log(`[agente de prueba] JWKS en ${paIssuer}/jwks.json`));
}

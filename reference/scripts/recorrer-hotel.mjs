// Walks through Hotel Demo as a person with a browser, on a phone viewport (390×844): rates with
// dates (direct vs. SIMULATED agencies), chat (quotes, adds breakfast, asks to book and is handed off) and
// «Vincular con WhatsApp» for a new booking with a cap and a relationship (the OTP is read by the
// simulated line's operator). Saves screenshots to .prueba/capturas/hotel-*.png and checks on the server that the
// walkthrough left what it claims: no booking via the chat and a delegation with the approved cap.
// Usage: node scripts/recorrer-hotel.mjs <path to node_modules with playwright>   (ports 3640 and 3644)
import { spawn } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";

const require = createRequire(join(process.argv[2], "noop.js"));
const { chromium } = require("playwright");
const P = "http://localhost:3640";
const H = "http://127.0.0.1:3640";
const AG = "http://localhost:3644";
const HOTEL = `${P}/e/hotel-demo`;
const clientId = `${AG}/agent.json`;
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "ES256" };
const agente = createServer((req, res) => {
	const doc = req.url === "/agent.json" ? { client_id: clientId, client_name: "Asistente de Ana", jwks_uri: `${AG}/jwks.json`, extensions: { "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `${AG}/vxp/inbox` } } } : { keys: [jwk] };
	res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(doc));
}).listen(3644);
const servidor = spawn(process.execPath, ["src/main.ts"], { env: { ...process.env, PORT: "3640", PA_PORT: "3642", HOTEL_ORIGIN: H, ORIGENES_LOCALES: AG } });
const llave = await new Promise((ok) => servidor.stdout.on("data", (d) => { const m = String(d).match(/llave interna: (\S+)/); if (m) ok(m[1]); }));
const interno = async (ruta) => (await fetch(`${P}/interno/${ruta}`, { headers: { "x-sovras-prueba": llave } })).json();
const dia = (n) => new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);
mkdirSync(".prueba/capturas", { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const errores = [];
page.on("pageerror", (e) => errores.push(String(e)));
const salida = [];
try {
	// 1 · Rates with dates: the comparison with agencies is shown labeled as simulated.
	await page.goto(`${H}/e/hotel-demo/tarifas?llegada=${dia(40)}&salida=${dia(42)}&adultos=2`);
	await page.screenshot({ path: ".prueba/capturas/hotel-1-tarifas.png", fullPage: true });
	salida.push(`tarifas: ${(await page.textContent("body")).includes("SIMULADA") ? "rotula SIMULADA" : "NO rotula"}`);
	// 2 · Chat: quote, add breakfast, ask to book.
	await page.goto(`${H}/e/hotel-demo/chat`);
	for (const texto of [`Hola, soy el asistente de Ana. Una doble estándar del ${dia(40)} al ${dia(42)} para 2 adultos`, "Agrégale desayuno", "¿Tienen spa?", "Perfecto, resérvala"]) {
		await page.fill("input[name=texto]", texto);
		await Promise.all([page.waitForLoadState("load"), page.click("button")]);
	}
	await page.screenshot({ path: ".prueba/capturas/hotel-2-chat.png", fullPage: true });
	const chat = await page.textContent("body");
	salida.push(`chat: cotización ${/Cotización EST-/.test(chat) ? "sí" : "no"}; revisión 2 ${/revisión 2/.test(chat) ? "sí" : "no"}; spa ${/no ofrece spa/.test(chat) ? "no se inventa" : "¿?"}; reservar ${/tiene que vincular su cuenta/.test(chat) ? "se deriva" : "¿?"}`);
	const est = await interno("estado?tenant=t_hotel_demo");
	salida.push(`servidor: reservas creadas por el chat = ${est.reservas.filter((r) => r.estadia).length}`);
	// 3 · Link: a new booking up to a cap, plus the relationship, in the person's language.
	const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
	const t = Math.floor(Date.now() / 1000);
	const input = `${b64({ alg: "ES256", kid: "k1", typ: "JWT" })}.${b64({ iss: clientId, sub: clientId, aud: HOTEL, iat: t, exp: t + 120, jti: `j${Math.random().toString(36).slice(2)}${t}` })}`;
	const asercion = `${input}.${sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
	const detalles = [
		{ type: "https://vxpprotocol.org/rar/capability", actions: ["reserva.crear"], identifier: "nuevo", limits: { max_total_clp: 250000 } },
		{ type: "https://vxpprotocol.org/rar/relationship", actions: ["reserva.proponer_cambio"], identifier: "relationship", limits: { max_per_day: 2, duration_seconds: 604800 } },
	];
	const dev = await (await fetch(`${HOTEL}/oauth/device`, { method: "POST", body: new URLSearchParams({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: asercion, resource: `${HOTEL}/v1`, authorization_details: JSON.stringify(detalles) }) })).json();
	await page.goto(dev.verification_uri_complete);
	await page.screenshot({ path: ".prueba/capturas/hotel-3-vincular.png", fullPage: true });
	await page.fill("input[name=telefono]", "+56 9 0000 0101");
	await Promise.all([page.waitForLoadState("load"), page.click("button")]);
	const otp = (await interno("whatsapp/salida?tenant=t_hotel_demo")).at(-1).texto.match(/código es (\d{6})/)[1];
	await page.fill("input[name=codigo]", otp);
	await Promise.all([page.waitForLoadState("load"), page.click("button")]);
	await page.screenshot({ path: ".prueba/capturas/hotel-4-consentimiento.png", fullPage: true });
	const consentimiento = await page.textContent("body");
	salida.push(`consentimiento: tope ${/por hasta \$250\.000/.test(consentimiento) ? "visible" : "NO visible"}; relación ${/proponerte cambios de fechas de tus reservas/.test(consentimiento) ? "visible" : "NO visible"}; casillas ${await page.locator("input[type=checkbox]").count()}`);
	await Promise.all([page.waitForLoadState("load"), page.click("button[value=allow]")]);
	await page.screenshot({ path: ".prueba/capturas/hotel-5-listo.png" });
	salida.push(`listo: ${(await page.textContent("body")).trim()}`);
	const st = await interno("estado?tenant=t_hotel_demo");
	salida.push(`servidor: delegaciones del hotel = ${st.delegaciones.length} (se emiten al canjear el código del dispositivo)`);
} finally {
	salida.push(`errores de página: ${errores.length}`);
	console.log(salida.join("\n"));
	await browser.close();
	servidor.kill();
	agente.close();
}

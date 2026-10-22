// Walks through «Vincular con WhatsApp» with a requested bilateral relationship (VXP Relationship), on a
// phone viewport (390×844), against the live gateway on :3300 and a test agent on :3304.
// Usage: node scripts/recorrer-relacion.mjs <path to node_modules with playwright>
import { spawn } from "node:child_process";
import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";

const require = createRequire(join(process.argv[2], "noop.js"));
const { chromium } = require("playwright");
const P = "http://localhost:3300";
const AG = "http://localhost:3304";
const FERRETERIA = `${P}/e/ferreteria-demo`;
const clientId = `${AG}/agent.json`;
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "ES256" };
const agente = createServer((req, res) => {
	const doc = req.url === "/agent.json" ? { client_id: clientId, client_name: "Asistente de Ana", jwks_uri: `${AG}/jwks.json`, extensions: { "vxpprotocol.org/relationship": { version: "0.1", inbox_uri: `${AG}/vxp/inbox` } } } : { keys: [jwk] };
	res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(doc));
}).listen(3304);
const servidor = spawn(process.execPath, ["src/main.ts"], { env: { ...process.env, PORT: "3300", PA_PORT: "3302", ORIGENES_LOCALES: AG } });
const llave = await new Promise((ok) => servidor.stdout.on("data", (d) => { const m = String(d).match(/llave interna: (\S+)/); if (m) ok(m[1]); }));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const t = Math.floor(Date.now() / 1000);
const input = `${b64({ alg: "ES256", kid: "k1", typ: "JWT" })}.${b64({ iss: clientId, sub: clientId, aud: FERRETERIA, iat: t, exp: t + 120, jti: `j${Math.random().toString(36).slice(2)}${t}` })}`;
const asercion = `${input}.${sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
const detalles = [
	{ type: "https://vxpprotocol.org/rar/capability", actions: ["pedido.reprogramar_despacho"], identifier: "P-1042" },
	{ type: "https://vxpprotocol.org/rar/relationship", actions: ["despacho.proponer_cambio"], identifier: "relationship", limits: { max_per_day: 2, duration_seconds: 2592000 } },
];
const dev = await (await fetch(`${FERRETERIA}/oauth/device`, { method: "POST", body: new URLSearchParams({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: asercion, resource: `${FERRETERIA}/v1`, authorization_details: JSON.stringify(detalles) }) })).json();
mkdirSync(".prueba/capturas", { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const errores = [];
page.on("pageerror", (e) => errores.push(String(e)));
await page.goto(dev.verification_uri_complete);
await page.screenshot({ path: ".prueba/capturas/rel-1-enlace.png" });
await page.fill("input[name=telefono]", "+56 9 0000 0101");
await page.click("button");
const salida = await (await fetch(`${P}/interno/whatsapp/salida?tenant=t_ferreteria_demo`, { headers: { "x-sovras-prueba": llave } })).json();
const whatsapp = salida.at(-1).texto;
await page.fill("input[name=codigo]", whatsapp.match(/código es (\d{6})/)[1]);
await page.click("button");
await page.screenshot({ path: ".prueba/capturas/rel-2-consentimiento.png" });
const casillas = await page.$$eval("input[type=checkbox]", (xs) => xs.map((x) => x.value));
await page.click("button[value=allow]");
await page.screenshot({ path: ".prueba/capturas/rel-3-listo.png" });
await browser.close();
servidor.kill();
agente.close();
console.log(JSON.stringify({ whatsapp, casillas, errores }, null, 1));

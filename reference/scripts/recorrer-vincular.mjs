// Walks through «Vincular con WhatsApp» as a person, on a phone viewport (390×844), against the live gateway.
// Usage: node scripts/recorrer-vincular.mjs <path to node_modules with playwright>
import { createPrivateKey, sign } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const require = createRequire(join(process.argv[2], "noop.js"));
const { chromium } = require("playwright");
const P = "http://localhost:3100";
const llave = readFileSync(".prueba/server.log", "utf8").match(/llave interna: (\S+)/g).at(-1).split(" ").at(-1);
const jwk = JSON.parse(readFileSync(".prueba/pa-private.jwk", "utf8"));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const t = Math.floor(Date.now() / 1000);
const input = `${b64({ alg: "ES256", kid: jwk.kid, typ: "JWT" })}.${b64({ iss: "http://localhost:3102", sub: "ana-captura", aud: `${P}/a2a`, iat: t, exp: t + 120 })}`;
const jwt = `${input}.${sign("sha256", Buffer.from(input), { key: createPrivateKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
const dev = await fetch(`${P}/a2a/t_ferreteria_demo/oauth/device_authorization`, {
	method: "POST",
	headers: { authorization: `Bearer ${jwt}`, "content-type": "application/x-www-form-urlencoded" },
	body: new URLSearchParams({ client_id: "http://localhost:3102", scope: "pedidos:leer pedidos:modificar" }),
}).then((r) => r.json());

mkdirSync(".prueba/capturas", { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const errores = [];
page.on("pageerror", (e) => errores.push(String(e)));
const foto = (n) => page.screenshot({ path: `.prueba/capturas/${n}.png` });
await page.goto(dev.verification_uri_complete);
await foto("1-enlace");
await page.fill("input[name=telefono]", "+56 9 0000 0101");
await page.click("button");
await foto("2-codigo-enviado");
const salida = await fetch(`${P}/interno/whatsapp/salida?tenant=t_ferreteria_demo`, { headers: { "x-sovras-prueba": llave } }).then((r) => r.json());
const whatsapp = salida.at(-1).texto;
await page.fill("input[name=codigo]", whatsapp.match(/código es (\d{6})/)[1]);
await page.click("button");
await foto("3-consentimiento");
await page.uncheck("input[value='pedidos:modificar']");
await page.click("button[value=allow]");
await foto("4-listo");
await browser.close();
const tok = await fetch(`${P}/a2a/t_ferreteria_demo/oauth/token`, {
	method: "POST",
	headers: { authorization: `Bearer ${jwt}`, "content-type": "application/x-www-form-urlencoded" },
	body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dev.device_code, client_id: "http://localhost:3102" }),
}).then((r) => r.json());
console.log(JSON.stringify({ whatsapp, scope_emitido: tok.scope, errores }, null, 1));

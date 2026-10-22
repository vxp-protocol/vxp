// Walks through, on a phone viewport (390×844), the purchase via the public sandbox's web chat, as an assistant:
// price → quote → negotiation → «haz el pedido». Screenshots every step.
// Usage: node scripts/recorrer-compra-chat.mjs <node_modules with playwright> <public url>
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const require = createRequire(join(process.argv[2], "noop.js"));
const { chromium } = require("playwright");
const U = process.argv[3];
mkdirSync(".prueba/capturas", { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const errores = [];
page.on("pageerror", (e) => errores.push(String(e)));
await page.goto(`${U}/e/ferreteria-demo/catalogo`);
await page.screenshot({ path: ".prueba/capturas/compra-0-catalogo.png", fullPage: true });
await page.goto(`${U}/e/ferreteria-demo/chat`);
const pasos = [
	"Hola, soy el asistente de Ana. ¿Qué precio tienen los taladros?",
	"Necesito 3 taladros percutores con despacho a Calle Ejemplo 100, Santiago, antes del viernes",
	"¿Me pueden hacer un 15% de descuento?",
	"Perfecto, haz el pedido",
];
for (const [i, texto] of pasos.entries()) {
	await page.fill("input[name=texto]", texto);
	await Promise.all([page.waitForLoadState("load"), page.click("button")]);
	await page.screenshot({ path: `.prueba/capturas/compra-${i + 1}.png`, fullPage: true });
}
const ultimo = await page.locator("p").filter({ hasText: "Ferretería Demo:" }).last().innerText();
await browser.close();
console.log(JSON.stringify({ ultimo, errores }, null, 1));

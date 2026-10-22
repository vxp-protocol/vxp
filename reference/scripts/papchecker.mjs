// Runs PAP Checker (papchecker.com, an independent Poppy validator) against the public sandbox and
// saves the screenshot and the result text. Usage: node scripts/papchecker.mjs <node_modules with playwright> <domain>
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const require = createRequire(join(process.argv[2], "noop.js"));
const { chromium } = require("playwright");
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
await page.goto("https://papchecker.com/");
await page.fill("#domain", process.argv[3]);
await Promise.all([page.waitForLoadState("networkidle"), page.click("form.check button[type=submit]")]);
await page.waitForTimeout(4000);
await page.screenshot({ path: ".prueba/publico/papchecker.png", fullPage: true });
const texto = await page.innerText("main").catch(() => page.innerText("body"));
writeFileSync(".prueba/publico/papchecker.txt", texto);
console.log(page.url());
console.log(texto.slice(0, 3000));
await browser.close();

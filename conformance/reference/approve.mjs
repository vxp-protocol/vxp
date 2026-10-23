// Test aid of the REFERENCE implementation only, not part of VXP: plays the person who approves a device
// authorization on the company's page. The reference company sends the linking code through a simulated
// channel; this helper reads it through the reference's internal test route, which needs the key the
// reference prints at start-up. Against another implementation, use "approve": "manual" or your own helper.
// Env: VXP_VERIFICATION_URI, VXP_USER_CODE, VXP_SCOPE (from the validator); REF_INTERNAL_KEY, REF_TENANT, REF_PHONE.
const uri = new URL(process.env.VXP_VERIFICATION_URI);
const issuer = uri.origin + uri.pathname.replace(/\/vincular.*$/, "");
const form = (o) => {
	const b = new URLSearchParams();
	for (const [k, v] of Object.entries(o)) for (const x of [v].flat()) b.append(k, x);
	return b;
};
const post = (paso, o) => fetch(`${issuer}/vincular/${paso}`, { method: "POST", body: form(o), redirect: "manual" });
await post("telefono", { user_code: process.env.VXP_USER_CODE, telefono: process.env.REF_PHONE });
const salida = await (await fetch(`${uri.origin}/interno/whatsapp/salida?tenant=${process.env.REF_TENANT}`, { headers: { "x-sovras-prueba": process.env.REF_INTERNAL_KEY } })).json();
const otp = String(salida.at(-1)?.texto ?? "").match(/(\d{6})/)?.[1];
if (!otp) {
	console.error("approve.mjs: no code found in the simulated channel");
	process.exit(1);
}
// The person approves what the consent page shows: every checkbox the page offers, as presented (all checked).
let pagina = await post("codigo", { user_code: process.env.VXP_USER_CODE, codigo: otp });
if (pagina.status >= 300 && pagina.status < 400 && pagina.headers.get("location")) pagina = await fetch(new URL(pagina.headers.get("location"), issuer + "/"));
const html = await pagina.text();
const casillas = [...html.matchAll(/name="scope" value="([^"]+)"/g)].map((m) => m[1].replace(/&amp;/g, "&").replace(/&quot;/g, '"'));
if (!casillas.length) {
	console.error("approve.mjs: the consent page shows no checkbox");
	process.exit(1);
}
const d = await post("decision", { user_code: process.env.VXP_USER_CODE, decision: "allow", scope: casillas });
process.exit(d.status === 303 || d.status === 200 ? 0 : 1);

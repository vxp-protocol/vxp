import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as firmar } from "node:crypto";
import { WebBotAuth, hostInterno } from "../src/webbotauth.ts";

const ahoraS = Math.floor(Date.now() / 1000);

function pedido(operador: string, privateKey?: import("node:crypto").KeyObject, kid = "k1") {
	const url = "https://tienda.example/e/x/chat";
	const params = `("@authority" "signature-agent");created=${ahoraS};expires=${ahoraS + 60};keyid="${kid}";alg="ed25519";tag="web-bot-auth"`;
	const base = `"@authority": tienda.example\n"signature-agent": "${operador}"\n"@signature-params": ${params}`;
	const s = privateKey ? firmar(null, Buffer.from(base), privateKey).toString("base64") : "AAAA";
	return new Request(url, { headers: { "signature-agent": `"${operador}"`, "signature-input": `sig1=${params}`, signature: `sig1=:${s}:` } });
}

test("WBA-S1 · no se pide el directorio de llaves a hosts internos ni a puertos fuera del estándar", async () => {
	const pedidos: string[] = [];
	const wba = new WebBotAuth(async (u) => {
		pedidos.push(u);
		return new Response("{}", { status: 404 });
	});
	for (const op of ["https://127.0.0.1", "https://localhost", "https://10.0.0.5", "https://169.254.169.254", "https://192.168.1.1", "https://[::1]", "https://2130706433", "https://metadata.internal", "https://operador.example:8443"]) {
		const r = await wba.verificar(pedido(op));
		assert.equal(r?.verificada, false);
		assert.equal((r as { motivo: string }).motivo, "operador_no_publico", op);
	}
	assert.deepEqual(pedidos, [], "ningún fetch");
	assert.equal(hostInterno("operador.example"), false);
	assert.equal(hostInterno("8.8.8.8"), false);
	for (const h of ["localhost.", "metadata.internal.", "[::ffff:7f00:1]", "[::ffff:127.0.0.1]", "[::7f00:1]", "[64:ff9b::a9fe:a9fe]", "[2002:c0a8:101::]", "[fd00::1]", "[fe80::1]", "[ff02::1]", "[0:0:0:0:0:0:0:1]", "[1::2::3]", "[64:ff9b:1::808:808]", "[fec0::1]", "[2001::1]", "[2001:db8::1]", "[100::1]", "198.18.0.1", "192.0.2.10", "203.0.113.5", "240.0.0.1"]) assert.equal(hostInterno(h), true, h);
	for (const h of ["[2606:4700::1111]", "[64:ff9b::808:808]", "[2002:808:808::]"]) assert.equal(hostInterno(h), false, h);
	assert.equal(hostInterno("[::ffff:808:808]"), true, "IPv4-mapped is refused even when public: the operator should use its IPv4 or a name");
	// What the URL parser actually hands over is also caught.
	for (const u of ["https://[::ffff:127.0.0.1]", "https://[::127.0.0.1]", "https://0x7f.1", "https://127.1", "https://localhost./"]) assert.equal(hostInterno(new URL(u).hostname), true, u);
});

test("WBA-S2 · un directorio que falla se recuerda un rato: una ráfaga firmada no se vuelve una ráfaga de fetch", async () => {
	let n = 0;
	const wba = new WebBotAuth(async () => {
		n++;
		throw new Error("ECONNREFUSED 10.1.2.3");
	});
	for (let i = 0; i < 20; i++) {
		const r = await wba.verificar(pedido("https://operador-caido.example"));
		assert.equal((r as { motivo: string }).motivo, "directorio_inaccesible", "no filtra el error de red interno");
	}
	assert.equal(n, 1);
});

test("WBA-S3 · el registro tiene tope", async () => {
	const wba = new WebBotAuth(async () => new Response("{}", { status: 404 }));
	for (let i = 0; i < 10_050; i++) wba.registro.push({ at: "", ruta: "/", resultado: { verificada: false, motivo: "x" } });
	await wba.observar(pedido("https://otro.example"));
	assert.equal(wba.registro.length, 10_000);
});

test("WBA-S4 · sólo un operador permitido comparte cupo entre IPs; uno cualquiera con firma válida, no", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
	const dir = () => new Response(JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", x, kid: "k1" }] }), { status: 200 });
	const abierta = new WebBotAuth(async () => dir());
	const r = await abierta.verificar(pedido("https://cualquiera.example", privateKey));
	assert.equal(r?.verificada, true);
	assert.equal(abierta.confiable("https://cualquiera.example"), false);
	const cerrada = new WebBotAuth(async () => dir(), ["https://operador.example"]);
	assert.equal((await cerrada.verificar(pedido("https://operador.example", privateKey)))?.verificada, true);
	assert.equal(cerrada.confiable("https://operador.example"), true);
});

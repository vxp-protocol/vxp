// Persistent proof keys (VXP_KEYS_DIR): the operator, log and company key rings survive a restart, a
// rotation keeps the earlier public key published, and no private key is ever published.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { EmisorPruebas } from "../src/prueba.ts";

const ISSUER = "https://auth.example/e/tienda";
const nuevo = (dir: string | null) => {
	const p = new EmisorPruebas("https://auth.example/vxp/operator", "auth.example/vxp/log/v0", dir);
	p.registrarEmpresa("t_tienda", ISSUER);
	return p;
};
const kids = (jwks: { keys: { kid: string }[] }) => jwks.keys.map((k) => k.kid);

test("llaves persistentes: un reinicio con el mismo directorio publica las mismas llaves", () => {
	const dir = mkdtempSync(join(tmpdir(), "vxp-llaves-"));
	const a = nuevo(dir);
	const b = nuevo(dir);
	assert.deepEqual(kids(b.jwksEmpresa("t_tienda")), kids(a.jwksEmpresa("t_tienda")));
	assert.deepEqual(kids(b.jwksOperador()), kids(a.jwksOperador()));
	assert.deepEqual(kids(b.jwksRegistro()), kids(a.jwksRegistro()));
	// The log-tag key persists too, so tags stay unlinkable but stable across restarts.
	const anillo = JSON.parse(readFileSync(join(dir, "company-t_tienda.json"), "utf8"));
	assert.equal(typeof anillo.extra.tag, "string");
	assert.ok("d" in anillo.current, "the private key is kept in the key directory");
});

test("llaves persistentes: una rotación sobrevive al reinicio y deja la llave anterior publicada", () => {
	const dir = mkdtempSync(join(tmpdir(), "vxp-llaves-"));
	const a = nuevo(dir);
	const antes = kids(a.jwksEmpresa("t_tienda"))[0];
	const nueva = a.rotarEmpresa("t_tienda");
	const b = nuevo(dir);
	assert.deepEqual(kids(b.jwksEmpresa("t_tienda")), [nueva, antes]);
	assert.equal(b.retirarLlaveEmpresa("t_tienda", antes), true);
	assert.deepEqual(kids(nuevo(dir).jwksEmpresa("t_tienda")), [nueva], "a retired key stays retired after another restart");
});

test("llaves: ningún JWKS publica una llave privada, con o sin directorio", () => {
	for (const p of [nuevo(null), nuevo(mkdtempSync(join(tmpdir(), "vxp-llaves-")))]) {
		p.rotarEmpresa("t_tienda");
		p.rotarOperador();
		for (const j of [p.jwksEmpresa("t_tienda"), p.jwksOperador(), p.jwksRegistro()]) for (const k of j.keys) assert.ok(!("d" in k));
	}
});

test("llaves en memoria: sin directorio, cada arranque genera llaves nuevas (comportamiento anterior)", () => {
	assert.notDeepEqual(kids(nuevo(null).jwksEmpresa("t_tienda")), kids(nuevo(null).jwksEmpresa("t_tienda")));
});

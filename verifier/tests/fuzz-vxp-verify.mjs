// Differential fuzz: vxp-verify.js against the Python reference verificar_cadena.
// The Python (fuzz_vxp_gen.py) generates the chains and the reference verdicts; this script
// verifies the same chains in JS and compares verdict by verdict.
//
//   node fuzz-vxp-verify.mjs [chains=3000] [seed=20261022] [log path]
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain, verdictJson, _internals as I } from "../vxp-verify.js";

const N = parseInt(process.argv[2] || "3000", 10);
const SEED = parseInt(process.argv[3] || "20261022", 10);
const LOG = process.argv[4] || join(tmpdir(), "vxp-fuzz-web.log");
const HERE = dirname(fileURLToPath(import.meta.url));
const VEC = JSON.parse(readFileSync(join(HERE, "..", "..", "vectors", "vectores-0.1.json"), "utf8"));
const KEYS = { company: VEC.keys.company, operator: VEC.keys.operator };
const EMP = VEC.keys.company.issuer;

const out = [];
const say = (s) => { out.push(s); console.log(s); };
const t0 = Date.now();
say("== 17-fuzz-web · " + new Date().toISOString() + " · node fuzz-vxp-verify.mjs " + N + " " + SEED + " (" + process.version + ")");
say("generator: verifier/tests/fuzz_vxp_gen.py (reuses reference/scripts/fuzz-diferencial.py: cadena, guion, cuerpo, test keys)");

const file = join(mkdtempSync(join(tmpdir(), "vxp-fuzz-")), "fuzz.jsonl");
const g = spawnSync("python", [join(HERE, "fuzz_vxp_gen.py"), String(N), String(SEED), file], { encoding: "utf8", env: { ...process.env, PYTHONIOENCODING: "utf-8" } });
if (g.status !== 0) { console.error(g.stderr); process.exit(2); }
const rows = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

// Python value -> type-exact tagged view (same as fuzz_vxp_gen.tagged)
function pyCodePoints(s) {
  const cps = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0xfdd0 && i > 0 && /[\ud800-\udbff]/.test(s[i - 1]) && /[\udc00-\udfff]/.test(s[i + 1] || "")) continue; // pair guard
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff) {
      cps.push(0x10000 + ((c - 0xd800) << 10) + (s.charCodeAt(i + 1) - 0xdc00)); i++;
    } else cps.push(c);
  }
  return cps;
}
function tagged(v) {
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "number" || typeof v === "bigint") return ["int", String(v)];
  if (v instanceof I.PyFloat) return ["float", I.pyJsonDumps(v).replace(/^NaN$/, "nan").replace(/^Infinity$/, "inf").replace(/^-Infinity$/, "-inf")];
  if (typeof v === "string") return ["str", pyCodePoints(v)];
  if (Array.isArray(v)) return ["list", v.map(tagged)];
  return ["dict", Array.from(v, ([k, x]) => [tagged(k), tagged(x)])];
}
const outcome = (f) => {
  try { return f(); } catch (e) {
    if (e && e.code && e.constructor.name === "VerificationFailure") return "FALLA:" + e.code;
    if (e instanceof I.PyError) return "EXC";
    throw e;
  }
};

let chains = 0, prims = { b64d: 0, json: 0 }, disc = 0, valid = 0, pyexc = 0;
const codes = {};
for (const r of rows) {
  if (r.prim) {
    prims[r.prim]++;
    let js;
    if (r.prim === "b64d") js = outcome(() => Buffer.from(I.b64d(r.in)).toString("hex"));
    else js = outcome(() => tagged(I.leerJson(new Uint8Array(Buffer.from(r.in_hex, "hex")))));
    const a = JSON.stringify(r.ref), b = JSON.stringify(js);
    if (a !== b) { disc++; if (disc <= 10) say("DISCREPANCY primitive " + r.prim + " input " + JSON.stringify(r.in ?? r.in_hex) + "\n  python: " + a + "\n  js:     " + b); }
    continue;
  }
  chains++;
  const v = await verifyChain(r.chain, KEYS, EMP, "operator_hosted");
  const js = v.error === "malformed_input" ? "PYTHON_EXCEPTION" : verdictJson(v);
  if (js !== r.ref) {
    disc++;
    if (disc <= 10) say("DISCREPANCY chain it=" + r.it + "\n  python: " + r.ref + "\n  js:     " + js + "\n  chain: " + JSON.stringify(r.chain));
  }
  const key = r.ref === "PYTHON_EXCEPTION" ? "python_exception" : JSON.parse(r.ref).valid ? "valid:" + JSON.parse(r.ref).final_state : JSON.parse(r.ref).error;
  if (key.startsWith("valid")) valid++;
  if (key === "python_exception") pyexc++;
  codes[key] = (codes[key] || 0) + 1;
}
const n1 = Math.floor((N * 40) / 100), n2 = Math.floor((N * 65) / 100) - n1;
say("chains: " + chains + " (" + n1 + " from fuzz-diferencial.cadena unchanged, " + n2 + " guided protocol chains, " + (N - n1 - n2) + " mutated), valid per reference: " + valid + ", reference exceptions: " + pyexc);
say("primitives: b64d " + prims.b64d + ", leer_json " + prims.json);
say("verdicts: " + JSON.stringify(Object.fromEntries(Object.entries(codes).sort((a, b) => b[1] - a[1]))));
say("distinct verdicts: " + Object.keys(codes).length + " · seconds: " + ((Date.now() - t0) / 1000).toFixed(1));
say("");
say("TOTAL: " + (chains + prims.b64d + prims.json) + " differential cases (" + chains + " chains + " + (prims.b64d + prims.json) + " primitive inputs), " + disc + " discrepancies");
writeFileSync(LOG, out.join("\n") + "\n");
process.exit(disc ? 1 : 0);

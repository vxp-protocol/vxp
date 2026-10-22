// Differential test: vxp-verify.js against the Python reference verifier, verdict by verdict.
// Runs the Python, runs the JS, compares the exact output (vector report lines; the JSON
// verdict line in material mode). Exit 0 only with 0 discrepancies.
//
//   node test-vxp-verify.mjs [log path]
//
// Paths are relative to the repository. Set VXP_PY_LEGACY to the pre-rename reference verifier to
// also run the legacy-0.1 naming checks; without it those checks are skipped.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyVectors, verifyPactVectors, verifyPackage, verdictJson, explain } from "../vxp-verify.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PY_NEW = join(ROOT, "verifier", "verificar_paquete.py");
const PY_OLD = process.env.VXP_PY_LEGACY || null; // identifiers before the 22-oct-2026 rename (optional)
const VEC = process.env.VXP_VEC ?? join(ROOT, "vectors", "vectores-0.1.json");
const VEC_PACT = process.env.VXP_VEC_PACT ?? join(ROOT, "vectors", "vectores-pact-0.1.json");
const DL = join(ROOT, "site", "downloads");
const CAP = join(DL, "native-run-2026-10-22");
const PACT = join(DL, "pact-run-2026-10-22");
const LOG = process.argv[2] || join(tmpdir(), "vxp-verificador-web.log");

const out = [];
const say = (s) => { out.push(s); console.log(s); };
const TMP = mkdtempSync(join(tmpdir(), "vxp-web-"));
let nfile = 0;
const tmp = (obj) => { const p = join(TMP, "f" + nfile++ + ".json"); writeFileSync(p, typeof obj === "string" ? obj : JSON.stringify(obj)); return p; };
const read = (p) => readFileSync(p, "utf8");

function python(script, args) {
  const r = spawnSync("python", [script, ...args], { encoding: "utf8", env: { ...process.env, PYTHONIOENCODING: "utf-8" }, maxBuffer: 1 << 26 });
  return { stdout: r.stdout.replace(/\r\n/g, "\n"), stderr: r.stderr, status: r.status };
}

let comparisons = 0, discrepancies = 0;
function compare(name, py, js) {
  comparisons++;
  if (py === js) return true;
  discrepancies++;
  say("DISCREPANCY " + name + "\n  python: " + py + "\n  js:     " + js);
  return false;
}

say("== 16-verificador-web · " + new Date().toISOString() + " · node test-vxp-verify.mjs (" + process.version + ")");
say("module: verifier/vxp-verify.js · reference: " + PY_NEW + " · legacy reference: " + PY_OLD);

// ---------- 1 and 2: conformance vectors, line by line ----------
for (const [mode, file, fn] of [["vectores", VEC, verifyVectors], ["pact", VEC_PACT, verifyPactVectors]]) {
  const py = python(PY_NEW, [mode, file]);
  const pyLines = py.stdout.replace(/\n$/, "").split("\n");
  const js = await fn(read(file));
  let bad = 0;
  const n = Math.max(pyLines.length, js.lines.length);
  for (let i = 0; i < n; i++) if (!compare(mode + " line " + (i + 1), pyLines[i], js.lines[i])) bad++;
  say(`[${mode}] ${file.split("/").pop()}: python "${pyLines[pyLines.length - 1]}" (exit ${py.status}) · js "${js.lines[js.lines.length - 1]}" · ${js.total} checks compared line by line, ${bad} discrepancies`);
}

// ---------- 3: real proofs in material mode, valid and altered ----------
const b64urlDecode = (s) => Buffer.from(s, "base64url");
const b64urlEncode = (b) => Buffer.from(b).toString("base64url");
function payloadOf(sd) { return JSON.parse(b64urlDecode(sd.split("~")[0].split(".")[1]).toString("utf8")); }
function replacePayloadKeepSignature(sd, mutate) {
  const [jwt, ...rest] = sd.split("~");
  const [h, p, s] = jwt.split(".");
  const obj = JSON.parse(b64urlDecode(p).toString("utf8"));
  mutate(obj);
  return [h, b64urlEncode(Buffer.from(JSON.stringify(obj))), s].join(".") + "~" + rest.join("~");
}
function flipSignature(sd) {
  const [jwt, ...rest] = sd.split("~");
  const [h, p, s] = jwt.split(".");
  const sig = Buffer.from(b64urlDecode(s));
  sig[10] ^= 0x01;
  return [h, p, b64urlEncode(sig)].join(".") + "~" + rest.join("~");
}
const clone = (x) => JSON.parse(JSON.stringify(x));

const REAL = [
  { id: "pact-run/pact-op_01NpsuOhdE3C", pkg: join(PACT, "pact-op_01NpsuOhdE3C.json"), mat: join(PACT, "pact-op_01NpsuOhdE3C.material.json"), receipt: join(PACT, "pact-op_01NpsuOhdE3C.recibo.json") },
  { id: "pact-run/pact-op_kXk0fUY1M3Eq", pkg: join(PACT, "pact-op_kXk0fUY1M3Eq.json"), mat: join(PACT, "pact-op_kXk0fUY1M3Eq.material.json"), op: join(PACT, "pact-op_kXk0fUY1M3Eq.op.json") },
  { id: "captura/op_B6__ICZlCe_c", pkg: join(CAP, "paquete-op_B6__ICZlCe_c.json"), mat: join(CAP, "material-op_B6__ICZlCe_c.json"), op: join(CAP, "operacion-op_B6__ICZlCe_c.json") },
  { id: "captura/op_NBbN47CrhrtM", pkg: join(CAP, "paquete-op_NBbN47CrhrtM.json"), mat: join(CAP, "material-op_NBbN47CrhrtM.json"), op: join(CAP, "operacion-op_NBbN47CrhrtM.json") },
];

function variants(c) {
  const pkg = JSON.parse(read(c.pkg));
  const mat = JSON.parse(read(c.mat));
  const op = c.op ? JSON.parse(read(c.op)) : null;
  const st = pkg.statements;
  const kindIdx = (k) => st.findIndex((s) => payloadOf(s).kind === k);
  const V = [{ v: "as captured", pkg, mat, op }];
  V.push({ v: "aud of another agent", pkg, mat, op, aud: "https://otro-agente.example" });
  { const p = clone(pkg); p.statements[p.statements.length - 1] = flipSignature(p.statements[p.statements.length - 1]); V.push({ v: "signature of the last statement altered", pkg: p, mat, op }); }
  { const t = kindIdx("terms"); const p = clone(pkg); p.statements[t] = replacePayloadKeepSignature(p.statements[t], (o) => { o.body.terms_digest = o.body.terms_digest.slice(0, -2) + (o.body.terms_digest.endsWith("AA") ? "BB" : "AA"); }); V.push({ v: "signed terms digest altered (term changed in the statement)", pkg: p, mat, op }); }
  if (op) {
    const o = clone(op);
    const k = Object.keys(o.terms || {}).find((x) => !x.endsWith("_salt")) ;
    if (k !== undefined) { o.terms[k] = typeof o.terms[k] === "string" ? o.terms[k] + " (alterado)" : { alterado: o.terms[k] }; V.push({ v: "operation term '" + k + "' changed", pkg, mat, op: o }); }
    const o2 = clone(op); o2.state = o2.state === "succeeded" ? "failed" : "succeeded"; V.push({ v: "operation state changed", pkg, mat, op: o2 });
  }
  { const p = clone(pkg); [p.statements[2], p.statements[3]] = [p.statements[3], p.statements[2]]; V.push({ v: "order: statements 2 and 3 swapped", pkg: p, mat, op }); }
  { const p = clone(pkg); p.statements.pop(); V.push({ v: "last statement dropped", pkg: p, mat, op }); }
  { const p = clone(pkg); p.statements = [p.statements[0]]; V.push({ v: "only the request", pkg: p, mat, op }); }
  if (pkg.log) { const p = clone(pkg); p.log.inclusion = p.log.inclusion.slice(1); V.push({ v: "log inclusion of seq 0 removed", pkg: p, mat, op }); }
  if (pkg.log) { const p = clone(pkg); p.log.inclusion[1].path = p.log.inclusion[1].path.slice(1); V.push({ v: "log inclusion path cut", pkg: p, mat, op }); }
  { const m = clone(mat); m.anchor = { domain: "otra-empresa.example" }; V.push({ v: "anchor to another domain", pkg, mat: m, op }); }
  // material documents may be stored as objects or as JSON text: edit them in the same form
  const editDoc = (m, k, f) => { const asText = typeof m.docs[k] === "string"; const d = asText ? JSON.parse(m.docs[k]) : m.docs[k]; f(d); m.docs[k] = asText ? JSON.stringify(d) : d; };
  { const m = clone(mat); const k = Object.keys(m.docs).find((u) => u.includes("oauth-authorization-server")); if (k) { editDoc(m, k, (d) => { d.issuer = d.issuer + "/x"; }); V.push({ v: "metadata issuer not identical", pkg, mat: m, op }); } }
  { const m = clone(mat); const k = Object.keys(m.docs).find((u) => /proof-jwks\.json$/.test(u) && u.includes("/e/")); if (k) { editDoc(m, k, (d) => { const key = d.keys[0]; key.x = key.x.slice(0, 5) + (key.x[5] === "A" ? "B" : "A") + key.x.slice(6); }); V.push({ v: "company key in material altered", pkg, mat: m, op }); } }
  { const p = clone(pkg); p.statements[1] = p.statements[1] + "WyJzYWx0IiwibmFtZSIsMV0~"; V.push({ v: "unreferenced disclosure appended", pkg: p, mat, op }); }
  if (c.receipt) V.push({ v: "with PACT receipt (Poppy anchor)", pkg, mat, op, receipt: JSON.parse(read(c.receipt)) });
  return V;
}

let realCount = 0;
for (const c of REAL) {
  for (const x of variants(c)) {
    // the Python reads files; the JS receives the same bytes as text
    const fp = tmp(x.pkg), fm = tmp(x.mat), fo = x.op ? tmp(x.op) : null, fr = x.receipt ? tmp(x.receipt) : null;
    const runs = c.legacy
      ? [["legacy 0.1 naming", PY_OLD, "legacy-0.1"], ["vxp naming (must reject)", PY_NEW, "vxp"]]
      : [["vxp naming", PY_NEW, "vxp"], ["legacy 0.1 naming (must reject)", PY_OLD, "legacy-0.1"]];
    for (const [label, script, naming] of runs) {
      if (x.v !== "as captured" && label.includes("must reject")) continue; // cross-naming only on the captured proof
      if (!script) continue; // legacy reference not provided (VXP_PY_LEGACY)
      const args = ["material", "--material", fm, "--paquete", fp];
      if (fo) args.push("--operacion", fo);
      if (x.aud) args.push("--aud", x.aud);
      if (fr) args.push("--recibo-pact", fr);
      const py = python(script, args);
      const pyLine = py.stderr.includes("Traceback") ? "PYTHON_EXCEPTION" : py.stdout.trim();
      const v = await verifyPackage({ package: read(fp), material: read(fm), operation: fo ? read(fo) : null, aud: x.aud ?? null, receipt: fr ? read(fr) : null, naming });
      const jsLine = v.error === "malformed_input" ? "PYTHON_EXCEPTION" : verdictJson(v);
      realCount++;
      const ok = compare(c.id + " · " + x.v + " · " + label, pyLine, jsLine);
      const short = v.valid ? "valid:true final_state=" + v.final_state + " " + (v.derived_assurance || []).join(",") + " single_root=" + v.single_root + " logged=" + v.logged : "valid:false " + v.error + (v.seq !== null ? " seq=" + v.seq : "");
      say((ok ? "SAME " : "DIFF ") + c.id + " · " + x.v + " · " + label + " -> " + short);
    }
  }
}
say("[material] real proofs: " + REAL.length + " captured proofs, " + realCount + " verdicts compared (captured + altered + cross-naming)");

// ---------- explain() smoke check on a real verdict ----------
{
  const c = REAL[2];
  const v = await verifyPackage({ package: read(c.pkg), material: read(c.mat), operation: read(c.op) });
  const e = explain(v);
  say("[explain] " + c.id + ": " + e.length + " controls; " + e.filter((x) => x.status === "pass").length + " pass, " + e.filter((x) => x.status === "fail").length + " fail");
  for (const x of e) say("    " + x.status.padEnd(11) + x.control + ": " + x.text);
}

say("");
say("TOTAL: " + comparisons + " comparisons with the Python reference, " + discrepancies + " discrepancies");
mkdirSync(dirname(LOG), { recursive: true });
writeFileSync(LOG, out.join("\n") + "\n");
process.exit(discrepancies ? 1 : 0);

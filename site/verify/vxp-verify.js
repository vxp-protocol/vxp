// vxp-verify.js - independent web verifier for VXP Proof 0.1.
//
// A third implementation of the VXP Proof verifier (VXP spec section 4, annex section 9),
// written for the browser and Node >= 20 with no dependencies: WebCrypto (crypto.subtle) for
// ECDSA P-256 / SHA-256 / HMAC, and its own RFC 8785 (JCS) canonicalization.
//
// It mirrors, rule by rule and in the same order, the reference verifier
// verifier/verificar_paquete.py, so it returns the same verdict object and the same
// error codes. Where the reference behaviour depends on Python semantics (json.loads, the
// non-strict base64 decoder, urllib.parse.urlparse, True == 1, ...), those semantics are
// reproduced here on purpose: a verdict that differs from the reference is a bug.
//
// No network: only the "material" mode (public material already downloaded). The page never
// fetches third-party URLs.
//
// One documented difference: where the reference raises an uncaught Python exception
// (a malformed input it does not classify), this module returns
// {valid: false, error: "malformed_input", seq: null, python_exception: "<Type>"}.

// ---------------------------------------------------------------- identifiers (SPEC 8.1)

export const NAMING_VXP = Object.freeze({
  id: "vxp-0.1",
  EXT_POPPY: "vxpprotocol.org/proof",
  EXT_A2A: "https://vxpprotocol.org/ext/proof/v0.1",
  META_PROOF: "vxp_proof",
  STMT_TYP: "vxp-stmt+sd-jwt",
  CHECKPOINT_TYP: "vxp-checkpoint+jwt",
  TERMS_SALT: "vxp_salt",
});

// "legacy 0.1 naming": the identifiers of annex 0.1 BEFORE the VXP spec 8.1 rename (22-oct-2026).
// Only for proofs issued before the rename (e.g. OP-5 of 21-oct). Explicit opt-in, never automatic.
export const NAMING_LEGACY_0_1 = Object.freeze({
  id: "legacy-0.1-sovras",
  EXT_POPPY: "sovras.io/outcome-proof",
  EXT_A2A: "https://sovras.io/ext/outcome-proof/v0.1",
  META_PROOF: "sovras_outcome_proof",
  STMT_TYP: "sovras-stmt+sd-jwt",
  CHECKPOINT_TYP: "sovras-checkpoint+jwt",
  TERMS_SALT: "sovras_salt",
});

function namingOf(n) {
  if (n === undefined || n === null || n === "vxp" || n === "vxp-0.1") return NAMING_VXP;
  if (n === "legacy-0.1" || n === "legacy-0.1-sovras") return NAMING_LEGACY_0_1;
  throw new Error("unknown naming: " + n + " (use \"vxp\" or \"legacy-0.1\")");
}

const MEMBERS_OF_TRUST = ["version", "company", "jwks_uri", "operator", "custody", "log", "domains", "pact"];
const ROLES = {
  company: new Set(["terms", "company_review", "outcome", "correction", "revocation"]),
  operator: new Set(["request", "counter", "user_approval", "execution", "read_back"]),
};
const POPPY_STATE = new Map([["succeeded", "succeeded"], ["failed", "failed"], ["cancelled", "cancelled"], ["expired", "expired"]]);
const STATES = ["succeeded", "failed", "cancelled", "expired", "unknown"];
const READ_METHODS = ["system_read_back", "manual", "none"];
const B64_ALPHABET = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

// ---------------------------------------------------------------- errors

/** A verification failure with a protocol error code (Python: Falla). */
export class VerificationFailure extends Error {
  constructor(code, seq = null) {
    super(code);
    this.code = code;
    this.seq = seq;
  }
}
const Falla = VerificationFailure;

/** An exception the Python reference would raise (and not classify). */
class PyError extends Error {
  constructor(type, msg = "") {
    super(type + (msg ? ": " + msg : ""));
    this.pyType = type;
  }
}
const VALUE_ERRORS = new Set(["ValueError", "UnicodeEncodeError", "UnicodeDecodeError", "JSONDecodeError", "binascii.Error"]);
const isPy = (e) => e instanceof Falla || e instanceof PyError; // Python `except Exception`
const isValueOrKey = (e) => e instanceof PyError && (VALUE_ERRORS.has(e.pyType) || e.pyType === "KeyError");

// ---------------------------------------------------------------- Python value model
// null, boolean, number (safe int), bigint (int beyond 2^53), PyFloat, string, Array, Map.

class PyFloat {
  constructor(v) { this.v = v; }
}
const isMap = (v) => v instanceof Map;
const isList = Array.isArray;
const isStr = (v) => typeof v === "string";
const isNum = (v) => typeof v === "boolean" || typeof v === "number" || typeof v === "bigint" || v instanceof PyFloat;
const isIntLike = (v) => typeof v === "boolean" || typeof v === "number" || typeof v === "bigint";
const unhashable = (v) => isList(v) || isMap(v);

function numVal(v) { // as JS number (for comparisons where precision is irrelevant)
  if (typeof v === "boolean") return v ? 1 : 0;
  if (v instanceof PyFloat) return v.v;
  return Number(v);
}
function bigVal(v) {
  if (typeof v === "boolean") return v ? 1n : 0n;
  return BigInt(v);
}

function pyEq(a, b) {
  if (isNum(a) && isNum(b)) {
    if (a instanceof PyFloat || b instanceof PyFloat) {
      const f = a instanceof PyFloat ? a.v : b.v;
      const o = a instanceof PyFloat ? b : a;
      if (o instanceof PyFloat) return a.v === b.v;
      if (!Number.isFinite(f) || !Number.isInteger(f)) return false;
      return BigInt(f) === bigVal(o);
    }
    return bigVal(a) === bigVal(b);
  }
  if (a === null || b === null) return a === b;
  if (isStr(a) || isStr(b)) return a === b;
  if (isList(a) && isList(b)) return a.length === b.length && a.every((x, i) => pyEq(x, b[i]));
  if (isMap(a) && isMap(b)) {
    if (a.size !== b.size) return false;
    for (const [k, x] of a) if (!b.has(k) || !pyEq(x, b.get(k))) return false;
    return true;
  }
  return false;
}
const pyNe = (a, b) => !pyEq(a, b);

function truthy(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "bigint") return v !== 0n;
  if (v instanceof PyFloat) return v.v !== 0;
  if (isStr(v)) return v.length > 0;
  if (isList(v)) return v.length > 0;
  if (isMap(v)) return v.size > 0;
  return true;
}

// dict.get(k, d): o must be a dict
function get(o, k, d = null) {
  if (!isMap(o)) throw new PyError("AttributeError", "'" + pyTypeName(o) + "' object has no attribute 'get'");
  if (unhashable(k)) throw new PyError("TypeError", "unhashable type");
  if (!isStr(k)) return d;
  return o.has(k) ? o.get(k) : d;
}
// k in dict (dict-only uses in the reference)
function has(o, k) {
  if (isMap(o)) {
    if (unhashable(k)) throw new PyError("TypeError", "unhashable type");
    return isStr(k) && o.has(k);
  }
  if (isList(o)) return o.some((x) => pyEq(x, k));
  if (isStr(o)) {
    if (!isStr(k)) throw new PyError("TypeError", "'in <string>' requires string as left operand");
    return o.includes(k);
  }
  throw new PyError("TypeError", "argument of type '" + pyTypeName(o) + "' is not iterable");
}
// o[k]
function idx(o, k) {
  if (isMap(o)) {
    if (unhashable(k)) throw new PyError("TypeError", "unhashable type");
    if (isStr(k) && o.has(k)) return o.get(k);
    throw new PyError("KeyError", String(k));
  }
  if (isList(o) || isStr(o)) {
    if (!isIntLike(k)) throw new PyError("TypeError", "indices must be integers");
    const arr = isList(o) ? o : Array.from(o);
    let i = Number(bigVal(k));
    if (i < 0) i += arr.length;
    if (i < 0 || i >= arr.length) throw new PyError("IndexError", "index out of range");
    return arr[i];
  }
  throw new PyError("TypeError", "'" + pyTypeName(o) + "' object is not subscriptable");
}
function pyIter(v) {
  if (isList(v)) return v;
  if (isMap(v)) return Array.from(v.keys());
  if (isStr(v)) return Array.from(v);
  throw new PyError("TypeError", "'" + pyTypeName(v) + "' object is not iterable");
}
function pyLen(v) {
  if (isList(v) || isStr(v)) return pyIter(v).length;
  if (isMap(v)) return v.size;
  throw new PyError("TypeError", "object of type '" + pyTypeName(v) + "' has no len()");
}
function inSet(v, set) { // v in {str, ...}
  if (unhashable(v)) throw new PyError("TypeError", "unhashable type");
  return isStr(v) && set.has(v);
}
function inTuple(v, arr) { return arr.some((x) => pyEq(v, x)); }
function pyTypeName(v) {
  if (v === null) return "NoneType";
  if (typeof v === "boolean") return "bool";
  if (typeof v === "number" || typeof v === "bigint") return "int";
  if (v instanceof PyFloat) return "float";
  if (isStr(v)) return "str";
  if (isList(v)) return "list";
  if (isMap(v)) return "dict";
  return typeof v;
}
function pyCmp(a, b) { // -1, 0, 1 or TypeError (Python ordering of < >=)
  if (isNum(a) && isNum(b)) {
    if (a instanceof PyFloat || b instanceof PyFloat) {
      const x = numVal(a), y = numVal(b);
      if (Number.isNaN(x) || Number.isNaN(y)) return NaN;
      return x < y ? -1 : x > y ? 1 : 0;
    }
    const x = bigVal(a), y = bigVal(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  if (isStr(a) && isStr(b)) {
    const x = Array.from(a, (c) => c.codePointAt(0)), y = Array.from(b, (c) => c.codePointAt(0));
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return x.length < y.length ? -1 : x.length > y.length ? 1 : 0;
  }
  throw new PyError("TypeError", "'<' not supported");
}
const pyLt = (a, b) => pyCmp(a, b) < 0;
const pyGe = (a, b) => pyCmp(a, b) >= 0;
const pyGt = (a, b) => pyCmp(a, b) > 0;
function pyAdd1(v) {
  if (v instanceof PyFloat) return new PyFloat(v.v + 1);
  if (typeof v === "bigint") return v + 1n;
  if (typeof v === "boolean" || typeof v === "number") {
    const r = Number(v) + 1;
    return Number.isSafeInteger(r) ? r : BigInt(Number(v)) + 1n;
  }
  throw new PyError("TypeError", "unsupported operand type(s) for +");
}
function pyKey(v) { // hash key with Python equality (1 == True == 1.0)
  if (unhashable(v)) throw new PyError("TypeError", "unhashable type");
  if (v === null) return "n";
  if (isStr(v)) return "s" + v;
  if (v instanceof PyFloat) {
    if (Number.isFinite(v.v) && Number.isInteger(v.v)) return "d" + BigInt(v.v).toString();
    return "f" + String(v.v);
  }
  return "d" + bigVal(v).toString();
}

// str(x) / repr(x)
function floatRepr(x) {
  if (Number.isNaN(x)) return "nan";
  if (x === Infinity) return "inf";
  if (x === -Infinity) return "-inf";
  if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
  const neg = x < 0;
  const e = Math.abs(x).toExponential(); // shortest round-trip digits
  const [mant, expS] = e.split("e");
  const exp = parseInt(expS, 10);
  const digits = mant.replace(".", "");
  let out;
  if (exp >= -4 && exp < 16) {
    if (exp >= digits.length - 1) out = digits + "0".repeat(exp - digits.length + 1) + ".0";
    else if (exp >= 0) out = digits.slice(0, exp + 1) + "." + digits.slice(exp + 1);
    else out = "0." + "0".repeat(-exp - 1) + digits;
  } else {
    out = (digits.length > 1 ? digits[0] + "." + digits.slice(1) : digits) + "e" + (exp < 0 ? "-" : "+") + String(Math.abs(exp)).padStart(2, "0");
  }
  return (neg ? "-" : "") + out;
}
function strRepr(s) {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'";
  let o = q;
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === q || ch === "\\") o += "\\" + ch;
    else if (ch === "\n") o += "\\n";
    else if (ch === "\r") o += "\\r";
    else if (ch === "\t") o += "\\t";
    else if (c < 0x20 || c === 0x7f || (c >= 0x80 && c <= 0xa0) || c === 0xad) o += "\\x" + c.toString(16).padStart(2, "0");
    else if ((c >= 0xd800 && c <= 0xdfff) || c === 0x2028 || c === 0x2029) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += ch;
  }
  return o + q;
}
function pyRepr(v) {
  if (isStr(v)) return strRepr(v);
  if (isList(v)) return "[" + v.map(pyRepr).join(", ") + "]";
  if (isMap(v)) return "{" + Array.from(v, ([k, x]) => strRepr(k) + ": " + pyRepr(x)).join(", ") + "}";
  return pyStr(v);
}
function pyStr(v) {
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "number" || typeof v === "bigint") return String(v);
  if (v instanceof PyFloat) return floatRepr(v.v);
  if (isStr(v)) return v;
  return pyRepr(v);
}

// ---------------------------------------------------------------- text encodings

function utf8Encode(s, what = "utf-8") { // str.encode("utf-8"), strict
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
    }
    if (c >= 0xd800 && c <= 0xdfff) throw new PyError("UnicodeEncodeError", "surrogates not allowed");
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}
function asciiEncode(s) { // str.encode("ascii")
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) throw new PyError("UnicodeEncodeError", "ascii");
    out[i] = c;
  }
  return out;
}
const asciiDecode = (b) => String.fromCharCode(...b);

// A Python str may hold two separate surrogate code points that JS would read as one pair.
// They come only from byte decoding with 'surrogatepass'; a sentinel between them keeps both
// lone (as in Python) so canonicalization rejects them exactly as the reference does.
const PAIR_GUARD = "﷐";
function fromCodePoints(cps) {
  let s = "";
  for (let i = 0; i < cps.length; i++) {
    const c = cps[i];
    s += String.fromCodePoint(c);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < cps.length && cps[i + 1] >= 0xdc00 && cps[i + 1] <= 0xdfff) s += PAIR_GUARD;
  }
  return s;
}
function decodeUtf8(b, start = 0) { // bytes.decode("utf-8", "surrogatepass")
  const cps = [];
  const bad = () => { throw new PyError("UnicodeDecodeError", "utf-8"); };
  for (let i = start; i < b.length;) {
    const b0 = b[i];
    if (b0 < 0x80) { cps.push(b0); i++; continue; }
    let n, cp, lo = 0x80, hi = 0xbf;
    if (b0 >= 0xc2 && b0 <= 0xdf) { n = 1; cp = b0 & 0x1f; }
    else if (b0 >= 0xe0 && b0 <= 0xef) { n = 2; cp = b0 & 0x0f; if (b0 === 0xe0) lo = 0xa0; }
    else if (b0 >= 0xf0 && b0 <= 0xf4) { n = 3; cp = b0 & 0x07; if (b0 === 0xf0) lo = 0x90; if (b0 === 0xf4) hi = 0x8f; }
    else bad();
    for (let j = 1; j <= n; j++) {
      const x = b[i + j];
      if (x === undefined) bad();
      if (j === 1 ? x < lo || x > hi : x < 0x80 || x > 0xbf) bad();
      cp = (cp << 6) | (x & 0x3f);
    }
    cps.push(cp);
    i += n + 1;
  }
  return fromCodePoints(cps);
}
function decodeUtf16(b, start, le) {
  if ((b.length - start) % 2) throw new PyError("UnicodeDecodeError", "utf-16 truncated");
  const units = [];
  for (let i = start; i < b.length; i += 2) units.push(le ? b[i] | (b[i + 1] << 8) : (b[i] << 8) | b[i + 1]);
  // valid pairs combine into one code point; lone surrogates pass (surrogatepass)
  const cps = [];
  for (let i = 0; i < units.length; i++) {
    const u = units[i];
    if (u >= 0xd800 && u <= 0xdbff && i + 1 < units.length && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff) {
      cps.push(0x10000 + ((u - 0xd800) << 10) + (units[i + 1] - 0xdc00)); i++;
    } else cps.push(u);
  }
  return fromCodePoints(cps);
}
function decodeUtf32(b, start, le) {
  if ((b.length - start) % 4) throw new PyError("UnicodeDecodeError", "utf-32 truncated");
  const cps = [];
  for (let i = start; i < b.length; i += 4) {
    const c = le ? (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0 : ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
    if (c > 0x10ffff) throw new PyError("UnicodeDecodeError", "utf-32 code point not in range");
    cps.push(c);
  }
  return fromCodePoints(cps);
}
function decodeJsonBytes(b) { // json.loads(bytes): json.detect_encoding + 'surrogatepass'
  const sw = (...p) => p.every((x, i) => b[i] === x);
  if (sw(0x00, 0x00, 0xfe, 0xff)) return decodeUtf32(b, 4, false);
  if (sw(0xff, 0xfe, 0x00, 0x00)) return decodeUtf32(b, 4, true);
  if (sw(0xfe, 0xff)) return decodeUtf16(b, 2, false);
  if (sw(0xff, 0xfe)) return decodeUtf16(b, 2, true);
  if (sw(0xef, 0xbb, 0xbf)) return decodeUtf8(b, 3);
  if (b.length >= 4) {
    if (!b[0]) return b[1] ? decodeUtf16(b, 0, false) : decodeUtf32(b, 0, false);
    if (!b[1]) return b[2] || b[3] ? decodeUtf16(b, 0, true) : decodeUtf32(b, 0, true);
  } else if (b.length === 2) {
    if (!b[0]) return decodeUtf16(b, 0, false);
    if (!b[1]) return decodeUtf16(b, 0, true);
  }
  return decodeUtf8(b, 0);
}

// ---------------------------------------------------------------- JSON exactly as CPython json

function pyJsonParse(text, dupCheck) {
  const err = (m) => { throw new PyError("JSONDecodeError", m); };
  let i = 0;
  const n = text.length;
  const ws = () => { while (i < n) { const c = text[i]; if (c === " " || c === "\t" || c === "\n" || c === "\r") i++; else break; } };
  const isDig = (c) => c >= "0" && c <= "9";
  const hex4 = (at) => {
    const h = text.slice(at, at + 4);
    if (h.length < 4 || !/^[0-9a-fA-F]{4}$/.test(h)) err("Invalid \\uXXXX escape");
    return parseInt(h, 16);
  };
  function str() { // at opening quote
    i++;
    let out = "";
    let escHigh = false; // last char appended was a lone high surrogate written as an escape
    for (;;) {
      if (i >= n) err("Unterminated string");
      const c = text[i];
      const code = text.charCodeAt(i);
      if (c === '"') { i++; return out; }
      if (code < 0x20) err("Invalid control character");
      if (c !== "\\") {
        // Python keeps an escaped high surrogate and a following raw low one as two code points
        if (escHigh && code >= 0xdc00 && code <= 0xdfff) out += PAIR_GUARD;
        out += c; i++; escHigh = false; continue;
      }
      i++;
      if (i >= n) err("Unterminated string");
      const e = text[i];
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
      if (simple !== undefined) { out += simple; i++; escHigh = false; continue; }
      if (e !== "u") err("Invalid \\escape");
      let cp = hex4(i + 1);
      i += 5;
      if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < n && text[i] === "\\" && text[i + 1] === "u") {
        const c2 = hex4(i + 2);
        if (c2 >= 0xdc00 && c2 <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + (c2 - 0xdc00); i += 6; }
      }
      // an escaped low surrogate never joins a preceding (raw or escaped) high one in Python
      if (cp >= 0xdc00 && cp <= 0xdfff && out.length && /[\ud800-\udbff]$/.test(out)) out += PAIR_GUARD;
      out += String.fromCodePoint(cp);
      escHigh = cp >= 0xd800 && cp <= 0xdbff;
    }
  }
  function num() {
    const st = i;
    if (text[i] === "-") i++;
    if (i < n && text[i] >= "1" && text[i] <= "9") { while (i < n && isDig(text[i])) i++; }
    else if (i < n && text[i] === "0") i++;
    else err("Expecting value");
    let isFloat = false;
    if (i < n - 1 && text[i] === "." && isDig(text[i + 1])) { i += 2; while (i < n && isDig(text[i])) i++; isFloat = true; }
    if (i < n - 1 && (text[i] === "e" || text[i] === "E")) {
      const save = i;
      i++;
      if (i < n && (text[i] === "+" || text[i] === "-")) i++;
      const ds = i;
      while (i < n && isDig(text[i])) i++;
      if (i > ds) isFloat = true; else i = save;
    }
    const s = text.slice(st, i);
    if (isFloat) return new PyFloat(Number(s));
    const digits = s.replace("-", "");
    if (digits.length > 4300) throw new PyError("ValueError", "Exceeds the limit (4300 digits) for integer string conversion");
    const v = BigInt(s);
    return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
  function value() {
    if (i >= n) err("Expecting value");
    const c = text[i];
    if (c === '"') return str();
    if (c === "{") {
      i++; ws();
      const pairs = [];
      if (text[i] === "}") { i++; return finishObj(pairs); }
      for (;;) {
        if (text[i] !== '"') err("Expecting property name enclosed in double quotes");
        const k = str();
        ws();
        if (text[i] !== ":") err("Expecting ':' delimiter");
        i++; ws();
        const v = value();
        pairs.push([k, v]);
        ws();
        if (text[i] === "}") { i++; return finishObj(pairs); }
        if (text[i] !== ",") err("Expecting ',' delimiter");
        i++; ws();
      }
    }
    if (c === "[") {
      i++; ws();
      const arr = [];
      if (text[i] === "]") { i++; return arr; }
      for (;;) {
        arr.push(value());
        ws();
        if (text[i] === "]") { i++; return arr; }
        if (text[i] !== ",") err("Expecting ',' delimiter");
        i++; ws();
      }
    }
    if (c === "n" && text.startsWith("null", i)) { i += 4; return null; }
    if (c === "t" && text.startsWith("true", i)) { i += 4; return true; }
    if (c === "f" && text.startsWith("false", i)) { i += 5; return false; }
    if (c === "N" && text.startsWith("NaN", i)) { i += 3; return new PyFloat(NaN); }
    if (c === "I" && text.startsWith("Infinity", i)) { i += 8; return new PyFloat(Infinity); }
    if (c === "-" && text.startsWith("-Infinity", i)) { i += 9; return new PyFloat(-Infinity); }
    if (c === "-" || isDig(c)) return num();
    err("Expecting value");
  }
  function finishObj(pairs) {
    const m = new Map();
    for (const [k, v] of pairs) {
      if (dupCheck && m.has(k)) throw new Falla("duplicate_member");
      m.set(k, v);
    }
    return m;
  }
  ws();
  const v = value();
  ws();
  if (i !== n) err("Extra data");
  return v;
}

/** json.loads(x, object_pairs_hook=sin_duplicados) - leer_json in the reference. */
function leerJson(x) {
  if (isStr(x)) {
    if (x.startsWith("﻿")) throw new PyError("JSONDecodeError", "Unexpected UTF-8 BOM");
    return pyJsonParse(x, true);
  }
  return pyJsonParse(decodeJsonBytes(x), true);
}

/** json.load: Python parsing of a JSON text without duplicate check (last value wins). */
export function parsePythonJson(text) {
  if (text.startsWith("﻿")) throw new PyError("JSONDecodeError", "Unexpected UTF-8 BOM");
  return pyJsonParse(text, false);
}

function jsonDumpsStr(s, ensureAscii) {
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const c = s.charCodeAt(i);
    if (ch === '"') o += '\\"';
    else if (ch === "\\") o += "\\\\";
    else if (ch === "\n") o += "\\n";
    else if (ch === "\r") o += "\\r";
    else if (ch === "\t") o += "\\t";
    else if (ch === "\b") o += "\\b";
    else if (ch === "\f") o += "\\f";
    else if (c < 0x20 || (ensureAscii && c > 0x7e)) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += ch;
  }
  return o + '"';
}

/** json.dumps(v) with default separators; ensureAscii as the reference uses it. */
export function pyJsonDumps(v, ensureAscii = false) {
  if (v === null || v === undefined) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number" || typeof v === "bigint") return String(v);
  if (v instanceof PyFloat) {
    if (Number.isNaN(v.v)) return "NaN";
    if (v.v === Infinity) return "Infinity";
    if (v.v === -Infinity) return "-Infinity";
    return floatRepr(v.v);
  }
  if (isStr(v)) return jsonDumpsStr(v, ensureAscii);
  if (isList(v)) return "[" + v.map((x) => pyJsonDumps(x, ensureAscii)).join(", ") + "]";
  if (isMap(v)) return "{" + Array.from(v, ([k, x]) => jsonDumpsStr(String(k), ensureAscii) + ": " + pyJsonDumps(x, ensureAscii)).join(", ") + "}";
  if (typeof v === "object") return pyJsonDumps(fromJs(v), ensureAscii);
  throw new Error("not serializable");
}

/** Converts a JS value (e.g. from JSON.parse) into the Python value model. */
export function fromJs(v) {
  if (v === undefined) return null;
  if (v === null || typeof v === "boolean" || typeof v === "string" || typeof v === "bigint") return v;
  if (v instanceof PyFloat || v instanceof Map) return v;
  if (typeof v === "number") {
    if (Number.isInteger(v)) return Number.isSafeInteger(v) ? (Object.is(v, -0) ? 0 : v) : BigInt(v);
    return new PyFloat(v);
  }
  if (Array.isArray(v)) return v.map(fromJs);
  if (v instanceof Uint8Array) throw new Error("bytes are not JSON");
  const m = new Map();
  for (const k of Object.keys(v)) m.set(k, fromJs(v[k]));
  return m;
}
function toJs(v) {
  if (v instanceof PyFloat) return v.v;
  if (typeof v === "bigint") return Number.isSafeInteger(Number(v)) ? Number(v) : v.toString();
  if (isList(v)) return v.map(toJs);
  if (isMap(v)) {
    const o = {};
    for (const [k, x] of v) Object.defineProperty(o, k, { value: toJs(x), enumerable: true, writable: true, configurable: true });
    return o;
  }
  return v;
}
function input(x) { // public API inputs: JSON text (exact Python semantics) or JS values
  if (isStr(x)) return parsePythonJson(x);
  return fromJs(x);
}

// ---------------------------------------------------------------- primitives

const B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64TABLE = new Map(Array.from(B64CHARS, (c, i) => [c, i]));

/** base64.urlsafe_b64decode(s + padding): non-strict CPython binascii.a2b_base64. */
function b64d(s) {
  if (!isStr(s)) throw new Falla("not_sd_jwt");
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) throw new PyError("ValueError", "string argument should contain only ASCII characters");
  const padded = s + "=".repeat(((-s.length % 4) + 4) % 4);
  const t = padded.replace(/-/g, "+").replace(/_/g, "/");
  const out = [];
  let quad = 0, left = 0, pads = 0;
  let done = false;
  for (const ch of t) {
    if (ch === "=") {
      if (quad >= 2 && quad + ++pads >= 4) { done = true; break; }
      continue;
    }
    const v = B64TABLE.get(ch);
    if (v === undefined) continue;
    pads = 0;
    if (quad === 0) { quad = 1; left = v; }
    else if (quad === 1) { quad = 2; out.push(((left << 2) | (v >> 4)) & 0xff); left = v & 0x0f; }
    else if (quad === 2) { quad = 3; out.push(((left << 4) | (v >> 2)) & 0xff); left = v & 0x03; }
    else { quad = 0; out.push(((left << 6) | v) & 0xff); left = 0; }
  }
  if (!done && quad !== 0) {
    throw new PyError("binascii.Error", quad === 1 ? "Invalid base64-encoded string" : "Incorrect padding");
  }
  return new Uint8Array(out);
}
function b64e(b) {
  let o = "";
  for (let i = 0; i < b.length; i += 3) {
    const x = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    o += B64CHARS[(x >> 18) & 63] + B64CHARS[(x >> 12) & 63];
    if (i + 1 < b.length) o += B64CHARS[(x >> 6) & 63];
    if (i + 2 < b.length) o += B64CHARS[x & 63];
  }
  return o.replace(/\+/g, "-").replace(/\//g, "_");
}
function b64Canonico(seg, i) { // SPEC 9.2
  if (!isStr(seg) || Array.from(seg).some((c) => !B64_ALPHABET.has(c)) || seg.length % 4 === 1) throw new Falla("non_canonical_encoding", i);
  let crudo;
  try { crudo = b64d(seg); } catch (e) { if (!isPy(e)) throw e; throw new Falla("non_canonical_encoding", i); }
  if (b64e(crudo) !== seg) throw new Falla("non_canonical_encoding", i);
  return crudo;
}
const concat = (...xs) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const bytesEq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function subtle() {
  const c = globalThis.crypto && globalThis.crypto.subtle;
  if (!c) throw new Error("WebCrypto (crypto.subtle) is not available; use a secure context or Node >= 20");
  return c;
}
async function sha(b) { return new Uint8Array(await subtle().digest("SHA-256", b)); }
async function dig(b) { return "sha-256:" + b64e(await sha(b)); }
async function hmacSha256(key, msg) {
  const k = await subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, msg));
}

/** RFC 8785 with the 0.1 profile of SPEC 9.3 (safe integers only). */
function jcs(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number" || typeof v === "bigint") {
    const a = typeof v === "bigint" ? (v < 0n ? -v : v) : BigInt(Math.abs(v));
    if (a > 2n ** 53n - 1n) throw new Falla("number_out_of_profile");
    return String(v);
  }
  if (v instanceof PyFloat) throw new Falla("number_out_of_profile");
  if (isStr(v)) {
    if (hasLoneSurrogate(v)) throw new Falla("lone_surrogate");
    return jsonDumpsStr(v, false);
  }
  if (isList(v)) return "[" + v.map(jcs).join(",") + "]";
  if (isMap(v)) {
    const keys = Array.from(v.keys());
    for (const k of keys) if (hasLoneSurrogate(k)) throw new PyError("UnicodeEncodeError", "utf-16-be surrogates not allowed");
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)); // UTF-16 code units == utf-16-be bytes
    return "{" + keys.map((k) => jsonDumpsStr(k, false) + ":" + jcs(v.get(k))).join(",") + "}";
  }
  throw new Falla("not_json");
}
function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { i++; continue; }
      return true;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}
async function digJcs(x) { return dig(utf8Encode(jcs(x))); }
async function huellaDeclaracion(jwt) { // SPEC 9.2: digest of header.payload (the signature is malleable)
  const p = jwt.lastIndexOf(".");
  return dig(asciiEncode(p < 0 ? jwt : jwt.slice(0, p)));
}
async function thumbprint(jwk) {
  const m = new Map([["crv", idx(jwk, "crv")], ["kty", idx(jwk, "kty")], ["x", idx(jwk, "x")], ["y", idx(jwk, "y")]]);
  return b64e(await sha(utf8Encode(jcs(m))));
}

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const keyCache = new Map();
function bytesToBig(b) { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; }
function bigTo32(x) { const o = new Uint8Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; }

/** ES256 with WebCrypto. Mirrors verificar_es256 (which catches ValueError and KeyError). */
async function verifyEs256(jwk, entrada, firma) {
  if (pyNe(get(jwk, "kty"), "EC") || pyNe(get(jwk, "crv"), "P-256") || has(jwk, "d") || firma.length !== 64) return false;
  let x, y;
  try {
    x = bytesToBig(b64d(idx(jwk, "x")));
    y = bytesToBig(b64d(idx(jwk, "y")));
  } catch (e) {
    if (isValueOrKey(e)) return false;
    throw e;
  }
  if (x >= P256_P || y >= P256_P) return false;
  const ck = x.toString(16) + ":" + y.toString(16);
  let key = keyCache.get(ck);
  if (key === undefined) {
    try {
      key = await subtle().importKey("raw", concat(new Uint8Array([4]), bigTo32(x), bigTo32(y)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    } catch {
      key = null; // not a point on P-256 (Python: ValueError)
    }
    keyCache.set(ck, key);
  }
  if (key === null) return false;
  try {
    return await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, firma, entrada);
  } catch {
    return false;
  }
}

async function codigoVisible(td) { // SPEC 6.3 display code
  if (!isStr(td)) throw new PyError("AttributeError", "'" + pyTypeName(td) + "' object has no attribute 'encode'");
  const h = await sha(utf8Encode(td));
  const n = ((h[0] << 24) >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3];
  return String(n % 1000000).padStart(6, "0");
}

// ---------------------------------------------------------------- log (RFC 9162)

const hoja = (d) => sha(concat(new Uint8Array([0]), d));
const nodo = (l, r) => sha(concat(new Uint8Array([1]), l, r));
async function mth(D) {
  if (D.length === 0) return sha(new Uint8Array());
  if (D.length === 1) return hoja(D[0]);
  let k = 1;
  while (k * 2 < D.length) k *= 2;
  return nodo(await mth(D.slice(0, k)), await mth(D.slice(k)));
}
function pySub1(v) {
  if (v instanceof PyFloat) return new PyFloat(v.v - 1);
  if (isIntLike(v)) return bigVal(v) - 1n;
  throw new PyError("TypeError", "unsupported operand type(s) for -");
}
/** RFC 9162 2.1.3.2 */
async function inclusion(indice, tam, h, camino, raiz) {
  if (pyGe(indice, tam)) return false;
  const sn0 = pySub1(tam);
  if (camino.length === 0) return pyEq(sn0, 0) && bytesEq(h, raiz);
  if (pyEq(sn0, 0)) return false;
  if (!isIntLike(indice) || !isIntLike(tam)) throw new PyError("TypeError", "unsupported operand type(s) for &");
  let fn = bigVal(indice), sn = bigVal(tam) - 1n, r = h;
  for (const p of camino) {
    if (sn === 0n) return false;
    if (fn & 1n || fn === sn) {
      r = await nodo(p, r);
      if (!(fn & 1n)) while (!(fn & 1n) && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else r = await nodo(r, p);
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && bytesEq(r, raiz);
}
/** RFC 9162 2.1.4.2 */
async function consistencia(primero, segundo, raiz1, raiz2, camino) {
  if (pyEq(primero, segundo)) return camino.length === 0 && bytesEq(raiz1, raiz2);
  if (pyLt(primero, 1) || pyGt(primero, segundo)) return false;
  if (!isIntLike(primero) || !isIntLike(segundo)) throw new PyError("TypeError", "unsupported operand type(s) for &");
  const a = bigVal(primero), b = bigVal(segundo);
  let c = camino.slice();
  if ((a & (a - 1n)) === 0n) c = [raiz1, ...c];
  if (c.length === 0) return false;
  let fn = a - 1n, sn = b - 1n;
  while (fn & 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = c[0], sr = c[0];
  for (const x of c.slice(1)) {
    if (sn === 0n) return false;
    if (fn & 1n || fn === sn) {
      fr = await nodo(x, fr);
      sr = await nodo(x, sr);
      if (!(fn & 1n)) while (!((fn & 1n) || fn === 0n)) { fn >>= 1n; sn >>= 1n; }
    } else sr = await nodo(sr, x);
    fn >>= 1n;
    sn >>= 1n;
  }
  return bytesEq(fr, raiz1) && bytesEq(sr, raiz2) && sn === 0n;
}

// ---------------------------------------------------------------- urllib.parse (CPython 3.14)

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]$/;
const USES_PARAMS = new Set(["", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu", "sip", "sips", "mms", "sftp", "tel"]);
function checkIPv6(h) {
  const z = h.split("%")[0];
  if (h.includes("%") && h.split("%")[1] === "") return false;
  let parts = z.split(":");
  if (parts.length < 3) return false;
  let ipv4 = parts[parts.length - 1].includes(".");
  if (ipv4) {
    const q = parts[parts.length - 1].split(".");
    if (q.length !== 4 || !q.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255 && !(x.length > 1 && x[0] === "0"))) return false;
    parts = parts.slice(0, -1).concat(["0", "0"]);
  }
  if (parts.length > 9) return false;
  const empties = parts.map((p, i) => (p === "" && i > 0 && i < parts.length - 1 ? i : -1)).filter((i) => i >= 0);
  if (empties.length > 1) return false;
  let lead = parts, cnt;
  if (empties.length === 1) {
    const s = empties[0];
    const before = parts.slice(0, s), after = parts.slice(s + 1);
    if (before.length === 1 && before[0] === "") before.shift(); else if (before[0] === "") return false;
    if (after.length === 1 && after[0] === "") after.pop(); else if (after[after.length - 1] === "") return false;
    if (before.length + after.length > 7) return false;
    lead = before.concat(after);
  } else {
    if (parts.length !== 8) return false;
  }
  return lead.every((p) => /^[0-9a-fA-F]{1,4}$/.test(p));
}
function checkBracketedNetloc(netloc) {
  const hp = netloc.slice(netloc.lastIndexOf("@") + 1);
  let hostname, port;
  const ob = hp.indexOf("[");
  if (ob >= 0) {
    if (ob > 0) throw new PyError("ValueError", "Invalid IPv6 URL");
    const br = hp.slice(ob + 1);
    const cb = br.indexOf("]");
    hostname = cb >= 0 ? br.slice(0, cb) : br;
    port = cb >= 0 ? br.slice(cb + 1) : "";
    if (port && !port.startsWith(":")) throw new PyError("ValueError", "Invalid IPv6 URL");
  } else {
    const cb = hp.indexOf("]");
    hostname = cb >= 0 ? hp.slice(0, cb) : hp;
  }
  if (hostname.startsWith("v")) {
    if (!/^v[a-fA-F0-9]+\..+$/s.test(hostname)) throw new PyError("ValueError", "IPvFuture address is invalid");
  } else {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) && hostname.split(".").every((x) => Number(x) <= 255 && !(x.length > 1 && x[0] === "0"))) throw new PyError("ValueError", "An IPv4 address cannot be in brackets");
    if (!checkIPv6(hostname)) throw new PyError("ValueError", "does not appear to be an IPv4 or IPv6 address");
  }
}
function urlparse(url) {
  let s = url.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let scheme = "", netloc = "", query = "", fragment = "";
  const i = s.indexOf(":");
  if (i > 0 && /^[A-Za-z]$/.test(s[0]) && Array.from(s.slice(0, i)).every((c) => SCHEME_CHARS.test(c))) {
    scheme = s.slice(0, i).toLowerCase();
    s = s.slice(i + 1);
  }
  if (s.slice(0, 2) === "//") {
    let delim = s.length;
    for (const c of "/?#") { const w = s.indexOf(c, 2); if (w >= 0) delim = Math.min(delim, w); }
    netloc = s.slice(2, delim);
    s = s.slice(delim);
    if ((netloc.includes("[") && !netloc.includes("]")) || (netloc.includes("]") && !netloc.includes("["))) throw new PyError("ValueError", "Invalid IPv6 URL");
    if (netloc.includes("[") && netloc.includes("]")) checkBracketedNetloc(netloc);
  }
  if (s.includes("#")) { const k = s.indexOf("#"); fragment = s.slice(k + 1); s = s.slice(0, k); }
  if (s.includes("?")) { const k = s.indexOf("?"); query = s.slice(k + 1); s = s.slice(0, k); }
  if (netloc && /[^\x00-\x7f]/.test(netloc)) {
    const nn = netloc.replace(/[@:#?]/g, "");
    const n2 = nn.normalize("NFKC");
    if (nn !== n2) for (const c of "/?#@:") if (n2.includes(c)) throw new PyError("ValueError", "netloc contains invalid characters under NFKC normalization");
  }
  let path = s, params = "";
  if (USES_PARAMS.has(scheme) && path.includes(";")) {
    let k;
    if (path.includes("/")) { k = path.indexOf(";", path.lastIndexOf("/")); if (k < 0) k = null; }
    else k = path.indexOf(";");
    if (k !== null) { params = path.slice(k + 1); path = path.slice(0, k); }
  }
  return { scheme, netloc, path, params, query, fragment };
}
const rstripSlash = (s) => s.replace(/\/+$/, "");
function bajo(base, url) { // url under base: same scheme and host, path below base's path
  if (!isStr(base) || !isStr(url)) return false;
  const b = urlparse(base), u = urlparse(url);
  return b.scheme === u.scheme && b.netloc.toLowerCase() === u.netloc.toLowerCase() && u.path.startsWith(rstripSlash(b.path) + "/") && !u.query && !u.fragment;
}
function urlMetadata(issuer) { // RFC 8414 3.1
  const u = urlparse(issuer);
  return u.scheme + "://" + u.netloc + "/.well-known/oauth-authorization-server" + rstripSlash(u.path);
}
function quotePlus(s) {
  let o = "";
  for (const b of utf8Encode(s)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9_.\-~]/.test(c)) o += c;
    else if (c === " ") o += "+";
    else o += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return o;
}
const PY_WS = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]);
function pyStrip(v) {
  if (!isStr(v)) throw new PyError("AttributeError", "'" + pyTypeName(v) + "' object has no attribute 'strip'");
  let a = 0, b = v.length;
  while (a < b && PY_WS.has(v.charCodeAt(a))) a++;
  while (b > a && PY_WS.has(v.charCodeAt(b - 1))) b--;
  return v.slice(a, b);
}
function pyLower(v) {
  if (!isStr(v)) throw new PyError("AttributeError", "'" + pyTypeName(v) + "' object has no attribute 'lower'");
  return v.toLowerCase();
}
function startsWithHttp(v) { return isStr(v) && (v.startsWith("https://") || v.startsWith("http://")); }

// ---------------------------------------------------------------- the engine (one per naming)

function makeEngine(N) {
  // ---------- SD-JWT (RFC 9901 7.1) ----------
  async function procesarSd(payload, discl, i) {
    if (has(payload, "_sd_alg") && pyNe(idx(payload, "_sd_alg"), "sha-256")) throw new Falla("bad_sd_alg", i);
    const porHuella = new Map();
    for (const d of discl) {
      const h = b64e(await sha(asciiEncode(d)));
      if (porHuella.has(h)) throw new Falla("disclosure_repeated", i);
      const crudo = b64Canonico(d, i);
      let val;
      try { val = leerJson(crudo); } catch (e) { if (!isPy(e)) throw e; throw new Falla("disclosure_malformed", i); }
      porHuella.set(h, val);
    }
    const vistas = new Set();
    const usadas = new Set();
    const salOk = (sal) => {
      if (!isStr(sal)) throw new Falla("disclosure_malformed", i);
      let n;
      try { n = b64d(sal).length; } catch (e) { if (!isPy(e)) throw e; throw new Falla("disclosure_malformed", i); }
      if (n < 16) throw new Falla("weak_salt", i);
    };
    const huellaNueva = (h) => {
      if (vistas.has(h)) throw new Falla("sd_digest_repeated", i);
      vistas.add(h);
    };
    const recorrer = (v, raiz = false) => {
      if (isMap(v)) {
        if (!raiz && v.has("_sd_alg")) throw new Falla("bad_sd_alg", i);
        const salida = new Map();
        for (const [k, x] of v) if (k !== "_sd" && k !== "_sd_alg") salida.set(k, recorrer(x));
        if (v.has("_sd")) {
          const lista = v.get("_sd");
          if (!isList(lista) || lista.some((h) => !isStr(h))) throw new Falla("bad_sd", i);
          for (const h of lista) {
            huellaNueva(h);
            if (!porHuella.has(h)) continue; // decoy digest or undisclosed claim: ignored
            const c = porHuella.get(h);
            if (!isList(c) || c.length !== 3 || !isStr(c[1])) throw new Falla("disclosure_malformed", i);
            salOk(c[0]);
            if (c[1] === "_sd" || c[1] === "...") throw new Falla("disclosure_bad_name", i);
            if (salida.has(c[1])) throw new Falla("disclosure_claim_exists", i);
            usadas.add(h);
            salida.set(c[1], recorrer(c[2]));
          }
        }
        return salida;
      }
      if (isList(v)) {
        const salida = [];
        for (const x of v) {
          if (isMap(x) && x.has("...")) {
            if (x.size !== 1 || !isStr(x.get("..."))) throw new Falla("bad_sd", i);
            const h = x.get("...");
            huellaNueva(h);
            if (!porHuella.has(h)) continue;
            const c = porHuella.get(h);
            if (!isList(c) || c.length !== 2) throw new Falla("disclosure_malformed", i);
            salOk(c[0]);
            usadas.add(h);
            salida.push(recorrer(c[1]));
          } else salida.push(recorrer(x));
        }
        return salida;
      }
      return v;
    };
    const procesado = recorrer(payload, true);
    for (const h of porHuella.keys()) if (!usadas.has(h)) throw new Falla("disclosure_digest_mismatch", i);
    return procesado;
  }

  // ---------- statement (SPEC 9.5 steps 1-4) ----------
  async function abrir(sdjwt, llaves, i) {
    if (!isStr(sdjwt)) throw new Falla("not_sd_jwt", i);
    const partes = sdjwt.split("~");
    if (partes.length < 2 || partes[partes.length - 1] !== "") throw new Falla("not_sd_jwt", i);
    const jwt = partes[0], discl = partes.slice(1, -1);
    const trozos = jwt.split(".");
    if (trozos.length !== 3) throw new Falla("not_sd_jwt", i);
    const [h64, p64] = trozos;
    const hbytes = b64Canonico(trozos[0], i), pbytes = b64Canonico(trozos[1], i), firma = b64Canonico(trozos[2], i);
    let header, payload;
    try {
      header = leerJson(hbytes);
      payload = leerJson(pbytes);
    } catch (e) {
      if (e instanceof Falla) throw e;
      if (!isPy(e)) throw e;
      throw new Falla("not_sd_jwt", i);
    }
    if (!isMap(header) || !isMap(payload)) throw new Falla("not_sd_jwt", i);
    if (pyNe(get(header, "typ"), N.STMT_TYP) || pyNe(get(header, "alg"), "ES256") || has(header, "crit")) throw new Falla("bad_header", i);
    const iss = get(payload, "iss");
    let rol = null;
    for (const [r, k] of llaves) if (pyEq(idx(k, "issuer"), iss)) { rol = r; break; }
    if (rol === null) throw new Falla("unknown_issuer", i);
    let jwk = null;
    for (const k of pyIter(get(idx(llaves.get(rol), "jwks"), "keys", []))) if (pyEq(get(k, "kid"), get(header, "kid"))) { jwk = k; break; }
    if (jwk === null || pyNe(await thumbprint(jwk), idx(jwk, "kid"))) throw new Falla("unknown_key", i);
    if (!(await verifyEs256(jwk, asciiEncode(h64 + "." + p64), firma))) throw new Falla("signature_invalid", i);
    if (!bytesEq(utf8Encode(jcs(payload)), pbytes)) throw new Falla("non_canonical_payload", i);
    if (!inSet(get(payload, "kind"), ROLES[rol])) throw new Falla("role_mismatch", i);
    return [jwt, await procesarSd(payload, discl, i), rol];
  }

  function lecturaCompleta(lectura, terms) { // SPEC 9.4.7
    const campos = truthy(terms) ? get(terms, "read_back_terms") : null;
    const obs = isMap(lectura) ? get(lectura, "observed") : null;
    return truthy(campos) && isMap(obs) && pyIter(campos).every((c) => has(obs, c));
  }

  // ---------- chain (SPEC 9.5 rules 5-9 and 9.7) ----------
  async function verificarCadena(cadena, llaves, empresa, custodia, audEsperado = null) {
    let prev = null, op = null, aud = null, user = null;
    let ultimaRev = 0, ultimosTerminos = null, ultimoTerms = null;
    let aprobada = null, revisionEmpresa = null, ejecutada = null, lectura = null;
    let lecturasPost = new Map();
    let huboLecturaOk = false, estado = null, ultimoFinal = null;
    const jwts = [], payloads = [];
    const items = pyIter(cadena);
    for (let i = 0; i < items.length; i++) {
      const [jwt, p] = await abrir(items[i], llaves, i);
      if (pyNe(get(p, "v"), "0.1")) throw new Falla("bad_version", i);
      if (pyNe(get(p, "company"), empresa)) throw new Falla("company_mismatch", i);
      if (i === 0) { op = get(p, "op"); aud = get(p, "aud"); user = get(p, "user"); }
      if (pyNe(get(p, "op"), op)) throw new Falla("op_mismatch", i);
      if (pyNe(get(p, "aud"), aud) || (audEsperado !== null && pyNe(aud, audEsperado))) throw new Falla("aud_mismatch", i);
      if (pyNe(get(p, "user"), user)) throw new Falla("user_mismatch", i);
      if (pyNe(get(p, "seq"), i)) throw new Falla("seq_error", i);
      if (pyNe(get(p, "prev"), prev)) throw new Falla("chain_broken", i);
      const b = get(p, "body");
      if (!isMap(b)) throw new Falla("bad_body", i);
      const k = idx(p, "kind");
      const h = await huellaDeclaracion(jwt);
      if (estado !== null && !["read_back", "correction", "revocation"].includes(k)) throw new Falla("after_final", i);
      if ((k === "request") !== (i === 0)) throw new Falla("order_violation", i);
      if (k === "terms") {
        if (pyNe(get(b, "revision"), pyAdd1(ultimaRev)) || aprobada !== null) throw new Falla("revision_error", i);
        const rbt = get(b, "read_back_terms");
        if (typeof get(b, "company_review_required") !== "boolean" || !isList(rbt) || !rbt.every(isStr) || new Set(rbt).size !== rbt.length) throw new Falla("bad_terms", i);
        ultimaRev = idx(b, "revision"); ultimosTerminos = get(b, "terms_digest"); ultimoTerms = b;
      } else if (k === "counter") {
        if (aprobada !== null) throw new Falla("order_violation", i);
        if (pyLt(ultimaRev, 1) || pyNe(get(b, "base_revision"), ultimaRev)) throw new Falla("revision_error", i);
      } else if (k === "user_approval") {
        if (aprobada !== null || pyLt(ultimaRev, 1)) throw new Falla("order_violation", i);
        if (pyNe(get(b, "revision"), ultimaRev)) throw new Falla("approval_not_latest_revision", i);
        if (pyNe(get(b, "terms_digest"), ultimosTerminos)) throw new Falla("approval_terms_mismatch", i);
        if (!inTuple(get(b, "method"), ["agent_asserted", "company_channel"])) throw new Falla("bad_approval_method", i);
        if (pyEq(get(b, "method"), "company_channel") && pyNe(get(b, "display_code"), await codigoVisible(idx(b, "terms_digest")))) throw new Falla("display_code_mismatch", i);
        aprobada = b;
      } else if (k === "company_review") {
        if (aprobada === null || ejecutada !== null || revisionEmpresa !== null) throw new Falla("order_violation", i);
        if (pyNe(get(b, "terms_digest"), idx(aprobada, "terms_digest")) || pyNe(get(b, "revision"), idx(aprobada, "revision"))) throw new Falla("order_violation", i);
        if (!inTuple(get(b, "decision"), ["approved", "denied"])) throw new Falla("bad_decision", i);
        revisionEmpresa = idx(b, "decision");
      } else if (k === "execution") {
        if (aprobada === null || ejecutada !== null || revisionEmpresa === "denied") throw new Falla("order_violation", i);
        if (truthy(idx(ultimoTerms, "company_review_required")) && revisionEmpresa !== "approved") throw new Falla("order_violation", i);
        if (pyNe(get(b, "terms_digest"), idx(aprobada, "terms_digest")) || pyNe(get(b, "revision"), idx(aprobada, "revision"))) throw new Falla("execution_terms_mismatch", i);
        ejecutada = b;
      } else if (k === "read_back") {
        if (ejecutada === null) throw new Falla("order_violation", i);
        if (!inTuple(get(b, "method"), READ_METHODS) || typeof get(b, "matches_terms") !== "boolean") throw new Falla("bad_read_back", i);
        const coincide = pyEq(idx(b, "method"), "system_read_back") && idx(b, "matches_terms") === true;
        huboLecturaOk = huboLecturaOk || coincide;
        if (estado === null) lectura = b;
        else lecturasPost.set(h, [coincide, b]);
      } else if (k === "outcome") {
        if (pyLt(ultimaRev, 1)) throw new Falla("order_violation", i);
        if (pyNe(get(b, "terms_digest"), ultimosTerminos) || pyNe(get(b, "revision"), ultimaRev)) throw new Falla("outcome_terms_mismatch", i);
        if (!inTuple(get(b, "state"), STATES)) throw new Falla("bad_state", i);
        if (revisionEmpresa === "denied" && pyNe(idx(b, "state"), "failed")) throw new Falla("outcome_after_denial", i);
        if (pyEq(idx(b, "state"), "succeeded") && (ejecutada === null || lectura === null || get(lectura, "matches_terms") !== true || pyNe(get(lectura, "method"), "system_read_back"))) throw new Falla("succeeded_without_matching_read_back", i);
        if (pyEq(idx(b, "state"), "succeeded") && !lecturaCompleta(lectura, ultimoTerms)) throw new Falla("read_back_incomplete", i);
        estado = idx(b, "state");
        ultimoFinal = h;
        lecturasPost = new Map();
      } else if (k === "correction" || k === "revocation") {
        const ref = k === "correction" ? get(b, "corrects") : get(b, "revokes");
        if (estado === null || pyNe(ref, ultimoFinal)) throw new Falla("order_violation", i);
        if (k === "correction") {
          if (!inTuple(get(b, "state"), STATES)) throw new Falla("bad_state", i);
          const rk = get(b, "read_back");
          if (unhashable(rk)) throw new PyError("TypeError", "unhashable type");
          const citada = isStr(rk) && lecturasPost.has(rk) ? lecturasPost.get(rk) : null;
          if (pyEq(idx(b, "state"), "succeeded") && (citada === null || citada[0] !== true)) throw new Falla("correction_without_read_back", i);
          if (pyEq(idx(b, "state"), "succeeded") && !lecturaCompleta(citada[1], ultimoTerms)) throw new Falla("read_back_incomplete", i);
          estado = idx(b, "state");
        } else estado = "revoked";
        ultimoFinal = h;
        lecturasPost = new Map();
      }
      prev = h;
      jwts.push(jwt);
      payloads.push(p);
    }
    if (estado === null) throw new Falla("no_outcome");
    const vigente = revisionEmpresa !== "denied" ? aprobada : null;
    const asegura = ["issuer_key_attested"];
    if (ejecutada !== null) asegura.push("operator_observed");
    if (huboLecturaOk) asegura.push("operator_reported_read_back");
    if (vigente !== null) asegura.push(pyEq(get(vigente, "method"), "company_channel") ? "operator_reported_channel_approval" : "operator_reported_agent_approval");
    const veredicto = new Map([
      ["valid", true],
      ["final_state", estado],
      ["revision", vigente !== null ? idx(vigente, "revision") : null],
      ["approval", vigente !== null ? get(vigente, "method") : null],
      ["derived_assurance", asegura],
      ["single_root", "operator"], // SPEC 9.6: no verifiable evidence of another root in 0.1
      ["custody_declared", custodia],
      ["logged", false],
    ]);
    return [veredicto, jwts, payloads];
  }

  // ---------- public material and anchoring (SPEC 9.9.1) ----------
  class Material {
    constructor(docs) { this.docs = docs; }
    esquema(host) { if (!isStr(host)) throw new PyError("AttributeError", "no attribute 'split'"); return "https"; }
    traer(url, crudo = false) {
      const NA = "issuer_not_anchored";
      const docs = this.docs;
      if (!isMap(docs)) {
        if (isList(docs)) { if (docs.some((x) => pyEq(x, url))) throw new PyError("TypeError", "list indices must be integers"); throw new Falla(NA); }
        if (isStr(docs)) { if (!isStr(url)) throw new PyError("TypeError", "'in <string>' requires string"); if (docs.includes(url)) throw new PyError("TypeError", "string indices must be integers"); throw new Falla(NA); }
        throw new PyError("TypeError", "material docs are not a dict");
      }
      if (unhashable(url)) throw new PyError("TypeError", "unhashable type");
      if (!isStr(url) || !docs.has(url)) throw new Falla(NA);
      const v = docs.get(url);
      if (crudo || !isStr(v)) return v;
      try { return leerJson(v); } catch (e) { if (e instanceof Falla) throw e; if (!isPy(e)) throw e; throw new Falla(NA); }
    }
  }

  function interfazHttpJson(card) {
    for (const i of pyIter(get(card, "supportedInterfaces") || [])) {
      if (isMap(i) && pyEq(get(i, "protocolBinding"), "HTTP+JSON") && pyEq(get(i, "protocolVersion"), "1.0")) return get(i, "url");
    }
    return null;
  }
  const or = (a, b) => (truthy(a) ? a : b);

  function confianzaDe(material, issuer) {
    if (!startsWithHttp(issuer)) throw new Falla("issuer_not_anchored");
    const meta = material.traer(urlMetadata(issuer));
    if (!isMap(meta) || pyNe(get(meta, "issuer"), issuer)) throw new Falla("issuer_not_anchored");
    return [meta, get(meta, N.META_PROOF)];
  }

  function anclarPact(material, ancla) {
    const NA = "issuer_not_anchored";
    let marca, empresa, copia, interfaz, asPact, metaAs, tipo;
    if (truthy(get(ancla, "brand_domain"))) {
      marca = idx(ancla, "brand_domain");
      const card = material.traer(material.esquema(marca) + "://" + pyStr(marca) + "/.well-known/agent-card.json");
      if (!isMap(card)) throw new Falla(NA);
      const exts = or(get(or(get(card, "capabilities"), new Map()), "extensions"), []);
      const ext = pyIter(exts).find((x) => isMap(x) && pyEq(get(x, "uri"), N.EXT_A2A)) ?? null;
      if (ext === null) throw new Falla("discovery_without_extension");
      copia = or(get(ext, "params"), new Map());
      empresa = get(copia, "company");
      interfaz = interfazHttpJson(card);
      asPact = null; metaAs = null; tipo = "brand_domain";
    } else {
      asPact = idx(ancla, "pact_issuer");
      [metaAs, copia] = confianzaDe(material, asPact);
      if (!isMap(copia)) throw new Falla(NA);
      empresa = get(copia, "company");
      interfaz = null; tipo = "pact_issuer";
    }
    const [, confianza] = confianzaDe(material, empresa);
    if (!isMap(confianza) || pyNe(get(confianza, "company"), empresa)) throw new Falla(NA);
    const vinculos = pyIter(or(get(confianza, "pact"), [])).filter(isMap);
    if (tipo === "brand_domain") {
      const doms = pyIter(or(get(confianza, "domains"), [])).map((x) => pyLower(pyStr(x)));
      if (!doms.includes(pyLower(marca))) throw new Falla(NA);
      const v = vinculos.find((x) => pyEq(get(x, "interface"), interfaz)) ?? null;
      if (v === null) throw new Falla(NA);
      asPact = get(v, "authorization_server");
      let copiaAs;
      [metaAs, copiaAs] = confianzaDe(material, asPact);
      if (!isMap(copiaAs)) throw new Falla(NA);
      for (const m of MEMBERS_OF_TRUST) if (jcs(get(copiaAs, m)) !== jcs(get(confianza, m))) throw new Falla(NA);
    } else {
      const v = vinculos.find((x) => pyEq(get(x, "authorization_server"), asPact)) ?? null;
      if (v === null) throw new Falla(NA);
      interfaz = get(v, "interface");
    }
    if (!bajo(asPact, get(metaAs, "jwks_uri"))) throw new Falla(NA);
    return [empresa, copia, { interface: interfaz, authorization_server: asPact, jwks_uri: idx(metaAs, "jwks_uri") }, tipo];
  }

  /** SPEC 9.9.1. Returns [trust block, issuer, profile, anchor type, pact or null]. */
  function anclarExt(material, ancla) {
    const NA = "issuer_not_anchored";
    const dominio = get(ancla, "domain");
    let bloquePerfil = null, pact = null, issuer, perfil, tipo;
    if (truthy(get(ancla, "brand_domain")) || truthy(get(ancla, "pact_issuer"))) {
      [issuer, bloquePerfil, pact, tipo] = anclarPact(material, ancla);
      perfil = "pact";
    } else if (truthy(dominio)) {
      const doc = material.traer(material.esquema(dominio) + "://" + pyStr(dominio) + "/.well-known/poppy.json");
      const org = get(or(get(doc, "organization"), new Map()), "domain");
      if (!isStr(org) || pyLower(org) !== pyLower(dominio)) throw new Falla(NA); // Poppy 3 rule 1
      issuer = get(or(get(doc, "auth"), new Map()), "issuer");
      if (get(ancla, "issuer") !== null && pyNe(idx(ancla, "issuer"), issuer)) throw new Falla(NA);
      bloquePerfil = get(or(get(doc, "extensions"), new Map()), N.EXT_POPPY);
      perfil = "poppy"; tipo = "poppy_domain";
    } else if (truthy(get(ancla, "issuer"))) {
      issuer = idx(ancla, "issuer");
      perfil = "issuer"; tipo = "issuer";
      if (truthy(get(ancla, "card"))) {
        const card = material.traer(idx(ancla, "card"));
        const ext = pyIter(or(get(or(get(card, "capabilities"), new Map()), "extensions"), [])).find((x) => pyEq(get(x, "uri"), N.EXT_A2A)) ?? null;
        if (ext === null) throw new Falla("discovery_without_extension");
        bloquePerfil = or(get(ext, "params"), new Map());
        perfil = "a2a";
      }
    } else throw new Falla("no_anchor");
    if (!startsWithHttp(issuer)) throw new Falla(NA);
    const meta = material.traer(urlMetadata(issuer));
    if (pyNe(get(meta, "issuer"), issuer)) throw new Falla(NA); // RFC 8414 3.3
    if (truthy(dominio) && !pyIter(or(get(meta, "poppy_domains"), [])).map((x) => pyLower(pyStr(x))).includes(pyLower(dominio))) throw new Falla(NA); // Poppy 3 rule 2
    const confianza = get(meta, N.META_PROOF);
    if (!isMap(confianza) || pyNe(get(confianza, "company"), issuer)) throw new Falla(NA);
    const operador = or(get(confianza, "operator"), new Map());
    if (!bajo(issuer, get(confianza, "jwks_uri")) || !bajo(get(operador, "issuer"), get(operador, "jwks_uri"))) throw new Falla(NA);
    if (bloquePerfil !== null) {
      for (const m of MEMBERS_OF_TRUST) if (jcs(get(bloquePerfil, m)) !== jcs(get(confianza, m))) throw new Falla(NA);
    }
    return [confianza, issuer, perfil, tipo, pact];
  }

  async function verificarReciboPact(material, pact, recibo) { // PACT 5.6
    if (!isMap(recibo) || !isStr(get(recibo, "jws")) || get(recibo, "jws").split(".").length - 1 !== 2) throw new Falla("pact_receipt_invalid", 0);
    const [h64, p64, s64] = get(recibo, "jws").split(".");
    let header, claims, firma;
    try {
      header = leerJson(b64d(h64));
      claims = leerJson(b64d(p64));
      firma = b64d(s64);
    } catch (e) {
      if (!isPy(e)) throw e;
      throw new Falla("pact_receipt_invalid", 0);
    }
    if (pyNe(get(header, "alg"), "ES256")) throw new Falla("pact_receipt_invalid", 0);
    const jwks = material.traer(pact.jwks_uri);
    let jwk = null;
    for (const k of pyIter(get(or(jwks, new Map()), "keys", []))) if (pyEq(get(k, "kid"), get(header, "kid"))) { jwk = k; break; }
    if (jwk === null || !(await verifyEs256(jwk, asciiEncode(h64 + "." + p64), firma))) throw new Falla("pact_receipt_invalid", 0);
    return claims;
  }

  async function cruzarReciboPact(payloads, material, pact, recibo) {
    const body0 = idx(payloads[0], "body");
    const cita = get(body0, "pact_proposal_receipt");
    if (cita === null) {
      if (recibo !== null) throw new Falla("pact_receipt_mismatch", 0);
      return new Map();
    }
    if (!isMap(cita) || pyNe(get(cita, "argsHash"), get(body0, "request_digest"))) throw new Falla("pact_receipt_mismatch", 0);
    if (recibo === null) return new Map([["pact_receipt", "not_presented"]]);
    if (pact === null) throw new Falla("pact_receipt_not_anchored", 0);
    const claims = await verificarReciboPact(material, pact, recibo);
    const acciones = isList(get(claims, "actions")) ? get(claims, "actions") : [];
    if (pyNe(get(claims, "grantId"), get(cita, "grantId")) || pyNe(get(claims, "brand"), pact.interface) || pyNe(get(claims, "pa"), get(payloads[0], "aud")) || !acciones.some((a) => isMap(a) && pyEq(get(a, "argsHash"), get(cita, "argsHash")))) throw new Falla("pact_receipt_mismatch", 0);
    return new Map([["pact_receipt", "verified"]]);
  }

  function llavesAncladas(material, confianza, issuer) {
    const companyJwks = material.traer(idx(confianza, "jwks_uri"));
    const opIssuer = idx(idx(confianza, "operator"), "issuer");
    const opJwks = material.traer(idx(idx(confianza, "operator"), "jwks_uri"));
    return new Map([
      ["company", new Map([["issuer", issuer], ["jwks", companyJwks]])],
      ["operator", new Map([["issuer", opIssuer], ["jwks", opJwks]])],
    ]);
  }

  async function verificarJws(jws, jwks, typ) {
    if (!isStr(jws)) throw new PyError("AttributeError", "no attribute 'split'");
    const parts = jws.split(".");
    if (parts.length !== 3) throw new PyError("ValueError", "not enough values to unpack");
    const [h64, p64, s64] = parts;
    const header = leerJson(b64d(h64));
    if (pyNe(get(header, "alg"), "ES256") || pyNe(get(header, "typ"), typ)) return null;
    let jwk = null;
    for (const k of pyIter(get(jwks, "keys", []))) if (pyEq(get(k, "kid"), get(header, "kid"))) { jwk = k; break; }
    if (jwk === null || pyNe(await thumbprint(jwk), idx(jwk, "kid"))) return null;
    if (!(await verifyEs256(jwk, asciiEncode(h64 + "." + p64), b64d(s64)))) return null;
    return leerJson(b64d(p64));
  }

  async function verificarRegistro(paquete, jwts, bloque, material) { // SPEC 9.8, 9.9 step 3
    const log = get(paquete, "log");
    if (!truthy(log)) return new Map([["log_inclusion", "absent"]]);
    const jwksLog = material.traer(idx(idx(bloque, "log"), "jwks_uri"));
    const cp = await verificarJws(idx(log, "checkpoint"), jwksLog, N.CHECKPOINT_TYP);
    if (cp === null) throw new Falla("checkpoint_signature_invalid");
    if (pyNe(get(cp, "origin"), idx(idx(bloque, "log"), "origin")) || pyNe(get(log, "origin"), idx(idx(bloque, "log"), "origin"))) throw new Falla("log_origin_mismatch");
    const tam = idx(cp, "tree_size"), raiz = b64d(idx(cp, "root_hash"));
    const porSeq = new Map();
    for (const x of pyIter(get(log, "inclusion", []))) {
      const k = pyKey(idx(x, "seq"));
      porSeq.set(k, x);
    }
    for (let seq = 0; seq < jwts.length; seq++) {
      const x = porSeq.has(pyKey(seq)) ? porSeq.get(pyKey(seq)) : null;
      if (x === null) throw new Falla("log_inclusion_missing", seq);
      const entrada = concat(await sha(concat(b64d(idx(x, "salt")), asciiEncode(jwts[seq]))), b64d(idx(x, "tag")));
      if (b64d(idx(x, "salt")).length !== 32 || b64d(idx(x, "tag")).length !== 32) throw new Falla("log_bad_leaf", seq);
      const li = idx(x, "leaf_index");
      const hh = await hoja(entrada);
      const camino = pyIter(idx(x, "path")).map(b64d);
      if (!(await inclusion(li, tam, hh, camino, raiz))) throw new Falla("log_inclusion_failed", seq);
    }
    const vivo = await verificarJws(pyStrip(material.traer(idx(idx(bloque, "log"), "checkpoint_url"), true)), jwksLog, N.CHECKPOINT_TYP);
    if (vivo === null) throw new Falla("checkpoint_signature_invalid");
    const t2 = idx(vivo, "tree_size"), r2 = b64d(idx(vivo, "root_hash"));
    if (pyLt(t2, tam)) throw new Falla("equivocation_detected");
    if (pyEq(t2, tam) && !bytesEq(r2, raiz)) throw new Falla("equivocation_detected");
    if (pyGt(t2, tam)) {
      const cu = idx(idx(bloque, "log"), "consistency_url");
      if (!isStr(cu)) throw new PyError("TypeError", "can only concatenate str");
      const url = cu + "?" + "first=" + quotePlus(pyStr(tam)) + "&second=" + quotePlus(pyStr(t2));
      const prueba = material.traer(url);
      const camino = pyIter(get(prueba, "path", [])).map(b64d);
      if (!(await consistencia(tam, t2, raiz, r2, camino))) throw new Falla("equivocation_detected");
    }
    const testigos = or(get(idx(bloque, "log"), "witnesses"), []);
    return new Map([
      ["log_inclusion", "ok"],
      ["tree_size", tam],
      ["live_tree_size", t2],
      ["consistency", "ok"],
      ["witnesses", pyLen(testigos)], // no external witness co-signature in 0.1: never `logged`
    ]);
  }

  async function cruzarOperacion(operacion, empresa, payloads) {
    if (pyNe(get(operacion, "operation_id"), idx(payloads[0], "op"))) throw new Falla("operation_id_mismatch");
    const terms = payloads.filter((p) => idx(p, "kind") === "terms" && pyEq(idx(idx(p, "body"), "revision"), get(operacion, "revision")));
    if (!terms.length) throw new Falla("operation_revision_unknown");
    const m = new Map();
    m.set("company", empresa);
    m.set("operation_id", idx(operacion, "operation_id"));
    m.set("revision", idx(operacion, "revision"));
    m.set("summary", idx(operacion, "summary"));
    m.set("terms", get(operacion, "terms"));
    m.set("expires_at", get(operacion, "expires_at"));
    m.set("user_approval_required", idx(operacion, "user_approval_required"));
    const calculada = await digJcs(m);
    if (pyNe(calculada, idx(idx(terms[terms.length - 1], "body"), "terms_digest"))) throw new Falla("operation_terms_mismatch");
    const sal = isMap(get(operacion, "terms")) ? get(or(get(operacion, "terms"), new Map()), N.TERMS_SALT) : null;
    let salOk;
    try { salOk = isStr(sal) && b64e(b64d(sal)) === sal && b64d(sal).length >= 16; } catch (e) { if (!isPy(e)) throw e; salOk = false; }
    if (!salOk) throw new Falla("weak_terms_salt");
    const terminos = or(get(operacion, "terms"), new Map());
    for (const p of payloads) {
      if (idx(p, "kind") !== "read_back" || get(idx(p, "body"), "matches_terms") !== true) continue;
      const obs = or(get(idx(p, "body"), "observed"), new Map());
      if (!isMap(obs)) throw new PyError("AttributeError", "no attribute 'items'");
      for (const [nombre, valor] of obs) if (has(terminos, nombre) && jcs(idx(terminos, nombre)) !== jcs(valor)) throw new Falla("read_back_terms_mismatch", idx(p, "seq"));
    }
    const estado = get(operacion, "state");
    const finales = payloads.filter((p) => idx(p, "kind") === "outcome" || idx(p, "kind") === "correction");
    if (unhashable(estado)) throw new PyError("TypeError", "unhashable type");
    if (isStr(estado) && POPPY_STATE.has(estado)) {
      if (!finales.length || pyNe(idx(idx(finales[finales.length - 1], "body"), "state"), POPPY_STATE.get(estado))) throw new Falla("operation_state_mismatch");
      const resumen = get(or(get(operacion, "result"), new Map()), "summary", "");
      if (pyNe(get(idx(finales[finales.length - 1], "body"), "result_summary_digest"), await digJcs(resumen))) throw new Falla("operation_result_mismatch");
    } else if (finales.length && pyNe(idx(idx(finales[finales.length - 1], "body"), "state"), "unknown")) throw new Falla("operation_state_mismatch");
    return new Map([["operation", "matches"]]);
  }

  async function verificarPaquete(paquete, material, ancla, aud = null, operacion = null, reciboPact = null) {
    const [bloque, empresa, perfil, tipo, pact] = anclarExt(material, ancla);
    const llaves = llavesAncladas(material, bloque, empresa);
    if (pyNe(get(paquete, "v"), "0.1")) throw new Falla("bad_version");
    if (pyNe(get(paquete, "company"), empresa)) throw new Falla("company_mismatch");
    const estados = or(get(paquete, "statements"), []);
    if (!truthy(estados)) throw new Falla("no_outcome");
    const [veredicto, jwts, payloads] = await verificarCadena(estados, llaves, empresa, get(bloque, "custody"), aud);
    if (pyNe(get(paquete, "op"), idx(payloads[0], "op"))) throw new Falla("op_mismatch");
    veredicto.set("company", empresa);
    veredicto.set("anchor", tipo);
    veredicto.set("key_source", "issuer_metadata_live");
    veredicto.set("profile", perfil);
    veredicto.set("statements", pyLen(estados));
    for (const [k, v] of await verificarRegistro(paquete, jwts, bloque, material)) veredicto.set(k, v);
    if (operacion !== null) for (const [k, v] of await cruzarOperacion(operacion, empresa, payloads)) veredicto.set(k, v);
    for (const [k, v] of await cruzarReciboPact(payloads, material, pact, reciboPact)) veredicto.set(k, v);
    if (pact !== null) veredicto.set("pact_interface", pact.interface);
    return veredicto;
  }

  return { abrir, procesarSd, verificarCadena, Material, anclarExt, llavesAncladas, verificarPaquete, cruzarOperacion };
}

const ENGINES = { "vxp-0.1": makeEngine(NAMING_VXP), "legacy-0.1-sovras": makeEngine(NAMING_LEGACY_0_1) };
const engineFor = (naming) => ENGINES[namingOf(naming).id];

// ---------------------------------------------------------------- verdict objects

const VERDICT_JSON = Symbol("vxp.verdict.python_json");
function finishVerdict(m, naming) {
  const o = toJs(m);
  Object.defineProperty(o, VERDICT_JSON, { value: pyJsonDumps(m, false) });
  if (naming && naming !== NAMING_VXP) Object.defineProperty(o, "naming", { value: naming.id, enumerable: false });
  return o;
}
function failureVerdict(e) {
  if (e instanceof Falla) {
    const m = new Map([["valid", false], ["error", e.code], ["seq", e.seq]]);
    if (e.code === "no_outcome") m.set("final_state", "unknown");
    return m;
  }
  if (e instanceof PyError) return new Map([["valid", false], ["error", "malformed_input"], ["seq", null], ["python_exception", e.pyType]]);
  throw e;
}

/**
 * The exact JSON line the Python reference prints for this verdict (same key order and
 * formatting). For a "malformed_input" verdict the reference prints a traceback instead.
 */
export function verdictJson(verdict) {
  return verdict[VERDICT_JSON] ?? pyJsonDumps(fromJs(verdict), false);
}

/**
 * Verifies a VXP Proof package with already-downloaded public material (reference "material"
 * mode). Inputs may be JSON text (recommended: exact Python number semantics) or JS values.
 *   pkg:       {v, company, op, statements[], log?}
 *   material:  {anchor: {domain} | {brand_domain} | {pact_issuer} | {issuer, card?}, docs: {url: content}}
 *   operation: optional operation the agent saw (Poppy operation / vxpprotocol.org/operation)
 *   aud:       optional expected audience (the verifying agent)
 *   receipt:   optional PACT receipt {jws}
 *   naming:    "vxp" (default) or "legacy-0.1" (identifiers before VXP spec 8.1)
 */
export async function verifyPackage({ package: pkg, material, operation = null, aud = null, receipt = null, naming = "vxp" } = {}) {
  const N = namingOf(naming);
  const E = engineFor(naming);
  let m;
  try {
    const mat = input(material);
    const paquete = input(pkg);
    const op = operation === null || operation === undefined ? null : input(operation);
    const rec = receipt === null || receipt === undefined ? null : input(receipt);
    const docs = idx(mat, "docs");
    if (docs === null) throw new Falla("material_docs_missing"); // the reference would go to the network
    const ancla = or2(get(mat, "anchor"), new Map());
    m = await E.verificarPaquete(paquete, new E.Material(docs), ancla, aud === undefined ? null : aud, op, rec);
  } catch (e) {
    m = failureVerdict(e);
  }
  return finishVerdict(m, N);
}
const or2 = (a, b) => (truthy(a) ? a : b);

/**
 * Verifies a bare chain of statements against known keys (reference verificar_cadena).
 * keys: {company: {issuer, jwks}, operator: {issuer, jwks}}.
 */
export async function verifyChain(statements, keys, company, custody = null, { aud = null, naming = "vxp" } = {}) {
  const E = engineFor(naming);
  let m;
  try {
    const k = input(keys);
    const llaves = new Map([["company", idx(k, "company")], ["operator", idx(k, "operator")]]);
    [m] = await E.verificarCadena(input(statements), llaves, fromJs(company), fromJs(custody), aud);
  } catch (e) {
    m = failureVerdict(e);
  }
  return finishVerdict(m, namingOf(naming));
}

// ---------------------------------------------------------------- conformance vectors

const VERDICT_KEYS = ["valid", "final_state", "revision", "approval", "derived_assurance", "single_root", "custody_declared", "logged"];
const sub = (m, keys) => new Map(keys.map((k) => [k, idx(m, k)]));
const fmtFail = (e, expect) => pyStr(e.code) + " en seq " + pyStr(e.seq) + "; esperado " + pyStr(expect);

function reporter() {
  const checks = [];
  return {
    checks,
    add(name, ok, detail = "") { checks.push({ name, ok, detail }); },
    done() {
      const failures = checks.filter((c) => !c.ok).length;
      const lines = checks.map((c) => (c.ok ? "OK   " : "FALLA") + " " + c.name + (c.detail ? " - " + c.detail : ""));
      lines.push("", checks.length + " comprobaciones, " + failures + " fallas");
      return { checks, total: checks.length, failures, lines };
    },
  };
}

function aplicar(cadena, n) {
  if (has(n, "chain")) return pyIter(idx(n, "chain")).slice();
  const c = cadena.slice();
  const reps = (has(n, "replace") ? [idx(n, "replace")] : []).concat(pyIter(get(n, "replace_many", [])));
  for (const r of reps) {
    const s = Number(idx(r, "seq"));
    c[s] = [idx(r, "jwt")].concat(c[s].split("~").slice(1)).join("~");
  }
  if (has(n, "replace_disclosure")) {
    const r = idx(n, "replace_disclosure");
    const s = Number(idx(r, "seq"));
    const partes = c[s].split("~");
    partes[1 + Number(idx(r, "index"))] = idx(r, "disclosure");
    c[s] = partes.join("~");
  }
  return c;
}

/** Reference mode `vectores` (SPEC appendix A). Returns {checks, total, failures, lines}. */
export async function verifyVectors(json) {
  const E = engineFor("vxp");
  const v = input(json);
  const keys = idx(v, "keys");
  const llaves = new Map([["company", idx(keys, "company")], ["operator", idx(keys, "operator")]]);
  const empresa = idx(idx(keys, "company"), "issuer");
  const custodia = idx(idx(keys, "company"), "custody");
  const chainV1 = idx(v, "chain_v1");
  const cadena = chainV1.map((s) => idx(s, "sdjwt"));
  const pay = chainV1.map((s) => parsePythonJson(idx(s, "payload_jcs")));
  const ins = idx(v, "inputs");
  const R = reporter();
  const body = (n) => idx(pay[n], "body");

  R.add("terms_digest_1", (await digJcs(idx(ins, "terminos1"))) === idx(ins, "terms_digest_1"));
  R.add("terms_digest_2", (await digJcs(idx(ins, "terminos2"))) === idx(ins, "terms_digest_2"));
  R.add("display_code_2", (await codigoVisible(idx(ins, "terms_digest_2"))) === idx(ins, "display_code_2"));
  R.add("request_digest", pyEq(idx(body(0), "request_digest"), await digJcs(idx(ins, "solicitud"))));
  R.add("idempotency_key_digest", pyEq(idx(body(0), "idempotency_key_digest"), await digJcs(idx(ins, "idempotency_key"))));
  R.add("counter_digest", pyEq(idx(body(2), "counter_digest"), await digJcs(idx(ins, "contra"))));
  R.add("release", pyEq(idx(body(5), "release"), await digJcs(idx(ins, "release_closure"))));
  R.add("result_summary_digest", pyEq(idx(body(7), "result_summary_digest"), await digJcs(idx(ins, "resumenResultado"))));
  for (const s of chainV1) R.add("huella seq " + pyStr(idx(s, "seq")), pyEq(await huellaDeclaracion(idx(s, "sdjwt").split("~")[0]), idx(s, "digest")));
  const m = idx(v, "malleated_outcome");
  R.add("firma maleada (s -> n-s): misma huella", pyEq(await huellaDeclaracion(idx(m, "jwt")), idx(chainV1[7], "digest")));
  const [ver, , procesados] = await E.verificarCadena(cadena, llaves, empresa, custodia);
  R.add("V1", pyEq(sub(ver, VERDICT_KEYS), idx(v, "expected_v1")), pyJsonDumps(sub(ver, VERDICT_KEYS), true));
  R.add("V1 divulgacion procesada en su lugar", pyEq(idx(idx(procesados[6], "body"), "observed"), idx(v, "expected_processed_observed_seq6")));
  const [verM] = await E.verificarCadena(cadena.slice(0, 7).concat([idx(m, "jwt") + "~"]), llaves, empresa, custodia);
  R.add("V1 con la firma maleada sigue valida", verM.get("final_state") === "succeeded");
  for (const nombre of ["v2", "v3"]) {
    const x = idx(v, "chain_" + nombre);
    const [ver2] = await E.verificarCadena(cadena.concat(pyIter(idx(x, "extra"))), llaves, empresa, custodia);
    R.add(nombre.toUpperCase(), pyEq(sub(ver2, VERDICT_KEYS), idx(x, "expected")), pyJsonDumps(sub(ver2, VERDICT_KEYS), true));
  }
  const x4 = idx(v, "chain_v4");
  const [ver4] = await E.verificarCadena(idx(x4, "chain"), llaves, empresa, custodia);
  R.add("V4", pyEq(sub(ver4, VERDICT_KEYS), idx(x4, "expected")), pyJsonDumps(sub(ver4, VERDICT_KEYS), true));
  const ch4 = idx(x4, "chain"), dg4 = idx(x4, "digests");
  for (let j = 0; j < Math.min(ch4.length, dg4.length); j++) {
    R.add("V4 huella seq " + ch4.indexOf(ch4[j]), pyEq(await huellaDeclaracion(ch4[j].split("~")[0]), dg4[j]));
  }
  for (const caso of pyIter(get(v, "operation_cases", []))) {
    try {
      const [, , procesados5] = await E.verificarCadena(idx(caso, "chain"), llaves, empresa, custodia);
      const r5 = await E.cruzarOperacion(idx(caso, "operation"), empresa, procesados5);
      R.add(idx(caso, "id"), pyEq(idx(caso, "expect"), "valid") && pyEq(get(r5, "operation"), "matches"), pyJsonDumps(r5, true));
    } catch (e) {
      if (!(e instanceof Falla)) throw e;
      R.add(idx(caso, "id"), pyEq(e.code, idx(caso, "expect")) && (get(caso, "seq") === null || pyEq(e.seq, idx(caso, "seq"))), fmtFail(e, idx(caso, "expect")));
    }
  }
  const log = idx(v, "log");
  const D = pyIter(idx(log, "leaves")).map((x) => b64d(idx(x, "leaf_input")));
  const raiz = await mth(D);
  R.add("raiz", b64e(raiz) === idx(log, "root_hash"));
  const kTag = b64d(idx(log, "tag_key_TEST_ONLY"));
  for (const x of pyIter(idx(log, "leaves"))) {
    const jwt = idx(cadena, idx(x, "seq")).split("~")[0];
    const tag = await hmacSha256(kTag, utf8Encode(pyStr(idx(pay[0], "op")) + "|" + pyStr(idx(x, "seq"))));
    R.add("hoja " + pyStr(idx(x, "seq")), bytesEq(concat(await sha(concat(b64d(idx(x, "salt")), asciiEncode(jwt))), tag), b64d(idx(x, "leaf_input"))));
  }
  for (const seq of [7, 3]) {
    R.add("inclusion " + seq, await inclusion(seq, D.length, await hoja(D[seq]), pyIter(idx(log, "inclusion_of_seq" + seq)).map(b64d), raiz));
  }
  R.add("inclusion falla con otra hoja", !(await inclusion(7, D.length, await hoja(D[6]), pyIter(idx(log, "inclusion_of_seq7")).map(b64d), raiz)));
  for (const n of pyIter(idx(v, "negative"))) {
    try {
      await E.verificarCadena(aplicar(cadena, n), llaves, empresa, custodia);
      R.add(idx(n, "id"), false, "acepto lo que debia fallar con " + idx(n, "expect"));
    } catch (e) {
      if (!(e instanceof Falla)) throw e;
      R.add(idx(n, "id"), pyEq(e.code, idx(n, "expect")), fmtFail(e, idx(n, "expect")));
    }
  }
  const disc = idx(v, "discovery");
  const mat = new E.Material(idx(disc, "docs"));
  for (const caso of pyIter(idx(disc, "cases"))) {
    try {
      const [bloque, issuer] = E.anclarExt(mat, idx(caso, "anchor"));
      const ll = E.llavesAncladas(mat, bloque, issuer);
      const [ver3] = await E.verificarCadena(cadena, ll, issuer, get(bloque, "custody"));
      const ok = pyEq(idx(caso, "expect"), "valid") && ver3.get("final_state") === "succeeded" && pyEq(issuer, empresa);
      R.add(idx(caso, "id"), ok, "anclado a " + issuer);
    } catch (e) {
      if (!(e instanceof Falla)) throw e;
      R.add(idx(caso, "id"), pyEq(e.code, idx(caso, "expect")), pyStr(e.code) + "; esperado " + pyStr(idx(caso, "expect")));
    }
  }
  return R.done();
}

/** Reference mode `pact` (SPEC appendix A.9). Returns {checks, total, failures, lines}. */
export async function verifyPactVectors(json) {
  const E = engineFor("vxp");
  const v = input(json);
  const R = reporter();
  for (const caso of pyIter(idx(v, "cases"))) {
    const docs = new Map(idx(v, "docs"));
    const ov = or2(get(caso, "docs_override"), new Map());
    for (const [k, x] of ov) docs.set(k, x);
    const mat = new E.Material(docs);
    let ok, detalle;
    try {
      const r = await E.verificarPaquete(or2(get(caso, "package"), idx(v, "package")), mat, idx(caso, "anchor"), get(v, "aud"), null, get(caso, "receipt"));
      ok = pyEq(idx(caso, "expect"), "valid") && Array.from(or2(get(caso, "expect_fields"), new Map())).every(([k, x]) => pyEq(get(r, k), x));
      detalle = pyJsonDumps(new Map(["valid", "company", "anchor", "final_state", "pact_receipt"].map((k) => [k, get(r, k)])), false);
    } catch (e) {
      if (!(e instanceof Falla)) throw e;
      ok = pyEq(e.code, idx(caso, "expect")) && (get(caso, "seq") === null || pyEq(e.seq, idx(caso, "seq")));
      detalle = fmtFail(e, idx(caso, "expect"));
    }
    R.add(idx(caso, "id"), ok, detalle);
  }
  return R.done();
}

// ---------------------------------------------------------------- explain()

const CONTROLS = [
  ["anchor", "Issuer anchoring (SPEC 9.9.1)"],
  ["keys", "Keys from issuer metadata"],
  ["package", "Package header"],
  ["statement_format", "Statement format (SD-JWT, base64url, header)"],
  ["issuer_and_key", "Statement issuer and key"],
  ["signature", "ES256 signature"],
  ["canonical_payload", "Canonical payload (JCS)"],
  ["role", "Role of the signer"],
  ["selective_disclosure", "Selective disclosure (RFC 9901)"],
  ["chain_binding", "Chain binding (v, company, op, aud, user, seq, prev)"],
  ["chain_order", "Statement order"],
  ["terms_and_approval", "Terms, counter-offers and approval"],
  ["execution_and_read_back", "Execution and read-back"],
  ["final_state", "Outcome, corrections and revocation"],
  ["log", "Transparency log (RFC 9162)"],
  ["operation", "Match with the operation the agent saw"],
  ["pact_receipt", "PACT receipt"],
  ["assurance", "Derived assurance"],
];
const ERRORS = {
  issuer_not_anchored: ["anchor", "the public material does not anchor this issuer: a document is missing, or the domain, issuer, metadata or trust members do not match"],
  discovery_without_extension: ["anchor", "the discovery document does not declare the VXP Proof extension"],
  no_anchor: ["anchor", "no anchor was given (domain, brand domain, PACT issuer or issuer)"],
  material_docs_missing: ["anchor", "the material has no documents; this verifier does not go to the network"],
  bad_version: ["chain_binding", "the version is not 0.1"],
  company_mismatch: ["chain_binding", "the statement or package names another company than the anchored issuer"],
  op_mismatch: ["chain_binding", "the operation id changes along the chain or differs from the package"],
  aud_mismatch: ["chain_binding", "the audience changes along the chain or is not the expected agent (replay)"],
  user_mismatch: ["chain_binding", "the user changes along the chain"],
  seq_error: ["chain_binding", "seq is not the position of the statement"],
  chain_broken: ["chain_binding", "prev is not the digest of the previous statement"],
  bad_body: ["chain_binding", "the body is not an object"],
  no_outcome: ["final_state", "there is no final statement: the result is treated as unknown"],
  not_sd_jwt: ["statement_format", "not a compact SD-JWT (header.payload.signature~disclosures~)"],
  non_canonical_encoding: ["statement_format", "a segment is not canonical unpadded base64url"],
  bad_header: ["statement_format", "the header typ/alg is not the VXP statement profile, or it carries crit"],
  duplicate_member: ["statement_format", "a JSON object repeats a member"],
  number_out_of_profile: ["canonical_payload", "a number is outside the 0.1 profile (only safe integers)"],
  lone_surrogate: ["canonical_payload", "a string has a lone UTF-16 surrogate"],
  not_json: ["canonical_payload", "a value is not JSON"],
  unknown_issuer: ["issuer_and_key", "the statement issuer is neither the company nor the operator"],
  unknown_key: ["issuer_and_key", "the kid is not in the anchored JWKS or is not its RFC 7638 thumbprint"],
  signature_invalid: ["signature", "the ES256 signature does not verify with the anchored key"],
  non_canonical_payload: ["canonical_payload", "the payload bytes are not its JCS (RFC 8785) form"],
  role_mismatch: ["role", "this kind of statement is not signed by that role"],
  bad_sd_alg: ["selective_disclosure", "_sd_alg is not sha-256 or appears below the root"],
  disclosure_repeated: ["selective_disclosure", "a disclosure is repeated"],
  disclosure_malformed: ["selective_disclosure", "a disclosure is malformed"],
  weak_salt: ["selective_disclosure", "a disclosure salt is shorter than 128 bits"],
  sd_digest_repeated: ["selective_disclosure", "a digest appears twice"],
  bad_sd: ["selective_disclosure", "_sd or an array element digest is malformed"],
  disclosure_bad_name: ["selective_disclosure", "a disclosure uses a reserved claim name"],
  disclosure_claim_exists: ["selective_disclosure", "a disclosure overwrites an existing claim"],
  disclosure_digest_mismatch: ["selective_disclosure", "a disclosure does not match any digest"],
  after_final: ["chain_order", "a statement other than read_back/correction/revocation comes after the final one"],
  order_violation: ["chain_order", "a statement is out of the order the protocol allows"],
  revision_error: ["terms_and_approval", "terms revisions are not consecutive, or come after approval"],
  bad_terms: ["terms_and_approval", "terms lack company_review_required or a valid read_back_terms list"],
  approval_not_latest_revision: ["terms_and_approval", "the approval is not for the latest revision"],
  approval_terms_mismatch: ["terms_and_approval", "the approval names other terms than the latest revision"],
  bad_approval_method: ["terms_and_approval", "unknown approval method"],
  display_code_mismatch: ["terms_and_approval", "the display code is not derived from the approved terms"],
  bad_decision: ["terms_and_approval", "the company review decision is not approved/denied"],
  execution_terms_mismatch: ["execution_and_read_back", "the execution names other terms than the approved ones"],
  bad_read_back: ["execution_and_read_back", "the read-back method or matches_terms is invalid"],
  outcome_terms_mismatch: ["final_state", "the outcome does not name the latest revision"],
  bad_state: ["final_state", "unknown state"],
  outcome_after_denial: ["final_state", "after a company denial the only outcome allowed is failed"],
  succeeded_without_matching_read_back: ["final_state", "succeeded without an execution and a matching system read-back"],
  read_back_incomplete: ["final_state", "the read-back does not observe every term the company required"],
  correction_without_read_back: ["final_state", "a correction to succeeded does not cite a later matching read-back"],
  checkpoint_signature_invalid: ["log", "the log checkpoint is not signed by the anchored log key"],
  log_origin_mismatch: ["log", "the log origin is not the anchored one"],
  log_inclusion_missing: ["log", "a statement has no inclusion proof"],
  log_bad_leaf: ["log", "a leaf salt or tag is not 32 bytes"],
  log_inclusion_failed: ["log", "an inclusion proof does not reach the checkpoint root"],
  equivocation_detected: ["log", "the live checkpoint is not the same tree or a consistent extension"],
  operation_id_mismatch: ["operation", "the operation id is not the chain's"],
  operation_revision_unknown: ["operation", "the operation revision has no terms statement"],
  operation_terms_mismatch: ["operation", "the operation terms do not hash to the signed terms_digest"],
  weak_terms_salt: ["operation", "the terms lack a salt of at least 128 bits"],
  read_back_terms_mismatch: ["operation", "an observed value differs from the term of the same name"],
  operation_state_mismatch: ["operation", "the visible operation state is not the last final statement"],
  operation_result_mismatch: ["operation", "the result summary does not hash to the signed digest"],
  pact_receipt_mismatch: ["pact_receipt", "the PACT receipt does not match the request citation"],
  pact_receipt_not_anchored: ["pact_receipt", "a PACT receipt was presented without a PACT anchor"],
  pact_receipt_invalid: ["pact_receipt", "the PACT receipt is not a valid ES256 JWS from the PACT authorization server"],
  malformed_input: ["statement_format", "malformed input that the reference verifier does not classify (it raises an exception)"],
};
const STATEMENT_LEVEL = new Set(["statement_format", "issuer_and_key", "signature", "canonical_payload", "role", "selective_disclosure", "chain_binding", "chain_order", "terms_and_approval", "execution_and_read_back", "final_state"]);
const LEVEL_TEXT = {
  issuer_key_attested: "a final statement is signed by the key anchored to the company issuer (whoever controls that key; not that the claim is true)",
  operator_observed: "the operator signed an execution (the operator's word, not the company system's)",
  operator_reported_read_back: "the operator reports a system read-back that matches the terms (reported, not signed by the system of record)",
  operator_reported_channel_approval: "the operator reports an approval with the display code on the company channel (not signed by the user)",
  operator_reported_agent_approval: "the operator reports that the agent said the user approved (nothing signed by the agent)",
};

/**
 * One short English line per control: [{control, title, status: "pass"|"fail"|"not_reached"|"info", text}].
 */
export function explain(verdict) {
  const v = verdict || {};
  const out = [];
  const push = (control, status, text) => out.push({ control, title: CONTROLS.find((c) => c[0] === control)[1], status, text });
  if (v.valid === true) {
    push("anchor", "pass", "Anchored to " + v.company + " via " + v.anchor + " (profile " + v.profile + ").");
    push("keys", "pass", "Company and operator keys taken from the issuer's RFC 8414 metadata (" + v.key_source + "), never from the package.");
    push("package", "pass", "Version 0.1, company and op match the chain.");
    for (const c of STATEMENT_LEVEL) if (c !== "final_state") push(c, "pass", "All " + v.statements + " statements passed this check.");
    push("final_state", "pass", "Final state: " + v.final_state + (v.approval ? "; approval " + v.approval + " on revision " + v.revision : "; no standing approval") + ".");
    if (v.log_inclusion === "ok") push("log", "pass", "Every statement is included in the log checkpoint (tree " + v.tree_size + ", live tree " + v.live_tree_size + ", consistent). Witnesses: " + v.witnesses + ", so not `logged`.");
    else push("log", "info", "No log proof in the package: inclusion not checked.");
    push("operation", v.operation === "matches" ? "pass" : "info", v.operation === "matches" ? "The operation the agent saw hashes to the signed terms, and its state is the last final statement." : "No operation given: not cross-checked.");
    push("pact_receipt", v.pact_receipt === "verified" ? "pass" : "info", v.pact_receipt === "verified" ? "The PACT receipt verifies and matches the request citation." : v.pact_receipt === "not_presented" ? "The request cites a PACT receipt that was not presented." : "No PACT receipt cited.");
    push("assurance", "info", "Derived by this verifier, never by the issuer: " + (v.derived_assurance || []).map((l) => l + " = " + (LEVEL_TEXT[l] || l)).join("; ") + ". single_root: " + v.single_root + " (no evidence of a second, independent root); logged: " + v.logged + " (no external witness). A valid signature does not prove the claim is true.");
    return out;
  }
  const [failing, why] = ERRORS[v.error] || ["statement_format", "error " + v.error];
  const seqTxt = v.seq === null || v.seq === undefined ? "" : " at statement seq " + v.seq;
  // package-level failures reported without seq belong to the package header
  const ctl = (v.seq === null || v.seq === undefined) && ["bad_version", "company_mismatch", "op_mismatch"].includes(v.error) ? "package" : failing;
  const order = CONTROLS.map((c) => c[0]);
  const fi = order.indexOf(ctl);
  for (const [c] of CONTROLS) {
    const ci = order.indexOf(c);
    if (c === "assurance") { push(c, "not_reached", "No assurance is derived from an invalid proof."); continue; }
    if (c === ctl) push(c, "fail", "Fails" + seqTxt + ": " + why + " (" + v.error + ").");
    else if (STATEMENT_LEVEL.has(ctl) && STATEMENT_LEVEL.has(c) && typeof v.seq === "number") push(c, ci < fi ? "pass" : "not_reached", ci < fi ? "Passed for statements up to seq " + v.seq + "." : "Passed for statements before seq " + v.seq + "; not reached for the rest.");
    else push(c, ci < fi ? "pass" : "not_reached", ci < fi ? "Passed." : "Not reached: verification stopped earlier.");
  }
  return out;
}

// for the differential tests only
export const _internals = { b64d: (s) => b64d(s), leerJson, jcs, pyJsonDumps, parsePythonJson, PyFloat, PyError, urlparse, fromJs, toJs };

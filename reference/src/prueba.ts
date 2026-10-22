// Outcome-proof issuer for VXP Proof 0.1.
//
// Each operation produces a chain of SD-JWT statements (RFC 9901) signed with ES256, with the
// payload in JCS (RFC 8785, narrow profile of §9.3) and the digest of the previous one in `prev`. The
// company signs what it offers and what it asserts (`terms`, `company_review`, `outcome`, `correction`);
// the operator signs what it received, executed and read (`request`, `counter`, `user_approval`,
// `execution`, `read_back`). Each statement enters a Merkle log (RFC 9162 §2.1) as a blinded leaf,
// and the log's checkpoint is signed by a separate log key.
//
// Custody: `operator_hosted`. The operator (SOVRAS) holds each company's key, so both
// signatures share a single root; the verifier must report this (§9.6). Without witnesses, no package
// reaches `logged` (§9.7).
//
// node:crypto only. No parameter properties or enums (Node in type-stripping mode).

import { createHash, createHmac, createPrivateKey, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type JwkPublica = { kty: "EC"; crv: "P-256"; x: string; y: string; kid: string; alg: "ES256"; use: "sig" };

const b64u = (v: Buffer | Uint8Array | string) => Buffer.from(v).toString("base64url");
const sha = (v: Buffer | string) => createHash("sha256").update(v).digest();

/** JCS (RFC 8785) with the 0.1 profile: safe integers only, no lone surrogates, JSON types only. */
export function jcs(v: unknown): string {
	if (v === null) return "null";
	if (typeof v === "boolean") return v ? "true" : "false";
	if (typeof v === "number") {
		if (!Number.isSafeInteger(v)) throw new Error("jcs: perfil 0.1 sólo admite enteros seguros");
		return JSON.stringify(v);
	}
	if (typeof v === "string") {
		if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(v)) throw new Error("jcs: surrogate suelto");
		return JSON.stringify(v);
	}
	if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
	if (typeof v === "object") {
		const o = v as Record<string, unknown>;
		const claves = Object.keys(o).filter((k) => o[k] !== undefined);
		if (claves.length !== Object.keys(o).length) throw new Error("jcs: undefined no es JSON");
		return `{${claves.sort().map((k) => `${JSON.stringify(k)}:${jcs(o[k])}`).join(",")}}`;
	}
	throw new Error(`jcs: tipo no JSON (${typeof v})`);
}

/** `sha-256:` + base64url(SHA-256(bytes)). */
export const huellaBytes = (bytes: Buffer | string) => `sha-256:${b64u(sha(bytes))}`;
/** JCS digest of any JSON value, object or string (§9.3). */
export const huellaJcs = (x: unknown) => huellaBytes(Buffer.from(jcs(x), "utf8"));
/** Digest of a statement (§9.2): covers `header.payload`, not the ECDSA signature, which is malleable. */
export const huellaDeclaracion = (jwt: string) => huellaBytes(Buffer.from(jwt.slice(0, jwt.lastIndexOf(".")), "ascii"));

/** `display_code` from §6.3 rule 2: big-endian uint32 of SHA-256(UTF-8(terms_digest)) mod 10^6. */
export function codigoVisible(termsDigest: string): string {
	return String(sha(Buffer.from(termsDigest, "utf8")).readUInt32BE(0) % 1_000_000).padStart(6, "0");
}

/** Terms digest (§9.3): covers `summary` in addition to `terms`. */
export function huellaTerminos(t: {
	company: string;
	operation_id: string;
	revision: number;
	summary: string;
	terms: unknown;
	expires_at: string | null;
	user_approval_required: boolean;
}): string {
	return huellaJcs({
		company: t.company,
		operation_id: t.operation_id,
		revision: t.revision,
		summary: t.summary,
		terms: t.terms ?? null,
		expires_at: t.expires_at ?? null,
		user_approval_required: t.user_approval_required,
	});
}

type Llave = { privateKey: KeyObject; publica: JwkPublica };

function deLlavePrivada(privateKey: KeyObject): Llave {
	const j = privateKey.export({ format: "jwk" }) as { x: string; y: string };
	const miembros = { crv: "P-256", kty: "EC", x: j.x, y: j.y };
	const kid = b64u(sha(jcs(miembros))); // RFC 7638: required members, lexicographic order
	return { privateKey, publica: { kty: "EC", crv: "P-256", x: j.x, y: j.y, kid, alg: "ES256", use: "sig" } };
}

function nuevaLlave(): Llave {
	return deLlavePrivada(generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey);
}

/**
 * A key ring: the current signing key plus the earlier public keys, which stay published so that statements
 * signed before a rotation still verify. Without a directory it lives in memory (one per process, as before
 * the evening revision of 22 Oct 2026). With a directory it survives restarts: `<dir>/<name>.json` holds the current private key
 * (JWK) and the earlier public keys. A key removed from the ring is no longer published; statements it
 * signed then verify only against material saved while it was published (historical verification).
 */
class Anillo {
	actual: Llave;
	anteriores: JwkPublica[] = [];
	extra: Record<string, string> = {};
	private readonly ruta: string | null;

	constructor(dir: string | null, nombre: string) {
		this.ruta = dir ? join(dir, `${nombre}.json`) : null;
		if (this.ruta && existsSync(this.ruta)) {
			const d = JSON.parse(readFileSync(this.ruta, "utf8")) as { current: JsonWebKey; previous?: JwkPublica[]; extra?: Record<string, string> };
			this.actual = deLlavePrivada(createPrivateKey({ key: d.current, format: "jwk" }));
			this.anteriores = d.previous ?? [];
			this.extra = d.extra ?? {};
		} else {
			this.actual = nuevaLlave();
			this.guardar();
		}
	}

	publicas(): JwkPublica[] {
		return [this.actual.publica, ...this.anteriores];
	}

	rotar(): string {
		this.anteriores.unshift(this.actual.publica);
		this.actual = nuevaLlave();
		this.guardar();
		return this.actual.publica.kid;
	}

	retirar(kid: string): boolean {
		const antes = this.anteriores.length;
		this.anteriores = this.anteriores.filter((k) => k.kid !== kid);
		this.guardar();
		return this.anteriores.length < antes;
	}

	guardar(): void {
		if (!this.ruta) return;
		mkdirSync(join(this.ruta, ".."), { recursive: true });
		const current = this.actual.privateKey.export({ format: "jwk" });
		writeFileSync(this.ruta, JSON.stringify({ current, previous: this.anteriores, extra: this.extra }, null, 1), { encoding: "utf8", mode: 0o600 });
	}
}

function firmarJws(llave: Llave, typ: string, payload: Record<string, unknown>): string {
	const h = b64u(jcs({ alg: "ES256", kid: llave.publica.kid, typ }));
	const p = b64u(jcs(payload));
	const s = sign("sha256", Buffer.from(`${h}.${p}`, "ascii"), { key: llave.privateKey, dsaEncoding: "ieee-p1363" });
	return `${h}.${p}.${b64u(s)}`;
}

/**
 * Trust members of the block (SPEC §4.2 and §9.9.1): whose keys they are, where they live, who
 * holds the company's key and which log is used. They go in the issuer's RFC 8414 metadata
 * (`vxp_proof`); poppy.json and the Agent Card carry a copy that MUST be identical. This way the
 * verifier anchors the keys to the issuer and not to a document handed over by whoever presents the package.
 */
/** Extension version (SPEC §4.2.1): the same in `version`, in the A2A URI and in each statement's `v`. */
export const VERSION_PRUEBA = "0.1";

/** Bindings the company declares (SPEC §9.9.1): brand domains and PACT faces that may cite the block. */
export type Vinculos = { domains: string[]; pact: { interface: string; authorization_server: string }[] };

export function bloqueConfianza(p: { issuer: string; authOrigin: string; operadorIssuer: string; origenRegistro: string; vinculos?: Vinculos }) {
	return {
		version: VERSION_PRUEBA,
		company: p.issuer,
		...(p.vinculos ? { domains: p.vinculos.domains, pact: p.vinculos.pact } : {}),
		jwks_uri: `${p.issuer}/vxp/proof-jwks.json`,
		operator: { issuer: p.operadorIssuer, jwks_uri: `${p.operadorIssuer}/proof-jwks.json` },
		custody: "operator_hosted",
		log: {
			origin: p.origenRegistro,
			checkpoint_url: `${p.authOrigin}/vxp/log/checkpoint`,
			consistency_url: `${p.authOrigin}/vxp/log/consistency`,
			jwks_uri: `${p.authOrigin}/vxp/log/jwks.json`,
			witnesses: [],
		},
	};
}

/**
 * A company's `outcome-proof` block (SPEC §4.2) in poppy.json or in the Agent Card: the trust
 * members (a copy of the issuer metadata) plus what is specific to each profile.
 */
export function bloqueOutcomeProof(p: {
	issuer: string;
	authOrigin: string;
	operadorIssuer: string;
	origenRegistro: string;
	vinculos?: Vinculos;
	/** Extension endpoint in this profile (SPEC §12.1.3 under Poppy, §12.2.7 under PACT). */
	endpoint?: string;
	capacidades: { name: string; effect: "read" | "write"; aprobacion: "operator_reported_agent_approval" | "operator_reported_channel_approval" }[];
	canales: string[];
}) {
	return {
		...bloqueConfianza(p),
		endpoint: p.endpoint ?? `${p.issuer}/vxp/proof`,
		approval_channels: p.canales,
		capabilities: p.capacidades.map((c) => ({
			name: c.name,
			effect: c.effect,
			// A promise, not a proof: the verifier derives the actual level from the package.
			max_assurance: ["issuer_key_attested", "operator_observed", "operator_reported_read_back", c.aprobacion],
			third_party: [],
		})),
	};
}

// ── Merkle log (RFC 9162 §2.1) ──────────────────────────────────────────────────────────────────

const hHoja = (d: Buffer) => sha(Buffer.concat([Buffer.from([0]), d]));
const hNodo = (l: Buffer, r: Buffer) => sha(Buffer.concat([Buffer.from([1]), l, r]));
const potencia = (n: number) => {
	let k = 1;
	while (k * 2 < n) k *= 2;
	return k;
};
function mth(D: Buffer[]): Buffer {
	if (D.length === 0) return sha(Buffer.alloc(0));
	if (D.length === 1) return hHoja(D[0]);
	const k = potencia(D.length);
	return hNodo(mth(D.slice(0, k)), mth(D.slice(k)));
}
/** Inclusion path, RFC 9162 §2.1.3.1. */
function ruta(m: number, D: Buffer[]): Buffer[] {
	if (D.length <= 1) return [];
	const k = potencia(D.length);
	return m < k ? [...ruta(m, D.slice(0, k)), mth(D.slice(k))] : [...ruta(m - k, D.slice(k)), mth(D.slice(0, k))];
}
/** Consistency proof, RFC 9162 §2.1.4.1. */
function subprueba(m: number, D: Buffer[], b: boolean): Buffer[] {
	const n = D.length;
	if (m === n) return b ? [] : [mth(D)];
	const k = potencia(n);
	return m <= k ? [...subprueba(m, D.slice(0, k), b), mth(D.slice(k))] : [...subprueba(m - k, D.slice(k), false), mth(D.slice(0, k))];
}

// ── Chains ──────────────────────────────────────────────────────────────────────────────────────

export type Rol = "empresa" | "operador";
export type Kind =
	| "request"
	| "terms"
	| "counter"
	| "user_approval"
	| "company_review"
	| "execution"
	| "read_back"
	| "outcome"
	| "correction"
	| "revocation";

const KIND_DE_ROL: Record<Rol, Kind[]> = {
	empresa: ["terms", "company_review", "outcome", "correction", "revocation"],
	operador: ["request", "counter", "user_approval", "execution", "read_back"],
};

type Declaracion = {
	jwt: string;
	sdjwt: string;
	digest: string;
	payload: Record<string, unknown>;
	hoja: { index: number; salt: string; tag: string };
};

type Cadena = { tenantId: string; company: string; op: string; aud: string; user: string; declaraciones: Declaracion[] };

type EmpresaPrueba = { issuer: string; anillo: Anillo; etiqueta: Buffer; vinculos: Vinculos };

export class EmisorPruebas {
	readonly operadorIssuer: string;
	readonly origenRegistro: string;
	private readonly operador: Anillo;
	private readonly registro: Anillo;
	/** Where the key rings persist; null keeps them in memory. */
	readonly dirLlaves: string | null;
	private readonly empresas = new Map<string, EmpresaPrueba>();
	private readonly cadenas = new Map<string, Cadena>();
	private readonly hojas: Buffer[] = [];

	constructor(operadorIssuer: string, origenRegistro: string, dirLlaves: string | null = null) {
		this.operadorIssuer = operadorIssuer;
		this.origenRegistro = origenRegistro;
		this.dirLlaves = dirLlaves;
		// One key per purpose: none of these signs Poppy tokens or PACT receipts (§4.2).
		this.operador = new Anillo(dirLlaves, "operator");
		this.registro = new Anillo(dirLlaves, "log");
	}

	registrarEmpresa(tenantId: string, issuer: string, vinculos: Vinculos = { domains: [], pact: [] }): void {
		if (this.empresas.has(tenantId)) return;
		const anillo = new Anillo(this.dirLlaves, `company-${tenantId}`);
		// The tag key (unlinkable log tags) persists with the company's ring.
		if (!anillo.extra.tag) {
			anillo.extra.tag = b64u(randomBytes(32));
			anillo.guardar();
		}
		this.empresas.set(tenantId, { issuer, anillo, etiqueta: Buffer.from(anillo.extra.tag, "base64url"), vinculos });
	}

	/** Rotates the company's signing key. The earlier public key stays in its JWKS. Returns the new kid. */
	rotarEmpresa(tenantId: string): string {
		return this.empresa(tenantId).anillo.rotar();
	}
	/** Rotates the operator's signing key, keeping the earlier public key published. */
	rotarOperador(): string {
		return this.operador.rotar();
	}
	/** Stops publishing an earlier company key (for example, after a compromise). */
	retirarLlaveEmpresa(tenantId: string, kid: string): boolean {
		return this.empresa(tenantId).anillo.retirar(kid);
	}

	vinculos(tenantId: string): Vinculos {
		return this.empresa(tenantId).vinculos;
	}

	private empresa(tenantId: string): EmpresaPrueba {
		const e = this.empresas.get(tenantId);
		if (!e) throw new Error("prueba: empresa no registrada");
		return e;
	}

	issuer(tenantId: string): string {
		return this.empresa(tenantId).issuer;
	}

	jwksEmpresa(tenantId: string) {
		return { keys: this.empresa(tenantId).anillo.publicas() };
	}
	jwksOperador() {
		return { keys: this.operador.publicas() };
	}
	jwksRegistro() {
		return { keys: this.registro.publicas() };
	}

	/** Opens an operation's chain. `aud` is the agent's client_id; `user`, its per-company pseudonym. */
	iniciar(tenantId: string, op: string, aud: string, user: string): void {
		const clave = `${tenantId}|${op}`;
		if (this.cadenas.has(clave)) return;
		this.cadenas.set(clave, { tenantId, company: this.empresa(tenantId).issuer, op, aud, user, declaraciones: [] });
	}

	tiene(tenantId: string, op: string): boolean {
		return this.cadenas.has(`${tenantId}|${op}`);
	}

	private cadena(tenantId: string, op: string): Cadena {
		const c = this.cadenas.get(`${tenantId}|${op}`);
		if (!c) throw new Error("prueba: cadena no iniciada");
		return c;
	}

	/**
	 * Issues the next link. `ocultos` carries, for each member of `body`, the claims that go as
	 * selective disclosures (§9.3): they stay out of the payload and only their digest goes into `_sd`.
	 */
	emitir(
		tenantId: string,
		op: string,
		rol: Rol,
		kind: Kind,
		body: Record<string, unknown>,
		ocultos: Record<string, Record<string, unknown>> = {},
	): Declaracion {
		if (!KIND_DE_ROL[rol].includes(kind)) throw new Error(`prueba: ${rol} no firma ${kind}`);
		const c = this.cadena(tenantId, op);
		const e = this.empresa(tenantId);
		const divulgaciones: string[] = [];
		const cuerpo: Record<string, unknown> = { ...body };
		for (const [miembro, claims] of Object.entries(ocultos)) {
			const destino = { ...((cuerpo[miembro] as Record<string, unknown> | undefined) ?? {}) };
			const sd: string[] = [];
			for (const [nombre, valor] of Object.entries(claims)) {
				const d = b64u(JSON.stringify([b64u(randomBytes(16)), nombre, valor]));
				divulgaciones.push(d);
				sd.push(b64u(sha(Buffer.from(d, "ascii"))));
			}
			destino._sd = sd.sort();
			cuerpo[miembro] = destino;
		}
		const previa = c.declaraciones.at(-1);
		const payload: Record<string, unknown> = {
			v: VERSION_PRUEBA,
			kind,
			iss: rol === "empresa" ? e.issuer : this.operadorIssuer,
			company: c.company,
			op: c.op,
			seq: c.declaraciones.length,
			prev: previa ? previa.digest : null,
			iat: Math.floor(Date.now() / 1000),
			aud: c.aud,
			user: c.user,
			body: cuerpo,
		};
		const jwt = firmarJws(rol === "empresa" ? e.anillo.actual : this.operador.actual, "vxp-stmt+sd-jwt", payload);
		const sdjwt = `${jwt}~${divulgaciones.map((d) => `${d}~`).join("")}`;
		// Blinded leaf (§9.8): salted commitment ‖ per-company HMAC tag. The log sees no content.
		const salt = randomBytes(32);
		const tag = createHmac("sha256", e.etiqueta).update(`${c.op}|${payload.seq}`, "utf8").digest();
		const entrada = Buffer.concat([sha(Buffer.concat([salt, Buffer.from(jwt, "ascii")])), tag]);
		this.hojas.push(entrada);
		const d: Declaracion = {
			jwt,
			sdjwt,
			digest: huellaDeclaracion(jwt),
			payload,
			hoja: { index: this.hojas.length - 1, salt: b64u(salt), tag: b64u(tag) },
		};
		c.declaraciones.push(d);
		return d;
	}

	ultima(tenantId: string, op: string): string | null {
		const c = this.cadenas.get(`${tenantId}|${op}`);
		return c?.declaraciones.at(-1)?.sdjwt ?? null;
	}

	declaraciones(tenantId: string, op: string): { kind: string; digest: string; payload: Record<string, unknown> }[] {
		const c = this.cadenas.get(`${tenantId}|${op}`);
		return c ? c.declaraciones.map((d) => ({ kind: String(d.payload.kind), digest: d.digest, payload: d.payload })) : [];
	}

	/** Signed log checkpoint: {origin, tree_size, root_hash, iat}. */
	checkpoint(tamano = this.hojas.length): string {
		const D = this.hojas.slice(0, tamano);
		return firmarJws(this.registro.actual, "vxp-checkpoint+jwt", {
			origin: this.origenRegistro,
			tree_size: D.length,
			root_hash: b64u(mth(D)),
			iat: Math.floor(Date.now() / 1000),
		});
	}

	consistencia(primero: number, segundo: number): string[] | null {
		if (!Number.isInteger(primero) || !Number.isInteger(segundo) || primero < 1 || primero > segundo || segundo > this.hojas.length) return null;
		return subprueba(primero, this.hojas.slice(0, segundo), true).map(b64u);
	}

	/** §9.9 package: the chain, its disclosures and each link's inclusion in a checkpoint. */
	paquete(tenantId: string, op: string) {
		const c = this.cadena(tenantId, op);
		const tamano = this.hojas.length;
		const D = this.hojas.slice(0, tamano);
		return {
			v: VERSION_PRUEBA,
			company: c.company,
			op: c.op,
			statements: c.declaraciones.map((d) => d.sdjwt),
			log: {
				origin: this.origenRegistro,
				checkpoint: this.checkpoint(tamano),
				cosignatures: [],
				inclusion: c.declaraciones.map((d, seq) => ({
					seq,
					leaf_index: d.hoja.index,
					salt: d.hoja.salt,
					tag: d.hoja.tag,
					path: ruta(d.hoja.index, D).map(b64u),
				})),
			},
		};
	}
}

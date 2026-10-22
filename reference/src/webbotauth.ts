// Web Bot Auth: verification of the HTTP message signature (RFC 9421) an agent uses to identify itself on the web
// (draft-meunier-web-bot-auth-architecture; used by ChatGPT agent and others). It turns the signal
// «Signature-Agent header present» into «signature verified with the key that operator publishes».
//
// What it proves: that the request was signed by whoever controls a key published at
// `<Signature-Agent>/.well-known/http-message-signatures-directory`. It does NOT prove which person the agent
// acts for: that is still linking and authorization (VXP §2).

import { createPublicKey, verify } from "node:crypto";
import type { FetchLike } from "./identidad.ts";

export type ResultadoWba =
	| { verificada: true; operador: string; keyid: string; componentes: string[] }
	| { verificada: false; motivo: string; operador?: string };

type Jwk = { kty?: string; crv?: string; x?: string; kid?: string; nbf?: number; exp?: number };

const sinComillas = (s: string) => s.trim().replace(/^"(.*)"$/, "$1");

const MAX_CACHE = 1_000;
const MAX_REGISTRO = 10_000;
const TIMEOUT_DIRECTORIO_MS = 3_000;

function v4Interna([a, b]: number[]): boolean {
	return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

/** The 8 groups of an IPv6 literal (with or without an embedded IPv4 tail), or null if it is not one. */
function grupos6(h: string): number[] | null {
	let t = h;
	const cola = t.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
	if (cola) {
		const [a, b, c, d] = cola.slice(1).map(Number);
		t = `${t.slice(0, cola.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
	}
	const [izq, der, ...resto] = t.split("::");
	if (resto.length) return null;
	const L = izq ? izq.split(":") : [];
	const R = der !== undefined && der !== "" ? der.split(":") : [];
	const faltan = 8 - L.length - R.length;
	if (der === undefined ? faltan !== 0 : faltan < 1) return null;
	const g = [...L, ...Array(der === undefined ? 0 : faltan).fill("0"), ...R].map((x) => (/^[0-9a-f]{1,4}$/.test(x) ? parseInt(x, 16) : NaN));
	return g.length === 8 && g.every(Number.isFinite) ? g : null;
}

/** Hosts the gateway never fetches a key directory from: loopback, private, link-local, unique-local, multicast,
 * and IPv6 forms that embed an internal IPv4 address (mapped, compatible, NAT64, 6to4). Names that resolve to such
 * addresses (DNS rebinding) must also be blocked at the egress layer, at connect time. */
export function hostInterno(host: string): boolean {
	const h = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
	if (h === "" || h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
	const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)?.slice(1).map(Number);
	if (v4) return v4Interna(v4);
	if (!h.includes(":")) return false;
	const g = grupos6(h);
	if (!g) return true; // an unparseable literal is refused, not guessed
	const embebida = (alto: number, bajo: number) => v4Interna([alto >> 8, alto & 255, bajo >> 8, bajo & 255]);
	if (g.slice(0, 7).every((x) => x === 0) && g[7] <= 1) return true; // :: and ::1
	if (g.slice(0, 6).every((x) => x === 0)) return true; // IPv4-compatible (deprecated): never a public operator
	if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return embebida(g[6], g[7]); // IPv4-mapped
	if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return embebida(g[6], g[7]); // NAT64
	if (g[0] === 0x2002) return embebida(g[1], g[2]); // 6to4
	return (g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xff00) === 0xff00;
}

/** Splits a top-level Structured Fields Dictionary (RFC 8941), honoring parentheses and quotes. */
function diccionario(valor: string): Map<string, string> {
	const out = new Map<string, string>();
	let prof = 0;
	let comillas = false;
	let actual = "";
	const partes: string[] = [];
	for (const c of valor) {
		if (c === '"') comillas = !comillas;
		if (!comillas && c === "(") prof++;
		if (!comillas && c === ")") prof--;
		if (!comillas && prof === 0 && c === ",") {
			partes.push(actual);
			actual = "";
		} else actual += c;
	}
	if (actual.trim()) partes.push(actual);
	for (const p of partes) {
		const i = p.indexOf("=");
		if (i > 0) out.set(p.slice(0, i).trim(), p.slice(i + 1).trim());
	}
	return out;
}

export class WebBotAuth {
	private readonly fetch: FetchLike;
	private readonly cache = new Map<string, { keys: Jwk[]; hasta: number; error?: string }>();
	/** Operators whose directory is accepted. Empty = any public https origin. */
	private readonly permitidos: Set<string>;
	readonly registro: { at: string; ruta: string; resultado: ResultadoWba }[] = [];

	/** True when the operator was explicitly allowed. Only those may share one rate-limit bucket across IPs. */
	confiable(operador: string): boolean {
		return this.permitidos.has(operador);
	}

	constructor(fetch: FetchLike, permitidos: string[] = []) {
		this.fetch = fetch;
		this.permitidos = new Set(permitidos);
	}

	private async llaves(operador: string): Promise<Jwk[]> {
		const hit = this.cache.get(operador);
		if (hit && hit.hasta > Date.now()) {
			if (hit.error) throw new Error(hit.error);
			return hit.keys;
		}
		const guardar = (v: { keys: Jwk[]; hasta: number; error?: string }) => {
			this.cache.delete(operador);
			if (this.cache.size >= MAX_CACHE) this.cache.delete(this.cache.keys().next().value!);
			this.cache.set(operador, v);
		};
		let keys: Jwk[];
		try {
			const res = await this.fetch(`${operador}/.well-known/http-message-signatures-directory`, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_DIRECTORIO_MS), headers: { accept: "application/http-message-signatures-directory+json" } });
			if (res.status !== 200) throw new Error(`directorio_http_${res.status}`);
			const doc = (await res.json()) as { keys?: Jwk[] };
			keys = Array.isArray(doc.keys) ? doc.keys : [];
		} catch (e) {
			// Failures are cached briefly too, so a burst of signed requests does not become a burst of fetches.
			const error = (e as Error).message.startsWith("directorio_http_") ? (e as Error).message : "directorio_inaccesible";
			guardar({ keys: [], hasta: Date.now() + 60_000, error });
			throw new Error(error);
		}
		guardar({ keys, hasta: Date.now() + 10 * 60_000 });
		return keys;
	}

	async verificar(req: Request, ahora = Math.floor(Date.now() / 1000)): Promise<ResultadoWba | null> {
		const agente = req.headers.get("signature-agent");
		const entrada = req.headers.get("signature-input");
		const firma = req.headers.get("signature");
		if (!agente && !entrada) return null;
		const operador = agente ? sinComillas(agente) : undefined;
		if (!agente || !entrada || !firma || !operador) return { verificada: false, motivo: "cabeceras_incompletas", operador };
		let url: URL;
		try {
			url = new URL(operador);
		} catch {
			return { verificada: false, motivo: "signature_agent_invalido", operador };
		}
		if (url.protocol !== "https:") return { verificada: false, motivo: "signature_agent_no_https", operador };
		if (this.permitidos.size && !this.permitidos.has(url.origin)) return { verificada: false, motivo: "operador_no_permitido", operador };
		if (!this.permitidos.has(url.origin) && (hostInterno(url.hostname) || url.port !== "")) return { verificada: false, motivo: "operador_no_publico", operador };
		// The signature with tag="web-bot-auth" (required by the Web Bot Auth architecture).
		const entradas = diccionario(entrada);
		const firmas = diccionario(firma);
		const etiqueta = [...entradas.entries()].find(([, v]) => /;\s*tag="web-bot-auth"/.test(v))?.[0];
		if (!etiqueta) return { verificada: false, motivo: "sin_tag_web_bot_auth", operador };
		const params = entradas.get(etiqueta)!;
		const m = params.match(/^\(([^)]*)\)(.*)$/);
		const sig = firmas.get(etiqueta)?.match(/^:([A-Za-z0-9+/=]+):$/)?.[1];
		if (!m || !sig) return { verificada: false, motivo: "firma_malformada", operador };
		const componentes = [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
		const p = (n: string) => m[2].match(new RegExp(`;\\s*${n}=("?)([^;"]*)\\1`))?.[2];
		const created = Number(p("created"));
		const expires = Number(p("expires"));
		const keyid = p("keyid");
		const alg = p("alg");
		if (!Number.isFinite(created) || !Number.isFinite(expires) || created > ahora + 60 || expires < ahora) return { verificada: false, motivo: "fuera_de_vigencia", operador };
		if (!componentes.includes("@authority") || !componentes.includes("signature-agent")) return { verificada: false, motivo: "componentes_insuficientes", operador };
		if (alg && alg !== "ed25519") return { verificada: false, motivo: "algoritmo_no_soportado", operador };
		// Signature base (RFC 9421 §2.5).
		const lineas: string[] = [];
		for (const c of componentes) {
			let v: string | null;
			if (c === "@authority") v = new URL(req.url).host.toLowerCase();
			else if (c === "@method") v = req.method;
			else if (c === "@path") v = new URL(req.url).pathname;
			else if (c === "@target-uri") v = req.url;
			else v = req.headers.get(c);
			if (v === null) return { verificada: false, motivo: `falta_componente_${c}`, operador };
			lineas.push(`"${c}": ${v.trim()}`);
		}
		lineas.push(`"@signature-params": ${params}`);
		const base = Buffer.from(lineas.join("\n"), "utf8");
		let keys: Jwk[];
		try {
			keys = await this.llaves(url.origin);
		} catch (e) {
			return { verificada: false, motivo: String((e as Error).message), operador };
		}
		const jwk = keys.find((k) => k.kid === keyid && k.kty === "OKP" && k.crv === "Ed25519");
		if (!jwk) return { verificada: false, motivo: "llave_no_publicada", operador };
		if ((jwk.nbf && jwk.nbf > ahora) || (jwk.exp && jwk.exp < ahora)) return { verificada: false, motivo: "llave_fuera_de_vigencia", operador };
		const ok = verify(null, base, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }), Buffer.from(sig, "base64"));
		return ok ? { verificada: true, operador: url.origin, keyid: keyid!, componentes } : { verificada: false, motivo: "firma_invalida", operador };
	}

	/** Verifies and logs the result (the gateway log). */
	async observar(req: Request): Promise<ResultadoWba | null> {
		const r = await this.verificar(req);
		if (r) {
			this.registro.push({ at: new Date().toISOString(), ruta: new URL(req.url).pathname, resultado: r });
			if (this.registro.length > MAX_REGISTRO) this.registro.splice(0, this.registro.length - MAX_REGISTRO);
		}
		return r;
	}
}

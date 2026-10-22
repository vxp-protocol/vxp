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
	private readonly cache = new Map<string, { keys: Jwk[]; hasta: number }>();
	/** Operators whose directory is accepted. Empty = any with an https directory. */
	private readonly permitidos: Set<string>;
	readonly registro: { at: string; ruta: string; resultado: ResultadoWba }[] = [];

	constructor(fetch: FetchLike, permitidos: string[] = []) {
		this.fetch = fetch;
		this.permitidos = new Set(permitidos);
	}

	private async llaves(operador: string): Promise<Jwk[]> {
		const hit = this.cache.get(operador);
		if (hit && hit.hasta > Date.now()) return hit.keys;
		const res = await this.fetch(`${operador}/.well-known/http-message-signatures-directory`, { redirect: "manual", headers: { accept: "application/http-message-signatures-directory+json" } });
		if (res.status !== 200) throw new Error(`directorio_http_${res.status}`);
		const doc = (await res.json()) as { keys?: Jwk[] };
		const keys = Array.isArray(doc.keys) ? doc.keys : [];
		this.cache.set(operador, { keys, hasta: Date.now() + 10 * 60_000 });
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
		if (r) this.registro.push({ at: new Date().toISOString(), ruta: new URL(req.url).pathname, resultado: r });
		return r;
	}
}

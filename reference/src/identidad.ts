// Personal-agent identity and delegation state. It is platform-wide (an agent registers once
// with SOVRAS), but each delegation carries its tenantId and is only looked up with it.

import { type Alg, type Decoded, type Jwk, decodeJwt, ahora, randomId, sha256, verifyWith } from "./jose.ts";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export type Red = {
	fetch: FetchLike;
	/** http:// origins allowed on purpose (development). Everything else requires https. */
	origenesLocales: string[];
};

/** URLs supplied by the other party: https only, no redirects (Poppy 3, «Redirects and addresses»). */
async function traerJson(red: Red, url: string): Promise<unknown> {
	const u = new URL(url);
	if (u.protocol !== "https:" && !red.origenesLocales.includes(u.origin)) throw new Error("url_no_https");
	if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|\[::1\])/.test(u.hostname) && !red.origenesLocales.includes(u.origin))
		throw new Error("direccion_privada");
	const res = await red.fetch(url, { redirect: "manual", headers: { accept: "application/json" } });
	if (res.status !== 200) throw new Error(`http_${res.status}`);
	return res.json();
}

type Cache<T> = Map<string, { valor: T; hasta: number }>;

export class Directorio {
	private readonly jwks: Cache<Jwk[]> = new Map();
	private readonly clientes: Cache<ClienteMetadata> = new Map();
	private readonly red: Red;
	constructor(red: Red) {
		this.red = red;
	}

	async claves(jwksUri: string, kid: unknown, refrescar = false): Promise<Jwk[]> {
		const hit = this.jwks.get(jwksUri);
		const conoceKid = hit?.valor.some((k) => k.kid === kid);
		if (hit && hit.hasta > Date.now() && (conoceKid || !kid) && !refrescar) return hit.valor;
		const doc = (await traerJson(this.red, jwksUri)) as { keys?: Jwk[] };
		const keys = Array.isArray(doc.keys) ? doc.keys : [];
		this.jwks.set(jwksUri, { valor: keys, hasta: Date.now() + 5 * 60_000 });
		return keys;
	}

	/** Verifies a JWT against a JWKS; refetches the JWKS once if the `kid` is new (rotation). */
	async verificar(token: string, jwksUri: string, algs: Alg[]): Promise<Decoded | null> {
		const decoded = decodeJwt(token);
		if (!decoded) return null;
		for (const refrescar of [false, true]) {
			let keys: Jwk[];
			try {
				keys = await this.claves(jwksUri, decoded.header.kid, refrescar);
			} catch {
				return null;
			}
			const candidatas = decoded.header.kid ? keys.filter((k) => k.kid === decoded.header.kid) : keys;
			if (candidatas.some((k) => verifyWith(decoded, k, algs))) return decoded;
			if (candidatas.length > 0) return null;
		}
		return null;
	}

	/** OAuth Client ID Metadata Document (Poppy 4.1). */
	async cliente(clientId: string): Promise<ClienteMetadata | null> {
		const hit = this.clientes.get(clientId);
		if (hit && hit.hasta > Date.now()) return hit.valor;
		let doc: ClienteMetadata;
		try {
			doc = (await traerJson(this.red, clientId)) as ClienteMetadata;
		} catch {
			return null;
		}
		const host = (u: string) => {
			try {
				return new URL(u).host;
			} catch {
				return "";
			}
		};
		const mismoDominio = (u: string) => host(u) === host(clientId) && (u.startsWith("https://") || this.red.origenesLocales.includes(new URL(u).origin));
		if (doc.client_id !== clientId || !doc.jwks_uri || !mismoDominio(doc.jwks_uri)) return null;
		if ((doc.redirect_uris ?? []).some((u) => !mismoDominio(u))) return null;
		this.clientes.set(clientId, { valor: doc, hasta: Date.now() + 10 * 60_000 });
		return doc;
	}
}

export type ClienteMetadata = {
	client_id: string;
	client_name?: string;
	logo_uri?: string;
	jwks_uri: string;
	redirect_uris?: string[];
	extensions?: Record<string, { version: string }>;
};

// ── Personal-agent registration for PACT (§3.1): once per agent and provider ──────────────────

export type PlataformaPact = { nombre: string; issuer: string; jwksUri: string; enabled: boolean };

// ── Delegations (grants) ──────────────────────────────────────────────────────────────────────

export type Grant = {
	id: string;
	tenantId: string;
	protocolo: "poppy" | "pact" | "vxp";
	clientId: string;
	sub: string;
	clienteId: string;
	alcances: string[];
	expira: number;
	revocado: boolean;
	/** Hash of the current refresh token (PACT rotates it; Poppy reuses the same Account Token). */
	refreshVigente: string;
	refreshUsados: Set<string>;
};

export type Dispositivo = {
	deviceCode: string;
	userCode: string;
	tenantId: string;
	protocolo: "poppy" | "pact" | "vxp";
	clientId: string;
	clientName: string;
	sub: string | null;
	alcancesPedidos: string[];
	estado: "pendiente" | "aprobado" | "denegado" | "consumido";
	expira: number;
	intervalo: number;
	ultimoPoll: number;
	/** WhatsApp linking: the customer proves they own the number the company already knows. */
	telefono: string | null;
	otpHash: string | null;
	intentos: number;
	clienteId: string | null;
	alcancesAprobados: string[];
	grantId: string | null;
	/** Native mode: requested `authorization_details` (RFC 9396), shown to the user. */
	detalles?: { texto: string[]; rar: unknown[] };
};

export class Delegaciones {
	readonly grants = new Map<string, Grant>();
	readonly dispositivos = new Map<string, Dispositivo>();

	nuevoDispositivo(input: Omit<Dispositivo, "deviceCode" | "userCode" | "estado" | "expira" | "intervalo" | "ultimoPoll" | "telefono" | "otpHash" | "intentos" | "clienteId" | "alcancesAprobados" | "grantId">): Dispositivo {
		const letras = "BCDFGHJKLMNPQRSTVWXZ";
		const pick = () => Array.from({ length: 4 }, () => letras[Math.floor(Math.random() * letras.length)]).join("");
		const d: Dispositivo = {
			...input,
			deviceCode: randomId("dc_", 24),
			userCode: `${pick()}-${pick()}`,
			estado: "pendiente",
			expira: ahora() + 600,
			intervalo: 5,
			ultimoPoll: 0,
			telefono: null,
			otpHash: null,
			intentos: 0,
			clienteId: null,
			alcancesAprobados: [],
			grantId: null,
		};
		this.dispositivos.set(d.deviceCode, d);
		return d;
	}

	porUserCode(userCode: string): Dispositivo | undefined {
		return [...this.dispositivos.values()].find((d) => d.userCode === userCode && d.expira > ahora());
	}

	nuevoGrant(d: Dispositivo, sub: string): { grant: Grant; refresh: string } {
		const refresh = randomId(d.protocolo === "poppy" ? "pat_" : "rt_", 24);
		const grant: Grant = {
			id: randomId("grant_", 9),
			tenantId: d.tenantId,
			protocolo: d.protocolo,
			clientId: d.clientId,
			sub,
			clienteId: d.clienteId!,
			alcances: d.alcancesAprobados,
			expira: ahora() + 30 * 86_400,
			revocado: false,
			refreshVigente: sha256(refresh),
			refreshUsados: new Set(),
		};
		this.grants.set(grant.id, grant);
		d.grantId = grant.id;
		return { grant, refresh };
	}

	/** Finds the grant for a refresh token, only for the client it was issued to. */
	porRefresh(refresh: string, clientId: string): { grant: Grant; reuso: boolean } | null {
		const h = sha256(refresh);
		for (const g of this.grants.values()) {
			if (g.clientId !== clientId) continue;
			if (g.refreshVigente === h) return { grant: g, reuso: false };
			if (g.refreshUsados.has(h)) return { grant: g, reuso: true };
		}
		return null;
	}

	rotar(grant: Grant): string {
		const nuevo = randomId(grant.protocolo === "poppy" ? "pat_" : "rt_", 24);
		grant.refreshUsados.add(grant.refreshVigente);
		grant.refreshVigente = sha256(nuevo);
		return nuevo;
	}
}

// Network policy for everything the agent fetches from companies: HTTPS only (except origins the
// developer allowed on purpose for local testing), no redirects, a timeout and a size cap.

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export type NetOptions = {
	fetch?: FetchLike;
	/** http:// origins allowed on purpose (local development and tests). Everything else must be https. */
	allowHttpOrigins?: string[];
	timeoutMs?: number;
};

export class VxpHttpError extends Error {
	readonly status: number;
	readonly body: unknown;
	constructor(message: string, status: number, body: unknown) {
		super(message);
		this.status = status;
		this.body = body;
	}
}

const MAX_BYTES = 2_000_000;

/**
 * True when `url` is under `base`: written in canonical form, the same origin, no credentials, no encoded
 * separators, and a path below the base path on a segment boundary. Used before sending a company's
 * credentials to a URL it gave us.
 */
export function isUnder(url: string, base: string): boolean {
	let u: URL;
	let b: URL;
	try {
		u = new URL(url);
		b = new URL(base);
	} catch {
		return false;
	}
	if (u.origin !== b.origin || u.username || u.password) return false;
	// Only a URL already in canonical form: what the parser reads is exactly what was written, so no server
	// can resolve it differently (dot segments, backslashes and case would otherwise be normalized away).
	if (u.href !== String(url)) return false;
	if (/%2e|%2f|%5c/i.test(u.pathname)) return false;
	const prefix = b.pathname.endsWith("/") ? b.pathname : `${b.pathname}/`;
	return u.pathname.startsWith(prefix);
}

export class Net {
	private readonly f: FetchLike;
	readonly allowHttp: Set<string>;
	private readonly timeoutMs: number;
	constructor(o: NetOptions = {}) {
		this.f = o.fetch ?? ((u, i) => globalThis.fetch(u, i));
		this.allowHttp = new Set((o.allowHttpOrigins ?? []).map((x) => new URL(x).origin));
		this.timeoutMs = o.timeoutMs ?? 15_000;
	}

	/** The origin for a bare domain («hotel.example» or «127.0.0.1:3810»): https unless allowed as http. */
	originFor(domain: string): string {
		const http = `http://${domain}`;
		return this.allowHttp.has(new URL(http).origin) ? new URL(http).origin : new URL(`https://${domain}`).origin;
	}

	check(url: string): URL {
		const u = new URL(url);
		if (u.protocol === "https:") return u;
		if (u.protocol === "http:" && this.allowHttp.has(u.origin)) return u;
		throw new Error(`refused: ${u.origin} is not https (allow it explicitly for local tests)`);
	}

	async raw(url: string, init: RequestInit = {}): Promise<{ status: number; headers: Headers; text: string }> {
		this.check(url);
		const ac = new AbortController();
		const t = setTimeout(() => ac.abort(), this.timeoutMs);
		const method = (init.method ?? "GET").toUpperCase();
		try {
			// A GET is retried once if a pooled socket was already closed by the server (ECONNRESET); writes never are.
			const r = await this.f(url, { ...init, redirect: "manual", signal: ac.signal }).catch((e) => {
				if (method === "GET" && /ECONNRESET|UND_ERR_SOCKET/.test(String(e?.cause?.code ?? ""))) return this.f(url, { ...init, redirect: "manual", signal: ac.signal });
				throw e;
			});
			const buf = Buffer.from(await r.arrayBuffer());
			if (buf.length > MAX_BYTES) throw new Error(`response too large from ${url}`);
			return { status: r.status, headers: r.headers, text: buf.toString("utf8") };
		} finally {
			clearTimeout(t);
		}
	}

	async json(url: string, init: RequestInit = {}): Promise<{ status: number; headers: Headers; body: any }> {
		const r = await this.raw(url, init);
		let body: unknown = null;
		if (r.text) {
			try {
				body = JSON.parse(r.text);
			} catch {
				body = r.text;
			}
		}
		return { status: r.status, headers: r.headers, body };
	}

	/** GET a JSON document that must answer 200. */
	async doc(url: string): Promise<any> {
		const r = await this.json(url, { headers: { accept: "application/json" } });
		if (r.status !== 200 || !r.body || typeof r.body !== "object") throw new VxpHttpError(`GET ${url} → ${r.status}`, r.status, r.body);
		return r.body;
	}
}

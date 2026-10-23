// Starts the reference company gateway (reference/src/main.ts) in its own process, native profile only
// (VXP_ADAPTERS=none), with persistent proof keys in a temporary directory, and reads its console.
//
// Two things are read from that console, and neither is part of VXP:
// - the simulated company channel (VXP_SHOW_CHANNEL=1): the one-time code the company sends to the
//   person's phone to link their account. In real life the person reads it on their phone; here the test
//   plays the person and reads it where the simulated phone prints it.
// - the key of the reference's test-only /interno/ routes, used ONLY to act as the company's console
//   (starting a request inside a relationship). That is a test aid of the reference implementation.

import { type ChildProcess, spawn } from "node:child_process";
import { request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REFERENCE = join(import.meta.dirname, "..", "..", "..", "reference");

export type Reference = {
	origin: string;
	hotelDomain: string;
	storeDomain: string;
	internalKey: string;
	lines: string[];
	proc: ChildProcess;
	/** The next one-time code the company sends to `phone` after line index `since`. */
	waitForCode(since: number, timeoutMs?: number): Promise<string>;
	/** The first simulated-channel message after line `since` that matches `re` (what the person's phone shows). */
	waitForChannel(since: number, re: RegExp, timeoutMs?: number): Promise<RegExpMatchArray>;
	/** Company console (reference test aid): start an action inside a relationship. */
	companyStarts(tenant: string, relationshipId: string, action: string, params: Record<string, unknown>): Promise<{ status: number; body: any }>;
	/** Company console (reference test aid): revoke a relationship as the person or the company would. */
	companyRevokes(tenant: string, relationshipId: string, by?: "usuario" | "empresa"): Promise<{ status: number; body: any }>;
	/** Company console (reference test aid): any /interno/ route; GET without body, POST with one. */
	internal(path: string, body?: unknown): Promise<{ status: number; body: any }>;
	stop(): Promise<void>;
};

/**
 * `adapters`: VXP_ADAPTERS for the gateway ("none" = native profile only, the default; "poppy"; "pact").
 * With PACT the gateway trusts one test personal-agent platform, `http://localhost:<port + 2>` (reference main.ts).
 */
export async function startReference(o: { port: number; agentOrigins: string[]; keysDir?: string; adapters?: "none" | "poppy" | "pact" }): Promise<Reference> {
	const keysDir = o.keysDir ?? mkdtempSync(join(tmpdir(), "vxp-agent-ref-keys-"));
	const proc = spawn(process.execPath, ["src/main.ts"], {
		cwd: REFERENCE,
		env: { ...process.env, PORT: String(o.port), PA_PORT: String(o.port + 2), VXP_ADAPTERS: o.adapters ?? "none", VXP_KEYS_DIR: keysDir, VXP_SHOW_CHANNEL: "1", ORIGENES_LOCALES: o.agentOrigins.join(","), SOVRAS_MUTAR: "", VXP_CARRILES: "" },
		stdio: ["ignore", "pipe", "pipe"],
	});
	const lines: string[] = [];
	let buf = "";
	const onData = (d: Buffer) => {
		buf += d.toString("utf8");
		const parts = buf.split(/\r?\n/);
		buf = parts.pop() ?? "";
		lines.push(...parts);
	};
	proc.stdout!.on("data", onData);
	proc.stderr!.on("data", onData);
	const origin = `http://localhost:${o.port}`;
	const internalKey = await new Promise<string>((ok, fail) => {
		const t = setTimeout(() => fail(new Error(`reference did not start:\n${lines.join("\n")}`)), 20_000);
		const tick = setInterval(() => {
			const m = lines.join("\n").match(/llave interna: (\S+)/);
			if (m) {
				clearTimeout(t);
				clearInterval(tick);
				ok(m[1]);
			}
		}, 50);
		proc.once("exit", (c) => fail(new Error(`reference exited (${c}):\n${lines.join("\n")}`)));
	});
	// If the gateway dies mid-test, say how (exit code or signal) instead of a bare «fetch failed».
	let exited: string | null = null;
	proc.on("exit", (code, signal) => {
		exited = `reference gateway on ${o.port} exited: code ${code}, signal ${signal}`;
		lines.push(`[test] ${exited}`);
	});
	// The company console, on a fresh connection each time (no keep-alive): a reused socket the server has
	// already closed after its idle timeout would fail as ECONNRESET.
	const internal = (path: string, body?: unknown) =>
		new Promise<{ status: number; body: any }>((ok, fail) => {
			if (exited) return fail(new Error(exited));
			const data = body === undefined ? null : JSON.stringify(body);
			const req = httpRequest(`${origin}/interno/${path}`, { method: data ? "POST" : "GET", agent: false, headers: { "x-sovras-prueba": internalKey, "content-type": "application/json", ...(data ? { "content-length": Buffer.byteLength(data) } : {}) } }, (res) => {
				let t = "";
				res.setEncoding("utf8");
				res.on("data", (c) => (t += c));
				res.on("end", () => ok({ status: res.statusCode ?? 0, body: t ? JSON.parse(t) : null }));
			});
			req.on("error", (e) => fail(new Error(`${path}: ${e.message}${exited ? `; ${exited}` : ""}`)));
			req.end(data ?? undefined);
		});
	return {
		origin,
		hotelDomain: `127.0.0.1:${o.port}`,
		storeDomain: `localhost:${o.port}`,
		internalKey,
		lines,
		proc,
		async waitForCode(since, timeoutMs = 10_000) {
			const end = Date.now() + timeoutMs;
			while (Date.now() < end) {
				for (const l of lines.slice(since)) {
					const m = l.match(/^\[simulated company channel · [^\]]+\] .*código es (\d{6})/);
					if (m) return m[1];
				}
				await new Promise((r) => setTimeout(r, 50));
			}
			throw new Error("no code arrived on the simulated company channel");
		},
		internal,
		async waitForChannel(since, re, timeoutMs = 10_000) {
			const end = Date.now() + timeoutMs;
			while (Date.now() < end) {
				for (const l of lines.slice(since)) {
					const m = l.startsWith("[simulated company channel") ? l.match(re) : null;
					if (m) return m;
				}
				await new Promise((r) => setTimeout(r, 50));
			}
			throw new Error(`no message matching ${re} arrived on the simulated company channel`);
		},
		companyStarts: (tenant, relationship_id, action, params) => internal("relaciones/iniciar", { tenant, relationship_id, action, params }),
		companyRevokes: (tenant, relationship_id, by = "usuario") => internal("relaciones/revocar", { tenant, relationship_id, by }),
		stop: () =>
			new Promise<void>((ok) => {
				if (proc.exitCode !== null) return ok();
				proc.once("exit", () => ok());
				proc.kill();
			}),
	};
}

// Persistent agent state in one directory, so an agent can stop at any step and continue later:
// keys, tokens, requests in progress, device authorizations waiting for the person, relationships,
// inbox, mandates, approvals and proofs. Every document is a JSON file written atomically (temp file
// + rename) and re-read before each update, so the CLI, the MCP server and the inbox server can share it.
//
// The directory holds private keys and live access tokens: keep it out of any repository and logs.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

export type Doc = "identity" | "companies" | "sessions" | "requests" | "authorizations" | "relationships" | "inbox" | "mandates" | "approvals";

export class Store {
	readonly dir: string;
	constructor(dir: string) {
		this.dir = dir;
		mkdirSync(join(dir, "proofs"), { recursive: true });
	}

	private path(doc: string) {
		return join(this.dir, `${doc}.json`);
	}

	read<T>(doc: Doc, fallback: T): T {
		const p = this.path(doc);
		if (!existsSync(p)) return fallback;
		return JSON.parse(readFileSync(p, "utf8")) as T;
	}

	write(doc: Doc, value: unknown, secret = false): void {
		const p = this.path(doc);
		const tmp = `${p}.${randomBytes(4).toString("hex")}.tmp`;
		writeFileSync(tmp, JSON.stringify(value, null, 1), { mode: secret ? 0o600 : 0o644 });
		renameSync(tmp, p);
		if (secret) {
			try {
				chmodSync(p, 0o600);
			} catch {}
		}
	}

	/** Read-modify-write of one document. Returns what the function returns. */
	update<T, R>(doc: Doc, fallback: T, fn: (v: T) => R, secret = false): R {
		const v = this.read(doc, fallback);
		const r = fn(v);
		this.write(doc, v, secret);
		return r;
	}

	/** Files under proofs/ only: a name with a path separator or «..» is refused. */
	private proofPath(name: string) {
		if (!/^[A-Za-z0-9_.-]+$/.test(name) || name.includes("..")) throw new Error(`refused file name ${JSON.stringify(name)}`);
		return join(this.dir, "proofs", name);
	}

	saveFile(name: string, value: unknown): string {
		const p = this.proofPath(name);
		writeFileSync(p, JSON.stringify(value, null, 1));
		return p;
	}

	readFile<T>(name: string): T | null {
		const p = this.proofPath(name);
		return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as T) : null;
	}
}

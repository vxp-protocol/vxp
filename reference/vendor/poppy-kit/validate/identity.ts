// The test Personal Agent's identity, kept in .poppy/ in the current directory:
//
//   private-key.jwk   the ES256 signing key (mode 0600, never printed)
//   agent.json        client metadata, hosted at <base-url>/agent.json
//   jwks.json         the public key, hosted at <base-url>/jwks.json
//   config.json       client_id, and a random User ID for each Company issuer
//   last-results.json the latest check results, without secrets

import {
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
    appendFileSync,
    chmodSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { check } from "./schemas.ts";
import type { Http } from "./http.ts";
import { formatSchemaErrors } from "./schema.ts";
import {
    generateKey,
    importPrivateJwk,
    randomId,
    thumbprint,
    type EcPrivateJwk,
    type EcPublicJwk,
    type SigningKey,
} from "./jose.ts";

export const POPPY_DIR = ".poppy";

export type Config = {
    client_id: string;
    base_url: string;
    // A random User ID for each Company, keyed by auth.issuer.
    user_ids: Record<string, string>;
};

export type Identity = {
    dir: string;
    clientId: string;
    jwksUri: string;
    redirectUri: string;
    key: SigningKey;
    agent: Record<string, unknown>;
    jwks: { keys: EcPublicJwk[] };
    config: Config;
};

export function poppyDir(cwd: string = process.cwd()): string {
    return join(cwd, POPPY_DIR);
}

export function normalizeBaseUrl(input: string): string {
    let url: URL;
    try {
        url = new URL(input);
    } catch {
        throw new UsageError(
            `--base-url must be a full URL, such as https://staging.example.com/poppy-test (got "${input}").`,
        );
    }
    if (url.protocol !== "https:") {
        throw new UsageError(
            "--base-url must be an HTTPS URL. Companies fetch agent.json and jwks.json over HTTPS.",
        );
    }
    if (url.search || url.hash) throw new UsageError("--base-url can't have a query or fragment.");
    return url.toString().replace(/\/+$/, "");
}

export class UsageError extends Error {}

export type KeygenResult = {
    dir: string;
    clientId: string;
    files: { local: string; url: string }[];
    gitignore?: string;
};

export async function keygen(
    baseUrlInput: string,
    options: { force?: boolean; cwd?: string } = {},
): Promise<KeygenResult> {
    const cwd = options.cwd ?? process.cwd();
    const dir = poppyDir(cwd);
    const baseUrl = normalizeBaseUrl(baseUrlInput);
    const keyFile = join(dir, "private-key.jwk");
    if (existsSync(keyFile) && !options.force) {
        throw new UsageError(
            `${keyFile} already exists. Run keygen with --force to replace it; you'll then need to host the new agent.json and jwks.json.`,
        );
    }
    mkdirSync(dir, { recursive: true });

    const generated = await generateKey(true);
    const kid = (await thumbprint(generated.publicJwk)).slice(0, 16);
    const privateJwk: EcPrivateJwk = { ...generated.privateJwk!, kid, alg: "ES256", use: "sig" };
    const publicJwk: EcPublicJwk = { ...generated.publicJwk, kid, alg: "ES256", use: "sig" };

    const clientId = `${baseUrl}/agent.json`;
    const agent = {
        client_id: clientId,
        client_name: "Poppy validator (test)",
        jwks_uri: `${baseUrl}/jwks.json`,
        redirect_uris: [`${baseUrl}/callback`],
        token_endpoint_auth_method: "private_key_jwt",
    };
    const jwks = { keys: [publicJwk] };

    writeFileSync(keyFile, JSON.stringify(privateJwk, null, 2) + "\n", { mode: 0o600 });
    chmodSync(keyFile, 0o600);
    writeFileSync(join(dir, "agent.json"), JSON.stringify(agent, null, 2) + "\n");
    writeFileSync(join(dir, "jwks.json"), JSON.stringify(jwks, null, 2) + "\n");

    // Keep User IDs from an earlier key for the same client_id, so the Company sees the same User.
    const configFile = join(dir, "config.json");
    let userIds: Record<string, string> = {};
    if (existsSync(configFile)) {
        try {
            const old = JSON.parse(readFileSync(configFile, "utf8")) as Config;
            if (old.client_id === clientId) userIds = old.user_ids ?? {};
        } catch {
            // Replaced below.
        }
    }
    const config: Config = { client_id: clientId, base_url: baseUrl, user_ids: userIds };
    writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n");

    return {
        dir,
        clientId,
        files: [
            { local: join(dir, "agent.json"), url: clientId },
            { local: join(dir, "jwks.json"), url: agent.jwks_uri },
        ],
        gitignore: ensureGitignored(cwd),
    };
}

// Adds .poppy/ to .gitignore in `cwd` when `cwd` is in a git repository and no .gitignore between
// it and the repository root already ignores it. Returns the file changed, if any.
export function ensureGitignored(cwd: string): string | undefined {
    let root: string | undefined;
    for (let d = resolve(cwd); ; d = dirname(d)) {
        if (existsSync(join(d, ".git"))) {
            root = d;
            break;
        }
        if (dirname(d) === d) break;
    }
    if (!root) return undefined;
    const ignored = /^\s*\/?\.poppy\/?\s*$/m;
    for (let d = resolve(cwd); ; d = dirname(d)) {
        const file = join(d, ".gitignore");
        if (existsSync(file) && ignored.test(readFileSync(file, "utf8"))) return undefined;
        if (d === root || dirname(d) === d) break;
    }
    const file = join(cwd, ".gitignore");
    const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
    const prefix = existing === "" || existing.endsWith("\n") ? "" : "\n";
    appendFileSync(
        file,
        `${prefix}# Poppy validator test identity and results (private key)\n.poppy/\n`,
    );
    return file;
}

// Loads .poppy/, or explains what's missing.
export async function loadIdentity(
    cwd: string = process.cwd(),
): Promise<Identity | { missing: string }> {
    const dir = poppyDir(cwd);
    const keyFile = join(dir, "private-key.jwk");
    if (!existsSync(keyFile)) {
        return {
            missing: `No test Personal Agent in ${dir}. Run "node validate/index.ts keygen --base-url https://…" and host the agent.json and jwks.json it writes.`,
        };
    }
    try {
        const privateJwk = JSON.parse(readFileSync(keyFile, "utf8")) as EcPrivateJwk;
        const agent = JSON.parse(readFileSync(join(dir, "agent.json"), "utf8")) as Record<
            string,
            unknown
        >;
        const jwks = JSON.parse(readFileSync(join(dir, "jwks.json"), "utf8")) as {
            keys: EcPublicJwk[];
        };
        const config = JSON.parse(readFileSync(join(dir, "config.json"), "utf8")) as Config;
        config.user_ids ??= {};
        const key = await importPrivateJwk(privateJwk);
        return {
            dir,
            clientId: String(agent.client_id),
            jwksUri: String(agent.jwks_uri),
            redirectUri: Array.isArray(agent.redirect_uris) ? String(agent.redirect_uris[0]) : "",
            key,
            agent,
            jwks,
            config,
        };
    } catch (error) {
        return {
            missing: `${dir} is incomplete or unreadable (${error instanceof Error ? error.message : String(error)}). Run keygen again with --force.`,
        };
    }
}

// The test User ID for a Company, created at random on first use (spec 4.2).
export function userIdFor(identity: Identity, issuer: string): string {
    let id = identity.config.user_ids[issuer];
    if (!id) {
        id = `usr_${randomId(16)}`;
        identity.config.user_ids[issuer] = id;
        writeFileSync(
            join(identity.dir, "config.json"),
            JSON.stringify(identity.config, null, 2) + "\n",
        );
    }
    return id;
}

// Checks that the hosted agent.json and jwks.json match the local files, as the Company will see
// them. Returns the problems found, each with what to do about it.
export async function verifyHosted(identity: Identity, http: Http): Promise<string[]> {
    const problems: string[] = [];
    const agentEx = await http.request({
        url: identity.clientId,
        headers: { Accept: "application/json" },
    });
    if (agentEx.error) {
        problems.push(
            `Couldn't fetch ${identity.clientId} (${agentEx.error}). Host .poppy/agent.json at that URL.`,
        );
    } else if (agentEx.status && agentEx.status >= 300 && agentEx.status < 400) {
        problems.push(
            `${identity.clientId} redirects (${agentEx.status}). Companies fetch client_id without following redirects, so serve agent.json at exactly that URL.`,
        );
    } else if (agentEx.status !== 200) {
        problems.push(
            `${identity.clientId} returned ${agentEx.status}. Host .poppy/agent.json at that URL.`,
        );
    } else if (!agentEx.json || typeof agentEx.json !== "object") {
        problems.push(
            `${identity.clientId} didn't return JSON. Host .poppy/agent.json there unchanged.`,
        );
    } else {
        const hosted = agentEx.json as Record<string, unknown>;
        if (hosted.client_id !== identity.clientId) {
            problems.push(
                `The hosted agent.json has client_id ${JSON.stringify(hosted.client_id)}, but it must equal the URL it's served from, ${identity.clientId}. Host the agent.json from .poppy/ unchanged.`,
            );
        }
        if (hosted.jwks_uri !== identity.jwksUri) {
            problems.push(
                `The hosted agent.json has jwks_uri ${JSON.stringify(hosted.jwks_uri)}, but the local one has ${identity.jwksUri}. It looks like an agent.json from a different keygen run; host the one in .poppy/.`,
            );
        }
        const errors = check("client-metadata.schema.json", hosted);
        if (errors.length) {
            problems.push(
                `The hosted agent.json doesn't match the client metadata schema: ${formatSchemaErrors(errors).join("; ")}.`,
            );
        }
    }

    const jwksEx = await http.request({
        url: identity.jwksUri,
        headers: { Accept: "application/json" },
    });
    if (jwksEx.error) {
        problems.push(
            `Couldn't fetch ${identity.jwksUri} (${jwksEx.error}). Host .poppy/jwks.json at that URL.`,
        );
    } else if (jwksEx.status !== 200) {
        problems.push(
            `${identity.jwksUri} returned ${jwksEx.status}. Host .poppy/jwks.json at that URL.`,
        );
    } else {
        const keys = (jwksEx.json as { keys?: unknown } | undefined)?.keys;
        const local = identity.key.publicJwk;
        if (!Array.isArray(keys)) {
            problems.push(
                `${identity.jwksUri} isn't a JWK Set (no "keys" array). Host .poppy/jwks.json there unchanged.`,
            );
        } else if (
            !keys.some(
                (k: EcPublicJwk) => k && k.x === local.x && k.y === local.y && k.kid === local.kid,
            )
        ) {
            problems.push(
                `${identity.jwksUri} doesn't contain the local public key (kid ${local.kid}). The hosted jwks.json is probably from an earlier keygen run, or a cache is serving an old copy. Host .poppy/jwks.json there.`,
            );
        } else if (keys.some((k: Record<string, unknown>) => k && "d" in k)) {
            problems.push(
                `${identity.jwksUri} contains a private key ("d"). Host only .poppy/jwks.json, which has the public key, and run keygen --force to replace the exposed key.`,
            );
        }
    }
    return problems;
}

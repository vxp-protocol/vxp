// A fetch wrapper that records every exchange, so checks can report exactly what was sent and what
// came back. Redirects are never followed automatically: each hop is its own exchange.

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export type HttpRequest = {
    method?: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    // A short note on what makes this request special, such as "with the DPoP proof from
    // session.start again". Shown as part of "Sent".
    note?: string;
};

export type Exchange = {
    method: string;
    url: string;
    requestHeaders: Record<string, string>;
    requestBody?: string;
    note?: string;
    status?: number;
    statusText?: string;
    responseHeaders: Record<string, string>;
    body?: string;
    json?: unknown;
    error?: string;
    ms: number;
};

export type Http = {
    request(req: HttpRequest): Promise<Exchange>;
    log: Exchange[];
};

export const USER_AGENT = "poppy-validator/0.1 (+https://personalagentprotocol.org)";
const MAX_BODY = 1_000_000;

async function readBody(response: Response): Promise<string> {
    if (!response.body) return "";
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (size < MAX_BODY) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        size += value.length;
    }
    await reader.cancel().catch(() => undefined);
    return new TextDecoder().decode(Buffer.concat(chunks).subarray(0, MAX_BODY));
}

export function createHttp(options: { fetch?: FetchLike; timeoutMs?: number } = {}): Http {
    const doFetch: FetchLike = options.fetch ?? ((url, init) => fetch(url, init));
    const log: Exchange[] = [];
    return {
        log,
        async request(req) {
            const method = (req.method ?? "GET").toUpperCase();
            const requestHeaders: Record<string, string> = {
                "User-Agent": USER_AGENT,
                ...req.headers,
            };
            const exchange: Exchange = {
                method,
                url: req.url,
                requestHeaders,
                requestBody: req.body,
                note: req.note,
                responseHeaders: {},
                ms: 0,
            };
            const started = Date.now();
            try {
                const response = await doFetch(req.url, {
                    method,
                    headers: requestHeaders,
                    body: req.body,
                    redirect: "manual",
                    signal: AbortSignal.timeout(req.timeoutMs ?? options.timeoutMs ?? 20_000),
                });
                exchange.status = response.status;
                exchange.statusText = response.statusText;
                response.headers.forEach((value, name) => {
                    exchange.responseHeaders[name.toLowerCase()] = value;
                });
                exchange.body = await readBody(response);
                const trimmed = exchange.body.trim();
                if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                    try {
                        exchange.json = JSON.parse(trimmed);
                    } catch {
                        // Left as text.
                    }
                }
            } catch (error) {
                exchange.error = describeError(error);
            }
            exchange.ms = Date.now() - started;
            log.push(exchange);
            return exchange;
        },
    };
}

function describeError(error: unknown): string {
    if (error instanceof Error) {
        if (error.name === "TimeoutError" || error.name === "AbortError") return "timed out";
        const cause = (error as Error & { cause?: unknown }).cause;
        if (cause instanceof Error) {
            const code = (cause as Error & { code?: string }).code;
            return `${error.message}: ${code ? code + " " : ""}${cause.message}`;
        }
        return error.message;
    }
    return String(error);
}

export function header(exchange: Exchange, name: string): string | undefined {
    return exchange.responseHeaders[name.toLowerCase()];
}

// The `error` code from a JSON body, or from a WWW-Authenticate header.
export function errorCode(exchange: Exchange): string | undefined {
    const json = exchange.json as { error?: unknown } | undefined;
    if (json && typeof json === "object" && typeof json.error === "string") return json.error;
    return parseWwwAuthenticate(header(exchange, "www-authenticate")).params.error;
}

export function isJsonContentType(exchange: Exchange): boolean {
    const type = header(exchange, "content-type") ?? "";
    return /^application\/([a-z0-9.+-]*\+)?json\b/i.test(type);
}

// Parses the first challenge of a WWW-Authenticate header, such as
// `DPoP error="invalid_token", algs="ES256"`.
export function parseWwwAuthenticate(value: string | undefined): {
    scheme?: string;
    schemes: string[];
    params: Record<string, string>;
} {
    if (!value) return { schemes: [], params: {} };
    const schemes: string[] = [];
    for (const piece of value.split(",")) {
        if (/^\s*[A-Za-z0-9_-]+\s*=/.test(piece)) continue;
        const m = /^\s*([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)(\s|$)/.exec(piece);
        if (m) schemes.push(m[1]);
    }
    const scheme = /^\s*([A-Za-z][A-Za-z0-9_-]*)/.exec(value)?.[1];
    const params: Record<string, string> = {};
    for (const m of value.matchAll(/([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g)) {
        const name = m[1].toLowerCase();
        if (!(name in params))
            params[name] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : m[3];
    }
    return { scheme, schemes, params };
}

export type FollowResult = {
    chain: Exchange[];
    final?: Exchange;
    // Set when a redirect went to a non-HTTPS URL, there were too many, or a Location was missing.
    problem?: string;
    nonHttpsRedirect?: string;
};

// GETs a URL, following up to `max` redirects by hand so each hop is recorded. Stops at a redirect
// to a URL that isn't HTTPS.
export async function getFollowing(
    http: Http,
    url: string,
    options: { max?: number; headers?: Record<string, string> } = {},
): Promise<FollowResult> {
    const chain: Exchange[] = [];
    let current = url;
    for (let hop = 0; hop <= (options.max ?? 5); hop++) {
        const exchange = await http.request({ url: current, headers: options.headers });
        chain.push(exchange);
        const status = exchange.status ?? 0;
        if (status < 300 || status >= 400 || status === 304) return { chain, final: exchange };
        const location = header(exchange, "location");
        if (!location) {
            return {
                chain,
                final: exchange,
                problem: `${status} redirect without a Location header`,
            };
        }
        const next = new URL(location, current).toString();
        if (!next.startsWith("https://")) {
            return {
                chain,
                final: exchange,
                problem: `redirected to ${next}, which isn't HTTPS`,
                nonHttpsRedirect: next,
            };
        }
        current = next;
    }
    return { chain, final: chain[chain.length - 1], problem: "too many redirects" };
}

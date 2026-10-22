// Milestone 2: each listed OpenAPI description loads and declares OpenAPI 3.0 or 3.1 (section 6).

import { getFollowing, type Exchange } from "../http.ts";
import type { Context, Recorder } from "./types.ts";

export type OpenApiInfo = {
    url: string;
    exchange: Exchange;
    version?: string;
    title?: string;
    paths?: number;
    problem?: string;
};

// Reads the version and title from a JSON or YAML description, without a YAML parser.
export function readOpenApi(
    ex: Exchange,
): { version?: string; title?: string; paths?: number; swagger?: string } | undefined {
    const json = ex.json as
        | { openapi?: unknown; swagger?: unknown; info?: { title?: unknown }; paths?: object }
        | undefined;
    if (json && typeof json === "object") {
        return {
            version: typeof json.openapi === "string" ? json.openapi : undefined,
            swagger: typeof json.swagger === "string" ? json.swagger : undefined,
            title: typeof json.info?.title === "string" ? json.info.title : undefined,
            paths:
                json.paths && typeof json.paths === "object"
                    ? Object.keys(json.paths).length
                    : undefined,
        };
    }
    const text = ex.body ?? "";
    const version = /^openapi:\s*["']?([0-9][0-9.]*)["']?\s*$/m.exec(text)?.[1];
    const swagger = /^swagger:\s*["']?([0-9][0-9.]*)["']?\s*$/m.exec(text)?.[1];
    if (!version && !swagger) return undefined;
    const title = /^info:\s*\n(?:[ \t]+.*\n)*?[ \t]+title:\s*["']?(.*?)["']?\s*$/m.exec(text)?.[1];
    return { version, swagger, title };
}

export async function loadOpenApi(ctx: Context, url: string): Promise<OpenApiInfo> {
    const follow = await getFollowing(ctx.http, url, {
        max: 3,
        headers: { Accept: "application/json, application/yaml;q=0.9, */*;q=0.5" },
    });
    const ex = follow.final!;
    if (follow.problem) return { url, exchange: ex, problem: follow.problem };
    if (ex.error) return { url, exchange: ex, problem: `the request failed (${ex.error})` };
    if (ex.status !== 200) return { url, exchange: ex, problem: `it returned ${ex.status}` };
    const info = readOpenApi(ex);
    if (!info)
        return {
            url,
            exchange: ex,
            problem: "the response isn't a JSON or YAML OpenAPI description",
        };
    return {
        url,
        exchange: ex,
        version: info.version ?? (info.swagger ? `swagger ${info.swagger}` : undefined),
        title: info.title,
        paths: info.paths,
    };
}

export async function checkOpenApi(ctx: Context, r: Recorder): Promise<void> {
    const apis = (ctx.discovered.poppy?.apis ?? []).filter(
        (a) => a?.type === "openapi" && typeof a.url === "string",
    );
    if (apis.length === 0) {
        r.skip("openapi.loads", "poppy.json lists no OpenAPI APIs.");
        r.skip("openapi.version", "poppy.json lists no OpenAPI APIs.");
        return;
    }
    const loaded = await Promise.all(apis.map((a) => loadOpenApi(ctx, a.url!)));
    const failed = loaded.filter((l) => l.problem);
    if (failed.length) {
        r.fail("openapi.loads", {
            exchange: failed.map((f) => f.exchange),
            got: failed.map((f) => `${f.url}: ${f.problem}`).join("; "),
            expected: "200 with an OpenAPI description at each url",
            cause: "Serve the description at the url in poppy.json, publicly (Personal Agents fetch it before they have a token).",
        });
    } else
        r.pass("openapi.loads", {
            summary: loaded.map((l) => `${l.url}: ${l.title ?? "untitled"}`).join("; "),
        });
    const ok = loaded.filter((l) => !l.problem);
    const badVersion = ok.filter((l) => !/^3\.[01](\.\d+)?$/.test(l.version ?? ""));
    if (ok.length === 0) r.skip("openapi.version", "No description loaded.");
    else if (badVersion.length) {
        r.fail("openapi.version", {
            exchange: badVersion.map((b) => b.exchange),
            got: badVersion.map((b) => `${b.url}: ${b.version ?? "no openapi field"}`).join("; "),
            expected: "openapi 3.0.x or 3.1.x",
            cause: "Personal Agents expect OpenAPI 3.0 or 3.1. Convert Swagger 2.0 descriptions with a converter.",
        });
    } else r.pass("openapi.version", { summary: ok.map((l) => `openapi ${l.version}`).join("; ") });
}

// Milestone 1: how APIs and the conversation endpoint check Session Tokens and DPoP Proofs (4.3).
// The probe is a safe GET: an unknown conversation's events (expected 404 conversation_not_found
// with a good token), or a GET operation the engineer names with --probe (expected 2xx).

import { authedRequest, tokenForResource } from "../agent.ts";
import { errorCode, header, parseWwwAuthenticate, type Exchange } from "../http.ts";
import { generateKey, randomId } from "../jose.ts";
import { skipRest, type Context, type Recorder } from "./types.ts";

export const RESOURCE_IDS = [
    "dpop.accepted",
    "dpop.missing-proof",
    "dpop.bearer-scheme",
    "dpop.wrong-ath",
    "dpop.wrong-key",
    "dpop.resource-htu",
    "dpop.token-in-url",
];

export type Probe = {
    url: string;
    kind: "conversation" | "probe";
    resource?: string;
    describe: string;
};

export function findProbe(ctx: Context): Probe | undefined {
    const entry = ctx.discovered.poppy?.agent?.protocols?.find(
        (p) => p?.type === "poppy" && typeof p.endpoint === "string",
    );
    if (entry?.endpoint) {
        return {
            url: `${entry.endpoint.replace(/\/+$/, "")}/cnv_validator${randomId(9)}/events`,
            kind: "conversation",
            resource: entry.resource,
            describe: "the events of a conversation that doesn't exist",
        };
    }
    if (ctx.options.probe) {
        const api = ctx.discovered.poppy?.apis?.find(
            (a) => a?.url && ctx.options.probe!.startsWith(new URL(a.url).origin),
        );
        return {
            url: ctx.options.probe,
            kind: "probe",
            resource: api?.resource,
            describe: "the --probe URL",
        };
    }
    return undefined;
}

// Whether the probe treated the request as authenticated.
export function accepted(probe: Probe, ex: Exchange): boolean {
    if (probe.kind === "conversation")
        return ex.status === 404 && errorCode(ex) === "conversation_not_found";
    return ex.status !== undefined && ex.status >= 200 && ex.status < 300;
}

function rejected(ex: Exchange): boolean {
    return ex.status === 400 || ex.status === 401 || ex.status === 403;
}

function expectRejected(r: Recorder, id: string, probe: Probe, ex: Exchange, cause: string): void {
    if (accepted(probe, ex)) {
        r.fail(id, {
            exchange: ex,
            expected: "401 with WWW-Authenticate: DPoP",
            got: `${`${ex.status} ${ex.statusText ?? ""}`.trim()}, the request was handled`,
            cause,
        });
    } else if (rejected(ex)) {
        // The status has its own check (dpop.missing-proof). Here it's only noted.
        r.pass(id, {
            notes:
                ex.status === 401
                    ? undefined
                    : [
                          `Refused with HTTP ${ex.status}. DPoP failures at APIs and conversation endpoints return 401 (4.3).`,
                      ],
        });
    } else {
        r.warn(id, {
            exchange: ex,
            expected: "401 with WWW-Authenticate: DPoP",
            cause: "The response is neither an acceptance nor a token error, so this can't be decided.",
        });
    }
}

export async function checkResources(ctx: Context, r: Recorder): Promise<void> {
    if (!ctx.session.token) {
        skipRest(
            r,
            RESOURCE_IDS,
            ctx.identity
                ? "No Session Token (see session.start)."
                : (ctx.identityProblem ?? "No test Personal Agent."),
        );
        return;
    }
    const probe = findProbe(ctx);
    if (!probe) {
        skipRest(
            r,
            RESOURCE_IDS,
            "poppy.json lists no conversation endpoint to probe. Pass --probe with the URL of a GET operation in your API that needs a Session Token.",
        );
        return;
    }
    const token = await tokenForResource(ctx, probe.resource);
    if (!token) {
        skipRest(r, RESOURCE_IDS, `Couldn't get a Session Token for resource ${probe.resource}.`);
        return;
    }

    const control = (
        await authedRequest(ctx, {
            url: probe.url,
            proof: "none",
            note: `${probe.describe}, with no token`,
        })
    ).ex;
    const baseline = await authedRequest(ctx, { url: probe.url, token, note: probe.describe });
    if (!accepted(probe, baseline.ex)) {
        const www = parseWwwAuthenticate(header(baseline.ex, "www-authenticate"));
        r.fail("dpop.accepted", {
            exchange: baseline.exchanges,
            expected:
                probe.kind === "conversation"
                    ? "404 conversation_not_found (the token accepted, the conversation unknown)"
                    : "2xx",
            cause: `A fresh Session Token with a valid proof wasn't accepted${www.params.error ? ` (${www.params.error}${www.params.error_description ? `: ${www.params.error_description}` : ""})` : ""}. Check that this endpoint verifies tokens from your token endpoint and builds htu from its public URL.`,
        });
        skipRest(
            r,
            RESOURCE_IDS,
            "The probe didn't accept a valid request (see dpop.accepted), so rejections can't be told apart.",
        );
        return;
    }
    r.pass("dpop.accepted");
    if (accepted(probe, control)) {
        skipRest(
            r,
            RESOURCE_IDS,
            `The probe handles requests with no token at all (${control.status}), so it can't show whether bad tokens are rejected. ${probe.kind === "probe" ? "Choose a --probe URL that needs a Session Token." : "Conversation requests must carry a Session Token (7.2)."}`,
        );
        return;
    }

    if (r.wants("dpop.missing-proof")) {
        const ex = (
            await authedRequest(ctx, {
                url: probe.url,
                token,
                proof: "none",
                note: "with the DPoP token but no DPoP header",
            })
        ).ex;
        const www = parseWwwAuthenticate(header(ex, "www-authenticate"));
        if (accepted(probe, ex)) {
            expectRejected(
                r,
                "dpop.missing-proof",
                probe,
                ex,
                "The endpoint accepts a DPoP-bound token without a proof, so a copied token works on its own.",
            );
        } else if (!www.schemes.some((s) => s.toLowerCase() === "dpop")) {
            r.fail("dpop.missing-proof", {
                exchange: ex,
                expected:
                    '401 with WWW-Authenticate: DPoP error="invalid_dpop_proof" (or invalid_token)',
                cause: "The request was refused, but without a DPoP challenge in WWW-Authenticate, so a Personal Agent can't tell what to fix.",
            });
        } else if (ex.status !== 401) {
            r.fail("dpop.missing-proof", {
                exchange: ex,
                expected:
                    '401 with WWW-Authenticate: DPoP error="invalid_dpop_proof" (or invalid_token)',
                cause: `The request was refused with HTTP ${ex.status}. APIs and conversation endpoints return DPoP errors with 401, as RFC 9449 does; 400 is for the token endpoint.`,
            });
        } else r.pass("dpop.missing-proof");
    }

    if (r.wants("dpop.bearer-scheme")) {
        const ex = (
            await authedRequest(ctx, {
                url: probe.url,
                token,
                scheme: "Bearer",
                proof: "none",
                note: "with the DPoP Session Token sent as Authorization: Bearer",
            })
        ).ex;
        expectRejected(
            r,
            "dpop.bearer-scheme",
            probe,
            ex,
            "The endpoint accepts Session Tokens with the Bearer scheme. Only an MCP server without DPoP may, with a Bearer token issued for it.",
        );
    }

    if (r.wants("dpop.wrong-ath")) {
        const ex = (
            await authedRequest(ctx, {
                url: probe.url,
                token,
                proof: { accessToken: `not-this-token-${randomId(8)}` },
                note: "with a proof whose ath is the hash of a different token",
            })
        ).ex;
        expectRejected(
            r,
            "dpop.wrong-ath",
            probe,
            ex,
            "The endpoint doesn't compare the proof's ath with the hash of the token it came with.",
        );
    }

    if (r.wants("dpop.wrong-key")) {
        const other = await generateKey(false);
        const ex = (
            await authedRequest(ctx, {
                url: probe.url,
                token,
                proof: { key: other },
                note: "with a valid proof signed by a different key than the token is bound to",
            })
        ).ex;
        expectRejected(
            r,
            "dpop.wrong-key",
            probe,
            ex,
            "The endpoint checks the proof's signature but not that its key is the one the token is bound to (cnf.jkt).",
        );
    }

    if (r.wants("dpop.resource-htu")) {
        const other = `${new URL(probe.url).origin}/poppy-validator/other-path`;
        const ex = (
            await authedRequest(ctx, {
                url: probe.url,
                token,
                proof: { url: other },
                note: `with a proof whose htu is ${other}`,
            })
        ).ex;
        expectRejected(
            r,
            "dpop.resource-htu",
            probe,
            ex,
            "The endpoint doesn't compare htu and htm with the request.",
        );
    }

    if (r.wants("dpop.token-in-url")) {
        const url = `${probe.url}${probe.url.includes("?") ? "&" : "?"}access_token=${encodeURIComponent(token.accessToken)}`;
        const ex = (
            await authedRequest(ctx, {
                url,
                proof: { accessToken: token.accessToken },
                note: "with the token in the access_token query parameter and no Authorization header",
            })
        ).ex;
        expectRejected(
            r,
            "dpop.token-in-url",
            probe,
            ex,
            "The endpoint reads tokens from the URL query. Accept them only in the Authorization header.",
        );
    }
}

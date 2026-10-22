import assert from "node:assert/strict";
import { test } from "node:test";
import { check } from "../schemas.ts";
import {
    ath,
    b64url,
    b64urlDecode,
    decodeJwt,
    dpopProof,
    generateKey,
    htuOf,
    sha256,
    signAssertion,
    signJwt,
    thumbprint,
    verifyJwt,
} from "../jose.ts";

test("base64url round trip without padding", () => {
    const bytes = new Uint8Array([0, 250, 251, 252, 253, 254, 255]);
    const encoded = b64url(bytes);
    assert.doesNotMatch(encoded, /[+/=]/);
    assert.deepEqual([...b64urlDecode(encoded)], [...bytes]);
});

test("sign and verify an ES256 JWT", async () => {
    const key = await generateKey(false);
    const jwt = await signJwt({ alg: "ES256", typ: "JWT" }, { sub: "u" }, key.privateKey);
    assert.equal(b64urlDecode(jwt.split(".")[2]).length, 64, "r || s signature");
    assert.deepEqual((await verifyJwt(jwt, key.publicJwk))?.payload, { sub: "u" });
    const other = await generateKey(false);
    assert.equal(await verifyJwt(jwt, other.publicJwk), null);
    const [h, , s] = jwt.split(".");
    assert.equal(
        await verifyJwt(`${h}.${b64url(JSON.stringify({ sub: "v" }))}.${s}`, key.publicJwk),
        null,
    );
});

test("RFC 7638 thumbprint matches the RFC's EC example shape", async () => {
    const key = await generateKey(false);
    const t = await thumbprint(key.publicJwk);
    assert.match(t, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(await thumbprint({ ...key.publicJwk, kid: "ignored", alg: "ES256" }), t);
});

test("ath is the base64url SHA-256 of the token", async () => {
    // SHA-256("abc"), base64url.
    assert.equal(await sha256("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    assert.equal(await ath("abc"), await sha256("abc"));
});

test("DPoP proofs carry the fields RFC 9449 and spec 4.3 require", async () => {
    const key = await generateKey(false);
    const proof = await dpopProof({
        key,
        method: "get",
        url: "https://a.example/x?y=1#z",
        accessToken: "tok",
        nonce: "n1",
    });
    const { header, payload } = decodeJwt(proof);
    assert.equal(header.typ, "dpop+jwt");
    assert.equal(header.alg, "ES256");
    assert.deepEqual(
        Object.keys(header.jwk as object).sort(),
        ["crv", "kty", "x", "y"],
        "no private or extra members",
    );
    assert.equal(payload.htm, "GET");
    assert.equal(payload.htu, "https://a.example/x");
    assert.equal(payload.ath, await ath("tok"));
    assert.equal(payload.nonce, "n1");
    assert.equal(typeof payload.jti, "string");
    assert.deepEqual(check("dpop-proof.schema.json#/$defs/header", header), []);
    assert.deepEqual(check("dpop-proof.schema.json#/$defs/payload", payload), []);
    assert.ok(await verifyJwt(proof, key.publicJwk));
    const second = decodeJwt(await dpopProof({ key, method: "GET", url: "https://a.example/x" }));
    assert.notEqual(second.payload.jti, payload.jti, "a fresh jti per proof");
});

test("htuOf strips query and fragment", () => {
    assert.equal(htuOf("https://a.example:8443/p/q?x#y"), "https://a.example:8443/p/q");
});

test("assertions are short-lived and match the session assertion schema", async () => {
    const key = await generateKey(false);
    key.publicJwk.kid = "k1";
    const jwt = await signAssertion({
        key,
        iss: "https://agent.example/agent.json",
        sub: "usr_1",
        aud: "https://auth.example",
    });
    const { header, payload } = decodeJwt(jwt);
    assert.equal(header.kid, "k1");
    assert.equal((payload.exp as number) - (payload.iat as number), 60);
    assert.deepEqual(check("session-assertion.schema.json", payload), []);
});

// Minimal JOSE for a personal agent, on node:crypto only: ES256 compact JWS (RFC 7515), RFC 7638
// thumbprints, RFC 7523 client and user assertions, and DPoP proofs (RFC 9449).

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, randomBytes, sign, verify } from "node:crypto";

export type PublicJwk = { kty: "EC"; crv: "P-256"; x: string; y: string; kid?: string; alg?: string; use?: string };
export type PrivateJwk = PublicJwk & { d: string };
export type SigningKey = { privateKey: KeyObject; publicJwk: PublicJwk & { kid: string } };

export const b64u = (v: Buffer | Uint8Array | string) => Buffer.from(v).toString("base64url");
export const sha256b64u = (v: string | Buffer) => b64u(createHash("sha256").update(v).digest());
export const now = () => Math.floor(Date.now() / 1000);
export const randomToken = (bytes = 16) => randomBytes(bytes).toString("base64url");

/** RFC 7638 thumbprint of an EC P-256 key: members in lexicographic order, no whitespace. */
export function thumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
	return sha256b64u(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}

export function generatePrivateJwk(): PrivateJwk {
	const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const j = privateKey.export({ format: "jwk" }) as { x: string; y: string; d: string };
	return { kty: "EC", crv: "P-256", x: j.x, y: j.y, d: j.d };
}

export function signingKey(jwk: PrivateJwk): SigningKey {
	const privateKey = createPrivateKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d }, format: "jwk" });
	const pub = { kty: "EC" as const, crv: "P-256" as const, x: jwk.x, y: jwk.y };
	return { privateKey, publicJwk: { ...pub, kid: thumbprint(pub), alg: "ES256", use: "sig" } };
}

export function signJwt(key: SigningKey, header: Record<string, unknown>, payload: Record<string, unknown>): string {
	const h = b64u(JSON.stringify({ alg: "ES256", ...header }));
	const p = b64u(JSON.stringify(payload));
	const s = sign("sha256", Buffer.from(`${h}.${p}`), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
	return `${h}.${p}.${b64u(s)}`;
}

export type DecodedJws = { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: string; signature: Buffer };

export function decodeJws(jws: string): DecodedJws | null {
	if (typeof jws !== "string") return null;
	const parts = jws.split(".");
	if (parts.length !== 3) return null;
	try {
		const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
		const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
		if (!header || typeof header !== "object" || !payload || typeof payload !== "object" || Array.isArray(payload)) return null;
		return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], "base64url") };
	} catch {
		return null;
	}
}

/**
 * Verifies an ES256 compact JWS against a JWKS. The key is chosen by `kid` (and must match its own
 * RFC 7638 thumbprint when it declares one); `typ` must be the expected one. Returns the payload or null.
 */
export function verifyJws(jws: string, jwks: unknown, typ: string): Record<string, unknown> | null {
	const d = decodeJws(jws);
	if (!d || d.header.alg !== "ES256" || d.header.typ !== typ || typeof d.header.kid !== "string") return null;
	const keys = (jwks as { keys?: unknown })?.keys;
	if (!Array.isArray(keys)) return null;
	const jwk = keys.find((k) => k && typeof k === "object" && (k as PublicJwk).kid === d.header.kid) as PublicJwk | undefined;
	if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || ("d" in jwk)) return null;
	if (thumbprint(jwk) !== jwk.kid) return null;
	try {
		const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
		return verify("sha256", Buffer.from(d.signingInput), { key, dsaEncoding: "ieee-p1363" }, d.signature) ? d.payload : null;
	} catch {
		return null;
	}
}

/** RFC 7523 assertion. `sub` = client_id for client authentication; the per-company User ID otherwise. */
export function assertion(key: SigningKey, clientId: string, sub: string, aud: string): string {
	const t = now();
	return signJwt(key, { typ: "JWT", kid: key.publicJwk.kid }, { iss: clientId, sub, aud, iat: t, exp: t + 60, jti: randomToken(18) });
}

/** RFC 9449 DPoP proof. `htu` is the request URL without query and fragment; `ath` binds the access token. */
export function dpopProof(key: SigningKey, method: string, url: string, accessToken?: string): string {
	const u = new URL(url);
	const { kid: _kid, alg: _alg, use: _use, ...jwk } = key.publicJwk;
	return signJwt(key, { typ: "dpop+jwt", jwk }, {
		jti: randomToken(18),
		htm: method,
		htu: `${u.origin}${u.pathname}`,
		iat: now(),
		...(accessToken ? { ath: sha256b64u(accessToken) } : {}),
	});
}

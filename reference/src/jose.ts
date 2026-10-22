// JWT, JWKS and DPoP with node:crypto, no libraries. Only ES256 and RS256; nothing symmetric.

import {
	createHash,
	createPublicKey,
	generateKeyPairSync,
	type JsonWebKey,
	type KeyObject,
	randomBytes,
	sign,
	verify,
} from "node:crypto";

export type Jwk = JsonWebKey & { kid?: string; alg?: string; use?: string };
export type Alg = "ES256" | "RS256";

export const b64u = (value: Buffer | Uint8Array | string) => Buffer.from(value).toString("base64url");
export const sha256 = (value: string | Buffer) =>
	createHash("sha256").update(value).digest("base64url");
export const randomId = (prefix: string, bytes = 16) =>
	`${prefix}${randomBytes(bytes).toString("base64url")}`;
export const ahora = () => Math.floor(Date.now() / 1000);

export type Decoded = {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
	signingInput: string;
	signature: Buffer;
};

export function decodeJwt(token: string): Decoded | null {
	const parts = token.split(".");
	if (parts.length !== 3) return null;
	try {
		return {
			header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
			payload: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")),
			signingInput: `${parts[0]}.${parts[1]}`,
			signature: Buffer.from(parts[2], "base64url"),
		};
	} catch {
		return null;
	}
}

export function signJwt(
	header: Record<string, unknown>,
	payload: Record<string, unknown>,
	key: KeyObject,
): string {
	const alg = header.alg as Alg;
	const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
	const signature =
		alg === "ES256"
			? sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" })
			: sign("sha256", Buffer.from(input), key);
	return `${input}.${b64u(signature)}`;
}

/** Verifies the signature with a public key; `null` if the algorithm is not one of the allowed ones. */
export function verifyWith(decoded: Decoded, jwk: Jwk, allowed: Alg[]): boolean {
	const alg = decoded.header.alg;
	if (alg !== "ES256" && alg !== "RS256") return false;
	if (!allowed.includes(alg)) return false;
	if (alg === "ES256" && jwk.kty !== "EC") return false;
	if (alg === "RS256" && jwk.kty !== "RSA") return false;
	if ("d" in jwk && jwk.d) return false;
	try {
		const key = createPublicKey({ key: jwk, format: "jwk" });
		return alg === "ES256"
			? verify("sha256", Buffer.from(decoded.signingInput), { key, dsaEncoding: "ieee-p1363" }, decoded.signature)
			: verify("sha256", Buffer.from(decoded.signingInput), key, decoded.signature);
	} catch {
		return false;
	}
}

/** RFC 7638 thumbprint of a public key. */
export function thumbprint(jwk: Jwk): string {
	const members =
		jwk.kty === "EC"
			? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
			: { e: jwk.e, kty: jwk.kty, n: jwk.n };
	return sha256(JSON.stringify(members));
}

export type ClaveFirma = { privateKey: KeyObject; publicJwk: Jwk };

export function nuevaClaveEs256(): ClaveFirma {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const publicJwk = publicKey.export({ format: "jwk" }) as Jwk;
	publicJwk.kid = thumbprint(publicJwk);
	publicJwk.alg = "ES256";
	publicJwk.use = "sig";
	return { privateKey, publicJwk };
}

/** Public key in a DPoP Proof's `jwk`: public members only. */
export function publicOnly(jwk: Jwk): Jwk {
	return jwk.kty === "EC"
		? { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y }
		: { kty: "RSA", n: jwk.n, e: jwk.e };
}

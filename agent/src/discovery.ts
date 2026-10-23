// Discovery of companies that implement VXP (spec §8 «Discovery»).
//
// VXP has no global registry. The agent starts from a list of candidate domains that comes from
// outside VXP: the person names the company, a search engine or a directory suggests it, the company's
// own website or receipt links to it, or the agent remembers it from an earlier task. For each domain the
// agent reads https://<domain>/.well-known/vxp.json and the issuer's RFC 8414 metadata, and accepts the
// company only if both agree (organization.domain is the host that served vxp.json and is listed in
// vxp_proof.domains; the metadata's issuer is identical to the one vxp.json names).

import type { Net } from "./net.ts";

export type Capability = {
	id: string;
	effect: "read" | "write" | string;
	access?: string;
	admission?: string;
	authorization_details_type?: string;
	commitment_modes?: string[];
	outcome_proof?: boolean;
};

export type Company = {
	domain: string;
	name: string;
	issuer: string;
	endpoint: string;
	status: string | null;
	capabilities: Capability[];
	limits: Record<string, number>;
	relationshipActions: string[];
	tokenEndpoint: string;
	deviceEndpoint: string;
	metadataUrl: string;
	relationshipJwksUri: string | null;
	discoveredAt: string;
};

export type DiscoveryResult = { domain: string; ok: true; company: Company } | { domain: string; ok: false; reason: string };

/** RFC 8414 §3.1: the well-known segment goes between the host and the issuer's path. */
export function metadataUrlFor(issuer: string): string {
	const u = new URL(issuer);
	return `${u.origin}/.well-known/oauth-authorization-server${u.pathname.replace(/\/$/, "")}`;
}

export async function discoverOne(net: Net, domain: string): Promise<DiscoveryResult> {
	const d = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
	try {
		const origin = net.originFor(d);
		const vxp = await net.doc(`${origin}/.well-known/vxp.json`).catch((e) => {
			throw new Error(`no vxp.json (${e.message})`);
		});
		if (vxp.protocol !== "vxp") return { domain: d, ok: false, reason: "vxp.json: protocol is not «vxp»" };
		if (vxp.version !== "0.1") return { domain: d, ok: false, reason: `vxp.json: unsupported version ${vxp.version}` };
		if (String(vxp.organization?.domain ?? "").toLowerCase() !== d) return { domain: d, ok: false, reason: "vxp.json: organization.domain is not the host that served it" };
		if (typeof vxp.issuer !== "string" || typeof vxp.endpoint !== "string") return { domain: d, ok: false, reason: "vxp.json: issuer or endpoint missing" };
		net.check(vxp.issuer);
		net.check(vxp.endpoint);
		const metadataUrl = metadataUrlFor(vxp.issuer);
		const meta = await net.doc(metadataUrl);
		if (meta.issuer !== vxp.issuer) return { domain: d, ok: false, reason: "issuer metadata: issuer differs from vxp.json" };
		const domains = ((meta.vxp_proof?.domains ?? []) as unknown[]).map((x) => String(x).toLowerCase());
		if (!domains.includes(d)) return { domain: d, ok: false, reason: "issuer metadata: domain not listed in vxp_proof.domains" };
		if (typeof meta.token_endpoint !== "string" || typeof meta.device_authorization_endpoint !== "string") return { domain: d, ok: false, reason: "issuer metadata: token or device endpoint missing" };
		const company: Company = {
			domain: d,
			name: String(vxp.organization?.name ?? d),
			issuer: vxp.issuer,
			endpoint: vxp.endpoint,
			status: typeof vxp.status === "string" ? vxp.status : null,
			capabilities: Array.isArray(vxp.capabilities) ? vxp.capabilities : [],
			limits: vxp.limits ?? {},
			// The actions a company may start come from its metadata (R1), not from vxp.json alone.
			relationshipActions: Array.isArray(meta.vxp_relationship?.company_initiated_actions) ? meta.vxp_relationship.company_initiated_actions : [],
			tokenEndpoint: meta.token_endpoint,
			deviceEndpoint: meta.device_authorization_endpoint,
			metadataUrl,
			relationshipJwksUri: typeof meta.vxp_relationship?.jwks_uri === "string" ? meta.vxp_relationship.jwks_uri : null,
			discoveredAt: new Date().toISOString(),
		};
		return { domain: d, ok: true, company };
	} catch (e) {
		return { domain: d, ok: false, reason: (e as Error).message };
	}
}

export async function discover(net: Net, domains: string[]): Promise<DiscoveryResult[]> {
	return Promise.all(domains.map((d) => discoverOne(net, d)));
}

export const offers = (c: Company, operation: string) => c.capabilities.some((x) => x.id === operation);

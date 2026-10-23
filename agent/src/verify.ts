// Local verification of a VXP Proof package (spec §10) with the repository's independent verifier
// (verifier/vxp-verify.js, imported as is). The agent anchors by the issuer it learned on its own,
// from vxp.json on the domain it chose, and fetches the public material from the issuer's RFC 8414
// metadata only: never from a document handed over with the package.

import { verifyPackage } from "../../verifier/vxp-verify.js";
import { decodeJws } from "./jose.ts";
import type { Net } from "./net.ts";
import { metadataUrlFor } from "./discovery.ts";

export type Material = { anchor: { issuer: string }; docs: Record<string, string>; obtained_at: string };

/** The operation as the agent saw it, in the shape the verifier cross-checks (P8). */
export function operationView(view: any) {
	return {
		operation_id: view.operation_id,
		revision: view.proposal?.revision,
		summary: view.proposal?.summary,
		terms: view.proposal?.terms,
		expires_at: view.proposal?.expires_at,
		user_approval_required: view.proposal?.user_approval_required,
		state: view.projections?.poppy,
		result: view.result,
	};
}

/** Downloads what the verifier needs for this package, starting from the anchored issuer. */
export async function collectMaterial(net: Net, issuer: string, pkg: any): Promise<Material> {
	const docs: Record<string, string> = {};
	const get = async (url: string) => {
		if (!(url in docs)) {
			const r = await net.raw(url);
			if (r.status !== 200) throw new Error(`GET ${url} → ${r.status}`);
			docs[url] = r.text;
		}
		return docs[url];
	};
	const metaUrl = metadataUrlFor(issuer);
	const meta = JSON.parse(await get(metaUrl));
	const block = meta.vxp_proof ?? {};
	for (const u of [block.jwks_uri, block.operator?.jwks_uri]) if (typeof u === "string") await get(u);
	if (pkg?.log && block.log) {
		await get(block.log.jwks_uri);
		const live = await get(block.log.checkpoint_url);
		const first = decodeJws(String(pkg.log.checkpoint ?? ""))?.payload.tree_size;
		const second = decodeJws(live.trim())?.payload.tree_size;
		if (typeof first === "number" && typeof second === "number" && second > first && typeof block.log.consistency_url === "string")
			await get(`${block.log.consistency_url}?first=${first}&second=${second}`);
	}
	return { anchor: { issuer }, docs, obtained_at: new Date().toISOString() };
}

export type Verdict = Record<string, unknown> & { valid: boolean };

/** Verifies a package with saved material. `operation` and `aud` are optional cross-checks. */
export async function verifyWithMaterial(pkg: unknown, material: Material, opts: { operation?: unknown; aud?: string } = {}): Promise<Verdict> {
	return (await verifyPackage({ package: JSON.stringify(pkg), material: JSON.stringify({ anchor: material.anchor, docs: material.docs }), operation: opts.operation ? JSON.stringify(opts.operation) : null, aud: opts.aud ?? null })) as Verdict;
}

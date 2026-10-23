// Optional profiles for the agent side. VXP's native profile (vxp.json + /v1) is implemented in
// agent.ts. Poppy draft 0.2 and PACT 1.0 are separate external contracts that a company MAY offer
// through its own adapters (spec §8 «Adapters», I1): an agent that speaks them does not need VXP's
// native profile, and VXP never alters their discovery, authorization, operations or states.
//
// This file only fixes the seam where an agent-side adapter plugs in. None is implemented here.
// What each would need, using the official clients and kits (not copies):
// - Poppy: discovery from /.well-known/poppy.json, Poppy sign-in (Device Sign-In), conversations and
//   Operations as written; the `vxpprotocol.org/proof` extension listed in the agent's client metadata
//   so the company adds its domain-named member to each operation; the proof is then fetched from the
//   `proof` link in that member and verified exactly as in verify.ts, anchored by the Poppy domain
//   ({domain} anchor). Relationship over the Poppy conversation (spec R12–R16) instead of an HTTP inbox.
// - PACT: Agent Card discovery on the brand domain, PACT agent registration and delegated authority,
//   A2A tasks; the proof extension `https://vxpprotocol.org/ext/proof/v0.1` in message metadata next to
//   `pact.receipt` (untouched); verification anchored by {brand_domain} or {pact_issuer}, and the PACT
//   receipt cross-check. Under PACT every write requires `company_channel` approval (spec §6).

import type { Company } from "./discovery.ts";

export type ProfileName = "vxp-native" | "poppy-0.2" | "pact-1.0";

/** What the rest of an agent needs from any profile: the same steps, whatever the wire. */
export interface ProfileAdapter {
	readonly profile: ProfileName;
	/** Does this domain offer the profile? (vxp.json, poppy.json or the Agent Card). */
	detect(domain: string): Promise<boolean>;
	/** Starts the person's approval on the company's page; returns what to show the person. */
	authorize(company: Company, request: { operation: string; target: Record<string, unknown>; parameters: Record<string, unknown> }): Promise<{ verification_uri_complete: string; user_code: string }>;
	/** Asks; returns a handle and the current state, projected to VXP's internal states (spec E1). */
	request(company: Company, operation: string, target: Record<string, unknown>, parameters: Record<string, unknown>): Promise<{ handle: string; state: string }>;
	accept(handle: string, approvedBy: "user" | "standing_permission"): Promise<{ state: string }>;
	/** The proof package and the anchor to verify it with ({issuer} | {domain} | {brand_domain} | {pact_issuer}). */
	proof(handle: string): Promise<{ package: unknown; anchor: Record<string, string> }>;
}

/** Profiles available in this build. Poppy and PACT are not implemented (see the notes above). */
export const AVAILABLE_PROFILES: ProfileName[] = ["vxp-native"];

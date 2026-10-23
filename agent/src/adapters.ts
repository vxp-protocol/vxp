// Optional profiles for the agent side. VXP's native profile (vxp.json + /v1) is implemented in agent.ts
// and does not import anything from here: a native-only agent works the same without these files.
//
// Poppy draft 0.2 and PACT 1.0 are separate external contracts that a company MAY offer through its own
// adapters (spec §8 «Adapters», I1). The agent speaks them as written:
// - Poppy (adapters/poppy.ts): poppy.json, the agent's session, Device Sign-In with scopes, the
//   conversation and the Operations extension; VXP Proof in the operation's `vxpprotocol.org/proof`
//   member, anchored by the Poppy domain ({domain}).
// - PACT (adapters/pact.ts): the Agent Card on the brand domain, the personal-agent JWT, delegated authority,
//   A2A `message:send`; VXP Proof in message metadata under `https://vxpprotocol.org/ext/proof/v0.1`, next to
//   `pact.receipt`; anchored by the PACT authorization server ({pact_issuer}) with the receipt cross-checked.
//
// Both are conversational: the company's own agent turns the agent's text into a proposal. The adapters
// therefore take text (`say`) where the native profile takes {operation, target, parameters}.
//
// Not implemented: VXP Relationship over a Poppy conversation (spec R12–R16) and over PACT (pending in the
// spec itself).

import type { AcceptOutcome, Mandate } from "./agent.ts";
import type { Verdict } from "./verify.ts";

export type ProfileName = "vxp-native" | "poppy-0.2" | "pact-1.0";

export type AdapterAuthorization = { company: string; verification_uri_complete: string; user_code: string; expires_at: string; scopes: string[] };
export type AdapterPoll = { status: "granted" | "authorization_pending" | "access_denied" | "expired_token" | "none"; scopes?: string[] };

/** One turn of the conversation: what the company said, and any operation or missing authorization. */
export type AdapterTurn = {
	conversation: string;
	texts: string[];
	data: unknown[];
	/** The operation as the company shows it (Poppy operation / `vxpprotocol.org/operation`), if this turn proposed or reported one. */
	operation: any | null;
	authorization: { error: string; scopes: string[] } | null;
};

export type AdapterAccept =
	| AcceptOutcome
	| { status: "blocked_by_mandate"; reason: string; amount_clp: number | null; mandate: Mandate }
	| { status: "awaiting_company_channel"; reason: string; operation_id: string; summary: string };

export type AdapterProof = { verdict: Verdict; package_file: string; material_file: string };

/** What the rest of an agent needs from an optional profile: the same steps as the native one, on its wire. */
export interface ProfileAdapter {
	readonly profile: ProfileName;
	/** Does this domain offer the profile? Reads poppy.json or the Agent Card; null if not offered or not consistent. */
	detect(domain: string): Promise<unknown | null>;
	/** Starts the person's sign-in on the company's own page; returns what to show the person. */
	authorize(company: string, scopes: string[]): Promise<AdapterAuthorization>;
	pollAuthorization(company: string, waitSeconds?: number): Promise<AdapterPoll>;
	/** One message to the company's agent. `operation` names the capability asked for (it keys the person's cap). */
	say(company: string, text: string, o?: { operation?: string }): Promise<AdapterTurn>;
	status(company: string, operationId: string): Promise<any>;
	/** Accepts the current revision only within the person's rules (agent.decideAcceptance); under PACT, never by the agent. */
	accept(company: string, operationId: string): Promise<AdapterAccept>;
	/** The proof package, verified locally with the profile's own anchor. */
	proof(company: string, operationId: string): Promise<AdapterProof>;
}

/** Profiles available in this build. The adapters are loaded only by whoever imports them. */
export const AVAILABLE_PROFILES: ProfileName[] = ["vxp-native", "poppy-0.2", "pact-1.0"];

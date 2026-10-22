// Native state machine of the VXP native profile (design 0.1, §4) and its normative projection
// to Poppy operations v1 (operations.mdx §3) and to A2A 1.0.1 (TaskState, a2a.proto:186-208).
//
// Rule: the native state is the source; Poppy and A2A see only their projection, with values from THEIR
// enums. A2A requires it («Extensions should use existing enum values and annotate additional semantic
// meaning in the `metadata` field», extensions.md «Limitations»); Poppy only requires ignoring unknown
// fields, not values (spec.mdx §3.3). The native state travels as a separate field or metadata.

import { mutado } from "./mutar.ts";

export const ESTADOS_NATIVOS = [
	"received",
	"authorization_required",
	"proposed",
	"accepted",
	"waiting_human",
	"executing",
	"pending_verification",
	"succeeded",
	"failed",
	"cancelled",
	// Not in the design 0.1 table. It is needed by its own validity rule (§3.D «límites de
	// vigencia») and it is Poppy's `expired`: «Not confirmed before `expires_at`. Nothing was done».
	"expired",
] as const;

export type EstadoNativo = (typeof ESTADOS_NATIVOS)[number];

export const FINALES: ReadonlySet<EstadoNativo> = new Set(["succeeded", "failed", "cancelled", "expired"]);

/** Legal transitions. Anything not listed here is illegal. */
export const TRANSICIONES: Readonly<Record<EstadoNativo, readonly EstadoNativo[]>> = {
	received: ["authorization_required", "proposed", "failed"],
	authorization_required: ["proposed", "cancelled", "expired", "failed"],
	// proposed → proposed: new revision (immutable; the previous one can no longer be accepted).
	proposed: ["proposed", "accepted", "cancelled", "expired", "failed"],
	// accepted → cancelled only before execution starts; accepted → failed if, on re-checking
	// permissions or the precondition, it no longer holds.
	accepted: ["waiting_human", "executing", "cancelled", "failed"],
	waiting_human: ["executing", "pending_verification", "succeeded", "failed", "cancelled"],
	executing: ["pending_verification", "succeeded", "failed"],
	// pending_verification → cancelled only if the stop is confirmed with its effects known.
	pending_verification: ["succeeded", "failed", "cancelled", "waiting_human"],
	succeeded: [],
	failed: [],
	cancelled: [],
	expired: [],
};

export function transicionLegal(desde: EstadoNativo | null, hacia: EstadoNativo): boolean {
	if (mutado("transiciones_legales")) return true;
	if (desde === null) return hacia === "received";
	return TRANSICIONES[desde].includes(hacia);
}

export type EstadoPoppy = "proposed" | "in_progress" | "succeeded" | "failed" | "cancelled" | "expired";

/**
 * Projection to Poppy operations v1. `null` = no Poppy operation yet (Poppy has no
 * object before the proposal: without permissions it responds `insufficient_scope`/`sign_in_required`).
 */
export function proyectarPoppy(e: EstadoNativo): EstadoPoppy | null {
	if (mutado("proyeccion")) return e as EstadoPoppy;
	switch (e) {
		case "received":
		case "authorization_required":
			return null;
		case "proposed":
			return "proposed";
		case "accepted":
		case "waiting_human":
		case "executing":
		// operations §6: «MUST NOT report `failed` while it doesn't know whether the action took effect».
		case "pending_verification":
			return "in_progress";
		default:
			return e;
	}
}

export type EstadoA2A =
	| "TASK_STATE_SUBMITTED"
	| "TASK_STATE_WORKING"
	| "TASK_STATE_COMPLETED"
	| "TASK_STATE_FAILED"
	| "TASK_STATE_CANCELED"
	| "TASK_STATE_INPUT_REQUIRED"
	| "TASK_STATE_REJECTED"
	| "TASK_STATE_AUTH_REQUIRED";

/** Projection to A2A 1.0.1. Under PACT there are no tasks (PACT §4.2): it is only used in metadata. */
export function proyectarA2A(e: EstadoNativo): EstadoA2A {
	if (mutado("proyeccion")) return e as unknown as EstadoA2A;
	const m: Record<EstadoNativo, EstadoA2A> = {
		received: "TASK_STATE_SUBMITTED",
		authorization_required: "TASK_STATE_AUTH_REQUIRED",
		proposed: "TASK_STATE_INPUT_REQUIRED",
		accepted: "TASK_STATE_WORKING",
		// Waiting for a person at the COMPANY: it is not customer input.
		waiting_human: "TASK_STATE_WORKING",
		executing: "TASK_STATE_WORKING",
		pending_verification: "TASK_STATE_WORKING",
		succeeded: "TASK_STATE_COMPLETED",
		failed: "TASK_STATE_FAILED",
		cancelled: "TASK_STATE_CANCELED",
		// A2A has no «expired»: CANCELED («canceled before completion»), with the native state in metadata.
		expired: "TASK_STATE_CANCELED",
	};
	return m[e];
}

export const URI_PROTOCOLO = "https://vxpprotocol.org/ext/native/v0.1";

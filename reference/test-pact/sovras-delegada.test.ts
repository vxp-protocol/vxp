// PACT Delegated against the gateway, with the official @openpactprotocol/client client.
// It is copied into e2e/ of the openpactprotocol repo (commit 838c6bd) and runs against a live server
// (scripts/pact-e2e.sh). The official delegated suite does not work as-is: it hardcodes the scopes and the
// login form of its sample airline.

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { A2AHttpError, createPlatformSigner, fetchAgentCard, interfaceUrl } from "@openpactprotocol/client";
import {
	DelegatedA2AClient,
	DelegationTokenRejectedError,
	DeviceCodeClient,
	OAuthError,
	delegationScheme,
	fetchAuthorizationServerMetadata,
	verifyReceipt,
	type DelegationToken,
} from "@openpactprotocol/client/delegation";

const provider = process.env.PROVIDER_URL!;
const issuer = process.env.PA_ISSUER!;
const audience = process.env.PA_AUDIENCE!;
const privateJwk = process.env.PA_PRIVATE_JWK!;
const llave = process.env.LLAVE_INTERNA!;
const paquetesDir = process.env.PAQUETES_DIR;
const FERRETERIA = "t_ferreteria_demo";
/** A2A extension for VXP Proof (PACT profile). */
const EXT = "https://vxpprotocol.org/ext/proof/v0.1";
/** Trust members of the block (SPEC §4.2): the copy MUST be identical to the company's metadata. */
const CONFIANZA = ["version", "company", "jwks_uri", "operator", "custody", "log", "domains", "pact"];
const payloadDe = (sdjwt: string) => JSON.parse(Buffer.from(sdjwt.split("~")[0].split(".")[1], "base64url").toString("utf8"));
/** `display_code` from SPEC §6.3, recomputed on the agent's side, with no gateway code. */
const codigoVisible = (termsDigest: string) => String(createHash("sha256").update(termsDigest, "utf8").digest().readUInt32BE(0) % 1_000_000).padStart(6, "0");

const interno = async (path: string, body?: unknown) =>
	(
		await fetch(`${provider}/interno/${path}`, {
			method: body ? "POST" : "GET",
			headers: { "x-sovras-prueba": llave, "content-type": "application/json" },
			...(body ? { body: JSON.stringify(body) } : {}),
		})
	).json();
const despacho = async (id: string) => ((await interno(`sistema?tenant=${FERRETERIA}`)) as { id: string; despacho: string }[]).find((p) => p.id === id)?.despacho;

/** The person on their phone: opens the link, receives the code over WhatsApp, ticks scopes. */
async function vincularConWhatsapp(uri: string, telefono: string, marcar: string[], decision: "allow" | "deny" = "allow") {
	const u = new URL(uri);
	const userCode = u.searchParams.get("user_code")!;
	const base = `${u.origin}${u.pathname}`;
	const html = await (await fetch(uri)).text();
	expect(html).toContain("pide acceso a tu cuenta de");
	const post = (paso: string, form: URLSearchParams) => fetch(`${base}/${paso}`, { method: "POST", body: form, redirect: "manual" });
	await post("telefono", new URLSearchParams({ user_code: userCode, telefono }));
	const salida = (await interno(`whatsapp/salida?tenant=${FERRETERIA}`)) as { texto: string }[];
	const otp = salida.at(-1)!.texto.match(/código es (\d{6})/)![1];
	await post("codigo", new URLSearchParams({ user_code: userCode, codigo: otp }));
	const form = new URLSearchParams({ user_code: userCode, decision });
	for (const s of marcar) form.append("scope", s);
	return (await post("decision", form)).headers.get("location") ?? "";
}

describe.sequential("SOVRAS · PACT Delegated", () => {
	const sub = `ana-${crypto.randomUUID()}`;
	const signer = createPlatformSigner({ issuer, privateJwk });
	const getToken = () => signer.sign({ sub, aud: audience });
	let url = "";
	let oauth: DeviceCodeClient;
	let token: DelegationToken;
	let contextId: string | undefined;
	let jwks = "";
	let scheme: NonNullable<ReturnType<typeof delegationScheme>>;
	let extension: { required: boolean; params: Record<string, unknown> } | undefined;

	beforeAll(async () => {
		const card = await fetchAgentCard(`${provider}/a2a/${FERRETERIA}/.well-known/agent-card.json`);
		extension = card.capabilities.extensions?.find((x) => x.uri === EXT) as typeof extension;
		url = interfaceUrl(card);
		scheme = delegationScheme(card)!;
		// Ferretería Demo sells since 21-Oct: it also publishes the purchases scope. In the stress
		// sandbox, also the returns scope (pedido.devolver).
		expect(scheme.scopes.map((s) => s.id)).toEqual(["pedidos:leer", "pedidos:modificar", "compras:crear", "compras:sin_confirmar", "devoluciones:crear"]);
		const md = await fetchAuthorizationServerMetadata(scheme.metadataUrl);
		jwks = md.jwks_uri;
		oauth = new DeviceCodeClient({ scheme, clientId: issuer, getToken });
	});

	it("la Agent Card declara la extensión de prueba de resultado, no obligatoria, con su bloque", async () => {
		expect(extension).toBeDefined();
		expect(extension!.required).toBe(false);
		expect(extension!.params.custody).toBe("operator_hosted");
		expect(extension!.params.approval_channels).toEqual(["whatsapp"]);
		expect((extension!.params.capabilities as { max_assurance: string[] }[])[0].max_assurance).toContain("operator_reported_channel_approval");
		// Anchor (SPEC §9.9.1): the Agent Card's copy is identical to the RFC 8414 metadata of the company's issuer.
		const iss = new URL(String(extension!.params.company));
		const meta = (await (await fetch(`${iss.origin}/.well-known/oauth-authorization-server${iss.pathname}`)).json()) as Record<string, Record<string, unknown>>;
		for (const m of CONFIANZA) expect(extension!.params[m]).toEqual(meta.vxp_proof[m]);
		// Round 2 (M1): a PACT-only client anchors with what PACT gives it. The RFC 8414 metadata of the PACT
		// authorization server (the one at `oauth2MetadataUrl`, PACT §5.1) carries the same copy, and the company lists
		// that server, that interface and its brand domain.
		const as = (await (await fetch(scheme.metadataUrl)).json()) as Record<string, Record<string, unknown>> & { issuer: string };
		for (const m of CONFIANZA) expect(as.vxp_proof[m]).toEqual(meta.vxp_proof[m]);
		expect(meta.vxp_proof.pact).toEqual([{ interface: url, authorization_server: as.issuer }]);
		const a = new URL(as.issuer);
		expect((await fetch(`${a.origin}/.well-known/oauth-authorization-server${a.pathname}`)).status).toBe(200);
		// PACT §2.1: the Card on the brand's domain redirects to the provider's.
		const dominio = (meta.vxp_proof.domains as unknown as string[])[0];
		const enMarca = await fetch(`http://${dominio}/.well-known/agent-card.json`, { redirect: "manual" });
		expect(enMarca.status).toBe(302);
		expect(enMarca.headers.get("location")).toBe(`${provider}/a2a/${FERRETERIA}/.well-known/agent-card.json`);
		// Round 2 (m1): the endpoint the Card advertises is the PACT interface's, not Poppy's.
		expect(extension!.params.endpoint).toBe(`${url}/sovras/proof`);
	});

	it("A2A: la respuesta lista la extensión si el cliente la activa; un DataPart da CONTENT_TYPE_NOT_SUPPORTED (PACT §4.1)", async () => {
		const enviar = async (parts: unknown[], activar: boolean) =>
			fetch(`${url}/message:send`, {
				method: "POST",
				headers: { authorization: `Bearer ${await getToken()}`, "content-type": "application/json", "a2a-version": "1.0", ...(activar ? { "A2A-Extensions": EXT } : {}) },
				body: JSON.stringify({ message: { messageId: `m-${crypto.randomUUID()}`, role: "ROLE_USER", parts } }),
			});
		const activada = await enviar([{ text: "hola" }], true);
		expect(activada.status).toBe(200);
		expect(activada.headers.get("a2a-extensions")).toBe(EXT);
		const sinActivar = await enviar([{ text: "hola" }], false);
		expect(sinActivar.headers.get("a2a-extensions")).toBeNull();
		const conData = await enviar([{ text: "contrapropuesta" }, { data: { base_revision: 1 } }], true);
		expect(conData.status).toBe(400);
		expect(JSON.stringify(await conData.json())).toContain("CONTENT_TYPE_NOT_SUPPORTED");
	});

	it("sin delegación, pedir datos de la cuenta devuelve AUTH_REQUIRED con el alcance que falta", async () => {
		const r = await new DelegatedA2AClient({ url, getToken }).send("¿Dónde está mi pedido?");
		expect(r.kind).toBe("authRequired");
		if (r.kind !== "authRequired") return;
		expect(r.missingScopes).toEqual(["pedidos:leer"]);
		contextId = r.task.contextId;
	});

	it("un client_id que no es el issuer del agente se rechaza", async () => {
		const otro = new DeviceCodeClient({ scheme, clientId: "https://otro.example", getToken });
		await expect(otro.start(["pedidos:leer"])).rejects.toBeInstanceOf(A2AHttpError);
	});

	it("«Vincular con WhatsApp» emite un token sólo con los alcances que la persona dejó marcados", async () => {
		const a = await oauth.start(["pedidos:leer", "pedidos:modificar"]);
		expect((await oauth.poll(a.deviceCode)).status).toBe("pending");
		const location = await vincularConWhatsapp(a.verificationUriComplete, "+56900000101", ["pedidos:leer"]);
		expect(location).toMatch(/status=approved/);
		token = await oauth.waitForToken(a);
		expect(token.scopes).toEqual(["pedidos:leer"]);
	}, 30_000);

	it("con delegación responde sólo con los pedidos de la clienta y un recibo firmado verificable", async () => {
		const r = await new DelegatedA2AClient({ url, getToken, getDelegationToken: () => token.accessToken }).send("¿Dónde está mi pedido?", contextId ? { contextId } : {});
		expect(r.kind).toBe("message");
		if (r.kind !== "message") return;
		const texto = JSON.stringify(r.message.parts);
		expect(texto).toContain("P-1042");
		expect(texto).not.toContain("P-2001");
		const claims = await verifyReceipt(r.receipt!, { jwks, expected: { pa: issuer, brand: url } });
		expect(claims.scopesUsed).toEqual(["pedidos:leer"]);
		expect(claims.actions).toEqual([{ tool: "pedido.consultar" }]);
		contextId = r.message.contextId;
	});

	it("pedir un cambio sin el alcance de modificar sube de nivel sin cortar la conversación", async () => {
		const r = await new DelegatedA2AClient({ url, getToken, getDelegationToken: () => token.accessToken }).send("Cambia el despacho del P-1042 al 2026-10-28", { contextId: contextId! });
		expect(r.kind).toBe("authRequired");
		if (r.kind !== "authRequired") return;
		expect(r.missingScopes).toEqual(["pedidos:modificar"]);
		expect(r.task.contextId).toBe(contextId);
	});

	it("con el alcance, el cambio NO se ejecuta por el mensaje: se aprueba por WhatsApp y queda verificado", async () => {
		const a = await oauth.start(["pedidos:leer", "pedidos:modificar"]);
		await vincularConWhatsapp(a.verificationUriComplete, "+56900000101", ["pedidos:leer", "pedidos:modificar"]);
		token = await oauth.waitForToken(a);
		const client = new DelegatedA2AClient({ url, getToken, getDelegationToken: () => token.accessToken });
		const r = await client.send("Cambia el despacho del P-1042 al 2026-10-28", { contextId: contextId! });
		expect(r.kind).toBe("message");
		if (r.kind !== "message") return;
		expect(JSON.stringify(r.message.parts)).toMatch(/aprobación por WhatsApp/);
		const op = r.message.metadata?.["vxpprotocol.org/operation"] as { state: string; operation_id: string };
		expect(op.state).toBe("proposed");
		const recibo = await verifyReceipt(r.receipt!, { jwks, expected: { pa: issuer, brand: url } });
		expect(recibo.actions[0].tool).toBe("pedido.reprogramar_despacho.preparar");
		// `argsHash` = JCS digest of the request (SPEC §9.4.1), which the agent recomputes from the text it sent.
		const huellaPedido = `sha-256:${createHash("sha256").update(JSON.stringify({ binding: "pact.message", text: "Cambia el despacho del P-1042 al 2026-10-28" }), "utf8").digest("base64url")}`;
		expect(recibo.actions[0].argsHash).toBe(huellaPedido);
		expect(await despacho("P-1042")).toBe("2026-10-24");

		// The proof travels in another metadata key, next to `pact.receipt`, which is left untouched.
		const meta = r.message.metadata?.[EXT] as { operation_id: string; latest: string; bundle_url: string };
		expect(meta.operation_id).toBe(op.operation_id);
		const terminos = payloadDe(meta.latest);
		expect(terminos.kind).toBe("terms");
		expect(terminos.aud).toBe(issuer);

		// A «sí» through the agent's channel approves nothing.
		const si = await client.send("Sí, apruebo el cambio", { contextId: contextId! });
		expect(JSON.stringify(si.kind === "message" ? si.message.parts : [])).toMatch(/no confirma cambios/);
		expect(await despacho("P-1042")).toBe("2026-10-24");

		// The customer replies on the company's WhatsApp line.
		const salida = (await interno(`whatsapp/salida?tenant=${FERRETERIA}`)) as { telefono: string; texto: string }[];
		const pedido = salida.at(-1)!;
		expect(pedido.texto).toContain("P-1042");
		const codigo = pedido.texto.match(/APROBAR (\d{6})/)![1];
		// The WhatsApp code is bound to the exact revision: it derives from the digest the company signed.
		expect(codigo).toBe(codigoVisible(terminos.body.terms_digest));
		expect(pedido.texto).toContain(new URL(issuer).host);
		expect((await interno("whatsapp/entrada", { tenant: FERRETERIA, telefono: pedido.telefono, texto: "APROBAR 000000" })).aceptado).toBe(false);
		expect((await interno("whatsapp/entrada", { tenant: FERRETERIA, telefono: pedido.telefono, texto: `APROBAR ${codigo}` })).aceptado).toBe(true);
		expect(await despacho("P-1042")).toBe("2026-10-28");

		const estado = await client.send("¿Cómo va el cambio?", { contextId: contextId! });
		if (estado.kind !== "message") throw new Error("se esperaba un mensaje");
		expect((estado.message.metadata?.["vxpprotocol.org/operation"] as { state: string }).state).toBe("succeeded");
		expect(JSON.stringify(estado.message.parts)).toMatch(/Verificado en el sistema/);
		const ev = (await interno(`casos?tenant=${FERRETERIA}`)).eventos as { eventType: string; payload: Record<string, unknown> }[];
		expect(ev.some((e) => e.eventType === "approval.received_out_of_band")).toBe(true);
		expect(ev.some((e) => e.eventType === "tool.verified")).toBe(true);

		// Follow-up: the latest statement is already the outcome.
		const metaFinal = estado.message.metadata?.[EXT] as { latest: string; bundle_url: string };
		expect(payloadDe(metaFinal.latest).kind).toBe("outcome");
		expect(payloadDe(metaFinal.latest).body.state).toBe("succeeded");

		// The package, with the same PACT credentials (agent JWT + delegation).
		const conDelegacion = async (u: string, delegacion = true) =>
			fetch(u, { headers: { authorization: `Bearer ${await getToken()}`, ...(delegacion ? { "x-a2a-user-delegation": `Bearer ${token.accessToken}` } : {}) } });
		expect((await conDelegacion(metaFinal.bundle_url, false)).status).toBe(401);
		const res = await conDelegacion(metaFinal.bundle_url);
		expect(res.status).toBe(200);
		const paquete = (await res.json()) as { statements: string[] };
		const kinds = paquete.statements.map((s) => payloadDe(s).kind);
		expect(kinds).toEqual(["request", "terms", "user_approval", "execution", "read_back", "outcome"]);
		const aprobacion = payloadDe(paquete.statements[2]).body;
		expect(aprobacion.method).toBe("company_channel");
		expect(aprobacion.display_code).toBe(codigo);
		// The `request` cites the PACT receipt of the proposing turn, unmodified (SPEC §9.4.1). The
		// `execution` no longer cites anything: under PACT it happens out of band (round 2, M3).
		const pedida = payloadDe(paquete.statements[0]).body;
		expect(pedida.pact_proposal_receipt).toEqual({ grantId: recibo.grantId, argsHash: recibo.actions[0].argsHash });
		expect(pedida.request_digest).toBe(huellaPedido);
		expect(payloadDe(paquete.statements[3]).body.pact).toBeUndefined();
		// Round 2 (m1): the Card's `endpoint` serves the package with the PACT credentials.
		expect((await conDelegacion(`${extension!.params.endpoint}/operations/${op.operation_id}`)).status).toBe(200);
		expect(JSON.stringify(paquete)).not.toContain("Calle Ejemplo");
		expect(JSON.stringify(paquete)).not.toContain("+56");
		if (paquetesDir) {
			mkdirSync(paquetesDir, { recursive: true });
			writeFileSync(`${paquetesDir}/pact-${op.operation_id}.json`, JSON.stringify(paquete));
			writeFileSync(`${paquetesDir}/pact-${op.operation_id}.op.json`, JSON.stringify((estado.message.metadata?.["vxpprotocol.org/operation"])));
			writeFileSync(`${paquetesDir}/pact-${op.operation_id}.recibo.json`, JSON.stringify(r.receipt));
		}
	}, 30_000);

	it("contrapropuesta bajo PACT por el endpoint de la extensión: revisión nueva firmada y nueva aprobación por WhatsApp", async () => {
		const client = new DelegatedA2AClient({ url, getToken, getDelegationToken: () => token.accessToken });
		const r = await client.send("Cambia el despacho del P-1043 al 2026-10-29", { contextId: contextId! });
		if (r.kind !== "message") throw new Error("se esperaba un mensaje");
		const op = r.message.metadata?.["vxpprotocol.org/operation"] as { operation_id: string; revision: number };
		expect(op.revision).toBe(1);
		const salida1 = (await interno(`whatsapp/salida?tenant=${FERRETERIA}`)) as { telefono: string; texto: string }[];
		const codigo1 = salida1.at(-1)!.texto.match(/APROBAR (\d{6})/)![1];
		const meta = r.message.metadata?.[EXT] as { bundle_url: string };
		const post = async (body: unknown, delegacion = true) =>
			fetch(`${meta.bundle_url}/counter`, {
				method: "POST",
				headers: { authorization: `Bearer ${await getToken()}`, "content-type": "application/json", ...(delegacion ? { "x-a2a-user-delegation": `Bearer ${token.accessToken}` } : {}) },
				body: JSON.stringify(body),
			});
		expect((await post({ base_revision: 1, proposed_terms: { despacho_nuevo: "2026-10-30" } }, false)).status).toBe(401);
		expect((await post({ base_revision: 9, proposed_terms: { despacho_nuevo: "2026-10-30" } })).status).toBe(409);
		const res = await post({ base_revision: 1, proposed_terms: { despacho_nuevo: "2026-10-30" }, note: "Mejor el jueves." });
		expect(res.status).toBe(200);
		const cuerpo = (await res.json()) as { operation: { revision: number; terms: { despacho_nuevo: string } } };
		expect(cuerpo.operation.revision).toBe(2);
		expect(cuerpo.operation.terms.despacho_nuevo).toBe("2026-10-30");
		const salida2 = (await interno(`whatsapp/salida?tenant=${FERRETERIA}`)) as { telefono: string; texto: string }[];
		const pedido = salida2.at(-1)!;
		const codigo2 = pedido.texto.match(/APROBAR (\d{6})/)![1];
		expect(codigo2).not.toBe(codigo1);
		// The code for revision 1 no longer approves anything; the one for revision 2 does.
		expect((await interno("whatsapp/entrada", { tenant: FERRETERIA, telefono: pedido.telefono, texto: `APROBAR ${codigo1}` })).aceptado).toBe(false);
		expect(await despacho("P-1043")).toBe("2026-10-27");
		expect((await interno("whatsapp/entrada", { tenant: FERRETERIA, telefono: pedido.telefono, texto: `APROBAR ${codigo2}` })).aceptado).toBe(true);
		expect(await despacho("P-1043")).toBe("2026-10-30");
		const paquete = (await (
			await fetch(meta.bundle_url, { headers: { authorization: `Bearer ${await getToken()}`, "x-a2a-user-delegation": `Bearer ${token.accessToken}` } })
		).json()) as { statements: string[] };
		const kinds = paquete.statements.map((s) => payloadDe(s).kind);
		expect(kinds).toEqual(["request", "terms", "counter", "terms", "user_approval", "execution", "read_back", "outcome"]);
		expect(payloadDe(paquete.statements[3]).body.revision).toBe(2);
		expect(payloadDe(paquete.statements[4]).body.display_code).toBe(codigo2);
		if (paquetesDir) {
			writeFileSync(`${paquetesDir}/pact-${op.operation_id}.json`, JSON.stringify(paquete));
			writeFileSync(`${paquetesDir}/pact-${op.operation_id}.recibo.json`, JSON.stringify(r.receipt));
		}
	}, 30_000);

	it("rota el refresh token; reusar uno viejo revoca la delegación entera", async () => {
		const nuevo = await oauth.refresh(token.refreshToken!);
		expect(nuevo.scopes.sort()).toEqual(token.scopes.sort());
		await expect(oauth.refresh(token.refreshToken!)).rejects.toBeInstanceOf(OAuthError);
		await expect(oauth.refresh(nuevo.refreshToken!)).rejects.toBeInstanceOf(OAuthError);
		await expect(new DelegatedA2AClient({ url, getToken, getDelegationToken: () => nuevo.accessToken }).send("¿Dónde está mi pedido?")).rejects.toBeInstanceOf(DelegationTokenRejectedError);
	});

	it("rechazar el consentimiento termina en access_denied", async () => {
		const a = await oauth.start(["pedidos:leer"]);
		const location = await vincularConWhatsapp(a.verificationUriComplete, "+56900000101", ["pedidos:leer"], "deny");
		expect(location).toMatch(/status=denied/);
		await expect(oauth.poll(a.deviceCode)).rejects.toMatchObject({ error: "access_denied" });
	});

	it("una delegación no la usa otro usuario del mismo agente, ni sirve en otra empresa", async () => {
		const a = await oauth.start(["pedidos:leer"]);
		await vincularConWhatsapp(a.verificationUriComplete, "+56900000101", ["pedidos:leer"]);
		const t = await oauth.waitForToken(a);
		const otroUsuario = () => signer.sign({ sub: `otro-${crypto.randomUUID()}`, aud: audience });
		await expect(new DelegatedA2AClient({ url, getToken: otroUsuario, getDelegationToken: () => t.accessToken }).send("¿Dónde está mi pedido?")).rejects.toBeInstanceOf(DelegationTokenRejectedError);
		const libreria = `${provider}/a2a/t_libreria_demo`;
		await expect(new DelegatedA2AClient({ url: libreria, getToken, getDelegationToken: () => t.accessToken }).send("¿Dónde está mi pedido?")).rejects.toBeInstanceOf(DelegationTokenRejectedError);
	}, 30_000);
});

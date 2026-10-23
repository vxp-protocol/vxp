# VXP personal agent

The agent side of VXP: what a developer needs so that a person's agent can do tasks with companies
that implement VXP, act only with the person's permission, check what happened, and keep the
relationship the company continues afterwards. It works without SOVRAS and without a per-company
integration: everything comes from the company's own `/.well-known/vxp.json`, its issuer metadata
(RFC 8414) and the native endpoints (spec §8).

| Part | Where | What it is |
|---|---|---|
| Library | `src/` | Discovery, identity (CIMD + JWKS), sessions with `private_key_jwt` + DPoP, requests with idempotency, Device Authorization with RAR, proposals, counter, accept under the person's rules, cancel, proofs verified locally, VXP Relationship (agreement, signed inbox, replies). All state persists in a directory. |
| CLI | `bin/vxp-agent.ts` | One command per step; each command is its own process. |
| MCP server | `src/mcp.ts` (`vxp-agent mcp`) | Stdio, JSON-RPC 2.0, written by hand. Dual-era: MCP 2026-07-28 (per-request `_meta`, `server/discover`) and the `initialize` handshake of 2025-11-25 / 2025-06-18 / 2025-03-26 / 2024-11-05. |
| Example agent | `examples/hotel-santiago.ts` | Deterministic, no LLM: the hotel task end to end. |
| Tests | `test/` | `node --test`, against the reference company gateway in separate processes: native only, and with its Poppy or PACT adapter. |
| Optional adapters | `src/adapters.ts`, `src/adapters/` | Poppy draft 0.2 and PACT 1.0 on the agent side, for companies that offer them. The native profile does not import them. |

Status: **experimental**, like the native profile itself. Tested only against the reference
implementation in this repository (`reference/`), whose companies, customers, payments, PMS and
messaging line are fictitious and simulated.

## Install

Node 22.18 or newer (TypeScript runs natively; type stripping). No npm dependencies: only `node:*`.
The proof verifier is imported as is from `../verifier/vxp-verify.js`, so keep the repository layout.

```sh
git clone <this repository> vxp
cd vxp/agent
node bin/vxp-agent.ts help
```

Python 3 with `cryptography` is needed only by the tests (they also check every proof with the
Python reference verifier).

## Quickstart: the hotel task against the reference gateway

Two terminals. In the first, the company side (the reference gateway, native profile only, with proof
keys kept in a directory **outside** the repository, and the simulated company channel printed on the
console so you can read the one-time code that would reach your phone):

```sh
# bash
cd vxp/reference
PORT=3810 VXP_ADAPTERS=none VXP_SHOW_CHANNEL=1 VXP_KEYS_DIR=/tmp/vxp-ref-keys \
  ORIGENES_LOCALES=http://localhost:3811 node src/main.ts
```
```powershell
# PowerShell
cd vxp\reference
$env:PORT="3810"; $env:VXP_ADAPTERS="none"; $env:VXP_SHOW_CHANNEL="1"; $env:VXP_KEYS_DIR="$env:TEMP\vxp-ref-keys"; $env:ORIGENES_LOCALES="http://localhost:3811"; node src/main.ts
```

`ORIGENES_LOCALES` lets the gateway fetch the agent's CIMD over plain http on localhost; a real
deployment uses https. The gateway serves Ferretería Demo at `localhost:3810` and Hotel Demo at
`127.0.0.1:3810` (another host on the same process).

In the second terminal, the agent:

```sh
cd vxp/agent
node examples/hotel-santiago.ts --state .vxp-example --origin http://localhost:3811 --port 3811 \
  --allow-http http://localhost:3810,http://127.0.0.1:3810,http://localhost:3811 \
  localhost:3810 127.0.0.1:3810 localhost:3899
```

The three positional arguments are the candidate domains (VXP has no registry, see Discovery). The
example then:

1. discovers which candidates implement VXP and which one offers hotel bookings;
2. records the person's rules: book only up to $250.000, and answer «mantener» if the hotel asks
   about a late arrival;
3. reads availability, rates and services (`hotel.disponibilidad`, a public read);
4. picks the best room with breakfast that the cap allows, finds the hotel's packages for it, and asks
   for the stay; the hotel answers with its public quote;
5. prints a URL on the **hotel's own page** and waits. Open it, type `+56 9 0000 0101` (test
   customer A), type the code the first terminal prints as `[simulated company channel …]`, read
   the consent screen and press «Permitir». The consent covers the booking up to $250.000 and the
   relationship;
6. sends the same request again (same Idempotency-Key) and receives signed terms;
7. negotiates within the hotel's policy: a discretionary discount is declined (and the agent says so); the
   «Escapada» package (10 %, breakfast and parking) is accepted as a new revision with a lower total;
8. accepts the negotiated revision within the person's cap (`standing_permission`). If a revision were
   above the cap the person approved at the hotel, it would print the agent's approval page and the
   person's approval code instead;
9. downloads the proof and verifies it locally, anchored by the issuer;
10. waits for the hotel's late-arrival question in its inbox and answers it with the person's
    standing answer. The hotel's rule asks on the arrival day after 20:00 (Chile). To see it now,
    add `--hotel-console http://localhost:3810 --hotel-console-key <the "llave interna" the first
    terminal printed>`: that runs the hotel's rule with the reference's simulated clock through its
    test-only `/interno/` console, which is **not part of VXP**.

A recorded run is in `runs/`.

## Library

```ts
import { VxpAgent } from "./src/agent.ts";

const agent = VxpAgent.open({ stateDir: ".vxp-agent", publicOrigin: "https://agent.example.org" });
// Serve agent.clientMetadata() at agent.clientId, agent.jwks() at /jwks.json and the inbox:
//   import { startAgentServer } from "./src/server.ts"; await startAgentServer(agent, { port: 3811 });

const [r] = await agent.discover(["hotel.example"]);
const hotel = agent.company("hotel.example");
const av = await agent.read(hotel.issuer, "hotel.disponibilidad", { check_in, check_out, adults: 2 });
const q = await agent.createRequest(hotel.issuer, "reserva.crear", {}, { room_type, check_in, check_out, adults: 2, services: [{ code: "DESAYUNO" }] });
if (q.body.state === "authorization_required") {
  const a = await agent.authorize(hotel.issuer, { forRequest: q.record!.request_id, capClp: 250_000, relationship: { actions: ["alerta.mantener_o_liberar"] } });
  // show a.verification_uri_complete and a.user_code to the person, then:
  await agent.pollAuthorization(hotel.issuer, 60);
  await agent.resubmit(q.record!.request_id);
}
agent.setMandate(hotel.issuer, "reserva.crear", 250_000);         // the person's rule, never the model's
const acc = await agent.accept(q.record!.request_id);               // accepted | needs_user_approval | blocked_by_mandate | rejected_by_company
const { verdict } = await agent.proof(q.record!.request_id);        // verified locally, anchored by the issuer
```

`accept` sends `approved_by: "standing_permission"` only when a cap the person set covers the total
**and** the company marks the revision `user_approval_required: false` (it does when the total is within
the cap the person approved on its page). Otherwise it creates an approval for the person, bound to
the proposal id (which carries the revision), its summary and its terms: a new revision needs a new
approval. Above the person's cap it does not call the company at all.

State directory (`stateDir`): `identity.json` (private signing and DPoP keys, the secret behind the
per-company User IDs), `sessions.json` (access tokens), `authorizations.json` (pending device codes),
`requests.json` (each request with its Idempotency-Key and last view), `relationships.json`,
`inbox.json` (messages, seen `jti`, rejections), `mandates.json`, `approvals.json`, and `proofs/`
(packages, the public material used to verify them, and the verdicts). It holds secrets: keep it out
of repositories and logs (`agent/.gitignore` excludes the default names).

## CLI

Every command prints JSON. Global options: `--state DIR`, `--origin URL` (first run), `--allow-http
ORIGINS` (local tests only), or the variables `VXP_AGENT_STATE`, `VXP_AGENT_ORIGIN`, `VXP_AGENT_ALLOW_HTTP`.

```sh
A="node bin/vxp-agent.ts --state .vxp-agent --origin http://localhost:3811 --allow-http http://localhost:3810,http://127.0.0.1:3810,http://localhost:3811"
$A serve --port 3811 &                         # CIMD, JWKS, inbox, approval pages
$A discover localhost:3810 127.0.0.1:3810 --offers reserva.crear
$A read 127.0.0.1:3810 hotel.disponibilidad --params '{"check_in":"2026-11-20","check_out":"2026-11-22","adults":2}'
$A request 127.0.0.1:3810 reserva.crear --params '{"room_type":"DBL-EST","check_in":"2026-11-20","check_out":"2026-11-22","adults":2,"services":[{"code":"DESAYUNO"}]}'
$A authorize 127.0.0.1:3810 --request <request_id> --cap-clp 250000 --relationship alerta.mantener_o_liberar
$A approve-url 127.0.0.1:3810                  # the URL and code for the person, again
$A wait-authorization 127.0.0.1:3810 --timeout 60
$A resubmit <request_id>
$A counter <request_id> --terms '{"package":"ESCAPADA"}'
$A mandate set 127.0.0.1:3810 reserva.crear 250000      # the person's cap
$A accept <request_id>                                    # the person: approvals (codes) / approve <id> --yes
$A proof <request_id>
$A verify <request_id>                                    # offline, with the saved material
$A inbox
$A mandate reply 127.0.0.1:3810 alerta.mantener_o_liberar mantener
$A reply <alert_id> mantener
$A relationships | $A revoke-relationship <id>
```

`node bin/vxp-agent.ts help` lists every command. The agent's server must be running (`serve`, or `mcp --port`) whenever a company calls back: it fetches the CIMD and JWKS on every token request. Against the reference on localhost, the agent's http origin must also be listed in the gateway's `ORIGENES_LOCALES`.

## MCP

`vxp-agent mcp` runs the MCP server on stdio. With `--port N` the same process serves the CIMD, JWKS,
inbox and approval pages. Tools: `vxp_discover`, `vxp_list_companies`, `vxp_read`, `vxp_request`,
`vxp_resubmit`, `vxp_authorize`, `vxp_check_authorization`, `vxp_status`, `vxp_events`, `vxp_counter`,
`vxp_accept`, `vxp_cancel`, `vxp_proof`, `vxp_inbox`, `vxp_reply`, `vxp_relationships`,
`vxp_revoke_relationship`, `vxp_rules`.

Claude Code:

```sh
claude mcp add vxp-agent -- node /abs/path/vxp/agent/bin/vxp-agent.ts mcp --port 3811 \
  --state /abs/path/private/.vxp-agent --origin https://agent.example.org
```

Claude Desktop and other hosts: `mcp/claude_desktop_config.example.json` (production origin) and
`mcp/local-reference.example.json` (against the reference gateway on localhost).

Actions with effect (`vxp_accept`, `vxp_reply`) never run on the model's decision alone. They run
within a rule the person set with the CLI (a cap, a standing answer), or after the person confirms the
exact terms:
- through MCP elicitation when the host declares it (legacy: an `elicitation/create` request; 2026-07-28:
  an `input_required` result whose `requestState` is an HMAC bound to that approval);
- on the agent's approval page, typing an 8-digit code that is printed only in the person's own terminal
  (`vxp-agent approvals`, or the console of the agent's server when the page is opened). Five wrong codes
  deny the approval;
- or with `vxp-agent approve <id>` in the person's terminal.

What the model receives is the approval id, the summary, the amount and a URL **without** any secret.
No tool sets rules or decides approvals, and no tool result carries an approval secret or code
(`test/mcp.test.ts` checks that, with only that, the approval cannot be decided).

## Optional adapters: Poppy and PACT

A company MAY also offer Poppy draft 0.2 or PACT 1.0 through its own adapters (spec §8 «Adapters»). The
agent speaks them as written, with the same identity, state directory and person's rules as the native
profile. Both are conversational: the company's own agent turns the agent's text into a proposal, so the
adapters take text (`say`) where the native profile takes `{operation, target, parameters}`. They are a
library only: the CLI and the MCP server use the native profile.

```ts
import { PoppyAdapter } from "./src/adapters/poppy.ts";
import { PactAdapter } from "./src/adapters/pact.ts";

const poppy = new PoppyAdapter(agent);                    // declares Poppy Operations in the agent's client metadata
const c = await poppy.detect("hotel.example");            // poppy.json + issuer metadata (poppy_domains)
await poppy.say(c.issuer, "Quiero reservar del 2026-11-23 al 2026-11-25 una doble con vista para 2 adultos con desayuno", { operation: "reserva.crear" });
const a = await poppy.authorize(c.issuer, ["reservas:crear"]);   // Device Sign-In: show a.verification_uri_complete to the person
await poppy.pollAuthorization(c.issuer, 60);
const t = await poppy.say(c.issuer, "Resérvala", { operation: "reserva.crear" });
await poppy.accept(c.issuer, t.operation.operation_id);   // confirm only within the person's rules
await poppy.proof(c.issuer, t.operation.operation_id);    // anchored by the Poppy domain

const pact = new PactAdapter(agent, { audience: "<the audience the Provider assigned>" });
const p = await pact.detect("hotel.example");             // Agent Card on the brand domain (or its redirect)
// authorize / pollAuthorization / say as above; accept() returns «awaiting_company_channel»:
// under PACT the person approves each write on the company's own channel, never the agent.
await pact.proof(p.interface, operationId);               // anchored by the PACT authorization server, receipt cross-checked
```

| | Poppy draft 0.2 | PACT 1.0 over A2A 1.0.1 |
|---|---|---|
| Discovery | `/.well-known/poppy.json`; the issuer's metadata must list the domain in `poppy_domains` | Agent Card on the brand domain, one redirect to the Provider allowed; its proof block must list the domain |
| Agent identity | CIMD + `private_key_jwt`, the session from an RFC 7523 assertion, DPoP | Personal-agent JWT: `iss` = the agent's platform issuer (its public origin), `aud` = the audience the Provider assigned |
| Authorization | Device Sign-In with scopes, bound to the session; account token refreshed | Device code of the Card's `userDelegation` scheme; refresh token rotated |
| Asking | Conversation messages; the proposal arrives in the Operations extension | `message:send` with text parts; the operation arrives in `vxpprotocol.org/operation` metadata |
| Accepting | `confirm` of the exact revision, only within the person's rules (`agent_asserted`) | The person approves on the company's channel with a code bound to the revision (`company_channel`); the agent cannot |
| Proof | The operation's `vxpprotocol.org/proof` member; anchor `{domain}` | Message metadata under `https://vxpprotocol.org/ext/proof/v0.1`, next to `pact.receipt`; anchor `{pact_issuer}`, receipt cross-checked |

PACT onboarding happens outside the protocol: the Provider registers the agent's platform issuer and gives
it an audience. Against the reference, its test platform is `http://localhost:<PORT + 2>` and the audience
`<origin>/a2a`, so a PACT agent there runs with that public origin.

## Discovery: where the candidate domains come from

VXP has no global registry. The agent starts from domains that come from outside VXP: the person
names the company; a search engine, map or directory suggests it; the company's website, receipt or
booking email links to it; or the agent remembers it from an earlier task. For each domain it reads
`https://<domain>/.well-known/vxp.json` and the issuer's RFC 8414 metadata, and accepts the company only
if `organization.domain` is the host that served the document, that host is listed in
`vxp_proof.domains`, and the metadata's `issuer` is identical to the one in vxp.json. vxp.json carries no
location, category or catalogue beyond capability ids: criteria such as «in Santiago» belong to the
agent.

## What a developer outside SOVRAS needs

A domain they control over https for the agent (the company fetches `client_id` = `https://<agent>/agent.json`
and its JWKS, and posts to the inbox there), this directory, and a list of candidate domains. Nothing
else: no account with any operator, no private server, no per-company setup. The companies decide
whether to accept the agent (the reference accepts any agent: `agentesPersonales.modo: "abierto"`).

## Correspondence with the spec

What the agent itself does for each rule. Rules that bind only the company are marked «company».

| Rule | Agent side |
|---|---|
| §8 Discovery | Checks `organization.domain`, `vxp_proof.domains` and issuer identity before using a company (`discovery.ts`). |
| §8 Authorization | `resource` = endpoint (RFC 8707), `private_key_jwt` with its CIMD, DPoP ES256 on every call, the User ID as an RFC 7523 assertion, `authorization_details` per request; the verification URL must be on the issuer's origin. |
| §8 Idempotency | The key is generated once, persisted, and the same body re-sent after authorizing (`resubmit`). |
| §8 Commitment, limits, cancellation | Shown as received; `counter`, `cancel`; `revisions_left` comes in each proposal. |
| I1 | The native profile stands alone; the optional Poppy and PACT adapters speak those contracts as written and the native modules do not import them (tested). |
| I2, O6 | One `accept` per revision; repeating it does not execute again (tested). |
| ID1, O1 | The agent never sees the person's channel or code: the account is linked on the company's page. |
| ID3 | Stable per-company pseudonymous User ID and a persistent DPoP key, so the owner tuple survives restarts. |
| E1, E2 | Internal state and the Poppy/A2A projections are kept as received. |
| O2 | Asks only for what the request is missing, with the person's cap in `limits.max_total_clp`. |
| O3, O5, O7 | Company. The agent reads the result's `effects` and the proof's read-back level. |
| O4 | Approvals are bound to the exact revision; a new revision needs a new approval. |
| P1, P8 | The proof is verified with the operation the agent saw (terms digest, salt, state, result). |
| P2 | The verdict's `approval` is reported as is: `agent_asserted` in the native profile and under Poppy, `company_channel` under PACT. |
| P3–P6 | Company; the verifier reports them. |
| P7, §10 | Native: anchored by the issuer learned from vxp.json. Poppy: by the domain (`{domain}`). PACT: by the PACT authorization server (`{pact_issuer}`), with the PACT receipt cross-checked. Material fetched from those anchors only, saved with its date for offline verification; levels reported as the verifier derives them. |
| R1 | Relationship actions are checked against `vxp_relationship.company_initiated_actions` before asking. |
| R2 | `inbox_uri` in the CIMD, on the client_id's origin. |
| R3 | Company (the consent screen); the person can untick the relationship. |
| R4 | The agreement JWS is verified (`vxp-relationship+jwt`, iss, aud, sub, rel) with the relationship key. |
| R5 | Company messages are checked only with `vxp_relationship.jwks_uri` from the issuer metadata, on the issuer's origin. |
| R6, R9 | Company; the agent reports the company's errors (`relationship_revoked`, `relationship_expired`, …). |
| R7 | Signature, `typ`, `iss` known, `aud` = client_id, `sub` = this person's User ID, relationship held and usable, action in it, `exp`, and **`jti` not seen before** (persisted). The spec lists the agent's jti check as pending; this agent implements it. |
| R8 | A change the company proposes becomes a request the agent tracks and accepts only with the person. |
| R10, R11 | `revoke-relationship` (DELETE) and `relationship` (GET). |
| R12–R16 | Not implemented (relationship over a Poppy conversation): the Poppy adapter does not ask for, receive or answer relationships. |
| R17 | `reply` posts only one of the options, only to a `reply_url` under the endpoint, and verifies the `vxp-reply-receipt+jwt`. |

## Tests

```sh
cd vxp/agent && node --test test/*.test.ts
```

Each file starts the reference gateway in its own process (proof keys in a temporary directory) on
ports 3830–3893: `VXP_ADAPTERS=none` except `poppy.test.ts` (`poppy`) and `pact.test.ts` (`pact`).

- `scenario.test.ts`: the whole hotel task; the booking is checked in the hotel's system; the proof is
  verified by `vxp-verify.js` and by the Python reference verifier; negotiation through the «Escapada»
  package, executed on the negotiated revision.
- `persistence.test.ts`: every step in a new CLI process, the agent's server restarted mid-task.
- `negatives.test.ts`: cap exceeded (the agent does not ask for more, the company does not propose above
  the grant, the agent does not accept above the person's cap); the person denies; relationship revoked
  by the person, by the agent, or only locally; expired; forged signature, edited payload and replayed
  `jti`; altered proof, altered operation and foreign keys give `valid: false`.
- `poppy.test.ts`: the hotel task over the Poppy adapter (quote, discount refused, «Escapada» package,
  Device Sign-In, Operations confirm within the person's rules, booking in the PMS, proof anchored by the
  domain and verified by both verifiers).
- `pact.test.ts`: the hotel task over the PACT adapter (Agent Card through the brand redirect, delegated
  authority, package, the agent cannot confirm, the person approves on the company's channel, proof anchored
  by the PACT authorization server with the receipt `verified`, by both verifiers).
- `native-only.test.ts`: the native modules do not import the adapters; against `VXP_ADAPTERS=none` a
  native-only agent completes the task without one request to poppy.json, the Agent Card, A2A or Poppy routes;
  the adapters find nothing on that gateway.
- `untrusted-ids.test.ts`: identifiers from a company cannot choose where the agent writes or take over
  another company's request.
- `mcp.test.ts`: both MCP eras, version errors, the task through tools, confirmation by elicitation
  (declined, then accepted), MRTR `input_required` and a forged `requestState`, and self-approval with
  only what the model received (no code, the old `?k=` secret, guessed codes) refused and locked.

How the person is automated without tricks: `test/helpers/person.ts` does what a person with a
browser does on the company's page (follows its forms, reads its consent screen), and reads the
one-time code where the reference prints the simulated phone (`VXP_SHOW_CHANNEL=1`). The reference's
test-only `/interno/` console is used only as the company's console (to start a company request, revoke
as the person, run the late-arrival rule with a simulated clock, read the PMS); it is not part of VXP.

## Limits, honestly

- Only the reference gateway has been used; no company outside this repository has been tested, and
  this agent was written by the same team as the reference. Independence by a third-party developer
  is not demonstrated by this code; this README is what such a developer would start from.
- The Poppy and PACT adapters are a library; the CLI and MCP server speak the native profile only.
  VXP Relationship is native only: not over a Poppy conversation (R12–R16) nor over PACT (pending in the spec).
- The adapters were tested only against the reference's own Poppy and PACT faces, not against another
  Poppy or PACT implementation, and with the hotel's phrasing in Spanish: what text a company's agent
  understands is up to that company.
- Under Poppy the proof's poppy.json is named by its https URL, as the verifier asks; in local tests with an
  allowed http origin, the same document is fetched over that origin.
- The agent must be reachable by the company over https at its public origin (CIMD, JWKS, inbox).
  An agent on a laptop behind NAT needs a tunnel or a small hosted endpoint.
- The native profile has no refresh token: a delegated token lasts what the company says (1 h in the
  reference); later requests need a new consent. Replies inside a relationship work with a plain session.
- Approval is `agent_asserted`: the company learns only that the agent says the person approved.
- The company does not retry deliveries; if the inbox is down, the message is lost (the company records
  the failure).
- One person per state directory. Concurrent processes share it by re-reading before each write; there
  is no lock.
- MCP elicitation depends on the host. If the model also has a shell, it could run the CLI itself: the
  host's own permission prompts are then the guard for `vxp-agent approve` and `mandate`.
- The agent's server listens on every interface (localhost may resolve to IPv4 or IPv6); deciding on an
  approval page needs the person's code.
- Negotiation is what each company's policy allows: the reference hotel changes room, dates, services or
  package in a new revision (the «Escapada» package, the long-stay rate), matches lower agency rates it
  publishes, and refuses discretionary discounts.
- vxp.json publishes capability ids, not parameter schemas: the example's parameter names
  (`room_type`, `check_in`, `services[].code`) come from the reference's documentation and its
  availability read.

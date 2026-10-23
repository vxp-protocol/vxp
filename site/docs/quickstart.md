# Quickstart

> From a clean clone to a company and a personal agent in separate processes, an operation with its proof verified, a company-initiated request answered, and a conformance report, with no Poppy, no PACT and no SOVRAS service.

## Requirements

- Node.js 22.18 or newer. Nothing to install with npm: the repository has no dependencies.
- Python 3 with `cryptography`, for the Python verifier: `python3 -m pip install cryptography` (inside a virtual
  environment, `python3 -m venv .venv && . .venv/bin/activate`, where the system's Python refuses packages).
- Git.

```sh title="Clone"
git clone https://github.com/vxp-protocol/vxp.git
cd vxp
```

The commands below are for bash: Linux, macOS, WSL or Git Bash on Windows. Where `python3` does not exist, as in
Git Bash, use `python`.

## 1. Start a company

The reference implementation serves fictitious test companies and tells them apart by host name: Ferretería Demo
at `localhost:3100` and Hotel Demo at `127.0.0.1:3100`. They are Chilean, so their pages and messages are in
Spanish. Start it as a native-only gateway, with persistent keys outside the repository, and
with the company's channel printed to the console (the channel is simulated: it stands for the SMS or
WhatsApp line through which a real company would reach its customer).

```sh title="Terminal 1 · the company"
cd reference
VXP_ADAPTERS=none VXP_KEYS_DIR=/tmp/vxp-keys VXP_SHOW_CHANNEL=1 \
  ORIGENES_LOCALES=http://localhost:3811 node src/main.ts
```

`ORIGENES_LOCALES` lets the gateway fetch your agent's documents over plain `http` on localhost. In production
both sides use `https`. Check it from another terminal:

```sh title="Discovery"
curl http://127.0.0.1:3100/.well-known/vxp.json
```

You get the hotel's `vxp.json`: its issuer, its `/v1` endpoint and its capabilities, with
`"status": "experimental"`.

## 2. Run a personal agent

The agent is another process with its own identity, its own keys and its own HTTP server for the documents
companies fetch and for the inbox. The example does the task of the [agent guide](https://vxpprotocol.org/docs/guides/agent/): a hotel in
Santiago, two nights with breakfast, up to CLP 250,000 (printed as `$250.000`).

Terminal 1 prints an internal key for the reference's test console (`llave interna: …`). Pass it to the agent,
so that step 4 can run at once:

```sh title="Terminal 2 · the agent"
cd agent
KEY=<the value printed after "llave interna:" in Terminal 1>
node examples/hotel-santiago.ts --state /tmp/vxp-agent --origin http://localhost:3811 --port 3811 \
  --allow-http http://localhost:3100,http://127.0.0.1:3100,http://localhost:3811 \
  --hotel-console http://localhost:3100 --hotel-console-key "$KEY" \
  localhost:3100 127.0.0.1:3100 localhost:3999
```

The last three arguments are candidate domains: VXP has no registry, so the agent starts from domains the
person names or finds. The agent then:

1. discovers which candidates speak VXP and which one offers bookings (the third one does not answer);
2. records the person's rules: book up to CLP 250,000, and answer `mantener` (keep) to a late-arrival question;
3. reads availability, rates and services, a public read with no consent;
4. asks for the stay. The hotel answers `authorization_required` with exactly what to ask the person for.

The agent prints a link on the hotel's own page and waits. **You are the person now:** open the link, enter the
test phone `+56 9 0000 0101`, enter the code that Terminal 1 prints as `[simulated company channel …]`, read
the consent and press “Permitir” (allow). The consent covers the booking up to CLP 250,000 and a relationship so the hotel can ask
about a late arrival.

The agent continues on its own:

5. sends the same request again with the same `Idempotency-Key` and receives signed terms;
6. negotiates within the hotel's policy: a discretionary discount is refused, and the “Escapada” package lowers
   the total in a new revision;
7. accepts that exact revision within your cap (`approved_by: "standing_permission"`). The hotel executes it
   once and reads its system back;
8. downloads the proof and verifies it locally, anchored by the hotel's issuer.

## 3. Verify the proof yourself

The agent saved what it verified in its state directory. Check the same package with the Python verifier,
which shares no code with the agent's JavaScript verifier (its modes and flags are in Spanish: `paquete` is the
package, `operacion` the operation):

```sh title="From the repository root"
REQ=$(ls /tmp/vxp-agent/proofs/ | grep -m1 '.package.json' | sed 's/.package.json//')
python3 verifier/verificar_paquete.py material \
  --material /tmp/vxp-agent/proofs/$REQ.material.json \
  --paquete /tmp/vxp-agent/proofs/$REQ.package.json \
  --operacion /tmp/vxp-agent/proofs/$REQ.operation.json
```

Expected: `"valid": true`, `"final_state": "succeeded"` and `"key_source": "issuer_metadata_saved"`, since the
keys come from the material the agent saved. The terms travel signed inside each statement, so
the way to see a mismatch is to change what the agent claims it was shown. Lower the total in the operation
file and run the verifier again:

```sh title="Claim different terms"
sed 's/"total": *230400/"total": 200000/' /tmp/vxp-agent/proofs/$REQ.operation.json > /tmp/claimed.json
python3 verifier/verificar_paquete.py material \
  --material /tmp/vxp-agent/proofs/$REQ.material.json \
  --paquete /tmp/vxp-agent/proofs/$REQ.package.json \
  --operacion /tmp/claimed.json
```

Expected: `{"valid": false, "error": "operation_terms_mismatch", "seq": null}`. To alter the signed statements themselves
and see which link breaks, use the [verifier](https://vxpprotocol.org/verify/) in a browser. [Verifier guide](https://vxpprotocol.org/docs/guides/verifier/).

## 4. The company starts the next request

The hotel's rule asks the guest's agent, inside the relationship, whether to hold or release a booking when the
guest has not arrived after 20:00 on the arrival day ([R17](https://vxpprotocol.org/spec/#r17)). The gateway checks every minute; the
`--hotel-console` options of step 2 run the rule at once, with the reference's clock moved to that evening.
Without them, the agent waits for the real evening.

The hotel signs a closed question and posts it to the agent's inbox. The agent verifies the signature with the
key anchored to the issuer, rejects a repeated `jti`, answers `mantener` with the person's standing answer,
and verifies the signed receipt. The `/interno/` console is the reference's test-only console, standing in for
the hotel's own clock; it is not part of VXP.

## 5. Run the conformance validator

```sh title="From the repository root"
node conformance/reference/run.ts --report conformance-report.json
```

It starts its own native-only reference company, acts as a personal agent against it, and reports every check
with the rule it tests. Expected: `{"pass":51,"fail":0,"optional":0,"manual":3,"skipped":0}`. The report is in
`conformance-report.md`. To check your own company, see [Conformance](https://vxpprotocol.org/docs/conformance/).

## Where next

- [Guide for companies](https://vxpprotocol.org/docs/guides/company/): make your own systems speak VXP.
- [Guide for personal agents](https://vxpprotocol.org/docs/guides/agent/): build an agent that speaks VXP.
- [Examples and messages](https://vxpprotocol.org/docs/examples/): every message of one operation.

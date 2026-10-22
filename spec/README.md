# VXP specification

The normative text of VXP draft 0.1 is [`spec.tpl.html`](spec.tpl.html). It is built into
[`../site/spec/index.html`](../site/spec/index.html), published at https://vxpprotocol.org/spec/:

```sh
python spec/build.py    # from the repository root
```

The build only fills each `<!--J:name-->` marker with an object captured from the reference
implementation (`site/assets/recorrido-data.js`), so the examples in the specification are objects the
implementation actually produced. Edit the template, never the built page.

What it defines: the two public components, VXP Proof (§6) and VXP Relationship (§7); the operation
requirements O1 to O7 (§9); the experimental native profile and the optional adapters for Poppy
draft 0.2 and PACT 1.0 (§8); and how anyone verifies a proof (§10).

What the verifiers check, control by control, is in [`../verifier/CHECKS.md`](../verifier/CHECKS.md).
The conformance vectors are in [`../vectors/`](../vectors/).

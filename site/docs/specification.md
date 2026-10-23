# Specification and versions

> Where the normative text lives, how its rules are identified, and how versions work.

## The normative text

The [specification](https://vxpprotocol.org/spec/) is the only normative text of VXP. Its source is `spec/spec.tpl.html` in the
repository. Current version: **draft 0.1**, revised on 22 October 2026.

| Section | What it defines |
|---|---|
| §1–§3 | What VXP is, why it exists, principles and scope |
| §4 | Architecture, interoperability rules [I1](https://vxpprotocol.org/spec/#i1)–[I5](https://vxpprotocol.org/spec/#i5), states [E1](https://vxpprotocol.org/spec/#e1)–[E3](https://vxpprotocol.org/spec/#e3) |
| §5 | Identity model [ID1](https://vxpprotocol.org/spec/#id1)–[ID3](https://vxpprotocol.org/spec/#id3) |
| §6 | VXP Proof: format, statement kinds, chain rules, [P1](https://vxpprotocol.org/spec/#p1)–[P8](https://vxpprotocol.org/spec/#p8) |
| §7 | VXP Relationship: [R1](https://vxpprotocol.org/spec/#r1)–[R17](https://vxpprotocol.org/spec/#r17) |
| §8 | Native profile and optional adapters |
| §9 | Operation requirements [O1](https://vxpprotocol.org/spec/#o1)–[O7](https://vxpprotocol.org/spec/#o7), security, privacy, errors |
| §10 | Independent verification, reading a verdict, key rotation |
| §11–§13 | Examples, conformance, versions and status |

## Stable identifiers

Every requirement has an identifier you can link to: `https://vxpprotocol.org/spec/#r6`, `#p5`, `#o6`,
`#id1`. The docs, the conformance matrix and the validator's report all use them. Section anchors such as
`#native-only` or `#key-rotation` are stable too.

The key words MUST, MUST NOT, SHOULD and MAY follow BCP 14 (RFC 2119 and RFC 8174).

## Versions

- One version, the same in three places: the trust block's `version`, the A2A extension URI
  (`https://vxpprotocol.org/ext/proof/v0.1`) and the `v` of every statement and package.
- While VXP is a 0.x draft, every new draft is treated as incompatible with the previous one. A verifier
  rejects a `v` it does not know ([§13 versioning](https://vxpprotocol.org/spec/#versioning)).
- Each change to the specification is recorded in the [changelog](https://vxpprotocol.org/docs/changelog/).

## Changing it

A normative change cites the identifiers it touches and comes with a test or a vector. See `CONTRIBUTING.md`.

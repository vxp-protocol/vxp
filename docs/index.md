---
title: VXP documentation
description: How to understand, run, implement and verify VXP, the open protocol for work that personal agents do for people inside companies.
---

## Start here

| You are | Read |
|---|---|
| New to VXP | [Introduction](introduction.md): what it is, its two components, and what it does not do |
| Trying it on your machine | [Quickstart](quickstart.md): a company and a personal agent in separate processes, from a clean clone |
| Building the company side | [Guide for companies](guides/company.md), then prove it with the [conformance validator](conformance.md) |
| Building a personal agent | [Guide for personal agents](guides/agent.md) and the agent library in `agent/` |
| Checking a proof someone gave you | [Guide for verifiers](guides/verifier.md) |
| Already speaking Poppy or PACT | [Interoperability](guides/interoperability.md): the optional adapters |
| Checking the exact rules | [Specification](specification.md): the only normative text |

## How these docs relate to the specification

The [specification](/spec/) is the only normative text. These pages explain it and show how to use it.
Every rule they restate links to its identifier in the specification, like [[R6]] or [[O6]]. Where a page
and the specification differ, the specification wins: please [report it](https://github.com/vxp-protocol/vxp/issues).

Every page is also available as Markdown at the same path with `.md`, and [`/llms.txt`](/llms.txt) lists
them for AI agents.

## What is in the repository

| Path | What it is |
|---|---|
| `spec/` | The specification source |
| `docs/` | These pages, in Markdown |
| `reference/` | A reference company implementation: native profile, Proof, Relationship, optional Poppy and PACT adapters |
| `agent/` | Personal-agent tools: a client library, a command-line tool, an MCP server and an example agent |
| `verifier/` | Three independent verifiers: two in Python, one in JavaScript for the browser and Node.js |
| `vectors/` | Test vectors, positive and negative |
| `conformance/` | A validator that acts as a personal agent against any implementation, the conformance matrix and a checklist |

Everything is under the Apache License 2.0, and nothing requires SOVRAS, Poppy or PACT.

# Contributing to VXP

VXP is developed in the open at [github.com/vxp-protocol/vxp](https://github.com/vxp-protocol/vxp).
The specification, the reference implementation, the verifiers and the test vectors all live in this
repository. Issues and pull requests are welcome.

## Proposing a normative change

A normative change is any change to what the specification requires: a rule, a format, a state, an
error code or a verifier result.

1. Open an issue first, or a pull request if the change is small.
2. Cite the identifier of every rule you change or add, for example `R6`, `P5`, `O6` or `I1`, and link
   its anchor in the specification (`https://vxpprotocol.org/spec/#r6`).
3. Bring a test or a test vector that fails without the change and passes with it: a test under
   `reference/test/`, or a case in `vectors/` with the verdict two conforming verifiers must return.
4. Edit `spec/spec.tpl.html`, not `site/spec/index.html`, and rebuild with `python3 spec/build.py`.

Errata, broken links and wording fixes that change no requirement can go straight to a pull request.

## Adding a demo

A demo lives apart from the protocol's own code, so it can change, or be removed, without touching the
specification, the verifier or the captured data.

- **Its own folder.** Everything goes in `site/demos/<name>/`, with its own `index.html` and its own
  assets. The name uses lowercase letters, digits and hyphens.
- **No shared code.** A demo does not import from `assets/`, `verify/`, `spec/`, `docs/` or `downloads/`.
  If it needs a file from there, it keeps its own copy.
- **Honest data.** It uses the neutral test companies. Captured data names its source on screen;
  anything invented is labeled as illustrative.
- **Registered in one place.** One entry in `site/demos/demos.json` makes it appear on the
  [Demos](https://vxpprotocol.org/demos/) page. With `"embed": "page"` it gets a link to its own page;
  with `"embed": "iframe"` it can also be loaded there, in a sandboxed frame, only when the visitor asks.
- **Same bar as the site.** Usable at 390 px wide without horizontal scroll, reachable by keyboard, with
  visible focus, and with no motion under `prefers-reduced-motion`.

```json
{
  "demos": [
    {
      "slug": "my-demo",
      "title": "What the demo shows, in a few words",
      "description": "One sentence on what the visitor can try.",
      "kind": "Illustrative",
      "lang": "en",
      "embed": "iframe",
      "height": 680
    }
  ]
}
```

## Reporting a security problem

Do not open a public issue, pull request or discussion for a security problem in the specification,
the reference implementation or the verifiers.

Report it privately through GitHub's private vulnerability reporting: the **Security** tab of this
repository, then **Report a vulnerability**. Include what you found, the affected rule or file, and how
to reproduce it. Please give us a reasonable time to fix it before you disclose it.

## License

VXP is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution, you agree that it
is licensed under the same terms, as set out in section 5 of the license.

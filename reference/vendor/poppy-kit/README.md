# Vendored: Poppy (Personal Agent Protocol) company kit

This directory is an unmodified copy of `kit/company/schemas/` and `kit/company/validate/`
(without `validate/test/checks.test.ts`) from the official repository
https://github.com/personal-agent-protocol/personal-agent-protocol at commit
`39b35bdf240fc07f157d6ca4e29b5a41d4b36b5d` (short `39b35bd`, see `COMMIT`).

It is licensed under the Apache License 2.0; its license text is kept in `LICENSE`. The upstream
repository ships no NOTICE file. No file in this directory was changed by the VXP project.

The reference tests use it in two ways:

- `validate/jose.ts`: the official signing primitives the test agents use (DPoP, assertions, JWTs).
- `validate/run.ts`, `validate/http.ts`, `validate/identity.ts`, `validate/checks/`: the official
  Poppy validator, run in process by `test/poppy-validador.test.ts` and `test/exigencia-poppy.test.ts`.

To refresh it from upstream:

```sh
git clone https://github.com/personal-agent-protocol/personal-agent-protocol
cd personal-agent-protocol && git checkout 39b35bd
cp -r kit/company/schemas kit/company/validate <vxp>/reference/vendor/poppy-kit/
rm <vxp>/reference/vendor/poppy-kit/validate/test/checks.test.ts
```

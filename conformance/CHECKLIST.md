# What the validator cannot check

The validator acts as an agent from outside. Some requirements live where it cannot look: in what a person
sees, in how the company keeps its records, or in its logs. Go through this list yourself and keep your
answers with the validator's report. The validator marks these checks as `manual`.

| Check | Rule | What to confirm |
|---|---|---|
| A4 | [R3](https://vxpprotocol.org/spec/#r3) | The consent screen shows each authorization item in business language: the company, the action, the resource, and for a relationship its actions, limit and validity. The relationship has its own checkbox; unchecking it creates no relationship. |
| A4, M1 | [ID1](https://vxpprotocol.org/spec/#id1) | An account is linked to an agent only through an authentication the company controls (for example, a one-time code over a channel the company already has for that customer), never by a matching name, email or phone number. Evidence of that authentication is kept. |
| M1 | [ID2](https://vxpprotocol.org/spec/#id2) | An identifier shared by more than one account (a phone number used by two customers) is never used on its own to link or to give out data. |
| M2 | [privacy](https://vxpprotocol.org/spec/#privacy) | No personal data travels in clear in the proof: personal values go as selective disclosures. The `user` member is a per-company pseudonym. Keys, issuers and log tags are per company. Logs keep no personal data. |
| — | [O5](https://vxpprotocol.org/spec/#o5) | When the company's own rule requires it, a person at the company decides on the same terms digest, after the customer's approval and before execution. The validator cannot make the company's rule require a review. |
| — | [P2](https://vxpprotocol.org/spec/#p2) | If the company offers approval through its own channel (`company_channel`), the outgoing message names the company and the agent and carries the summary and the `display_code`; a message that could not be delivered approves nothing. |
| — | [Key rotation](https://vxpprotocol.org/spec/#key-rotation) | Proof keys persist across restarts. After a rotation, the earlier public key stays in the JWKS for as long as proofs signed with it are to be verified, and a retired key is never reused. |
| — | [Security](https://vxpprotocol.org/spec/#security) | The company's key custody is declared truthfully in `vxp_proof.custody`. |

This checklist and the validator's report are your own evidence. Neither is a certification.

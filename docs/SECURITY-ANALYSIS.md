# The EST profile of TACRA, analysed by role

What each party holds, what it can do on its own, and the check that bounds it. "Conduit" is the
EST Client and the EST Server taken together: neither has a RATS role, and TACRA Section 7.2
trusts neither. This is the analysis behind the "Analysis by Role" subsection proposed for the
draft; the two attacks it names were run, not argued (see `../formal/` and `../evidence/`).

| Role | Holds | Can do on its own | Bounded by |
|---|---|---|---|
| Attester | CSKpri or CEKpri; the Attesting Environment | produce Evidence over any 64-octet value it chooses; choose its Target | Evidence names the launch measurement and the platform; the CA and the Vault decide by policy, not by the Attester's word |
| Conduit (EST Client, EST Server) | every message in transit, including CEKpub and the Evidence | delay, replay, reorder; obtain a Handle from any server; carry a request to a different server; replace a response | single-use Handle (409 on reuse); Evidence-to-Target binding (a request matches at one server only); origin authentication of the bundle and the Attester's checks of `server_id` and `handle`; TLS server authentication where the Attester is the TLS peer |
| Verifier | reference values; vendor roots (AMD ARK, Intel root, mock root) | appraise Evidence; report the binding value, the platform form and the identifiers | it does not decide issuance or release; its results are one input to the Relying Party |
| Credential Authority | its signing key; issuance policy | issue for a CSR | recomputes the binding with its own `server_id`, the Handle and the CSR; verifies proof of possession; constrains identities to the attested context |
| Secret Vault | the group's secrets; its origin key | release to a CEKpub | recomputes the binding with CEKpub; authenticates its bundle; `group_id` from Attestation Results, not from Evidence |

## Which check closes which attack

| Attack | Who mounts it | Closed by | Where it was run |
|---|---|---|---|
| Key substitution: a different CSR or CEKpub than the one the Evidence was produced for | conduit | Evidence-to-CSR / Evidence-to-CEK binding, recomputed by the Relying Party | implied by D3 (any change to the subject changes the binding) |
| Replay of a request | conduit | single-use Handle | D7: second post answered 409 |
| Server substitution: a genuine CSR and Evidence carried to a server the Attester did not choose | conduit | Evidence-to-Target (`server_id` in the binding input); the Attester's comparison of `server_id` with its Target | ProVerif `enrollment-nobind` (attack) / `enrollment-bind` (proof); D4 (issued under -00) / D3 (refused under the PR text) |
| Bundle substitution: a container encrypted to CEKpub by someone other than the Vault | conduit, or anyone who saw CEKpub | origin authentication (HPKE `mode_auth` or a Vault signature); Attester Processing checks | ProVerif `retrieval-base` (attack) / `retrieval-auth` (proof); D6 (accepted under -00) / D5, D5b (refused under the PR text) |
| Stale Evidence | conduit | `expires_in`; Handle Lifetime floor | D8 burst: the stall that sets the floor |
| Identity over-issuance | Attester (via `credential_hint`) | CA policy on the attested identity context | CA refuses identities outside its allow-list (403 policy-denied) |

## What the analysis does not claim

- The conduit is not modelled as colluding with a dishonest server: with S2 dishonest, S2 can
  issue whatever it likes under its own key, which harms only relying parties that trust S2.
- Compromise of the Attesting Environment (a leaked TEE key or a debug-enabled guest) is outside
  the model; the Verifier refuses debug-enabled guests and pins the vendor root, which is the
  protocol's only handle on it.
- Provider-scoped Evidence (VLEK, CHIP_ID zero) satisfies every binding above but names a key
  domain rather than a machine; the Verifier reports the form and the CA's policy decides.

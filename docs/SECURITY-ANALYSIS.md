# The EST profile of TACRA, analysed by role

What each party holds, what it can do on its own, and the check that bounds it. "Conduit" is the
EST Client and the EST Server taken together: neither has a RATS role, and TACRA Section 7.2
trusts neither. This is the analysis behind the "Analysis by Role" subsection of the pull request
(Section 12.4 of the draft as built); the three substitution attacks it names, and the replay,
were run, not argued (see `../formal/` and `../evidence/`).

Two identities are bound and they are not the same thing. `server_id` names the EST Server that the
Attester's Credential Acquisition Interface is configured to use for the Target. The Target is the
RATS-unaware Relying Party for which the Attester seeks credentials (TACRA Section 2). Binding one
does not bind the other: `formal/enrollment-serveronly.pv` binds `server_id` alone and ProVerif
finds the Target substitution.

| Role | Holds | Can do on its own | Bounded by |
|---|---|---|---|
| Attester | CSKpri or CEKpri; the Attesting Environment | produce Evidence over any 64-octet value it chooses; choose its Target | Evidence names the launch measurement and the platform; the CA and the Vault decide by policy, not by the Attester's word |
| Conduit (EST Client, EST Server) | every message in transit, including CEKpub and the Evidence | delay, replay, reorder; obtain a Handle from any server and for any Target that server provisions; carry a request to a different server; replace a response | single-use Handle (409 on reuse); the Evidence-to-Server and Evidence-to-Target bindings (a request matches at one server and for one Target only); origin authentication of the bundle and the Attester's checks of `server_id`, `target` and `handle`; TLS server authentication where the Attester is the TLS peer |
| Verifier | reference values; vendor roots (AMD ARK, Intel root, mock root) | appraise Evidence; report the binding value, the platform form and the identifiers | it does not decide issuance or release; its results are one input to the Relying Party |
| Credential Authority | its signing key; issuance policy | issue for a CSR | recomputes the binding with its own `server_id`, the Handle, the Target the Handle was initiated for, and the CSR; verifies proof of possession; constrains identities to the attested context |
| Secret Vault | the group's secrets; its origin key | release to a CEKpub | recomputes the binding with its own `server_id`, the Handle, the Target and CEKpub; authenticates its bundle; `group_id` from Attestation Results, not from Evidence |

## Which check closes which attack

| Attack | Who mounts it | Closed by | Where it was run |
|---|---|---|---|
| Key substitution: a different CSR or CEKpub than the one the Evidence was produced for | conduit | Evidence-to-CSR / Evidence-to-CEK binding, recomputed by the Relying Party | ProVerif: the CSR is part of the proved correspondence (`enrollment-bind`, Q2 and Q3); not drilled separately |
| Replay of a request | conduit | single-use Handle | D7: second post answered 409 `handle-replay` |
| Server substitution: a genuine CSR and Evidence carried to a server the Attester did not choose | conduit | Evidence-to-Server binding (`server_id` in the binding input); the Attester's comparison of `server_id` with the EST Server configured for its Target | ProVerif `enrollment-nobind` (attack) / `enrollment-bind` (proof); D4 (issued under -00) / D3 (refused under the pull request's text) |
| Target substitution: at the server the Attester chose, the conduit initiates for another Target and obtains a credential for it | conduit | Evidence-to-Target binding (`target` in the binding input); `target` must equal the Target of the Handle's initiation | ProVerif `enrollment-serveronly` (attack remains with `server_id` alone) / `enrollment-bind` (proof); D10 (issued under -00) / D9 (refused under the pull request's text) |
| Bundle substitution: a container encrypted to CEKpub by someone other than the Vault | conduit, or anyone who saw CEKpub | origin authentication (HPKE `mode_auth` or a Vault signature); Attester Processing checks | ProVerif `retrieval-base` (attack) / `retrieval-auth` (proof); D6 (accepted under -00) / D5, D5b (refused under the pull request's text) |
| Stale Evidence | conduit | `expires_in`; the Handle Lifetime floor | D8 burst on SEV-SNP: every tenth report waits about 10.2 s (host rate limiting, AMD 56421 Section 4.1.7; Linux guest driver retry, 2 s steps up to 60 s) |
| Identity over-issuance | Attester (via `credential_hint`) | CA policy on the attested identity context | code path only: `CredentialAuthority.issue` in `impl/est_server.py` refuses an identity outside its allow-list, answered 403 `policy-denied`; not drilled |

## What the analysis rests on, and what it does not claim

- A dishonest second server is modelled: with S2 and its CA key in the attacker's hands
  (`enrollment-bind-compromised-s2`) and with Vault 2's keys in the attacker's hands
  (`retrieval-auth-compromised-vault2`), the guarantees for the honest server and Vault hold. S2
  can issue whatever it likes under its own key, which harms only relying parties that trust S2.
- A leaked TEE attestation key breaks every guarantee (`enrollment-bind-tee-key-leaked`: all three
  enrollment queries false). That is the assumption the protocol rests on; the Verifier's only
  handles on it are the pinned vendor root, the refusal of debug-enabled guests, and the TCB it
  reports.
- Provider-scoped Evidence (a VLEK signature, or a zero `CHIP_ID` set through MASK_CHIP_ID, AMD
  56860 Section 8.7) satisfies every binding above but names a key domain rather than a machine;
  the Verifier reports the form and the CA's policy decides. A report with MASK_CHIP_KEY set
  carries no signature (AMD 56860 Section 3.6) and is refused.

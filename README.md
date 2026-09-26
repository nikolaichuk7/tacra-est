# tacra-est: a reference implementation, formal model and hardware measurements for draft-novak-lamps-tacra-est

Companion to the pull request "seven items" against `TheBankster/lamps-tacra-est` (26 September 2026).
Everything here is reproducible from a clone; every number in the draft text that comes from this
repository names the file it comes from.

- `formal/` — the EST profile in the applied pi calculus for ProVerif: the two attacks the draft
  closes (server substitution by the conduit; bundle substitution) and the two proofs with the
  bindings in place.
- `impl/` — the reference implementation: Attester (in a SEV-SNP guest, or a mock TEE), EST Client
  (conduit), EST Server with the three resources, Verifier, Credential Authority, Secret Vault; the
  two attack drills.
- `vectors/` — test vectors for the four structures, from real Evidence.
- `evidence/` — raw outputs of every hardware run (reports, certificates, timings), never edited.
- `docs/` — results and the security analysis by role.

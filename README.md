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

## Reproduce

Formal model (ProVerif 2.05, built from the official source with OCaml):

    cd formal && python3 gen.py && for f in enrollment-nobind enrollment-bind retrieval-base retrieval-auth; do proverif $f.pv; done

Reference implementation on a laptop, mock TEE (Python 3.12, `cryptography`, `pyhpke`):

    python3 -m venv .venv && . .venv/bin/activate && pip install cryptography pyhpke
    python3 impl/run_drills.py --tee mock --out evidence/$(date -u +%Y%m%dT%H%M%SZ)-mock --burst 50
    python3 scripts/summarize_drills.py evidence/<stamp>-mock/drills.json

Reference implementation inside a live AMD SEV-SNP guest on Google Cloud (creates and deletes one
n2d-standard-2 confidential VM; needs `gcloud` with a project):

    scripts/gcp-snp-drill.sh <project> <zone>

The drills: D1 honest enrollment, D2 honest retrieval, D3/D4 server substitution by the conduit
against the pull request's text and against -00, D5/D5b/D6 bundle substitution against the pull
request's text and against -00, D7 Handle replay, D8 a burst of reports for the Handle-lifetime
floor. Every run writes `drills.json` (outcomes, timings, server logs), `vectors.json` (the
messages of D1 and D2) and, on hardware, the raw report and certificates.

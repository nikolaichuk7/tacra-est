# tacra-est: a reference implementation, formal model and hardware measurements for draft-novak-lamps-tacra-est

Companion to the pull request against `TheBankster/lamps-tacra-est` (26 September 2026).
Everything here is reproducible from a clone; every number in the draft text that comes from this
repository names the file it comes from, and `docs/RESULTS.md` collects them.

- `formal/` — the EST profile in the applied pi calculus for ProVerif, twenty-four models: the
  three attacks the -00 text admits (RRP substitution and Target substitution by the conduit;
  bundle substitution), the proofs with the bindings of the pull request in place, the same proofs
  with a dishonest second server or Vault, a leaked TEE key as the explicit assumption, and fifteen
  models on where the bound RRP identity comes from (the Attester's configuration or the initiation
  response) under five sources of freshness: a fresh Handle, a shared epoch, a received epoch, a
  Verifier's Handle that several servers accept, and the Attester's timestamp.
- `impl/` — the reference implementation: Attester (in a SEV-SNP guest, or a mock TEE), EST Client
  (conduit), EST Server with the three resources, Verifier, Credential Authority, Secret Vault; all
  five Freshness Kinds; and the drills that run each attack against the pull request's text and
  against -00.
- `cddl/` — the CDDL of the envelopes, identical to the draft's.
- `scripts/` — the Google Cloud runner, and the scripts that turn a run into tables, the test
  vector, the example appendix and the CDDL check.
- `interop/` — tests run against the TWI SIG implementation; see `interop/README.md`.
- `evidence/` — raw outputs of every run (reports, certificates, messages, timings, server logs),
  never edited; `vectors.json` in each run holds the messages.
- `docs/` — the results and the security analysis by role.

## Reproduce

Formal model (ProVerif 2.05, built from the official source with OCaml):

    cd formal && python3 gen.py && for f in *.pv; do proverif $f; done

Reference implementation on a laptop, mock TEE (Python 3.12):

    python3 -m venv .venv && . .venv/bin/activate && pip install cryptography pyhpke cbor2
    python3 impl/run_drills.py --tee mock --out evidence/$(date -u +%Y%m%dT%H%M%SZ)-mock --code-rev $(git rev-parse --short=12 HEAD)
    python3 scripts/summarize_drills.py evidence/<stamp>-mock/drills.json

Reference implementation inside a live AMD SEV-SNP guest on Google Cloud (creates and deletes one
`n2d-standard-2` confidential VM; needs `gcloud` with a project):

    scripts/gcp-snp-drill.sh <project> <zone>

Checks on any run:

    python3 scripts/validate_cddl.py evidence/<run>/vectors.json      # needs: gem install cddl
    python3 scripts/test_vector.py evidence/<run>/vectors.json        # refuses unless SHA-512 = REPORT_DATA
    python3 scripts/burst_stats.py evidence/<run>/drills.json         # hardware runs
    python3 scripts/vectors_to_appendix.py evidence/<run>/vectors.json

The drills: D1 honest enrollment, D2 honest retrieval, D3/D4 server substitution by the conduit
against the pull request's text and against -00, D5/D5b/D6 bundle substitution against the pull
request's text and against -00, D7 Handle replay, D9/D10 Target substitution by the conduit
against the pull request's text and against -00, and on hardware D8, a burst of 200 reports for
the Handle-lifetime floor. `attest-initiate` takes `target` and `credential_type`, and the EST
Server chooses the mode from its policy for the Target: in the drills `https://db.tacra.example`
and `https://payments.tacra.example` are provisioned by Enrollment and
`https://ledger.tacra.example` by Retrieval. Every run writes `drills.json` (outcomes, timings,
server logs, code revision), `vectors.json` (the messages of D1 and D2) and, on hardware, the raw
report and certificates with their SHA-256 sums.

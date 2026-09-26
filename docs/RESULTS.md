# Results

Every number below names the file it comes from. Mock-TEE runs are on a laptop; hardware runs
are inside a Google Cloud AMD SEV-SNP guest (n2d-standard-2, Milan), created and deleted by
`scripts/gcp-snp-drill.sh`.

## 1. Formal model (ProVerif 2.05), `formal/results/proverif-20260926.txt`

| model | query | result |
|---|---|---|
| enrollment as in -00 (Handle and CSR in the binding) | Issued(sid, csr) ⇒ AttesterIntends(sid, csr) | false, attack: S2 issues for a CSR made for S1 |
| enrollment with `server_id` in the binding (pull request) | same | true |
| retrieval, bundle encrypted to CEKpub (base mode) | AttesterUses(vid, s) ⇒ VaultReleased(vid, s) | false, attack: the Attester uses a secret no Vault released |
| retrieval with HPKE `mode_auth` (pull request) | same | true |

## 2. Drills on the mock TEE, `evidence/20260926T165650Z-mock/drills.json`

| drill | text | outcome |
|---|---|---|
| D1 honest enrollment at S1 | PR | 200, certificate issued by S1 for the Attester's CSK |
| D2 honest retrieval at S1 | PR | 200, bundle accepted, the group's signing key recovered |
| D3 server substitution (conduit says S1, carries to S2) | PR | 403 `binding-mismatch` at S2 |
| D4 server substitution | -00 | 200, **S2 issued** a certificate for a CSR the Attester made for S1 |
| D5 bundle substitution, base-mode container | PR | Attester refused: container does not authenticate its origin |
| D5b bundle substitution, forged `hpke-auth` under the attacker's key | PR | Attester refused: HPKE OpenError under the Vault's public key |
| D6 bundle substitution | -00 | **accepted**: the Attester now holds the attacker's signing key (fingerprints equal) |
| D7 Handle replay | PR | 409 `handle-replay` |

Message sizes (JSON, mock Evidence): enrollment request 1 499 bytes, retrieval request 1 264,
bundle 1 013. Hardware sizes are in section 3.

## 3. Drills on a live SEV-SNP guest

_Filled from `evidence/<stamp>-gcp-sev-snp/drills.json` when the run completes._

## 4. What the reference implementation does not cover

- Intel TDX and AWS Nitro Attesters (the Verifier is written for SEV-SNP and the mock; the
  platform-form text of the draft rests on the earlier measurements in `geoar-verifier`).
- CMS and COSE containers for the bundle; only HPKE is implemented.
- Background Check mode; only Passport mode is run.
- A CA identity as `server_id`; only the URI-origin form.

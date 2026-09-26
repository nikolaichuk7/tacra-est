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

## 3. Drills on a live SEV-SNP guest, `evidence/20260926T170405Z-gcp-sev-snp/drills.json`

Google Cloud `n2d-standard-2`, AMD EPYC Milan, SEV-SNP active (`dmesg-sev.txt`), Ubuntu 24.04
(`kernel.txt`), VCEK-signed reports with the host's certificate table, chain verified to the pinned
ARK-Milan by OpenSSL. Every outcome is the same as on the mock TEE; the numbers are the hardware's.

| drill | text | outcome | evidence ms | round trip ms |
|---|---|---|---|---|
| D1 honest enrollment at S1 | PR | 200 issued by CN=TACRA reference CA S1 | 200.4 | 44.9 |
| D2 honest retrieval at S1 | PR | 200 accepted; signing key fingerprint de5a877fb8e045f5 | 169.5 | 36.6 |
| D3 server substitution (conduit says S1, carries to S2) | PR | 403 refused: binding-mismatch | 159.9 | 33.9 |
| D4 server substitution | -00 | 200 issued by CN=TACRA reference CA S2-legacy | 161.3 | 34.3 |
| D5 bundle substitution, base-mode container | PR | 200 attester refused the bundle: AttesterError: container 'hpke-base' does not authenticate its origin | 169.7 | 34.1 |
| D5b bundle substitution, forged hpke-auth under the attacker's key | PR | 200 attester refused the bundle: OpenError: Failed to open. | 161.6 | 34.3 |
| D6 bundle substitution | -00 | 200 accepted; signing key fingerprint 05864e048404d2c7 | 160.5 | 36.4 |
| D7 Handle replay | PR | first: issued by CN=TACRA reference CA S1; second: 409 handle-replay | | |

Sizes (bytes): {"bundle_json": 1013, "enrollment_request_json": 13052, "evidence_certs_total": 4667, "evidence_chain_pem": 4602, "evidence_report": 1184, "retrieval_request_json": 12819}
Server S1: 6 successful requests; Verifier median 31.9 ms (min 30.6, max 41.1); CA/Vault median 0.6 ms

Burst: n=200, median 162.93 ms, p95 10381.01 ms, max 10416.7 ms, total 234.9 s; slow (>1 s): [(3, 8352.4), (13, 10373.8), (23, 10400.0), (33, 10376.8), (43, 10381.0), (53, 10416.7), (63, 10396.1), (73, 10360.8), (83, 10389.9), (93, 10394.4), (103, 10382.8), (113, 10393.2), (123, 10367.9), (133, 10373.1), (143, 10391.2), (153, 10368.5), (163, 10360.8), (173, 10415.0), (183, 10409.5), (193, 10377.6)]

Attester platform: sev-snp, form direct, chip 72096f47f0c0900a…, report_id 5119efb486fad68b…, measurement ccdc5cf01ba25526…; checks {'chain_to_ark': True, 'hwid_equals_chip_id': True, 'policy_no_debug': True, 'report_length': True, 'report_signature': True, 'report_version': True, 'signing_certificate_present': True}


Consistency check on the recorded report: `REPORT_DATA` of `D1-report.bin` equals
`SHA-512(binding_input(handle, server_id, csr))` for the handle and CSR in `vectors.json`
(`scripts/summarize_drills.py` does not do this; the check is in the RESULTS build step above).

The burst measures `SNP_GET_EXT_REPORT`, the request that also returns the host's certificate
table: 163 ms median for the 180 unstalled requests, against 7.7 ms for a plain `SNP_GET_REPORT`
measured on 22 September (hatls `evidence/runtime-cost-20260922T153300Z/snp-burst.json`). The host
throttle is the same: 20 of 200 requests stalled 10.36–10.42 s, one in every ten, and 200 requests
took 234.9 s, 1.17 s per report sustained. Both figures set the Handle-lifetime floor: an Attester
that needs one report can wait ten seconds for it.

Message sizes with real Evidence: enrollment request 13 052 bytes (report 1 184 + VCEK/ASK/ARK
4 667 + KDS chain PEM 4 602, base64), retrieval request 12 819, bundle 1 013.

## 4. What the reference implementation does not cover

- Intel TDX and AWS Nitro Attesters (the Verifier is written for SEV-SNP and the mock; the
  platform-form text of the draft rests on the earlier measurements in `geoar-verifier`).
- CMS and COSE containers for the bundle; only HPKE is implemented.
- Background Check mode; only Passport mode is run.
- A CA identity as `server_id`; only the URI-origin form.

## 5. Verifier checked against the primary specifications (26 September 2026)

Read in full for the fields the implementation touches: AMD 56860 SEV Secure Nested Paging Firmware
ABI Specification rev. 1.59 (August 2026, from docs.amd.com); Intel TDX Module ABI Reference
348551-008US and Base Architecture 348549-008US (May 2026); Intel TDX DCAP Quote Library API.
Four corrections to the SEV-SNP verifier resulted, each against a table number:

- Report `VERSION` is 6 in rev. 1.59 (Table 27); the verifier accepted 2–5 and would have refused a
  current report. It now accepts 2–6. Google Cloud Milan hosts still emit 5.
- `SIGNING_KEY` (Table 27, offset 48h, bits 4:2) has a value 2, the chip-secret VCEK; the parser
  now names it.
- With `MASK_CHIP_KEY` set the firmware writes zeroes instead of a signature (Section 3.6); the
  verifier had treated that bit as "provider-scoped". It now refuses an unsigned report, and
  classifies as provider-scoped only a VLEK signature or a zero `CHIP_ID` (`MASK_CHIP_ID`, set by
  the hypervisor through SNP_CONFIG, Section 8.7, Table 51).
- R and S are 72-byte zero-extended little-endian fields (Table 148); the verifier read 48 bytes
  and now reads 72 and requires the top 24 to be zero. Reserved must-be-zero ranges of Table 27
  are now checked, as the specification's note asks of verifiers.

Both recorded Google Cloud reports (12 and 26 September) pass every check; a report with
`MASK_CHIP_KEY` set and a report with a reserved byte set are refused.

Implementation note: AMD's VCEK certificate carries serial number 0 (`openssl x509 -serial` on
`D1-cert-VCEK.bin`: `serial=00`); RFC 5280 Section 4.1.2.2 requires a positive serial, and
`cryptography` warns that a future release will refuse to load it. Verifiers written against a
strict X.509 parser should expect this.

# Results

Every number below names the file it comes from. Mock-TEE runs are on a laptop; hardware runs
are inside Google Cloud AMD SEV-SNP guests (`n2d-standard-2`, EPYC Milan), each created and
deleted by `scripts/gcp-snp-drill.sh`.

## 0. The runs

| run (stamp in `drills.json`) | directory under `evidence/` | TEE | chip (first 8 octets of CHIP_ID) | code | drills |
|---|---|---|---|---|---|
| 20260926T203701Z | `20260926T202045Z-gcp-sev-snp` | SEV-SNP | 35e7e2308d049c75 | 9850c7dfe79e (recorded) | D1-D10, burst of 200 |
| 20260926T204536Z | `20260926T204536Z-mock` | mock | | 69d535f27d69 (recorded) | D1-D10 |
| 20260926T203701Z and 20260926T204536Z are the current runs, on the code after the fifteen corrections; the sections below are theirs. | | | | | |
| 20260926T185426Z | `20260926T185214Z-gcp-sev-snp` | SEV-SNP | 35e7e2308d049c75 | d2f8aa4de167 | D1-D10, burst; Attester still fetched the KDS chain |
| 20260926T183227Z | `20260926T183015Z-gcp-sev-snp` | SEV-SNP | 1d1f823a4c3294e2 | 2c25fd6; `attest-initiate` still took `mode` | D1-D10, burst |
| 20260926T165938Z | `20260926T165724Z-gcp-sev-snp` | SEV-SNP | 72096f47f0c0900a | 8836e0f, before the Target | D1-D7, burst |
| 20260926T165650Z | `20260926T165650Z-mock` | mock | | 8836e0f, before the Target | D1-D7 |

Each run records its code in `code_rev`; the first two commits (8836e0f) are established from the
commit times against the session log, no file under `impl/` having changed between them and the
launches. All four hardware hosts ran the same machine type, CPU (family 19h model 01h stepping 1),
SEV firmware 1.58 build 1, TCB (boot loader 4, TEE 0, SNP 29, microcode 222) and guest kernel
(Ubuntu `7.0.0-1011-gcp`); the current hardware run happened to land on the same chip as
20260926T185426Z.

## 1. Formal model (ProVerif 2.05), `formal/results/proverif-20260926T224122Z.txt`

| model | binding | Q1 | Q2 | Q3 | R1 | S |
|---|---|---|---|---|---|---|
| `enrollment-nobind` | draft -00: Handle and CSR | false | false | false | | |
| `enrollment-serveronly` | Handle, `server_id`, CSR | true | **false** | false | | |
| `enrollment-bind` | the pull request: Handle, `server_id`, Target, CSR | true | true | true | | |
| `enrollment-bind-nocompare` | as above, no Attester-side comparison of the wire `server_id`; bound identity from the CAI configuration | true | true | true | | |
| `enrollment-bind-compromised-s2` | as above; server 2 and its CA key are the attacker's | | true (server 1) | | | |
| `enrollment-bind-tee-key-leaked` | as above; the TEE attestation key has leaked | false | false | false | | |
| `retrieval-base` | draft -00: bundle encrypted to CEKpub | | | | false | true |
| `retrieval-auth` | the pull request: HPKE `mode_auth` | | | | true | true |
| `retrieval-auth-compromised-vault2` | as above; Vault 2's keys are the attacker's | | | | true | true |

Q1: a certificate issued by server *sid* for CSR *x* was intended by the Attester for *sid*; Q2:
for *sid* and the same Target; Q3: Q2, injective; R1: a secret the Attester uses was released for
it by the Vault and Target it intended; S: the Vault's secret stays secret. `formal/README.md`
explains the models and the three attacks found.

## 2. Drills on the mock TEE, `evidence/20260926T204536Z-mock/drills.json`

| drill | text | outcome |
|---|---|---|
| D1 honest enrollment at S1 | PR | 200, issued by S1 for Target `https://db.tacra.example` |
| D2 honest retrieval at S1 | PR | 200, bundle accepted (Target `https://ledger.tacra.example`) |
| D3 server substitution (conduit says S1, carries to S2) | PR | 403 `binding-mismatch` |
| D4 server substitution | -00 | 200, **S2 issued** a certificate for a CSR the Attester made for S1 |
| D5 bundle substitution, base-mode container | PR | Attester refused: container does not authenticate its origin |
| D5b bundle substitution, forged `hpke-auth` under the attacker's key | PR | Attester refused: HPKE open fails under the Vault's public key |
| D6 bundle substitution | -00 | **accepted**: the key the Attester now holds is the attacker's (fingerprints equal, 02f74ae6bed70e13) |
| D7 Handle replay | PR | first issued; second 409 `handle-replay` |
| D9 target substitution (conduit initiates for another Target) | PR | 403 `binding-mismatch` |
| D10 target substitution | -00 | 200, **issued for `https://payments.tacra.example`**, a Target the Attester did not ask for |

Message sizes with mock Evidence (bytes): enrollment request 1 985, Evidence 1 027, retrieval
request 1 754, bundle 1 053.

## 3. Drills on a live SEV-SNP guest, `evidence/20260926T202045Z-gcp-sev-snp/drills.json`

VCEK-signed reports; the Attester builds the [ASK, ARK] chain from the host's certificate table and
makes no network request; chain verified to the pinned ARK-Milan by OpenSSL. Every outcome is the
same as on the mock TEE; the numbers are the hardware's.

| drill | text | outcome | Evidence ms | round trip ms |
|---|---|---|---|---|
| D1 honest enrollment at S1 | PR | 200, issued by CN=TACRA reference CA S1 for `https://db.tacra.example` | 9.2 | 41.8 |
| D2 honest retrieval at S1 | PR | 200, accepted | 10.5 | 32.3 |
| D3 server substitution | PR | 403 `binding-mismatch` | 9.9 | 31.5 |
| D4 server substitution | -00 | 200, issued by CN=TACRA reference CA S2-legacy | 9.4 | 31.6 |
| D5 bundle substitution, base mode | PR | Attester refused: container does not authenticate its origin | 8.5 | 32.1 |
| D5b bundle substitution, forged `hpke-auth` | PR | Attester refused: HPKE open fails | 8.3 | 30.7 |
| D6 bundle substitution | -00 | accepted; the key is the attacker's (62ab01b5706d8f38) | 9.5 | 31.5 |
| D7 Handle replay | PR | first issued; second 409 `handle-replay` | | |
| D9 target substitution | PR | 403 `binding-mismatch` | 8.2 | 30.7 |
| D10 target substitution | -00 | 200, issued by CN=TACRA reference CA S1-legacy for `https://payments.tacra.example` | 8.1 | 31.8 |

D1's Evidence time is now the report ioctl alone, 9.2 ms: the Attester takes the VCEK, ASK and ARK
from the host's certificate table and reaches no network (the earlier runs' ~200 ms D1 was the
one-time KDS download the old Attester did, now gone). Server S1: 6 successful requests; Verifier
median 29.3 ms (min 28.0, max 38.7); CA and Vault median 0.4 ms.

Message sizes (bytes): enrollment request 17 395; Evidence 12 583 (report 1 184, VCEK/ASK/ARK
4 667, chain PEM 4 602 built from the host table, as JSON with base64url); retrieval request
17 164; bundle 1 053.

The three earlier hardware runs give the same outcomes for the drills each had (20260926T165938Z
had only D1-D7).

## 4. How long a report takes, and the host's throttle

`scripts/burst_stats.py` computes these from `drills.json`; the HATLS figures are from
`hatls/evidence/runtime-cost-20260922T153300Z/snp-burst.json`. All SEV-SNP rows time the
`SNP_GET_EXT_REPORT` ioctl alone, except the first run, which timed the whole `tee.report()` call
while its Attester downloaded the KDS chain per report.

| run | chip | unthrottled median | stalls | one stall | rate |
|---|---|---|---|---|---|
| 20260926T203701Z | 35e7e2308d049c75 | 7.91 ms (180 calls) | one in every ten of 200 | 10.23 s | 0.97 per s |
| 20260926T185426Z | 35e7e2308d049c75 | 8.13 ms (180 calls) | one in every ten of 200 | 10.23 s | 0.97 per s |
| 20260926T183227Z | 1d1f823a4c3294e2 | 8.16 ms (180 calls) | one in every ten of 200 | 10.23 s | 0.97 per s |
| HATLS, 22 September | 75bbd2bb8dfeeb00 | 7.7 ms (45 calls, SNP_GET_REPORT) | reports 10, 20, 30, 40 | 10.23-10.26 s | 45 in 41.3 s |
| 20260926T165938Z (whole call, KDS download) | 72096f47f0c0900a | 162.55 ms (180 calls) | one in every ten of 200 | 10.36-10.42 s | 0.85 per s |

Why every tenth report waits. Section 4.1.7 of the GHCB specification (AMD publication 56421,
revision 2.04, January 2025; `_LIBRARY/specs/amd-56421-ghcb.pdf`, page 55) says that access to the
SNP firmware is "a sequential and synchronous operation", recommends that the hypervisor rate-limit
a guest that issues many Guest Request events, and defines the answer that tells the guest to
retry (SW_EXITINFO2 = 0x0000000200000000). The Linux 7.0 guest driver turns that answer into
-EAGAIN, sleeps SNP_REQ_RETRY_DELAY (2 s) and retries, and gives up with -ETIMEDOUT once more than
SNP_REQ_MAX_RETRY_DURATION (60 s) has passed since the first attempt
(`arch/x86/coco/sev/core.c`, `__handle_guest_request`, lines 1786-1841;
`arch/x86/include/asm/sev.h`, lines 159-160). A stall of 10.2 s is five such sleeps and the
requests between them. Because the 60 s are counted before the last sleep, a report can still
arrive about 62 s after the first attempt.

What was and was not measured. The report ioctl is 7.7-8.2 ms wherever it was timed
alone. The one 162.55 ms figure is not the chip's and not the host's: it is the first run's
Attester (commit 8836e0f) downloading the KDS certificate chain on every report while the burst
timed the whole call. The current Attester downloads nothing (it uses the host's certificate
table), so that cost is gone; what the first run showed was the price of fetching per report, not a
property of the platform. The separate cost of one chain download was not isolated on its own.

## 5. Checks on the recorded Evidence

On the current run 20260926T203701Z (`evidence/20260926T202045Z-gcp-sev-snp/`):

- `scripts/test_vector.py` recomputes the binding input of the enrollment (Handle, `server_id`,
  Target, CSR; 319 octets) and refuses to print a test vector unless its SHA-512 digest equals
  REPORT_DATA of the report in the Evidence. It prints one, and an independent recomputation from
  the printed hex, with no code from `impl/`, gives the same digest.
- The report's ECDSA P-384 signature over octets 0h-29Fh verifies under the VCEK with `openssl
  dgst -sha384 -verify` (R and S read as 72-octet little-endian fields, AMD 56860 Table 148); the
  VCEK chains through the ASK to the pinned ARK with `openssl verify`.
- The pinned ARK (`impl/trust/ark-milan.pem`) is DER-identical to the ARK-Milan that AMD's KDS
  served on 26 September 2026 (`https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`), SHA-256
  69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd.
- `scripts/validate_cddl.py` validates all five messages against the CDDL of the draft
  (`cddl/tacra-est.cddl`, identical to the draft's CDDL block); both negative controls, a request
  without `target` and Evidence given as a map, are refused.
- The Attester makes no network request. Its chain, rebuilt from the host's ASK and ARK, is
  byte-identical to AMD's KDS chain and the report verifies offline. When the certificate table is
  stripped from the Evidence, the Verifier fetches the VCEK and the chain from the KDS and reaches
  the same binding value; a Verifier with `allow_kds_fetch=False` fails closed. This fallback was
  exercised offline against the recorded run, not on these hosts, whose tables are complete.

The current Verifier passes all five Google Cloud reports on record: 12 September 2026
(geoar-verifier run 20260912T224511Z, chip d29ed63f87559fe2) and the four SEV-SNP runs above.

## 6. What the reference implementation does not cover

- Intel TDX and AWS Nitro Attesters (the Verifier is written for SEV-SNP and the mock; the
  platform-form text of the draft rests on the primary specifications and the earlier
  measurements in `geoar-verifier`).
- CMS and COSE containers for the bundle; only HPKE is implemented.
- Background Check mode; only Passport mode is run.
- Every Freshness Kind but `present-nonce`; the drills exercise only `present-nonce`.
- A CA identity as `server_id`; only the URI-origin form.
- The Verifier's KDS fetch is exercised offline against recorded Evidence, not on a host whose
  certificate table is actually empty.

## 7. Verifier checked against the primary specifications (26 September 2026)

Read in full for the fields the implementation touches: AMD 56860 SEV Secure Nested Paging Firmware
ABI Specification rev. 1.59 (August 2026, from docs.amd.com); Intel TDX Module ABI Reference
348551-008US and Base Architecture 348549-008US (May 2026); Intel TDX DCAP Quote Library API.
Four corrections to the SEV-SNP verifier resulted, each against a table number:

- Report `VERSION` is 6 in rev. 1.59 (Table 27); the verifier accepted 2-5 and would have refused a
  current report. It now accepts 2-6. Google Cloud Milan hosts still emit 5.
- `SIGNING_KEY` (Table 27, offset 48h, bits 4:2) has a value 2, the chip-secret VCEK; the parser
  now names it.
- With `MASK_CHIP_KEY` set the firmware writes zeroes instead of a signature (Section 3.6); the
  verifier had treated that bit as "provider-scoped". It now refuses an unsigned report, and
  classifies as provider-scoped only a VLEK signature or a zero `CHIP_ID` (`MASK_CHIP_ID`, set by
  the hypervisor through SNP_CONFIG, Section 8.7, Table 51).
- R and S are 72-byte zero-extended little-endian fields (Table 148); the verifier read 48 bytes
  and now reads 72 and requires the top 24 to be zero. Reserved must-be-zero ranges of Table 27
  are now checked, as the specification's note asks of verifiers.

Implementation note: AMD's VCEK certificate carries serial number 0 (`openssl x509 -serial` on
`D1-cert-VCEK.bin`: `serial=00`); RFC 5280 Section 4.1.2.2 requires a positive serial, and
`cryptography` warns that a future release will refuse to load it. Verifiers written against a
strict X.509 parser should expect this.

# Results

Every number below names the file it comes from. Mock-TEE runs are on a laptop; hardware runs
are inside Google Cloud AMD SEV-SNP guests (`n2d-standard-2`, EPYC Milan), each created and
deleted by `scripts/gcp-snp-drill.sh`.

## 0. The runs

| run (stamp in `drills.json`) | directory under `evidence/` | TEE | chip (first 8 octets of CHIP_ID) | code | drills |
|---|---|---|---|---|---|
| 20260926T234654Z | `20260926T234444Z-gcp-sev-snp` | SEV-SNP | 1d1f823a4c3294e2 | e116768fe989 (recorded) | D1-D21, burst of 200 |
| 20260926T234423Z | `20260926T234423Z-mock` | mock | | e116768fe989 (recorded) | D1-D21 |
| 20260926T234654Z and 20260926T234423Z are the current runs, on the code after the review of 26 September (the RRP identifier `rrp_id`, all five Freshness Kinds, one binding method); the sections below are theirs. | | | | | |
| 20260926T203701Z | `20260926T202045Z-gcp-sev-snp` | SEV-SNP | 35e7e2308d049c75 | 9850c7dfe79e (recorded) | D1-D10, burst of 200; `server_id`, `present-nonce` only |
| 20260926T204536Z | `20260926T204536Z-mock` | mock | | 69d535f27d69 (recorded) | D1-D10; `server_id`, `present-nonce` only |
| 20260926T185426Z | `20260926T185214Z-gcp-sev-snp` | SEV-SNP | 35e7e2308d049c75 | d2f8aa4de167 | D1-D10, burst; Attester still fetched the KDS chain |
| 20260926T183227Z | `20260926T183015Z-gcp-sev-snp` | SEV-SNP | 1d1f823a4c3294e2 | 2c25fd6; `attest-initiate` still took `mode` | D1-D10, burst |
| 20260926T165938Z | `20260926T165724Z-gcp-sev-snp` | SEV-SNP | 72096f47f0c0900a | 8836e0f, before the Target | D1-D7, burst |
| 20260926T165650Z | `20260926T165650Z-mock` | mock | | 8836e0f, before the Target | D1-D7 |

Each run records its code in `code_rev`; the first two commits (8836e0f) are established from the
commit times against the session log, no file under `impl/` having changed between them and the
launches. All five hardware hosts ran the same machine type, CPU (family 19h model 01h stepping 1),
SEV firmware 1.58 build 1 (the report's CURRENT_MAJOR, CURRENT_MINOR and CURRENT_BUILD), TCB
(boot loader 4, TEE 0, SNP 29, microcode 222) and guest kernel (Ubuntu `7.0.0-1011-gcp`); the
current hardware run landed on the same chip as 20260926T183227Z, and 20260926T203701Z on the same
chip as 20260926T185426Z.

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
explains the models and the three attacks found. The server identity these models call `server_id`
is what the draft now calls `rrp_id`: the issuing server in the models is the Credential Authority.

Where the bound server identity comes from, `formal/results/proverif-20260926T232411Z-rrp-source.txt`
(six models, ProVerif `preciseActions` set; B1: the issuing server is the one the Attester bound, for
the same Target; U1: no two servers issue for one CSR and Target):

| freshness | identity the Attester binds | Q1 | B1 | U1 |
|---|---|---|---|---|
| fresh Handle per server | none | false | | true |
| fresh Handle per server | received in the initiation response | false | true | true |
| fresh Handle per server | from its own configuration | true | | true |
| shared epoch | none | false | | **false** |
| shared epoch | received in the initiation response | false | true | true |
| shared epoch | from its own configuration | true | | true |

The Q1 values in the first and third rows are those of `enrollment-nobind` and
`enrollment-bind-nocompare` above; the six models add U1 (and B1 where the identity is received).

Three more sources of freshness, `formal/results/proverif-20260926T233733Z-freshness-sources.txt`
(nine models, `preciseActions` set): the same three sources of the bound identity, with an epoch
value the Attester receives (present-epoch), a Verifier's Handle that both servers accept, and the
Attester's own timestamp sent in the request (absent-timestamp):

| freshness | identity the Attester binds | Q1 | B1 | U1 |
|---|---|---|---|---|
| epoch received in the response | none | false | | **false** |
| epoch received in the response | received in the initiation response | false | true | true |
| epoch received in the response | from its own configuration | true | | true |
| a Verifier's Handle, accepted by both servers | none | false | | **false** |
| a Verifier's Handle, accepted by both servers | received in the initiation response | false | true | true |
| a Verifier's Handle, accepted by both servers | from its own configuration | true | | true |
| the Attester's timestamp, in the request | none | false | | **false** |
| the Attester's timestamp, in the request | received in the initiation response | false | true | true |
| the Attester's timestamp, in the request | from its own configuration | true | | true |

Twenty-four models in all. Whenever the freshness value is not tied to one server's session, the
same Evidence is accepted by two servers unless an identity is bound; only an identity the
Attester holds makes the issuing server the intended one.

## 2. Drills on the mock TEE, `evidence/20260926T234423Z-mock/drills.json`

The table is the output of `scripts/summarize_drills.py` on that file. "PR" is the pull request's
text, "-00" the draft as posted.

| drill | text | outcome | evidence ms | round trip ms |
|---|---|---|---|---|
| D1 honest enrollment at S1, present-nonce | PR | 200 issued by CN=TACRA reference CA S1 for target https://db.tacra.example | 0.1 | 2.5 |
| D2 honest retrieval at S1, present-nonce | PR | 200 accepted; signing key fingerprint 75890d7dfac55268 | 0.1 | 2.3 |
| D3 RRP substitution, identifier held by the Attester (conduit says CA1, carries to S2) | PR | 403 refused: binding-mismatch | 0.1 | 1.3 |
| D3b RRP substitution, identifier taken from S2's response | PR | 200 issued by CN=TACRA reference CA S2 for target https://db.tacra.example | 0.1 | 1.5 |
| D4 RRP substitution | -00 | 200 issued by CN=TACRA reference CA S2-legacy for target https://db.tacra.example | 0.1 | 1.6 |
| D5 bundle substitution, base-mode container | PR | 200 attester refused the bundle: AttesterError: container 'hpke-base' does not authenticate its origin | 0.1 | 1.8 |
| D5b bundle substitution, forged hpke-auth under the attacker's key | PR | 200 attester refused the bundle: OpenError: Failed to open. | 0.1 | 1.7 |
| D6 bundle substitution | -00 | 200 accepted; signing key fingerprint 6018cd6d2ae57ff0 | 0.1 | 1.7 |
| D7 Handle replay | PR | first: issued by CN=TACRA reference CA S1 for target https://db.tacra.example; second: 409 handle-replay | | |
| D9 target substitution (conduit initiates for another Target) | PR | 403 refused: binding-mismatch | 0.1 | 1.2 |
| D10 target substitution | -00 | 200 issued by CN=TACRA reference CA S1-legacy for target https://payments.tacra.example | 0.1 | 1.4 |
| D11 honest enrollment, present-epoch | PR | 200 issued by CN=TACRA reference CA S1 for target https://cache.tacra.example | 0.1 | 1.4 |
| D12 present-epoch, epoch moved between the legs | PR | first: 409 epoch-moved; retry: issued by CN=TACRA reference CA S1 for target https://cache.tacra.example | | |
| D13 honest enrollment, absent-epoch | PR | 200 issued by CN=TACRA reference CA S1 for target https://queue.tacra.example | 0.1 | 1.4 |
| D14 honest enrollment, absent-timestamp | PR | 200 issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example | 0.1 | 1.5 |
| D15 absent-timestamp, attest-initiate completed locally | PR | 200 issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example | 0.1 | 1.4 |
| D16 absent-timestamp, clock 120 s behind, max_age 60 | PR | 409 refused: timestamp-out-of-window | 0.1 | 1.0 |
| D17 honest enrollment, absent-none | PR | 200 issued by CN=TACRA reference CA S1 for target https://logs.tacra.example | 0.1 | 1.5 |
| D18 honest retrieval, absent-timestamp | PR | 200 accepted; signing key fingerprint 75890d7dfac55268 | 0.1 | 1.7 |
| D19 one absent-timestamp request posted to S1, then to S2 | PR | S1: issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example; S2: refused: binding-mismatch | | |
| D20 one absent-timestamp request posted to S1, then to S2 | -00 | S1: issued by CN=TACRA reference CA S1-legacy for target https://metrics.tacra.example; S2: issued by CN=TACRA reference CA S2-legacy for target https://metrics.tacra.example | | |
| D21 one absent-timestamp request posted to S1 twice | PR | first: issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example; again: issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example | | |

What the new drills show. D3 is refused where it always was, at S2's recomputation of the binding
with its own identifier; the Attester no longer compares identifiers at all. D3b is the
case the formal model predicts: with no identifier held, the Attester binds the one in S2's
response, and S2 issues; the binding keeps the Evidence to one RRP, but the conduit chose it. D11
to D18 run each Freshness Kind, including a moved epoch (D12: 409, then a retry issues), a
timestamp older than `max_age` (D16: 409) and `attest-initiate` completed locally (D15). D19 to D21
are the shared-freshness cases: one `absent-timestamp` request is accepted at S1 and refused at S2
under the pull request's text, accepted at both under -00, and accepted twice at S1, since the
absent kinds are not single-use.

Message sizes with mock Evidence (bytes): enrollment request 1 980, Evidence 1 026, retrieval
request 1 754, bundle 1 054.

## 3. Drills on a live SEV-SNP guest, `evidence/20260926T234444Z-gcp-sev-snp/drills.json`

VCEK-signed reports; the Attester builds the [ASK, ARK] chain from the host's certificate table and
makes no network request; chain verified to the pinned ARK-Milan by OpenSSL. Every outcome is the
same as on the mock TEE; the numbers are the hardware's.

| drill | text | outcome | evidence ms | round trip ms |
|---|---|---|---|---|
| D1 honest enrollment at S1, present-nonce | PR | 200 issued by CN=TACRA reference CA S1 for target https://db.tacra.example | 10.2 | 44.5 |
| D2 honest retrieval at S1, present-nonce | PR | 200 accepted; signing key fingerprint eb0aaba22cbf2723 | 9.4 | 40.6 |
| D3 RRP substitution, identifier held by the Attester (conduit says CA1, carries to S2) | PR | 403 refused: binding-mismatch | 7.7 | 33.8 |
| D3b RRP substitution, identifier taken from S2's response | PR | 200 issued by CN=TACRA reference CA S2 for target https://db.tacra.example | 7.7 | 33.7 |
| D4 RRP substitution | -00 | 200 issued by CN=TACRA reference CA S2-legacy for target https://db.tacra.example | 9.1 | 33.9 |
| D5 bundle substitution, base-mode container | PR | 200 attester refused the bundle: AttesterError: container 'hpke-base' does not authenticate its origin | 8.8 | 32.8 |
| D5b bundle substitution, forged hpke-auth under the attacker's key | PR | 200 attester refused the bundle: OpenError: Failed to open. | 8.8 | 34.1 |
| D6 bundle substitution | -00 | 200 accepted; signing key fingerprint 75036e95c5b1b3a0 | 8.5 | 34.2 |
| D7 Handle replay | PR | first: issued by CN=TACRA reference CA S1 for target https://db.tacra.example; second: 409 handle-replay | | |
| D9 target substitution (conduit initiates for another Target) | PR | 403 refused: binding-mismatch | 9.3 | 32.5 |
| D10 target substitution | -00 | 200 issued by CN=TACRA reference CA S1-legacy for target https://payments.tacra.example | 10219.7 | 33.7 |
| D11 honest enrollment, present-epoch | PR | 200 issued by CN=TACRA reference CA S1 for target https://cache.tacra.example | 8.6 | 32.4 |
| D12 present-epoch, epoch moved between the legs | PR | first: 409 epoch-moved; retry: issued by CN=TACRA reference CA S1 for target https://cache.tacra.example | | |
| D13 honest enrollment, absent-epoch | PR | 200 issued by CN=TACRA reference CA S1 for target https://queue.tacra.example | 7.8 | 32.9 |
| D14 honest enrollment, absent-timestamp | PR | 200 issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example | 8.4 | 32.5 |
| D15 absent-timestamp, attest-initiate completed locally | PR | 200 issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example | 7.8 | 33.4 |
| D16 absent-timestamp, clock 120 s behind, max_age 60 | PR | 409 refused: timestamp-out-of-window | 8.6 | 2.6 |
| D17 honest enrollment, absent-none | PR | 200 issued by CN=TACRA reference CA S1 for target https://logs.tacra.example | 11.2 | 35.3 |
| D18 honest retrieval, absent-timestamp | PR | 200 accepted; signing key fingerprint eb0aaba22cbf2723 | 8.5 | 32.8 |
| D19 one absent-timestamp request posted to S1, then to S2 | PR | S1: issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example; S2: refused: binding-mismatch | | |
| D20 one absent-timestamp request posted to S1, then to S2 | -00 | S1: issued by CN=TACRA reference CA S1-legacy for target https://metrics.tacra.example; S2: issued by CN=TACRA reference CA S2-legacy for target https://metrics.tacra.example | | |
| D21 one absent-timestamp request posted to S1 twice | PR | first: issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example; again: issued by CN=TACRA reference CA S1 for target https://metrics.tacra.example | | |

D1's Evidence took 10.2 ms. D10's took 10 219.7 ms: that report met the host's throttle
(Section 4), a live instance, inside the drills, of the wait the Handle Lifetime floor provides
for. Server S1: 15 successful requests; Verifier median 31.1 ms (min 29.4, max 41.0); CA and Vault
median 0.5 ms.

Message sizes (bytes): enrollment request 17 395; Evidence 12 583 (report 1 184, VCEK/ASK/ARK
4 667, chain PEM 4 602 built from the host table, as JSON with base64url); retrieval request
17 164; bundle 1 054.

The earlier hardware runs give the same outcomes for the drills each had (D1-D10, or D1-D7 for
20260926T165938Z). D3 was refused there in the same place, at S2's recomputation of the binding
(403 `binding-mismatch`): the conduit told the Attester the identifier it expected, so the
Attester's comparison of `server_id`, which the current code no longer makes, passed.

## 4. How long a report takes, and the host's throttle

`scripts/burst_stats.py` computes these from `drills.json`; the HATLS figures are from
`hatls/evidence/runtime-cost-20260922T153300Z/snp-burst.json`. All SEV-SNP rows time the
`SNP_GET_EXT_REPORT` ioctl alone, except the first run, which timed the whole `tee.report()` call
while its Attester downloaded the KDS chain per report.

| run | chip | unthrottled median | stalls | one stall | rate |
|---|---|---|---|---|---|
| 20260926T234654Z | 1d1f823a4c3294e2 | 7.99 ms (180 calls) | one in every ten of 200 | 10.22-10.24 s | 0.97 per s |
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

On the current run 20260926T234654Z (`evidence/20260926T234444Z-gcp-sev-snp/`):

- `scripts/test_vector.py` recomputes the binding input of the enrollment (Handle, `rrp_id`,
  Target, CSR; 320 octets) and refuses to print a test vector unless its SHA-512 digest equals
  REPORT_DATA of the report in the Evidence. It prints one, and an independent recomputation from
  the printed hex, with no code from `impl/`, gives the same digest and equals REPORT_DATA of
  `D1-report.bin`.
- The report's ECDSA P-384 signature over octets 0h-29Fh verifies under the VCEK with `openssl
  dgst -sha384 -verify` (R and S read as 72-octet little-endian fields, AMD 56860 Table 148); the
  VCEK chains through the ASK to the pinned ARK with `openssl verify`.
- The pinned ARK (`impl/trust/ark-milan.pem`) is DER-identical to the ARK-Milan that AMD's KDS
  served on 26 September 2026 (`https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`), SHA-256
  69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd.
- `scripts/validate_cddl.py` validates all seven messages against the CDDL of the draft
  (`cddl/tacra-est.cddl`, identical to the draft's CDDL block), among them the `absent-timestamp`
  initiation response and request; all three negative controls, a request without `target`,
  Evidence given as a map, and a binding method other than `binding-input`, are refused.
- The Attester makes no network request. Its chain, rebuilt from the host's ASK and ARK, is
  byte-identical to AMD's KDS chain and the report verifies offline. When the certificate table is
  stripped from the Evidence, the Verifier fetches the VCEK and the chain from the KDS and reaches
  the same binding value; a Verifier with `allow_kds_fetch=False` fails closed. This fallback was
  exercised offline against the recorded run, not on these hosts, whose tables are complete.

The Verifier (`impl/verifier.py`, unchanged since 9850c7d) passes all six Google Cloud reports on
record: 12 September 2026 (geoar-verifier run 20260912T224511Z, chip d29ed63f87559fe2) and the five
SEV-SNP runs above.

## 6. What the reference implementation does not cover

- Intel TDX and AWS Nitro Attesters (the Verifier is written for SEV-SNP and the mock; the
  platform-form text of the draft rests on the primary specifications and the earlier
  measurements in `geoar-verifier`).
- CMS and COSE containers for the bundle; only HPKE is implemented.
- Background Check mode; only Passport mode is run.
- A trusted clock for `absent-timestamp`: the Attester reads the guest's system clock, which on a
  confidential VM the host can influence unless the platform protects it. The drills show the
  encoding, the binding and the `max_age` window, not a trusted time source.
- An epoch distribution protocol: `present-epoch` and `absent-epoch` use one in-process epoch
  shared by all servers (`EpochBell`), and the Attester reads the current marker directly, standing
  in for out-of-band distribution.
- Which source of the RRP identifier a deployment uses: the implementation supports both (held
  for the Target, or taken from the response); the choice is open in the draft.
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

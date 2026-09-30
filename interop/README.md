# Interop with the TWI SIG reference implementation

The Trustworthy Workload Identity SIG maintains a second, independent implementation of the EST
profile: `TWI-Unified-Model/globalsign-est` (a fork of `globalsign/est`, MIT, Go), with the
`attest-initiate`, `attest-enroll` and `attest-retrieve` resources in `attest.go` and a mock
Verifier, Credential Authority and Secret Vault in `internal/mockca/attest.go`. Its existence
means the two boxes the working group cares about — an independent implementation, and interop
between implementations — are already reachable.

`interop_tacra_test.go` drives that implementation through its public Go API. Placed in
`internal/mockca/` of a clone and run with `go test -run TestInterop -v`, it produces `RESULTS.txt`.

## What agrees

The happy path matches this specification and ours: `attest-initiate` returns a `present-nonce`
Handle with `expires_in` 300 s; the Attester embeds it in Evidence (they use an EAT COSE_Sign1,
RFC 9711, where we use a JSON mock, so the encodings differ but the shape is the same); the
Credential Authority verifies proof of possession and issues; a replayed Handle is refused. The
retrieval bundle already carries a `server_id` and the Handle in its associated data, as our
Attester-side checks expect (this profile's `rrp_id`, so named since the review of 26 September,
because what it identifies is the Relying Party, not the EST Server). `attest-initiate` takes the Target and the Credential Type as the
query parameters `target` and `credential_type` (`common.go`, lines 43-44), and the mock CA chooses
the mode, enrollment or retrieval, from a per-Target policy (`TargetPolicy` with a name, a mechanism and credential
types, `internal/mockca/attest.go`); the pull request's text and our server do the same.

## What the two findings show, in their own running code

- **T2, the CSR is not bound to Evidence.** The `csr-hash` binding method is declared and its
  presence is required, but `CSRHash()` is never called on the verify path and the mock EAT omits
  the CSR by design (`attest.go` line 190). A conduit that swaps the CSR after Evidence is
  produced still obtains a certificate for the swapped key. This is the CSR-substitution gap; the
  pull request closes it by putting the freshness element, the Target, the RRP identifier
  (`rrp_id`, formerly `server_id`) and the CSR in one binding input that the Credential Authority
  recomputes (in that order since TACRA master 912bd50, 30 September 2026).

- **T3, the bundle authenticates the key holder, not the sender.** `SealCredentialBundle` needs
  only CEKpub, which travels in the request through the untrusted conduit; `Open` checks the AEAD
  and the associated data but not who sealed. A bundle sealed by no Vault is accepted. This is the
  bundle-substitution gap; the pull request closes it with HPKE `mode_auth` or a Vault signature
  plus the Attester-side origin check.

## What this is not

These are implementation-status findings on a declared proof-of-concept, contributed toward the
draft, not a report of a production vulnerability. Both are the expected state of a POC whose
comments already name HPKE as "the baseline the specification will ultimately mandate"
(`attest.go` line 67); the tests turn "will mandate" into a reproducing case.

# The EST profile of TACRA in ProVerif: three attacks, the proofs, and the assumptions

`gen.py` writes twenty-four models from one template so that the "as in -00" and "as in the pull
request" variants differ only in the lines that the pull request changes. `results/` holds the
ProVerif 2.05 output, unedited.

Enrollment queries: **Q1** a certificate issued by server *sid* for CSR *x* was intended by the
Attester for *sid* (any Target); **Q2** it was intended for *sid* and for the same Target;
**Q3** the injective form of Q2 (one issuance per intent). Retrieval: **R1** a secret the
Attester uses was released for it by the Vault and Target it intended; **S** the Vault's secret
stays secret.

| model | binding | Q1 | Q2 | Q3 | R1 | S |
|---|---|---|---|---|---|---|
| `enrollment-nobind.pv` | draft -00: Handle and CSR | false | false | false | | |
| `enrollment-serveronly.pv` | Handle, server_id, CSR (no Target) | true | **false** | false | | |
| `enrollment-bind.pv` | the pull request: Handle, server_id, Target, CSR | true | true | true | | |
| `enrollment-bind-nocompare.pv` | as above, but the Attester does not compare the wire server_id; it binds the server identity from its own CAI configuration | true | true | true | | |
| `enrollment-bind-compromised-s2.pv` | as above; server 2 and its CA key are the attacker's | | true (for server 1) | | | |
| `enrollment-bind-tee-key-leaked.pv` | as above; the TEE attestation key has leaked | false | false | false | | |
| `retrieval-base.pv` | draft -00: bundle encrypted to CEKpub | | | | false | true |
| `retrieval-auth.pv` | the pull request: HPKE `mode_auth` | | | | true | true |
| `retrieval-auth-compromised-vault2.pv` | as above; Vault 2's keys are the attacker's | | | | true | true |

What the rows show. The Attester's comparison of the server_id it receives with the one it is configured for is not what carries the guarantee: without it (fourth row) all three queries still hold, because the Attester binds the server identity from its own configuration and every server recomputes the binding with its own. The CAS can therefore stay transparent to the Attester, as TACRA intends; what the binding needs is a server identity from inside the Attester's trust boundary. Binding server_id alone (the second row) stops a conduit from taking Evidence
to another server, but not from obtaining, at the right server, a credential for a Target the
Attester did not ask for; the Target must be bound too (third row). A compromised second server
or Vault does not weaken the guarantee for the honest one. A leaked TEE attestation key breaks
everything, which is the assumption the protocol rests on. In retrieval, draft -00 keeps the
secret confidential; what it loses is integrity: the Attester can be made to use a secret no
Vault released.

## Where the bound identity comes from: six more models

These ask what the binding guarantees depending on where the Attester gets the server identity it
binds, from its own configuration or from the initiation response that the untrusted conduit
delivers, and on whether the first leg returns a fresh Handle per server session or a shared
public epoch `ep` (absent-epoch with a remote initiate). The issuing server here plays the RATS
Relying Party, the Credential Authority. Two more queries: **B1** a certificate issued by *sid*
for CSR *x* was bound by the Attester to *sid* and the same Target, and **B2** its injective form;
**U1** no two servers issue for the same CSR and Target. Results:
`results/proverif-20260926T232411Z-rrp-source.txt`.

| model | freshness | identity the Attester binds | Q1 | B1 | B2 | U1 |
|---|---|---|---|---|---|---|
| `enrollment-nonce-norrp-uniqueness.pv` | fresh Handle per server | none (the -00 binding) | (false: `enrollment-nobind.pv`) | | | true |
| `enrollment-rrp-from-initiate.pv` | fresh Handle per server | received in the initiation response | false | true | true | true |
| `enrollment-nonce-rrp-configured-uniqueness.pv` | fresh Handle per server | from its own configuration | (true: `enrollment-bind-nocompare.pv`) | | | true |
| `enrollment-epoch-norrp.pv` | shared epoch | none | false | | | **false** |
| `enrollment-epoch-rrp-from-initiate.pv` | shared epoch | received in the initiation response | false | true | | true |
| `enrollment-epoch-rrp-configured.pv` | shared epoch | from its own configuration | true | | | true |

`enrollment-rrp-from-initiate.pv` also asks Q2 and Q3; both are false, by the same trace as Q1.

What the rows show. An identity received in the initiation response keeps any one Evidence to one
server: the server the Attester bound is the only one that can issue (B1, B2). The conduit,
however, chooses that server, so Q1 fails with a fresh Handle and with an epoch alike: it can
initiate at S2, hand S2's response to the Attester, and S2 issues. Only an identity from the
Attester's own configuration gives Q1. With a fresh Handle per server session the Handle alone
already keeps Evidence to one server (U1 holds with no identity bound); with a shared epoch it does
not, and the same Evidence is accepted by both servers (U1 false) until either identity is bound.
When `attest-initiate` is completed locally there is no response to take the identity from, so
configuration is the only source there.

These six models set ProVerif's `preciseActions`. Without it, ProVerif lets one Attester session
read two different initiation responses and reports U1 as "cannot be proved", with no attack trace,
in three of them; `results/proverif-20260926T231625Z-rrp-source-without-preciseActions.txt` is that
run, of the first five. Every other result is the same with or without the setting.

## Three more sources of freshness: nine more models

The same three sources of the bound identity (none, received in the initiation response, from the
Attester's own configuration), crossed with three more ways freshness arrives: the epoch value the
Attester receives in the initiation response (present-epoch); Handles issued by a Verifier and
accepted by both servers (one Handle originator shared across Relying Parties, modelled with a
table the Verifier inserts into and each server looks up); and a timestamp of the Attester's own,
sent in the request and recomputed with by the server (absent-timestamp; time windows are not
modelled, the timestamp is a fresh public value). Results:
`results/proverif-20260926T233733Z-freshness-sources.txt`.

| model | freshness | identity the Attester binds | Q1 | B1 | U1 |
|---|---|---|---|---|---|
| `enrollment-epoch-received-norrp.pv` | epoch received in the response | none | false | | **false** |
| `enrollment-epoch-received-rrp-from-initiate.pv` | epoch received in the response | received in the initiation response | false | true | true |
| `enrollment-epoch-received-rrp-configured.pv` | epoch received in the response | from its own configuration | true | | true |
| `enrollment-verifier-handles-norrp.pv` | a Verifier's Handle, accepted by both servers | none | false | | **false** |
| `enrollment-verifier-handles-rrp-from-initiate.pv` | a Verifier's Handle, accepted by both servers | received in the initiation response | false | true | true |
| `enrollment-verifier-handles-rrp-configured.pv` | a Verifier's Handle, accepted by both servers | from its own configuration | true | | true |
| `enrollment-timestamp-norrp.pv` | the Attester's timestamp, in the request | none | false | | **false** |
| `enrollment-timestamp-rrp-from-initiate.pv` | the Attester's timestamp, in the request | received in the initiation response | false | true | true |
| `enrollment-timestamp-rrp-configured.pv` | the Attester's timestamp, in the request | from its own configuration | true | | true |

What the rows show. Whenever the freshness value is not tied to one server's session, whether a
shared epoch, a Handle any server accepts, or the Attester's own timestamp, the same Evidence is
accepted by both servers unless an identity is bound (U1 false), and binding either identity
restores U1. As with a fresh Handle, only an identity from the Attester's own configuration gives
Q1. These nine models also set `preciseActions`; without it, U1 of the three
`rrp-from-initiate` models comes back "cannot be proved", with no attack trace, and every other
result is the same.

## What is modelled

- The attacker is the network, that is, the untrusted conduit of TACRA Section 7.2: the EST
  Client and the EST Server as conduits. Nothing else is dishonest.
- The TEE attestation key `tk` is private; Evidence is `sign((meas, report_data), tk)` and the
  attacker can obtain genuine Evidence only by getting the honest Attester to produce it.
- Two honest servers exist: S1 (`id1`), the one the Attester is configured to use, and S2 (`id2`),
  with its own CA and Vault. The Attester process always intends S1 and Target `tA`; a server
  accepts whatever Target the conduit names at initiation and requires the same one in the
  second leg, as TACRA Sections 5.2 and 5.3 require.
- Enrollment: the Attester makes a CSK and a self-signed CSR, reads the initiation response from
  the network, produces Evidence over the binding, and hands CSR and Evidence to the network. A
  server issues a Handle, receives CSR and Evidence, verifies the Evidence under `pk(tk)`, the
  measurement, the proof of possession and the binding, and issues.
- Retrieval: the Attester makes a CEK and binds `pk(cek)`; a Vault releases its secret encrypted
  to `pk(cek)`, in base mode or in auth mode; the Attester decrypts and uses the result.
- HPKE `mode_auth` is modelled as `aenc_auth(m, pkR, skS)` with `adec_auth(c, skR, pkS) = m` only
  when `c` was produced under `skS` (RFC 9180 Section 5.1.3: at most two parties can produce the
  shared secret).

## The attacks ProVerif finds

Enrollment, -00 binding. The conduit obtains a Handle from S2 and gives it to the Attester, which
cannot tell whose it is; the Attester binds that Handle and its CSR into Evidence for its intended
S1; the conduit posts CSR and Evidence to S2; S2's checks all pass and S2 issues a certificate for a
CSR the Attester never intended for S2. In the trace: `Issued(id2, csr)` without
`AttesterIntends(id2, csr)`.

Enrollment, `server_id` bound without the Target. The conduit initiates at S1 for a Target of its
own choosing and hands the Handle to the Attester, which binds that Handle, `id1` and its CSR as it
would for its own Target; S1's checks all pass and S1 issues under the conduit's Target. In the
output: from `AttesterIntends(id1, tA, csr)` and any Target `t` the attacker knows,
`Issued(id1, t, csr)`.

Retrieval, base mode. `pk(cek)` travels in the Evidence, so the attacker has it; it encrypts a
secret of its own to `pk(cek)`; the Attester decrypts and uses it. In the trace: `AttesterUses(id1,
s)` for an `s` no Vault released.

## Why the two fixes close them

With `server_id` in the binding input, the Attester only produces Evidence when the initiation
response names the server it is configured to use, and every server recomputes the binding with
its own identity; a Handle from S2 combined with `id1` matches nowhere. With the Target in the
binding input as well, a Handle the conduit obtained for another Target does not match the
Evidence the Attester produced for its own. With `mode_auth`, only a party holding the Vault's
private key can produce a ciphertext the Attester will open.

## Reproduce

    python3 gen.py
    for f in *.pv; do proverif $f; done

ProVerif 2.05 builds from the official source with OCaml; the results in `results/` were produced
on macOS with OCaml 5 and are what the tool printed, unedited, with `###` header lines added for
the version, the date and each model.

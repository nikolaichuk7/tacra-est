# The EST profile of TACRA in ProVerif: two attacks, two proofs

`gen.py` writes four models from one template so that the "as in -00" and "as in the pull
request" variants differ only in the lines that the pull request changes. `results/` holds the
ProVerif 2.05 output, unedited.

| model | what it models | query | result |
|---|---|---|---|
| `enrollment-nobind.pv` | draft-novak-lamps-tacra-est-00: Evidence binds the Freshness Handle and the CSR | `Issued(sid, csr) ==> AttesterIntends(sid, csr)` | **false**: attack found |
| `enrollment-bind.pv` | the pull request: `server_id` in the binding input, checked by the Attester and recomputed by the CA | same | **true** |
| `retrieval-base.pv` | -00: the bundle is "encrypted to CEKpub" (base mode) | `AttesterUses(vid, s) ==> VaultReleased(vid, s)` | **false**: attack found |
| `retrieval-auth.pv` | the pull request: HPKE `mode_auth`, the Attester decrypts under the Vault's public key | same | **true** |

## What is modelled

- The attacker is the network, that is, the untrusted conduit of TACRA Section 7.2: the EST
  Client and the EST Server as conduits. Nothing else is dishonest.
- The TEE attestation key `tk` is private; Evidence is `sign((meas, report_data), tk)` and the
  attacker can obtain genuine Evidence only by getting the honest Attester to produce it.
- Two honest servers exist: S1 (`id1`), the one the Attester intends, and S2 (`id2`), with its own
  CA and Vault. The Attester process always intends S1.
- Enrollment: the Attester makes a CSK and a self-signed CSR, reads the initiation response from
  the network, produces Evidence over the binding, and hands CSR and Evidence to the network. A
  server issues a Handle, receives CSR and Evidence, verifies the Evidence under `pk(tk)`, the
  measurement, the proof of possession and the binding, and issues.
- Retrieval: the Attester makes a CEK and binds `pk(cek)`; a Vault releases its secret encrypted
  to `pk(cek)`, in base mode or in auth mode; the Attester decrypts and uses the result.
- HPKE `mode_auth` is modelled as `aenc_auth(m, pkR, skS)` with `adec_auth(c, skR, pkS) = m` only
  when `c` was produced under `skS` (RFC 9180 Section 5.1.3: at most two parties can produce the
  shared secret).

## The two attacks ProVerif finds

Enrollment, -00 binding. The conduit obtains a Handle from S2 and gives it to the Attester, which
cannot tell whose it is; the Attester binds that Handle and its CSR into Evidence for its intended
S1; the conduit posts CSR and Evidence to S2; S2's checks all pass and S2 issues a certificate for a
CSR the Attester never intended for S2. In the trace: `Issued(id2, csr)` without
`AttesterIntends(id2, csr)`.

Retrieval, base mode. `pk(cek)` travels in the Evidence, so the attacker has it; it encrypts a
secret of its own to `pk(cek)`; the Attester decrypts and uses it. In the trace: `AttesterUses(id1,
s)` for an `s` no Vault released.

## Why the two fixes close them

With `server_id` in the binding input, the Attester only produces Evidence when the initiation
response names its intended server, and every server recomputes the binding with its own
identity; a Handle from S2 combined with `id1` matches nowhere. With `mode_auth`, only a party
holding the Vault's private key can produce a ciphertext the Attester will open.

## Reproduce

    python3 gen.py
    for f in enrollment-nobind enrollment-bind retrieval-base retrieval-auth; do proverif $f.pv; done

ProVerif 2.05 builds from the official source with OCaml; the results in `results/` were produced
on macOS with OCaml 5 and are byte-for-byte what the tool printed.

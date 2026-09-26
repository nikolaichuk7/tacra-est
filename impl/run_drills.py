#!/usr/bin/env python3
"""Runs the reference implementation end to end and records everything: the honest exchanges in
all five Freshness Kinds, the attacks with the -00 text (which succeed), the same attacks against
the pull request's text (which are refused), what binding an RRP identifier taken from the
initiation response does and does not give, Handle replay, a moved epoch, a stale timestamp, and,
on hardware, a burst of reports for the expires_in floor.

  python3 run_drills.py --tee mock     --out ../evidence/<stamp>-mock
  python3 run_drills.py --tee sev-snp  --out /root/evidence/<stamp>     (inside a SEV-SNP guest)

Two EST Servers run in-process, each fronting its own Relying Parties: S1 (CA1, Vault1), those the
Attester intends, and S2 (CA2, Vault2), another honest pair. The conduit is where the attacks live
(TACRA Section 7.2).
"""
import argparse
import base64
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from attester import Attester, AttesterError
from common import b64u, b64u_dec, canonical_json, utc_stamp, write_json
from conduit import Conduit, EvilConduit, ServerEndpoint, TargetSwapConduit
from est_server import CredentialAuthority, EpochBell, SecretVault, ServerState, start_server
from tee import MockTEE, SnpGuestTEE
from verifier import Verifier

# Each server fronts its own Relying Parties; the Evidence binds the RRP's identifier, not the server's.
CA1_ID = "https://ca1.tacra.example"
VAULT1_ID = "https://vault1.tacra.example"
CA2_ID = "https://ca2.tacra.example"
VAULT2_ID = "https://vault2.tacra.example"
HINT = "workload.tacra.example"
TARGET_A = "https://db.tacra.example"          # a Target the Attester seeks a new credential for (Enrollment)
TARGET_B = "https://payments.tacra.example"    # another Target the same servers provision (Enrollment)
TARGET_R = "https://ledger.tacra.example"      # a Target whose existing credential the Vault releases (Retrieval)
TARGET_PE = "https://cache.tacra.example"      # Enrollment, present-epoch
TARGET_AE = "https://queue.tacra.example"      # Enrollment, absent-epoch
TARGET_AT = "https://metrics.tacra.example"    # Enrollment, absent-timestamp
TARGET_AN = "https://logs.tacra.example"       # Enrollment, absent-none
TARGET_ATR = "https://archive.tacra.example"   # Retrieval, absent-timestamp
CTYPE = "x509"
MAX_AGE = 60
# The servers' policy: the mode and the Freshness Kind are decided per Target (TACRA Section 4.4, Goal 1)
TARGETS = {TARGET_A: {"mechanism": "enroll", "credential_types": {CTYPE}},
           TARGET_B: {"mechanism": "enroll", "credential_types": {CTYPE}},
           TARGET_R: {"mechanism": "retrieve", "credential_types": {CTYPE}},
           TARGET_PE: {"mechanism": "enroll", "credential_types": {CTYPE}, "freshness": "present-epoch"},
           TARGET_AE: {"mechanism": "enroll", "credential_types": {CTYPE}, "freshness": "absent-epoch"},
           TARGET_AT: {"mechanism": "enroll", "credential_types": {CTYPE}, "freshness": "absent-timestamp", "max_age": MAX_AGE},
           TARGET_AN: {"mechanism": "enroll", "credential_types": {CTYPE}, "freshness": "absent-none"},
           TARGET_ATR: {"mechanism": "retrieve", "credential_types": {CTYPE}, "freshness": "absent-timestamp", "max_age": MAX_AGE}}


def parse_pkcs7_certs(b64_body: bytes) -> list[x509.Certificate]:
    return pkcs7.load_der_pkcs7_certificates(base64.b64decode(b64_body))


def build_servers(tee_kind: str, mock_root: str | None, pinned_ark: bytes | None, out: str):
    allowed = {MockTEE.MEASUREMENT} if tee_kind == "mock" else None   # hardware: record the measurement, do not gate on it
    bell = EpochBell()                  # one deployment-wide epoch, shared by every server
    servers = {}
    for name, ca_id, vault_id, legacy in (("S1", CA1_ID, VAULT1_ID, False), ("S2", CA2_ID, VAULT2_ID, False),
                                          ("S1-legacy", CA1_ID, VAULT1_ID, True), ("S2-legacy", CA2_ID, VAULT2_ID, True)):
        st = ServerState(name, Verifier(pinned_ark_pem=pinned_ark, allowed_measurements=allowed, mock_root_pem=mock_root),
                         CredentialAuthority("TACRA reference CA %s" % name, {HINT}, ca_id), SecretVault(vault_id),
                         legacy_binding=legacy, bundle_auth_mode=True, log_path=os.path.join(out, "server-%s.jsonl" % name),
                         targets=TARGETS, bell=bell)
        srv, port, cert_path = start_server(st)
        servers[name] = {"state": st, "port": port, "cert": cert_path, "endpoint": ServerEndpoint("127.0.0.1", port, cert_path)}
    return servers, bell


def _certificate_record(rec, a, body):
    certs = parse_pkcs7_certs(body)
    cert = a.accept_certificate(certs[0].public_bytes(serialization.Encoding.DER))
    ext = [e for e in cert.extensions if e.oid.dotted_string == "1.3.6.1.4.1.32473.1"]
    issued_for = json.loads(ext[0].value.value).get("target") if ext else None
    rec["certificate"] = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                          "issued_for_target": issued_for,
                          "serial": hex(cert.serial_number), "der": b64u(cert.public_bytes(serialization.Encoding.DER))}
    rec["response_pkcs7_b64"] = body.decode("ascii")
    rec["outcome"] = "issued by %s for target %s" % (cert.issuer.rfc4514_string(), issued_for)


def drill_enroll(tee, conduit, target=TARGET_A, rrp_id=CA1_ID, legacy=False, local_kind=None,
                 clock=time.time, epoch_source=None):
    """rrp_id: the identifier the Attester holds for the Target (None: it takes the one in the
    initiation response). local_kind: complete attest-initiate locally with this absent-* kind."""
    a = Attester(tee, target, CTYPE, rrp_id=rrp_id, legacy_binding=legacy, clock=clock, epoch_source=epoch_source)
    rec = {"target": target, "rrp_id_held": rrp_id, "legacy_binding": legacy, "local_initiate": local_kind}
    try:
        if local_kind:
            a.local_initiation(local_kind, "enroll")
        else:
            init = conduit.initiate(**a.initiation_params())
            rec["initiation_response"] = init
            a.accept_initiation(init)
        rec["freshness_kind"] = a.freshness_kind
        rec["rrp_id_bound"] = a.bound_rrp_id
        req = a.make_enrollment_request(HINT)
        rec["enrollment_request"] = req
        rec["evidence_ms"] = a.evidence_ms
        st, ct, body = conduit.enroll(req)
        rec["status"] = st
        rec["timings_ms"] = dict(conduit.timings)
        if st == 200:
            _certificate_record(rec, a, body)
        else:
            rec["error"] = body
            rec["outcome"] = "refused: %s" % (body.get("error") if isinstance(body, dict) else body)
    except AttesterError as e:
        rec["outcome"] = "attester refused: %s" % e
    return rec, a


def drill_retrieve(tee, conduit, vault_origin, target=TARGET_R, rrp_id=VAULT1_ID, legacy_bundle=False, forge=None,
                   clock=time.time):
    a = Attester(tee, target, CTYPE, rrp_id=rrp_id, vault_origin_spki_der=vault_origin,
                 legacy_bundle_base_mode=legacy_bundle, clock=clock)
    rec = {"target": target, "rrp_id_held": rrp_id, "legacy_bundle_base_mode": legacy_bundle, "forged_bundle": forge is not None}
    try:
        init = conduit.initiate(**a.initiation_params())
        rec["initiation_response"] = init
        a.accept_initiation(init)
        rec["freshness_kind"] = a.freshness_kind
        rec["rrp_id_bound"] = a.bound_rrp_id
        req = a.make_retrieval_request(HINT)
        rec["retrieval_request"] = req
        rec["evidence_ms"] = a.evidence_ms
        st, ct, body = conduit.retrieve(req)
        rec["status"] = st
        rec["timings_ms"] = dict(conduit.timings)
        if st != 200:
            rec["error"] = body
            rec["outcome"] = "refused by server: %s" % body.get("error")
            return rec, a
        bundle = body
        if forge is not None:
            # the conduit hands the Attester a bundle it made itself, instead of the Vault's
            bundle = forge(a.cek_spki_der, a.bound_rrp_id, a.handle, HINT, body["aad"]["group_id"], target)
        rec["bundle"] = bundle
        try:
            items = a.accept_bundle(bundle, expected_group_id=body["aad"]["group_id"])
            key_pem = items["credential_items"][0]["value"]
            rec["outcome"] = "accepted; signing key fingerprint %s" % key_fingerprint(key_pem)
            rec["accepted"] = True
        except Exception as e:
            rec["outcome"] = "attester refused the bundle: %s: %s" % (type(e).__name__, e)
            rec["accepted"] = False
    except AttesterError as e:
        rec["outcome"] = "attester refused: %s" % e
    return rec, a


def post_again(conduit, req, a):
    """The conduit posts a request it has already seen, unchanged, to the server behind `conduit`."""
    st, ct, body = conduit.enroll(req)
    r = {"status": st}
    if st == 200:
        _certificate_record(r, a, body)
    else:
        r["error"] = body
        r["outcome"] = "refused: %s" % (body.get("error") if isinstance(body, dict) else body)
    return r


def key_fingerprint(pem: str) -> str:
    import hashlib
    k = serialization.load_pem_private_key(pem.encode(), password=None)
    return hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]


def burst(tee, n: int) -> dict:
    """n consecutive reports, for the Handle-lifetime evidence."""
    times = []
    t_start = time.monotonic()
    for i in range(n):
        t0 = time.monotonic()
        tee.report(bytes(64))
        ms = (time.monotonic() - t0) * 1000.0
        if getattr(tee, "last_ioctl_ms", None) is not None:
            ms = tee.last_ioctl_ms          # the chip's time, without certificate handling
        times.append(ms)
    total = time.monotonic() - t_start
    slow = [{"index": i + 1, "ms": round(t, 1)} for i, t in enumerate(times) if t > 1000.0]
    return {"n": n, "median_ms": round(statistics.median(times), 2), "p95_ms": round(sorted(times)[int(0.95 * n) - 1], 2),
            "max_ms": round(max(times), 1), "total_s": round(total, 1), "slow_reports": slow, "per_call_ms": [round(t, 2) for t in times]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tee", choices=["mock", "sev-snp"], required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--burst", type=int, default=0, help="number of consecutive reports to time (hardware)")
    ap.add_argument("--code-rev", default=None, help="git revision of the code, recorded in the evidence")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    stamp = utc_stamp()

    tee = MockTEE() if a.tee == "mock" else SnpGuestTEE()
    mock_root = tee.root_pem() if a.tee == "mock" else None
    pinned_ark = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "trust", "ark-milan.pem"), "rb").read() if a.tee == "sev-snp" else None

    servers, bell = build_servers(a.tee, mock_root, pinned_ark, a.out)
    S1, S2, S1L, S2L = (servers[k] for k in ("S1", "S2", "S1-legacy", "S2-legacy"))
    vault1 = S1["state"].vault.origin_spki_der()
    drills = {"stamp": stamp, "tee": a.tee, "host": os.uname().nodename, "code_rev": a.code_rev, "drills": {}}
    D = drills["drills"]

    # D1 honest enrollment at S1 (present-nonce)
    D["D1_enroll_honest"], _ = drill_enroll(tee, Conduit(S1["endpoint"]))
    # D2 honest retrieval at S1 (present-nonce), origin-authenticated bundle
    D["D2_retrieve_honest"], _ = drill_retrieve(tee, Conduit(S1["endpoint"]), vault1)
    # D3 RRP substitution against the PR text, identifier held by the Attester: the conduit carries the
    # request to S2 and tells the Attester it is CA1; S2's CA recomputes with its own identifier
    D["D3_rrp_substitution_held_id"], _ = drill_enroll(tee, EvilConduit(S2["endpoint"], pretend_rrp_id=CA1_ID))
    # D3b the same, with no identifier held: the Attester binds the one in S2's response, and S2 issues.
    # The binding keeps the Evidence to one RRP, but the conduit chose which (formal/README.md, Q1)
    D["D3b_rrp_substitution_id_from_response"], _ = drill_enroll(tee, EvilConduit(S2["endpoint"]), rrp_id=None)
    # D4 the same attack against the -00 binding (no RRP identifier): reproduces the vulnerability
    D["D4_rrp_substitution_draft00"], _ = drill_enroll(tee, EvilConduit(S2L["endpoint"], pretend_rrp_id=CA1_ID), legacy=True)
    # D5 bundle substitution against the PR text: forged base-mode bundle, Attester in auth mode
    attacker_vault = SecretVault(VAULT1_ID)   # the attacker's own keys; it never holds the real Vault's key
    def attacker_items():
        return {"credential_items": [{"type": "shared-signing-key", "format": "PKCS8-PEM",
                "value": attacker_vault.signing_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                   serialization.NoEncryption()).decode()}], "metadata": {"note": "attacker"}}
    def forge(cek, rid, handle, hint, gid, target=TARGET_R):
        return EvilConduit.forge_bundle(cek, rid, handle, hint, gid, attacker_items(), target)
    D["D5_bundle_substitution_pr_text"], _ = drill_retrieve(tee, Conduit(S1["endpoint"]), vault1, forge=forge)
    # D5b the forged bundle claims to be hpke-auth and is sealed with the attacker's own sender key
    def forge_auth(cek, rid, handle, hint, gid, target=TARGET_R):
        b = forge(cek, rid, handle, hint, gid, target)
        from pyhpke import KEMKey as _K
        from conduit import SUITE as _S
        from attester import hpke_info as _hi
        pkr = _K.from_pyca_cryptography_key(serialization.load_der_public_key(cek))
        enc, ctx = _S.create_sender_context(pkr, info=_hi(rid, handle), sks=_K.from_pyca_cryptography_key(attacker_vault.origin_key))
        b["container"] = "hpke-auth"; b["enc"] = b64u(enc)
        b["ciphertext"] = b64u(ctx.seal(canonical_json(attacker_items()), aad=canonical_json(b["aad"])))
        b["sender_pub"] = b64u(attacker_vault.origin_spki_der())
        return b
    D["D5b_bundle_substitution_forged_auth_pr_text"], _ = drill_retrieve(tee, Conduit(S1["endpoint"]), vault1, forge=forge_auth)
    # D6 the same attack against the -00 Attester (base mode, no origin check): reproduces the vulnerability
    D["D6_bundle_substitution_draft00"], _ = drill_retrieve(tee, Conduit(S1["endpoint"]), vault1, legacy_bundle=True, forge=forge)
    D["D6_bundle_substitution_draft00"]["attacker_key_fingerprint"] = key_fingerprint(attacker_items()["credential_items"][0]["value"])
    # D7 Handle replay: the same present-nonce enrollment request posted twice
    c = Conduit(S1["endpoint"])
    rec, att = drill_enroll(tee, c)
    st, ct, body = c.enroll(rec["enrollment_request"])
    D["D7_handle_replay"] = {"first": rec["outcome"], "second_status": st, "second_error": body if isinstance(body, dict) else None}
    # D9 target substitution against the PR text: the conduit initiates for TARGET_B at the intended server
    D["D9_target_substitution_pr_text"], _ = drill_enroll(tee, TargetSwapConduit(S1["endpoint"], TARGET_B))
    # D10 the same against the -00 binding (neither RRP nor Target bound): reproduces the vulnerability
    D["D10_target_substitution_draft00"], _ = drill_enroll(tee, TargetSwapConduit(S1L["endpoint"], TARGET_B), legacy=True)

    # The other four Freshness Kinds (TACRA Section 2.1), each chosen by the server's policy for a Target
    # D11 present-epoch: the Handle is the current epoch marker
    D["D11_present_epoch_honest"], _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_PE)
    # D12 present-epoch, the epoch moves between the two legs: 409, then a retry of attest-initiate succeeds
    c = Conduit(S1["endpoint"])
    a12 = Attester(tee, TARGET_PE, CTYPE, rrp_id=CA1_ID)
    a12.accept_initiation(c.initiate(**a12.initiation_params()))
    req12 = a12.make_enrollment_request(HINT)
    bell.rotate()
    st12, _, body12 = c.enroll(req12)
    retry, _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_PE)
    D["D12_present_epoch_moved"] = {"first_status": st12, "first_error": body12 if isinstance(body12, dict) else None,
                                    "retry": retry["outcome"], "retry_status": retry.get("status")}
    # D13 absent-epoch: no Handle is returned; the Attester embeds the epoch marker it holds
    D["D13_absent_epoch_honest"], _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_AE, epoch_source=bell.current)
    # D14 absent-timestamp: the Attester's time travels in `handle`, 8 octets, and in the binding input
    D["D14_absent_timestamp_honest"], _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_AT)
    # D15 absent-timestamp with attest-initiate completed locally: the server sees one leg only
    D["D15_absent_timestamp_local_initiate"], _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_AT,
                                                               local_kind="absent-timestamp")
    # D16 absent-timestamp from a clock 120 s behind, with max_age 60: 409
    D["D16_absent_timestamp_stale"], _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_AT,
                                                      clock=lambda: time.time() - 120)
    # D17 absent-none: no freshness element at all
    D["D17_absent_none_honest"], _ = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_AN)
    # D18 absent-timestamp retrieval: the timestamp is also in the bundle's associated data and HPKE info
    D["D18_absent_timestamp_retrieval"], _ = drill_retrieve(tee, Conduit(S1["endpoint"]), vault1, target=TARGET_ATR)
    # D19 shared freshness: one absent-timestamp request, posted to S1 and then, unchanged, to S2. There is
    # no single-use value, so only the RRP identifier in the binding keeps the Evidence to one RRP
    r19, a19 = drill_enroll(tee, Conduit(S1["endpoint"]), target=TARGET_AT, local_kind="absent-timestamp")
    D["D19_shared_freshness_two_rrps"] = {"at_S1": r19["outcome"], "at_S2": post_again(Conduit(S2["endpoint"]), r19["enrollment_request"], a19)["outcome"]}
    # D20 the same against the -00 binding: both CAs issue for the one CSR
    r20, a20 = drill_enroll(tee, Conduit(S1L["endpoint"]), target=TARGET_AT, local_kind="absent-timestamp", legacy=True)
    D["D20_shared_freshness_two_rrps_draft00"] = {"at_S1": r20["outcome"], "at_S2": post_again(Conduit(S2L["endpoint"]), r20["enrollment_request"], a20)["outcome"]}
    # D21 absent-timestamp replay at the same RRP within max_age: accepted; the absent kinds are not single-use
    D["D21_absent_timestamp_replay_same_rrp"] = {"first": r19["outcome"], "again_at_S1": post_again(Conduit(S1["endpoint"]), r19["enrollment_request"], a19)["outcome"]}
    # D8 burst (hardware)
    if a.burst:
        D["D8_report_burst"] = burst(tee, a.burst)

    # sizes of the messages that matter
    e = D["D1_enroll_honest"].get("enrollment_request", {})
    r = D["D2_retrieve_honest"].get("retrieval_request", {})
    drills["sizes_bytes"] = {
        "enrollment_request_json": len(canonical_json(e)) if e else None,
        "evidence_bytes": len(b64u_dec(e["evidence"])) if e else None,
        "evidence_report": len(b64u_dec(json.loads(b64u_dec(e["evidence"]))["report"])) if e else None,
        "evidence_certs_total": sum(len(b64u_dec(v)) for v in json.loads(b64u_dec(e["evidence"])).get("certs", {}).values()) if e else None,
        "evidence_chain_pem": len(json.loads(b64u_dec(e["evidence"])).get("chain", "")) if e else None,
        "retrieval_request_json": len(canonical_json(r)) if r else None,
        "bundle_json": len(canonical_json(D["D2_retrieve_honest"].get("bundle", {}))),
    }
    # server-side logs
    for name, s in servers.items():
        drills.setdefault("server_logs", {})[name] = s["state"].log
    write_json(os.path.join(a.out, "drills.json"), drills)

    # test vectors from the honest exchanges
    vectors = {"stamp": stamp, "tee": a.tee, "code_rev": a.code_rev,
               "enrollment": {"attest_initiate_query": {"target": TARGET_A, "credential_type": CTYPE},
                              "AttestationInitiationResponse": D["D1_enroll_honest"].get("initiation_response"),
                              "AttestedEnrollmentRequest": D["D1_enroll_honest"].get("enrollment_request"),
                              "response_pkcs7_base64": D["D1_enroll_honest"].get("response_pkcs7_b64")},
               "enrollment_absent_timestamp": {"attest_initiate_query": {"target": TARGET_AT, "credential_type": CTYPE},
                              "AttestationInitiationResponse": D["D14_absent_timestamp_honest"].get("initiation_response"),
                              "AttestedEnrollmentRequest": D["D14_absent_timestamp_honest"].get("enrollment_request")},
               "retrieval": {"attest_initiate_query": {"target": TARGET_R, "credential_type": CTYPE},
                             "AttestationInitiationResponse": D["D2_retrieve_honest"].get("initiation_response"),
                             "AttestedRetrievalRequest": D["D2_retrieve_honest"].get("retrieval_request"),
                             "EncryptedCredentialBundle": D["D2_retrieve_honest"].get("bundle"),
                             "vault_origin_spki_der": b64u(vault1)}}
    write_json(os.path.join(a.out, "vectors.json"), vectors)
    # raw hardware evidence as files
    if a.tee == "sev-snp" and e:
        ev = json.loads(b64u_dec(e["evidence"]))
        open(os.path.join(a.out, "D1-report.bin"), "wb").write(b64u_dec(ev["report"]))
        for k, v in ev.get("certs", {}).items():
            open(os.path.join(a.out, "D1-cert-%s.bin" % k), "wb").write(b64u_dec(v))
        open(os.path.join(a.out, "D1-kds-chain.pem"), "w").write(ev.get("chain", ""))

    print(json.dumps({k: v.get("outcome", v) if isinstance(v, dict) else v for k, v in D.items()}, indent=1, default=str)[:6000])
    print("sizes:", drills["sizes_bytes"])
    print("written:", a.out)


if __name__ == "__main__":
    main()

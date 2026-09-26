#!/usr/bin/env python3
"""Runs the reference implementation end to end and records everything: the honest exchanges,
the two attacks with the -00 text (which succeed), the same two attacks against the pull
request's text (which are refused), a Handle replay, and, on hardware, a burst of reports for the
expires_in floor.

  python3 run_drills.py --tee mock     --out ../evidence/<stamp>-mock
  python3 run_drills.py --tee sev-snp  --out /root/evidence/<stamp>     (inside a SEV-SNP guest)

Two EST Servers run in-process: S1, the server the Attester intends, and S2, another honest server
with its own CA and Vault. The conduit is where the attacks live (TACRA Section 7.2).
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
from est_server import CredentialAuthority, SecretVault, ServerState, start_server
from tee import MockTEE, SnpGuestTEE
from verifier import Verifier

S1_ID = "https://s1.tacra.example"
S2_ID = "https://s2.tacra.example"
HINT = "workload.tacra.example"
TARGET_A = "https://db.tacra.example"          # the Target the Attester seeks a new credential for (Enrollment)
TARGET_B = "https://payments.tacra.example"    # another Target the same servers provision (Enrollment)
TARGET_R = "https://ledger.tacra.example"      # a Target whose existing credential the Vault releases (Retrieval)
CTYPE = "x509"
# The servers' policy: Enrollment or Retrieval is decided per Target (TACRA Section 4.4, Goal 1)
TARGETS = {TARGET_A: {"mechanism": "enroll", "credential_types": {CTYPE}},
           TARGET_B: {"mechanism": "enroll", "credential_types": {CTYPE}},
           TARGET_R: {"mechanism": "retrieve", "credential_types": {CTYPE}}}


def parse_pkcs7_certs(b64_body: bytes) -> list[x509.Certificate]:
    return pkcs7.load_der_pkcs7_certificates(base64.b64decode(b64_body))


def build_servers(tee_kind: str, mock_root: str | None, pinned_ark: bytes | None, out: str):
    allowed = {MockTEE.MEASUREMENT} if tee_kind == "mock" else None   # hardware: record the measurement, do not gate on it
    servers = {}
    for name, sid, legacy in (("S1", S1_ID, False), ("S2", S2_ID, False), ("S1-legacy", S1_ID, True), ("S2-legacy", S2_ID, True)):
        st = ServerState(sid, Verifier(pinned_ark_pem=pinned_ark, allowed_measurements=allowed, mock_root_pem=mock_root),
                         CredentialAuthority("TACRA reference CA %s" % name, {HINT}), SecretVault(),
                         legacy_binding=legacy, bundle_auth_mode=True, log_path=os.path.join(out, "server-%s.jsonl" % name),
                         targets=TARGETS)
        srv, port, cert_path = start_server(st)
        servers[name] = {"state": st, "port": port, "cert": cert_path, "endpoint": ServerEndpoint("127.0.0.1", port, cert_path)}
    return servers


def drill_enroll(tee, server_id, conduit, vault_origin=None, legacy=False, target=TARGET_A):
    a = Attester(tee, server_id, target, CTYPE, vault_origin_spki_der=vault_origin, legacy_binding=legacy)
    rec = {"server_id": server_id, "target": target, "legacy_binding": legacy}
    try:
        init = conduit.initiate(**a.initiation_params())
        rec["initiation_response"] = init
        a.accept_initiation(init)
        req = a.make_enrollment_request(HINT)
        rec["enrollment_request"] = req
        rec["evidence_ms"] = a.evidence_ms
        st, ct, body = conduit.enroll(req)
        rec["status"] = st
        rec["timings_ms"] = dict(conduit.timings)
        if st == 200:
            certs = parse_pkcs7_certs(body)
            cert = a.accept_certificate(certs[0].public_bytes(serialization.Encoding.DER))
            ext = [e for e in cert.extensions if e.oid.dotted_string == "1.3.6.1.4.1.32473.1"]
            issued_for = json.loads(ext[0].value.value).get("target") if ext else None
            rec["certificate"] = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                                  "issued_for_target": issued_for,
                                  "serial": hex(cert.serial_number), "der": b64u(cert.public_bytes(serialization.Encoding.DER))}
            rec["response_pkcs7_b64"] = body.decode("ascii")
            rec["outcome"] = "issued by %s for target %s" % (cert.issuer.rfc4514_string(), issued_for)
        else:
            rec["error"] = body
            rec["outcome"] = "refused: %s" % (body.get("error") if isinstance(body, dict) else body)
    except AttesterError as e:
        rec["outcome"] = "attester refused: %s" % e
    return rec, a


def drill_retrieve(tee, server_id, conduit, vault_origin, legacy_bundle=False, forge=None, target=TARGET_R):
    a = Attester(tee, server_id, target, CTYPE, vault_origin_spki_der=vault_origin, legacy_bundle_base_mode=legacy_bundle)
    rec = {"server_id": server_id, "target": target, "legacy_bundle_base_mode": legacy_bundle, "forged_bundle": forge is not None}
    try:
        init = conduit.initiate(**a.initiation_params())
        rec["initiation_response"] = init
        a.accept_initiation(init)
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
            bundle = forge(a.cek_spki_der, server_id, a.handle, HINT, body["aad"]["group_id"], target)
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

    servers = build_servers(a.tee, mock_root, pinned_ark, a.out)
    S1, S2, S1L, S2L = (servers[k] for k in ("S1", "S2", "S1-legacy", "S2-legacy"))
    vault1 = S1["state"].vault.origin_spki_der()
    vault1L = S1L["state"].vault.origin_spki_der()
    drills = {"stamp": stamp, "tee": a.tee, "host": os.uname().nodename, "code_rev": a.code_rev, "drills": {}}
    D = drills["drills"]

    # D1 honest enrollment at S1
    D["D1_enroll_honest"], _ = drill_enroll(tee, S1_ID, Conduit(S1["endpoint"]))
    # D2 honest retrieval at S1, origin-authenticated bundle
    D["D2_retrieve_honest"], _ = drill_retrieve(tee, S1_ID, Conduit(S1["endpoint"]), vault1)
    # D3 server substitution against the PR text: the conduit says S1, carries to S2
    D["D3_server_substitution_pr_text"], _ = drill_enroll(tee, S1_ID, EvilConduit(S2["endpoint"], pretend_server_id=S1_ID))
    # D4 the same attack against the -00 binding (no server_id): reproduces the vulnerability
    D["D4_server_substitution_draft00"], _ = drill_enroll(tee, S1_ID, EvilConduit(S2L["endpoint"], pretend_server_id=S1_ID), legacy=True)
    # D5 bundle substitution against the PR text: forged base-mode bundle, Attester in auth mode
    attacker_vault = SecretVault()   # the attacker's own key; it never signs as S1's Vault
    def forge(cek, sid, handle, hint, gid, target=TARGET_R):
        items = {"credential_items": [{"type": "shared-signing-key", "format": "PKCS8-PEM",
                 "value": attacker_vault.signing_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                    serialization.NoEncryption()).decode()}], "metadata": {"note": "attacker"}}
        return EvilConduit.forge_bundle(cek, sid, handle, hint, gid, items, target)
    D["D5_bundle_substitution_pr_text"], _ = drill_retrieve(tee, S1_ID, Conduit(S1["endpoint"]), vault1, forge=forge)
    # D5b the forged bundle claims to be hpke-auth and is sealed with the attacker's own sender key
    def forge_auth(cek, sid, handle, hint, gid, target=TARGET_R):
        b = forge(cek, sid, handle, hint, gid, target)
        from cryptography.hazmat.primitives import serialization as _ser
        from pyhpke import KEMKey as _K
        pkr = _K.from_pyca_cryptography_key(_ser.load_der_public_key(cek))
        from conduit import SUITE as _S
        from attester import hpke_info as _hi
        enc, ctx = _S.create_sender_context(pkr, info=_hi(sid, handle), sks=_K.from_pyca_cryptography_key(attacker_vault.origin_key))
        items = {"credential_items": [{"type": "shared-signing-key", "format": "PKCS8-PEM",
                 "value": attacker_vault.signing_key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()).decode()}]}
        b["container"] = "hpke-auth"; b["enc"] = b64u(enc); b["ciphertext"] = b64u(ctx.seal(canonical_json(items), aad=canonical_json(b["aad"])))
        b["sender_pub"] = b64u(attacker_vault.origin_spki_der())
        return b
    D["D5b_bundle_substitution_forged_auth_pr_text"], _ = drill_retrieve(tee, S1_ID, Conduit(S1["endpoint"]), vault1, forge=forge_auth)
    # D6 the same attack against the -00 Attester (base mode, no origin check): reproduces the vulnerability
    D["D6_bundle_substitution_draft00"], _ = drill_retrieve(tee, S1_ID, Conduit(S1["endpoint"]), vault1, legacy_bundle=True, forge=forge)
    D["D6_bundle_substitution_draft00"]["attacker_key_fingerprint"] = key_fingerprint(
        attacker_vault.signing_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    # D7 Handle replay: the same enrollment request posted twice
    c = Conduit(S1["endpoint"])
    rec, att = drill_enroll(tee, S1_ID, c)
    st, ct, body = c.enroll(rec["enrollment_request"])
    D["D7_handle_replay"] = {"first": rec["outcome"], "second_status": st, "second_error": body if isinstance(body, dict) else None}
    # D9 target substitution against the PR text: the conduit initiates for TARGET_B at the intended server
    D["D9_target_substitution_pr_text"], _ = drill_enroll(tee, S1_ID, TargetSwapConduit(S1["endpoint"], TARGET_B))
    # D10 the same against the -00 binding (neither server nor Target bound): reproduces the vulnerability
    D["D10_target_substitution_draft00"], _ = drill_enroll(tee, S1_ID, TargetSwapConduit(S1L["endpoint"], TARGET_B), legacy=True)
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

    print(json.dumps({k: v.get("outcome", v) if isinstance(v, dict) else v for k, v in D.items()}, indent=1, default=str)[:4000])
    print("sizes:", drills["sizes_bytes"])
    print("written:", a.out)


if __name__ == "__main__":
    main()

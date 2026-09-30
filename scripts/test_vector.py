#!/usr/bin/env python3
"""Render the Test Vector appendix of the draft from the enrollment of a run, and check it.

The values (Handle, rrp_id, Target, CSR) are those of the run's honest enrollment, so the vector
is tied to the Example Exchange appendix of the same run: SHA-512 of the binding input must equal
REPORT_DATA of the attestation report inside that enrollment's Evidence. The script refuses to
print a vector that fails the check.

The binding input is in the order of TACRA master 912bd50 (30 September 2026): the freshness
element, the Target, the Relying Party identifier, the subject. Runs recorded before then bound
the Relying Party identifier before the Target; --rrp-first checks such a run in that order.

    python3 scripts/test_vector.py evidence/<stamp>-gcp-sev-snp/vectors.json > test-vector.md
    python3 scripts/test_vector.py --rrp-first evidence/20260926T234444Z-gcp-sev-snp/vectors.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "impl"))
import hashlib  # noqa: E402
from common import b64u_dec, binding_input, binding_input_rrp_first, parse_snp_report  # noqa: E402

COLS = 31   # octets per hex line: 2 spaces + 62 hex digits = 64 columns


def hexlines(b: bytes) -> list[str]:
    h = b.hex()
    return ["  " + h[i:i + 2 * COLS] for i in range(0, len(h), 2 * COLS)]


def main(path, rrp_first=False):
    v = json.load(open(path))
    e = v["enrollment"]
    ini, req = e["AttestationInitiationResponse"], e["AttestedEnrollmentRequest"]
    handle, csr = b64u_dec(req["handle"]), b64u_dec(req["csr"])
    rrp_id, target = ini["rrp_id"], req["target"]
    assert target == e["attest_initiate_query"]["target"], "request Target differs from the initiate Target"
    build = binding_input_rrp_first if rrp_first else binding_input
    bi = build(handle=handle, target=target, rrp_id=rrp_id, subject=csr)
    bv = hashlib.sha512(bi).digest()
    ev = json.loads(b64u_dec(req["evidence"]))
    if ev.get("type") == "sev-snp":
        report_data = parse_snp_report(b64u_dec(ev["report"]))["report_data"]
        where = "REPORT_DATA of the attestation report in that Evidence"
    else:
        report_data = bytes.fromhex(json.loads(b64u_dec(ev["report"]))["report_data"])
        where = "report_data of the mock report in that Evidence"
    if bv != report_data:
        sys.exit("binding value does not equal %s; not printing a vector" % where)
    rid, tgt = rrp_id.encode(), target.encode()
    print("# Test Vector for the Binding Input {#test-vector}")
    print()
    print("Enrollment, direct form, SHA-512. The values are those of the enrollment in {{examples}} "
          "(run %s); the SHA-512 digest of binding_input equals %s. The CSR is ECDSA P-256 with subject "
          "CN=workload.tacra.example." % (v["stamp"], where))
    print()
    first, second = (("rrp_id", rid, rrp_id), ("target", tgt, target)) if rrp_first else \
                    (("target", tgt, target), ("rrp_id", rid, rrp_id))
    print("~~~")
    print("handle (%d octets) =" % len(handle))
    print("\n".join(hexlines(handle)))
    for name, raw, text in (first, second):
        print()
        print('%s (%d octets) = "%s"' % (name, len(raw), text))
    print()
    print("subject = CSR DER (%d octets) =" % len(csr))
    print("\n".join(hexlines(csr)))
    print()
    print("binding_input = %08x || handle" % len(handle))
    print("             || %08x || %s" % (len(first[1]), first[0]))
    print("             || %08x || %s" % (len(second[1]), second[0]))
    print("             || %08x || subject        (%d octets)" % (len(csr), len(bi)))
    print()
    print("SHA-512(binding_input) =")
    print("\n".join(hexlines(bv)))
    print("~~~")


if __name__ == "__main__":
    args = sys.argv[1:]
    rrp_first = "--rrp-first" in args
    paths = [a for a in args if a != "--rrp-first"]
    main(paths[0], rrp_first)

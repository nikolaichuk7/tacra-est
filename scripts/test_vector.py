#!/usr/bin/env python3
"""Render the Test Vector appendix of the draft from the enrollment of a run, and check it.

The values (Handle, server_id, Target, CSR) are those of the run's honest enrollment, so the vector
is tied to the Example Exchange appendix of the same run: SHA-512 of the binding input must equal
REPORT_DATA of the attestation report inside that enrollment's Evidence. The script refuses to
print a vector that fails the check.

    python3 scripts/test_vector.py evidence/<stamp>-gcp-sev-snp/vectors.json > test-vector.md
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "impl"))
from common import b64u_dec, binding_input, binding_value, parse_snp_report  # noqa: E402

COLS = 31   # octets per hex line: 2 spaces + 62 hex digits = 64 columns


def hexlines(b: bytes) -> list[str]:
    h = b.hex()
    return ["  " + h[i:i + 2 * COLS] for i in range(0, len(h), 2 * COLS)]


def main(path):
    v = json.load(open(path))
    e = v["enrollment"]
    ini, req = e["AttestationInitiationResponse"], e["AttestedEnrollmentRequest"]
    handle, csr = b64u_dec(req["handle"]), b64u_dec(req["csr"])
    server_id, target = ini["server_id"], req["target"]
    assert target == e["attest_initiate_query"]["target"], "request Target differs from the initiate Target"
    bi = binding_input(handle, server_id, target, csr)
    bv = binding_value(handle, server_id, target, csr, "sha512")
    ev = json.loads(b64u_dec(req["evidence"]))
    if ev.get("type") == "sev-snp":
        report_data = parse_snp_report(b64u_dec(ev["report"]))["report_data"]
        where = "REPORT_DATA of the attestation report in that Evidence"
    else:
        report_data = bytes.fromhex(json.loads(b64u_dec(ev["report"]))["report_data"])
        where = "report_data of the mock report in that Evidence"
    if bv != report_data:
        sys.exit("binding value does not equal %s; not printing a vector" % where)
    sid, tgt = server_id.encode(), target.encode()
    print("# Test Vector for the Binding Input {#test-vector}")
    print()
    print("Enrollment, direct form, SHA-512. The values are those of the enrollment in {{examples}} "
          "(run %s); the SHA-512 digest of binding_input equals %s. The CSR is ECDSA P-256 with subject "
          "CN=workload.tacra.example." % (v["stamp"], where))
    print()
    print("~~~")
    print("handle (%d octets) =" % len(handle))
    print("\n".join(hexlines(handle)))
    print()
    print('server_id (%d octets) = "%s"' % (len(sid), server_id))
    print()
    print('target (%d octets) = "%s"' % (len(tgt), target))
    print()
    print("subject = CSR DER (%d octets) =" % len(csr))
    print("\n".join(hexlines(csr)))
    print()
    print("binding_input = %08x || handle" % len(handle))
    print("             || %08x || server_id" % len(sid))
    print("             || %08x || target" % len(tgt))
    print("             || %08x || subject        (%d octets)" % (len(csr), len(bi)))
    print()
    print("SHA-512(binding_input) =")
    print("\n".join(hexlines(bv)))
    print("~~~")


if __name__ == "__main__":
    main(sys.argv[1])

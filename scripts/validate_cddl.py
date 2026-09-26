#!/usr/bin/env python3
"""Validate the messages of a run (evidence/<stamp>/vectors.json) against the CDDL of the draft
(cddl/tacra-est.cddl), with the `cddl` tool (Ruby gem, Carsten Bormann). JSON members that are
`bstr` in the CDDL carry unpadded base64url, as the draft says; they are decoded and the message
is validated as CBOR. Two negative controls must fail: a request without `target`, and Evidence
given as a map instead of a byte string.

    gem install cddl && pip install cbor2
    python3 scripts/validate_cddl.py evidence/<stamp>/vectors.json
"""
import base64, json, os, subprocess, sys, tempfile
import cbor2

BSTR = {"handle", "csr", "cek_pub", "evidence", "enc", "ciphertext", "sender_pub"}


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def to_cbor(o):
    if isinstance(o, dict):
        return {k: (b64u_dec(v) if (k in BSTR and isinstance(v, str)) else to_cbor(v)) for k, v in o.items() if v is not None}
    if isinstance(o, list):
        return [to_cbor(x) for x in o]
    return o


def validate(spec, rule, obj):
    with tempfile.TemporaryDirectory() as t:
        sp = os.path.join(t, "s.cddl"); open(sp, "w").write("start = %s\n\n%s" % (rule, spec))
        ip = os.path.join(t, "i.cbor"); open(ip, "wb").write(cbor2.dumps(obj))
        return subprocess.run(["cddl", sp, "validate", ip], capture_output=True, text=True).returncode == 0


def main(path):
    here = os.path.dirname(os.path.abspath(__file__))
    spec = open(os.path.join(here, "..", "cddl", "tacra-est.cddl")).read()
    v = json.load(open(path))
    cases = [("attestation-initiation-response", v["enrollment"]["AttestationInitiationResponse"]),
             ("attested-enrollment-request", v["enrollment"]["AttestedEnrollmentRequest"]),
             ("attestation-initiation-response", v["retrieval"]["AttestationInitiationResponse"]),
             ("attested-retrieval-request", v["retrieval"]["AttestedRetrievalRequest"]),
             ("encrypted-credential-bundle", v["retrieval"]["EncryptedCredentialBundle"])]
    ok = True
    for rule, msg in cases:
        r = validate(spec, rule, to_cbor(msg)); ok &= r
        print("%-36s %s" % (rule, "VALID" if r else "INVALID"))
    bad = dict(v["enrollment"]["AttestedEnrollmentRequest"]); bad.pop("target")
    n1 = not validate(spec, "attested-enrollment-request", to_cbor(bad))
    bad2 = to_cbor(dict(v["enrollment"]["AttestedEnrollmentRequest"])); bad2["evidence"] = {"type": "x"}
    n2 = not validate(spec, "attested-enrollment-request", bad2)
    print("negative, request without target:   %s" % ("refused" if n1 else "ACCEPTED (error)"))
    print("negative, evidence as a map:        %s" % ("refused" if n2 else "ACCEPTED (error)"))
    sys.exit(0 if (ok and n1 and n2) else 1)


if __name__ == "__main__":
    main(sys.argv[1])

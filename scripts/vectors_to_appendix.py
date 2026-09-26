#!/usr/bin/env python3
"""Render the test vectors of a run (evidence/<stamp>/vectors.json) as a kramdown-rfc appendix:
one example per structure, JSON as sent, long byte strings shortened with their length and
SHA-256 so that the reader can verify them against the repository without wading through
kilobytes of base64.

    python3 scripts/vectors_to_appendix.py evidence/<stamp>-gcp-sev-snp/vectors.json > appendix.md
"""
import base64
import hashlib
import json
import sys


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def shorten(v, key=""):
    if key == "group_id" and isinstance(v, str) and len(v) == 64:
        return v[:16] + "... (64 hex digits)"
    if isinstance(v, str) and len(v) > 40 and key not in ("server_id", "credential_hint", "detail", "handle"):
        try:
            raw = b64u_dec(v) if not v.startswith("-----BEGIN") else v.encode()
            return "<%d octets, SHA-256 %s>" % (len(raw), hashlib.sha256(raw).hexdigest()[:16])
        except Exception:
            return v[:60] + "..."
    if isinstance(v, dict):
        return {k: shorten(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [shorten(x) for x in v]
    return v


def block(title, obj):
    print("## %s" % title)
    print("")
    print("~~~ json")
    print(json.dumps(shorten(obj), indent=2, sort_keys=True))
    print("~~~")
    print("")


def initiate(mode_title, q, mechanism):
    print("## %s: attest-initiate" % mode_title)
    print("")
    print("The EST Client sends `GET /.well-known/est/attest-initiate` with the query parameters "
          "`target=%s` and `credential_type=%s`, percent-encoded. The EST Server's policy provisions "
          "this Target by %s; its AttestationInitiationResponse:" % (q["target"], q["credential_type"], mechanism))
    print("")


def json_block(obj):
    print("~~~ json")
    print(json.dumps(shorten(obj), indent=2, sort_keys=True))
    print("~~~")
    print("")


def main(path):
    v = json.load(open(path))
    print("# Example Exchange {#examples}")
    print("")
    print("Messages of one enrollment and one retrieval as produced by the reference implementation "
          "{{TACRA-EST-IMPL}} with a %s Attester (run %s%s). Byte strings longer than 40 characters are "
          "shown as their length and SHA-256; the full messages are in the repository." % (
              "live AMD SEV-SNP" if v.get("tee") == "sev-snp" else "mock", v.get("stamp"),
              ", code %s" % v["code_rev"] if v.get("code_rev") else ""))
    print("")
    e = v["enrollment"]
    initiate("Enrollment", e["attest_initiate_query"], "Enrollment")
    json_block(e["AttestationInitiationResponse"])
    print("## Enrollment: AttestedEnrollmentRequest")
    print("")
    json_block(e["AttestedEnrollmentRequest"])
    ev = json.loads(b64u_dec(e["AttestedEnrollmentRequest"]["evidence"]))
    print("The byte string in `evidence`, decoded; `profile` names its format, the JSON object the "
          "Attesting Environment produced, with the attestation report and the certificates of its "
          "signing key:")
    print("")
    json_block(ev)
    r = v["retrieval"]
    initiate("Retrieval", r["attest_initiate_query"], "Retrieval")
    json_block(r["AttestationInitiationResponse"])
    print("## Retrieval: AttestedRetrievalRequest")
    print("")
    json_block(r["AttestedRetrievalRequest"])
    print("## Retrieval: EncryptedCredentialBundle")
    print("")
    json_block(r["EncryptedCredentialBundle"])


if __name__ == "__main__":
    main(sys.argv[1])

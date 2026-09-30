"""Shared definitions for the reference implementation of draft-novak-lamps-tacra-est with the
changes of the "seven items" pull request: the binding input, the JSON envelopes, and the
parsing of an AMD SEV-SNP attestation report.

Every structure here is the JSON form of a structure in the draft; the field names are the
draft's. Byte strings travel as unpadded base64url (RFC 4648 Section 5), as in
draft-ietf-lamps-attestation-freshness.
"""
import base64
import hashlib
import json
import os
import struct
import time

# ---------------------------------------------------------------------------------------------
# Encoding helpers

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_json(obj) -> bytes:
    """Deterministic JSON bytes, used wherever a JSON object is hashed or used as associated data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------------------------
# The binding input (TACRA, "Binding Credential Keys to Evidence"; the order of TACRA master
# 912bd50, 30 September 2026, which put the Target before the Relying Party identifier):
#
#   binding_input = len32(handle)  || handle
#                || len32(target)  || target
#                || len32(rrp_id)  || rrp_id
#                || len32(subject) || subject
#
# handle: the freshness element the request carries (the Freshness Handle for present-nonce and
# present-epoch, the locally held epoch marker for absent-epoch, the Attester's timestamp for
# absent-timestamp), empty only for absent-none; target: UTF-8 of the Target, the RATS-unaware
# Relying Party for which the Attester seeks credentials (TACRA Section 2); rrp_id: UTF-8 of the
# identifier of the RATS Relying Party that will rely on the Evidence (the Credential Authority for
# Enrollment, the Secret Vault for Retrieval); subject: DER of the CSR (Enrollment) or DER
# SubjectPublicKeyInfo of CEKpub (Retrieval). The digest is SHA-512 where the platform field is
# 64 octets.
#
# The arguments are keyword-only, so that no caller can pass the two strings in the wrong order.
# Evidence recorded before 30 September 2026 binds rrp_id before target;
# binding_input_rrp_first() recomputes that order, for checking those runs only.

def len32(b: bytes) -> bytes:
    return struct.pack(">I", len(b))


def binding_input(*, handle: bytes, target: str, rrp_id: str, subject: bytes) -> bytes:
    tgt = target.encode("utf-8")
    rid = rrp_id.encode("utf-8")
    return len32(handle) + handle + len32(tgt) + tgt + len32(rid) + rid + len32(subject) + subject


def binding_input_rrp_first(*, handle: bytes, target: str, rrp_id: str, subject: bytes) -> bytes:
    """The order used before 30 September 2026 (rrp_id before target); only to check old Evidence."""
    tgt = target.encode("utf-8")
    rid = rrp_id.encode("utf-8")
    return len32(handle) + handle + len32(rid) + rid + len32(tgt) + tgt + len32(subject) + subject


HASHES = {"sha512": hashlib.sha512, "sha384": hashlib.sha384, "sha256": hashlib.sha256}


def binding_value(*, handle: bytes, target: str, rrp_id: str, subject: bytes, hash_name: str = "sha512") -> bytes:
    return HASHES[hash_name](binding_input(handle=handle, target=target, rrp_id=rrp_id, subject=subject)).digest()


# absent-timestamp: the Attester's time travels in the request's `handle` field, and so in the
# binding input, as an 8-octet big-endian unsigned count of seconds since 1970-01-01T00:00:00Z
# (the NumericDate of RFC 7519, as an integer).

def encode_timestamp(t: float) -> bytes:
    return struct.pack(">Q", int(t))


def decode_timestamp(b: bytes) -> int:
    if len(b) != 8:
        raise ValueError("an absent-timestamp handle is 8 octets, not %d" % len(b))
    return struct.unpack(">Q", b)[0]


FRESHNESS_KINDS = ("absent-timestamp", "absent-none", "absent-epoch", "present-nonce", "present-epoch")


# Evidence travels as an opaque byte string ("Evidence blobs are opaque byte strings", draft -00,
# Media Types); `profile` names its format. The reference implementation's two profiles carry the
# JSON object the Attesting Environment produced.
PROFILE_SNP = "urn:tacra-est:evidence:sev-snp-json:1"
PROFILE_MOCK = "urn:tacra-est:evidence:mock-json:1"


def encode_evidence(ev: dict) -> bytes:
    return canonical_json(ev)


def decode_evidence(b: bytes) -> dict:
    return json.loads(b)


# ---------------------------------------------------------------------------------------------
# AMD SEV-SNP ATTESTATION_REPORT, as defined in AMD publication 56860, SEV Secure Nested Paging
# Firmware ABI Specification, revision 1.59 (August 2026), Table 27. The signed portion is bytes
# 0h..29Fh; SIGNATURE is at 2A0h..49Fh in the format of Table 148 (ECDSA P-384 with SHA-384): R at
# 000h and S at 048h, each 72 bytes, zero-extended little-endian.

SNP_REPORT_LEN = 1184
SNP_SIGNED_LEN = 0x2A0
SNP_KNOWN_VERSIONS = (2, 3, 4, 5, 6)      # rev 1.59 sets VERSION to 6h
# SIGNING_KEY, bits 4:2 of offset 48h (Table 27)
SNP_SIGNING_KEY = {0: "VCEK", 1: "VLEK", 2: "CSVCEK", 7: "none"}
# Byte ranges Table 27 marks reserved and must-be-zero in every report version 2..6
SNP_RESERVED_MBZ = ((0x4C, 0x50), (0x18B, 0x1A0), (0x208, 0x220), (0x280, 0x2A0))


def parse_snp_report(rep: bytes) -> dict:
    if len(rep) < SNP_REPORT_LEN:
        raise ValueError("report too short: %d bytes" % len(rep))
    rep = rep[:SNP_REPORT_LEN]
    version = struct.unpack_from("<I", rep, 0x00)[0]
    policy = struct.unpack_from("<Q", rep, 0x08)[0]
    flags = struct.unpack_from("<I", rep, 0x48)[0]
    reported_tcb = rep[0x180:0x188]
    sig_r = rep[0x2A0:0x2A0 + 72]
    sig_s = rep[0x2A0 + 72:0x2A0 + 144]
    reserved_ok = (flags >> 6) == 0 and all(rep[a:b] == bytes(b - a) for a, b in SNP_RESERVED_MBZ)
    return {
        "version": version,
        "policy": policy,
        "policy_debug": bool((policy >> 19) & 1),      # Table 12: DEBUG is bit 19
        "signing_key": SNP_SIGNING_KEY.get((flags >> 2) & 7, "reserved-%d" % ((flags >> 2) & 7)),
        "mask_chip_key": (flags >> 1) & 1,              # 1: the report is NOT signed (Section 3.6)
        "author_key_en": flags & 1,
        "reserved_mbz_ok": reserved_ok,
        "report_data": rep[0x50:0x90],
        "measurement": rep[0x90:0xC0],
        "host_data": rep[0xC0:0xE0],
        "id_key_digest": rep[0xE0:0x110],
        "author_key_digest": rep[0x110:0x140],
        "report_id": rep[0x140:0x160],
        "report_id_ma": rep[0x160:0x180],
        "reported_tcb": {"bl": reported_tcb[0], "tee": reported_tcb[1], "snp": reported_tcb[6], "ucode": reported_tcb[7]},
        "chip_id": rep[0x1A0:0x1E0],
        "chip_id_zero": rep[0x1A0:0x1E0] == bytes(64),  # MASK_CHIP_ID set by the hypervisor (Section 8.7, Table 51)
        "signature_r": sig_r,
        "signature_s": sig_s,
        # R and S are 72-byte zero-extended little-endian fields; a P-384 value fits in 48 bytes
        "signature_zero_extended": sig_r[48:] == bytes(24) and sig_s[48:] == bytes(24),
        "signature_all_zero": rep[0x2A0:0x4A0] == bytes(0x200),
    }


def kds_vcek_url(product: str, chip_id: bytes, tcb: dict) -> str:
    return ("https://kdsintf.amd.com/vcek/v1/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d"
            % (product, chip_id.hex(), tcb["bl"], tcb["tee"], tcb["snp"], tcb["ucode"]))


# ---------------------------------------------------------------------------------------------
# Envelopes. Each function returns a plain dict; the HTTP layer serialises it as JSON with the
# media types the draft asks IANA to register.

MEDIA = {
    "initiation": "application/est-attest-initiate+json",
    "enroll": "application/est-attest-enroll+json",
    "retrieve": "application/est-attest-retrieve+json",
    "bundle": "application/est-attest-bundle+json",
    "error": "application/problem+json",
}


def initiation_response(freshness_kind: str, handle: bytes | None, rrp_id: str, mode: str,
                        expires_in: int | None, acceptable: list[str],
                        acceptable_evidence: list[str] | None = None, max_age: int | None = None) -> dict:
    r = {"freshness_kind": freshness_kind, "rrp_id": rrp_id, "mode": mode}
    if handle is not None:
        r["handle"] = b64u(handle)
    if expires_in is not None:
        r["expires_in"] = expires_in
    if max_age is not None:
        r["max_age"] = max_age
    if mode == "enroll":
        r["acceptable_csk"] = acceptable
    else:
        r["acceptable_cek"] = acceptable
    if acceptable_evidence:
        r["acceptable_evidence"] = acceptable_evidence
    return r


def _request(freshness_kind: str, target: str, credential_type: str, handle: bytes | None,
             evidence: bytes, profile: str, hash_name: str, credential_hint: str | None) -> dict:
    r = {"freshness_kind": freshness_kind, "target": target, "credential_type": credential_type,
         "evidence": b64u(evidence), "profile": profile,
         "binding": {"method": "binding-input", "hash": hash_name}}
    if handle:
        r["handle"] = b64u(handle)
    if credential_hint:
        r["credential_hint"] = credential_hint
    return r


def enrollment_request(freshness_kind: str, target: str, credential_type: str, handle: bytes | None,
                       csr_der: bytes, evidence: bytes, profile: str, hash_name: str,
                       credential_hint: str | None = None) -> dict:
    r = _request(freshness_kind, target, credential_type, handle, evidence, profile, hash_name, credential_hint)
    r["csr"] = b64u(csr_der)
    return r


def retrieval_request(freshness_kind: str, target: str, credential_type: str, handle: bytes | None,
                      cek_spki_der: bytes, evidence: bytes, profile: str, hash_name: str,
                      credential_hint: str | None = None) -> dict:
    r = _request(freshness_kind, target, credential_type, handle, evidence, profile, hash_name, credential_hint)
    r["cek_pub"] = b64u(cek_spki_der)
    return r


def error_body(error: str, detail: str, correlation_id: str | None = None) -> dict:
    r = {"error": error, "detail": detail}
    if correlation_id:
        r["correlation_id"] = correlation_id
    return r


# ---------------------------------------------------------------------------------------------
# Timing: monotonic stamps for the measurement record.

def now_ms() -> float:
    return time.monotonic() * 1000.0


def utc_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=True, default=str)

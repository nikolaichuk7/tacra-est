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
# The binding input (pull request, "Binding Input"):
#
#   binding_input = len32(handle) || handle || len32(server_id) || server_id || len32(subject) || subject
#
# handle: the Freshness Handle, empty for absent-* kinds; server_id: UTF-8 of the server_id string;
# subject: DER of the CSR (Enrollment) or DER SubjectPublicKeyInfo of CEKpub (Retrieval).
# The digest is SHA-512 where the platform field is 64 octets.

def len32(b: bytes) -> bytes:
    return struct.pack(">I", len(b))


def binding_input(handle: bytes, server_id: str, subject: bytes) -> bytes:
    sid = server_id.encode("utf-8")
    return len32(handle) + handle + len32(sid) + sid + len32(subject) + subject


HASHES = {"sha512": hashlib.sha512, "sha384": hashlib.sha384, "sha256": hashlib.sha256}


def binding_value(handle: bytes, server_id: str, subject: bytes, hash_name: str = "sha512") -> bytes:
    return HASHES[hash_name](binding_input(handle, server_id, subject)).digest()


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


def initiation_response(freshness_kind: str, handle: bytes | None, server_id: str, mode: str,
                        expires_in: int | None, acceptable: list[str]) -> dict:
    r = {"freshness_kind": freshness_kind, "server_id": server_id, "mode": mode}
    if handle is not None:
        r["handle"] = b64u(handle)
    if expires_in is not None:
        r["expires_in"] = expires_in
    if mode == "enroll":
        r["acceptable_csk"] = acceptable
    else:
        r["acceptable_cek"] = acceptable
    return r


def enrollment_request(handle: bytes | None, csr_der: bytes, evidence: dict, hash_name: str,
                       credential_hint: str | None = None) -> dict:
    r = {"csr": b64u(csr_der), "evidence": evidence,
         "binding": {"method": "binding-input", "hash": hash_name}}
    if handle is not None:
        r["handle"] = b64u(handle)
    if credential_hint:
        r["credential_hint"] = credential_hint
    return r


def retrieval_request(handle: bytes | None, cek_spki_der: bytes, evidence: dict, hash_name: str,
                      credential_hint: str | None = None) -> dict:
    r = {"cek_pub": b64u(cek_spki_der), "evidence": evidence,
         "binding": {"method": "binding-input", "hash": hash_name}}
    if handle is not None:
        r["handle"] = b64u(handle)
    if credential_hint:
        r["credential_hint"] = credential_hint
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

"""The RATS Verifier of the reference implementation: appraises Evidence and produces
Attestation Results the Relying Parties (Credential Authority, Secret Vault) act on.

For SEV-SNP the appraisal is: report structure and version; ECDSA-P384 signature under the VCEK;
VCEK -> SEV-Milan (ASK) -> ARK-Milan chain, verified by OpenSSL against the pinned ARK (AMD's ASK
and ARK certificates encode the RSA-PSS trailerField explicitly, which the `cryptography` DER
parser rejects, so the chain step is delegated); the VCEK's hwID extension equals the report's
CHIP_ID; the guest policy does not permit debug; and, if configured, the launch measurement is
in the allow-list. The binding value the Relying Party recomputes is the report's REPORT_DATA.

For the mock the appraisal is the signature under the mock root.

Attestation Results carry what the Relying Party needs and nothing it does not: the binding
value and the hash it was produced with, the platform form (direct / provider-scoped), the
measurement, the per-instance identifiers, and the list of checks with their outcomes.
"""
import os
import subprocess
import tempfile
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asn1

from common import b64u_dec, parse_snp_report, SNP_SIGNED_LEN, SNP_REPORT_LEN, SNP_KNOWN_VERSIONS

HWID_OID = "1.3.6.1.4.1.3704.1.4"


def _load_cert(b: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(b) if b[:10] == b"-----BEGIN" else x509.load_der_x509_certificate(b)


def snp_signature_ok(rep: bytes, vcek: x509.Certificate) -> bool:
    r = int.from_bytes(rep[0x2A0:0x2A0 + 72], "little")         # Table 148: 72-byte fields
    s = int.from_bytes(rep[0x2A0 + 72:0x2A0 + 144], "little")
    try:
        vcek.public_key().verify(asn1.encode_dss_signature(r, s), rep[:SNP_SIGNED_LEN], ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False


def chain_ok_openssl(vcek_der: bytes, chain_pem: bytes, pinned_ark_pem: bytes | None) -> tuple[bool, str]:
    """VCEK -> ASK -> ARK by `openssl verify`. The KDS chain file is [ASK, ARK]. If a pinned ARK is
    given it is the trust anchor and the ARK from the chain must be byte-identical to it."""
    import re
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", chain_pem, re.S)
    if len(blocks) != 2:
        return False, "chain does not hold exactly two certificates"
    ask, ark = blocks
    if pinned_ark_pem is not None and ark.strip() != pinned_ark_pem.strip():
        return False, "ARK in the chain differs from the pinned ARK"
    with tempfile.TemporaryDirectory() as t:
        p_ask, p_ark, p_vcek = (os.path.join(t, n) for n in ("ask.pem", "ark.pem", "vcek.pem"))
        open(p_ask, "wb").write(ask)
        open(p_ark, "wb").write(ark)
        leaf = subprocess.run(["openssl", "x509", "-inform", "DER"], input=vcek_der, capture_output=True)
        if leaf.returncode:
            return False, "VCEK is not a DER certificate"
        open(p_vcek, "wb").write(leaf.stdout)
        anchor = subprocess.run(["openssl", "verify", "-CAfile", p_ark, p_ark], capture_output=True)
        r = subprocess.run(["openssl", "verify", "-CAfile", p_ark, "-untrusted", p_ask, p_vcek], capture_output=True)
        ok = anchor.returncode == 0 and r.returncode == 0 and b": OK" in r.stdout
        return ok, (r.stdout + r.stderr).decode("utf-8", "replace").strip()


class Verifier:
    def __init__(self, pinned_ark_pem: bytes | None = None, allowed_measurements: set[bytes] | None = None,
                 mock_root_pem: str | None = None, refuse_debug: bool = True):
        self.pinned_ark_pem = pinned_ark_pem
        self.allowed_measurements = allowed_measurements
        self.mock_root_pem = mock_root_pem
        self.refuse_debug = refuse_debug

    # -- entry point -------------------------------------------------------------------------
    def appraise(self, evidence: dict) -> dict:
        t = evidence.get("type")
        if t == "sev-snp":
            return self._appraise_snp(evidence)
        if t == "mock":
            return self._appraise_mock(evidence)
        return {"ok": False, "reason": "unknown evidence type %r" % t, "checks": {}}

    # -- SEV-SNP -----------------------------------------------------------------------------
    def _appraise_snp(self, ev: dict) -> dict:
        """Appraisal per AMD 56860 rev 1.59: Table 27 (report), Section 3.6 (MaskChipKey), Section 8.7
        Table 51 (MaskChipId), Table 148 (signature format)."""
        checks = {}
        try:
            rep = b64u_dec(ev["report"])
            p = parse_snp_report(rep)
        except Exception as e:
            return {"ok": False, "reason": "report unparsable: %s" % e, "checks": checks}
        checks["report_length"] = len(rep) >= SNP_REPORT_LEN
        checks["report_version_known"] = p["version"] in SNP_KNOWN_VERSIONS
        checks["reserved_fields_zero"] = p["reserved_mbz_ok"]
        # Section 3.6: with MaskChipKey set the firmware writes zeroes instead of a signature.
        checks["report_is_signed"] = not p["mask_chip_key"] and not p["signature_all_zero"]
        checks["signature_zero_extended"] = p["signature_zero_extended"]
        signer = p["signing_key"] if p["signing_key"] in ("VCEK", "VLEK", "CSVCEK") else None
        certs = {k: b64u_dec(v) for k, v in (ev.get("certs") or {}).items()}
        cert_der = certs.get(signer) if signer else None
        checks["signing_certificate_present"] = cert_der is not None
        sig_ok = False
        hwid_ok = None
        if cert_der and checks["report_is_signed"]:
            cert = _load_cert(cert_der)
            sig_ok = snp_signature_ok(rep, cert)
            if signer in ("VCEK", "CSVCEK") and not p["chip_id_zero"]:
                hw = [e for e in cert.extensions if e.oid.dotted_string == HWID_OID]
                hwid_ok = bool(hw) and hw[0].value.value[-64:] == p["chip_id"]
        checks["report_signature"] = sig_ok
        chain_ok, chain_detail = (False, "no chain")
        if cert_der and ev.get("chain"):
            chain_ok, chain_detail = chain_ok_openssl(cert_der, ev["chain"].encode("ascii"), self.pinned_ark_pem)
        checks["chain_to_ark"] = chain_ok
        if hwid_ok is not None:
            checks["hwid_equals_chip_id"] = hwid_ok
        checks["policy_no_debug"] = (not p["policy_debug"]) if self.refuse_debug else True
        if self.allowed_measurements is not None:
            checks["measurement_allowed"] = p["measurement"] in self.allowed_measurements
        # Platform form: a VLEK names the provider's key domain; a zero CHIP_ID (MaskChipId) names no chip.
        form = "provider-scoped" if (signer == "VLEK" or p["chip_id_zero"]) else "direct"
        ok = all(v for v in checks.values() if v is not None)
        reason = None if ok else "; ".join(k for k, v in checks.items() if v is False)
        if not chain_ok and cert_der:
            reason = (reason or "") + " [chain: %s]" % chain_detail
        return {
            "ok": ok, "reason": reason, "platform": "sev-snp", "platform_form": form,
            "report_version": p["version"],
            "binding_value": p["report_data"].hex(), "hash": "sha512",
            "measurement": p["measurement"].hex(), "chip_id": p["chip_id"].hex(), "report_id": p["report_id"].hex(),
            "signing_key": p["signing_key"], "reported_tcb": p["reported_tcb"], "checks": checks,
        }

    # -- mock --------------------------------------------------------------------------------
    def _appraise_mock(self, ev: dict) -> dict:
        checks = {}
        try:
            raw = b64u_dec(ev["report"])
            body = json.loads(raw)
            sig = b64u_dec(ev["sig"])
        except Exception as e:
            return {"ok": False, "reason": "mock report unparsable: %s" % e, "checks": checks}
        pub_pem = ev.get("pub", "")
        checks["root_is_the_configured_mock_root"] = (self.mock_root_pem is not None and pub_pem.strip() == self.mock_root_pem.strip())
        try:
            pub = serialization.load_pem_public_key(pub_pem.encode("ascii"))
            pub.verify(sig, raw, ec.ECDSA(hashes.SHA256()))
            checks["report_signature"] = True
        except Exception:
            checks["report_signature"] = False
        meas = bytes.fromhex(body.get("measurement", ""))
        if self.allowed_measurements is not None:
            checks["measurement_allowed"] = meas in self.allowed_measurements
        ok = all(checks.values())
        return {
            "ok": ok, "reason": None if ok else "; ".join(k for k, v in checks.items() if not v),
            "platform": "mock", "platform_form": ev.get("platform_form", "direct"),
            "binding_value": body.get("report_data", ""), "hash": "sha512",
            "measurement": meas.hex(), "chip_id": body.get("chip_id", ""), "report_id": body.get("report_id", ""),
            "signing_key": "mock", "checks": checks,
        }

"""The Attester of draft-novak-lamps-tacra-est: generates keys, Evidence and CSRs inside the
Attesting Environment, and performs the Attester-side checks the pull request adds.

The Attester never talks to the network itself; it hands messages to a conduit (the EST Client)
and receives responses from it, exactly as the draft's Figure 1 has it. Everything the conduit
returns is treated as untrusted input.

Two identities are kept apart, as TACRA keeps them apart:
  target  the Target: the RATS-unaware Relying Party for which the Attester seeks credentials
          (TACRA Section 2), e.g. a database the workload will authenticate to;
  rrp_id  the RATS Relying Party that will rely on the Evidence: the Credential Authority
          (Enrollment) or the Secret Vault (Retrieval). The Attester binds the identifier its
          Credential Acquisition Interface holds for the Target, if it holds one, and otherwise
          the one in the attest-initiate response, and compares the two with nothing. Only a held
          identifier makes the RRP the one the deployment intended; one taken from the response
          keeps the Evidence to a single RRP, which the conduit chooses (formal/README.md).
Both go into the binding input, so the conduit can change neither once the Evidence exists.

Freshness, the five kinds of TACRA Section 2.1: present-nonce and present-epoch take the Handle
from the response; absent-epoch embeds the epoch marker the Attester holds (epoch_source);
absent-timestamp embeds the Attester's time (clock) as an 8-octet big-endian count of seconds;
absent-none embeds nothing. For the absent kinds attest-initiate can be completed locally.
"""
import hashlib
import json
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import NameOID
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from common import (FRESHNESS_KINDS, PROFILE_MOCK, PROFILE_SNP, b64u_dec, binding_value, canonical_json,
                    encode_evidence, encode_timestamp, enrollment_request, retrieval_request)

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)


class AttesterError(Exception):
    pass


def hpke_info(rrp_id: str, handle: bytes | None) -> bytes:
    """info parameter of the HPKE context: the RRP identifier and the freshness element,
    length-prefixed, so that the ciphertext is bound to the sender's identity as RFC 9180
    Section 5.1.3 recommends."""
    rid = rrp_id.encode("utf-8")
    h = handle or b""
    return len(rid).to_bytes(4, "big") + rid + len(h).to_bytes(4, "big") + h


class Attester:
    def __init__(self, tee, target: str, credential_type: str, rrp_id: str | None = None,
                 vault_origin_spki_der: bytes | None = None, hash_name: str = "sha512",
                 subject_cn: str = "workload.tacra.example", epoch_source=None, clock=time.time,
                 legacy_bundle_base_mode: bool = False, legacy_binding: bool = False):
        self.tee = tee
        self.target = target                    # TACRA Target
        self.credential_type = credential_type
        self.rrp_id = rrp_id                    # held in the CAI's configuration for this Target, or None
        self.bound_rrp_id: str | None = None    # the identifier the Evidence binds
        self.epoch_source = epoch_source        # absent-epoch: returns the epoch marker held locally
        self.clock = clock                      # absent-timestamp: the Attester's trusted clock
        self.vault_origin_spki_der = vault_origin_spki_der
        self.hash_name = hash_name
        self.subject_cn = subject_cn
        self.legacy_bundle_base_mode = legacy_bundle_base_mode   # -00 behaviour, for the attack drills
        self.legacy_binding = legacy_binding                     # -00 binding H(handle || subject)
        self.handle: bytes | None = None
        self.freshness_kind: str | None = None
        self.mode: str | None = None
        self.csk = None
        self.cek = None
        self.csr_der: bytes | None = None
        self.cek_spki_der: bytes | None = None
        self.credential_hint: str | None = None
        self.evidence_ms: float | None = None

    def initiation_params(self) -> dict:
        """What the Attester asks the conduit to send in attest-initiate (TACRA Section 5.1)."""
        return {"target": self.target, "credential_type": self.credential_type}

    def _binding(self, subject: bytes) -> bytes:
        if self.freshness_kind == "absent-timestamp":
            self.handle = encode_timestamp(self.clock())    # stamped as the Evidence is produced
        if self.legacy_binding:
            return hashlib.sha512((self.handle or b"") + subject).digest()
        return binding_value(self.handle, self.bound_rrp_id, self.target, subject, self.hash_name)

    def _evidence(self, bv: bytes) -> tuple[bytes, str]:
        t0 = time.monotonic()
        ev = self.tee.report(bv)
        self.evidence_ms = (time.monotonic() - t0) * 1000.0
        profile = PROFILE_SNP if ev.get("type") == "sev-snp" else PROFILE_MOCK
        return encode_evidence(ev), profile

    def _set_freshness(self, kind: str, response_handle: bytes | None) -> None:
        if kind in ("present-nonce", "present-epoch"):
            self.handle = response_handle
        elif kind == "absent-epoch":
            if self.epoch_source is None:
                raise AttesterError("absent-epoch, but no epoch marker is held locally")
            self.handle = self.epoch_source()
        else:                                   # absent-timestamp: set when the Evidence is produced
            self.handle = b""
        self.freshness_kind = kind

    # -- first leg ---------------------------------------------------------------------------
    def accept_initiation(self, response: dict) -> None:
        """AttestationInitiationResponse, as delivered by the conduit."""
        kind = response.get("freshness_kind")
        if kind not in FRESHNESS_KINDS:
            raise AttesterError("unknown freshness_kind %r" % kind)
        if kind.startswith("present-") and "handle" not in response:
            raise AttesterError("freshness_kind %s without a handle" % kind)
        if kind.startswith("absent-") and "handle" in response:
            raise AttesterError("handle present for an absent-* freshness kind")
        self.mode = response.get("mode")
        if self.mode not in ("enroll", "retrieve"):
            raise AttesterError("unknown mode %r" % self.mode)
        self._set_freshness(kind, b64u_dec(response["handle"]) if "handle" in response else None)
        self.bound_rrp_id = self.rrp_id or response.get("rrp_id")
        if not self.bound_rrp_id:
            raise AttesterError("no RRP identifier: none held for the Target and none in the response")

    def local_initiation(self, freshness_kind: str, mode: str) -> None:
        """attest-initiate completed locally: only for an absent-* kind, and only with the RRP
        identifier held for the Target, since there is no response to take it from."""
        if not freshness_kind.startswith("absent-") or freshness_kind not in FRESHNESS_KINDS:
            raise AttesterError("only an absent-* freshness kind can be initiated locally")
        if not self.rrp_id:
            raise AttesterError("a local attest-initiate needs the RRP identifier held for the Target")
        if mode not in ("enroll", "retrieve"):
            raise AttesterError("unknown mode %r" % mode)
        self.mode = mode
        self._set_freshness(freshness_kind, None)
        self.bound_rrp_id = self.rrp_id

    # -- enrollment --------------------------------------------------------------------------
    def make_enrollment_request(self, credential_hint: str | None = None) -> dict:
        assert self.mode == "enroll" and self.handle is not None
        self.csk = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.subject_cn)]))
               .sign(self.csk, hashes.SHA256()))
        self.csr_der = csr.public_bytes(serialization.Encoding.DER)
        self.credential_hint = credential_hint
        evidence, profile = self._evidence(self._binding(self.csr_der))
        return enrollment_request(self.freshness_kind, self.target, self.credential_type, self.handle or None,
                                  self.csr_der, evidence, profile, self.hash_name, credential_hint)

    def accept_certificate(self, cert_der: bytes) -> x509.Certificate:
        cert = x509.load_der_x509_certificate(cert_der)
        mine = self.csk.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        theirs = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if mine != theirs:
            raise AttesterError("certificate is not for my CSK")
        return cert

    # -- retrieval ---------------------------------------------------------------------------
    def make_retrieval_request(self, credential_hint: str | None = None) -> dict:
        assert self.mode == "retrieve" and self.handle is not None
        self.cek = x25519.X25519PrivateKey.generate()
        self.cek_spki_der = self.cek.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.credential_hint = credential_hint
        evidence, profile = self._evidence(self._binding(self.cek_spki_der))
        return retrieval_request(self.freshness_kind, self.target, self.credential_type, self.handle or None,
                                 self.cek_spki_der, evidence, profile, self.hash_name, credential_hint)

    def accept_bundle(self, bundle: dict, expected_group_id: str | None = None) -> dict:
        """Attester Processing (pull request, 9.2.6): origin, then rrp_id, target and handle in
        the associated data, then decrypt and check group_id and credential_hint."""
        aad = bundle.get("aad") or {}
        if aad.get("rrp_id") != self.bound_rrp_id:
            raise AttesterError("bundle rrp_id %r is not the RRP %r my Evidence binds" % (aad.get("rrp_id"), self.bound_rrp_id))
        if aad.get("target") != self.target:
            raise AttesterError("bundle target %r is not my Target %r" % (aad.get("target"), self.target))
        h = b64u_dec(aad["handle"]) if aad.get("handle") else b""
        if h != (self.handle or b""):
            raise AttesterError("bundle handle differs from the freshness element I embedded")
        if (aad.get("credential_hint") or None) != (self.credential_hint or None):
            raise AttesterError("bundle credential_hint differs from the one I requested")
        aad_bytes = canonical_json(aad)
        info = hpke_info(self.bound_rrp_id, self.handle)
        skr = KEMKey.from_pyca_cryptography_key(self.cek)
        enc = b64u_dec(bundle["enc"])
        ct = b64u_dec(bundle["ciphertext"])
        if self.legacy_bundle_base_mode:
            # draft -00: "encrypted to CEKpub", no origin check
            pt = SUITE.create_recipient_context(enc, skr, info=info).open(ct, aad=aad_bytes)
        else:
            if bundle.get("container") != "hpke-auth":
                raise AttesterError("container %r does not authenticate its origin" % bundle.get("container"))
            if self.vault_origin_spki_der is None:
                raise AttesterError("no trust anchor for the Secret Vault's origin key")
            pks = KEMKey.from_pyca_cryptography_key(serialization.load_der_public_key(self.vault_origin_spki_der))
            # OpenError unless the sender held the Vault's private key (RFC 9180 Section 5.1.3)
            pt = SUITE.create_recipient_context(enc, skr, info=info, pks=pks).open(ct, aad=aad_bytes)
        items = json.loads(pt)
        if expected_group_id is not None and aad.get("group_id") != expected_group_id:
            raise AttesterError("group_id differs from the one I expected")
        return items

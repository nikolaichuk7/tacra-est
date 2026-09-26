"""The EST Server of draft-novak-lamps-tacra-est with its Verifier, Credential Authority and
Secret Vault behind it, as one process for the reference implementation. The three resources:

  GET  /.well-known/est/attest-initiate            -> AttestationInitiationResponse
  POST /.well-known/est/attest-enroll              -> certificate (PKCS#7 certs-only, base64, as EST simpleenroll)
  POST /.well-known/est/attest-retrieve            -> EncryptedCredentialBundle

The EST Server is a conduit: it never sees a private key of the Attester's, does not appraise
Evidence itself (the Verifier does) and does not decide issuance (the CA and the Vault do). It
does not mint present-nonce Freshness Handles either (the draft forbids the EST Server and Client
to); the Relying Party mints them, through a FreshnessOriginator, and the EST Server forwards the
Handle and correlates the two legs.

`attest-initiate` takes the two query parameters of the draft, `target` and `credential_type`. The
server decides the Credential Acquisition Mode, Enrollment or Retrieval, and the Freshness Kind
from its policy for that Target (TACRA Section 4.4: the CAS decides, per Target, what can be
provisioned; Goal 1), as in the TWI SIG implementation's TargetPolicy (name, mechanism, credential
types), with the Freshness Kind added.

Each Relying Party has its own identifier, `rrp_id`, which the Evidence binds and which it
recomputes the binding with: the Credential Authority for Enrollment, the Secret Vault for
Retrieval. The EST Server has none; it is not the party the Evidence is for.

Freshness, per Target: present-nonce (single-use Handle minted by the Relying Party), present-epoch
and absent-epoch (the current marker of the deployment's EpochBell, returned as the Handle or held
by the Attester), absent-timestamp (the Attester's time in `handle`, accepted within `max_age`),
absent-none (nothing to check).

Implementation conveniences beyond the draft, documented here so they are not mistaken for it:
  * `--legacy-binding` makes the CA and the Vault recompute the -00 binding, H(handle || subject)
    without the RRP identifier or the Target, to reproduce the attacks the pull request closes.
"""
import argparse
import datetime
import hashlib
import json
import os
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from common import (MEDIA, PROFILE_MOCK, PROFILE_SNP, b64u, b64u_dec, binding_value, canonical_json,
                    decode_evidence, decode_timestamp, error_body, initiation_response, now_ms, write_json)
from verifier import Verifier
from attester import hpke_info
from common import FRESHNESS_KINDS

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)


# ---------------------------------------------------------------------------------------------
# Credential Authority

class CredentialAuthority:
    def __init__(self, name: str, allowed_sans: set[str], rrp_id: str):
        self.rrp_id = rrp_id                    # the identifier the Evidence binds for this RRP
        self.key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .sign(self.key, hashes.SHA256()))
        self.allowed_sans = allowed_sans

    def issue(self, csr_der: bytes, results: dict, credential_hint: str | None, target: str = "") -> x509.Certificate:
        csr = x509.load_der_x509_csr(csr_der)
        if not csr.is_signature_valid:
            raise ValueError("CSR proof of possession failed")
        san = credential_hint or csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if san not in self.allowed_sans:
            raise ValueError("policy: identity %r is outside the attested identity context" % san)
        now = datetime.datetime.now(datetime.timezone.utc)
        return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.cert.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.32473.1"),  # RFC 5612 reserves PEN 32473 for documentation
                               canonical_json({"target": target, "measurement": results.get("measurement"), "platform": results.get("platform"),
                                               "platform_form": results.get("platform_form"), "report_id": results.get("report_id")})),
                               critical=False)
                .sign(self.key, hashes.SHA256()))


# ---------------------------------------------------------------------------------------------
# Secret Vault

class SecretVault:
    def __init__(self, rrp_id: str = "", policy_version: str = "1"):
        self.rrp_id = rrp_id                    # the identifier the Evidence binds for this RRP
        self.origin_key = x25519.X25519PrivateKey.generate()   # the Vault's static HPKE sender key
        self.policy_version = policy_version
        self.signing_key = ec.generate_private_key(ec.SECP256R1())  # the shared signing key of the group

    def origin_spki_der(self) -> bytes:
        return self.origin_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def group_id(self, results: dict, credential_hint: str | None) -> str:
        subject = (results.get("measurement") or "") + "|" + (results.get("platform") or "")
        return hashlib.sha256((subject + "|" + (credential_hint or "") + "|" + self.policy_version).encode()).hexdigest()

    def release(self, cek_spki_der: bytes, results: dict, handle: bytes, target: str,
                credential_hint: str | None, auth_mode: bool = True) -> dict:
        gid = self.group_id(results, credential_hint)
        items = {"credential_items": [
            {"type": "shared-signing-key", "format": "PKCS8-PEM",
             "value": self.signing_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()).decode("ascii")}],
            "metadata": {"validity_seconds": 3600, "rotation_epoch": 1}}
        aad = {"group_id": gid, "rrp_id": self.rrp_id, "target": target, "credential_hint": credential_hint}
        if handle:
            aad["handle"] = b64u(handle)
        aad_bytes = canonical_json(aad)
        pkr = KEMKey.from_pyca_cryptography_key(serialization.load_der_public_key(cek_spki_der))
        info = hpke_info(self.rrp_id, handle)
        if auth_mode:
            enc, ctx = SUITE.create_sender_context(pkr, info=info, sks=KEMKey.from_pyca_cryptography_key(self.origin_key))
            container = "hpke-auth"
        else:
            enc, ctx = SUITE.create_sender_context(pkr, info=info)
            container = "hpke-base"
        ct = ctx.seal(canonical_json(items), aad=aad_bytes)
        return {"container": container,
                "suite": {"kem": "DHKEM(X25519, HKDF-SHA256)", "kdf": "HKDF-SHA256", "aead": "AES-256-GCM"},
                "enc": b64u(enc), "ciphertext": b64u(ct), "aad": aad,
                "sender_pub": b64u(self.origin_spki_der()) if auth_mode else None}


# ---------------------------------------------------------------------------------------------
# Epoch markers

class EpochBell:
    """The deployment's epoch markers, for present-epoch (returned as the Handle) and absent-epoch
    (held by the Attester, distributed out of band). One marker per epoch; rotate() starts the
    next. The drills share one bell among all servers, as a deployment-wide epoch would be."""

    def __init__(self):
        self.lock = threading.RLock()
        self.epoch = 1
        self.marker = os.urandom(32)

    def current(self) -> bytes:
        with self.lock:
            return self.marker

    def rotate(self) -> None:
        with self.lock:
            self.epoch += 1
            self.marker = os.urandom(32)


# ---------------------------------------------------------------------------------------------
# Freshness Handle originator

class FreshnessOriginator:
    """The party that mints present-nonce Freshness Handles and correlates them with the second
    leg. In TACRA the originator is the Verifier or the Relying Party, never the EST Server or
    Client, which MUST NOT mint present-nonce or present-epoch Handles. Here each Relying Party
    owns one: the Credential Authority for Enrollment, the Secret Vault for Retrieval."""

    def __init__(self, expires_in: int = 300):
        self.expires_in = expires_in
        self.handles: dict[bytes, dict] = {}
        self.lock = threading.RLock()

    def issue(self, mode: str, target: str, credential_type: str) -> bytes:
        handle = os.urandom(32)
        with self.lock:
            self.handles[handle] = {"issued": time.time(), "mode": mode, "used": False,
                                    "target": target, "credential_type": credential_type}
        return handle

    def lookup(self, handle: bytes) -> dict | None:
        with self.lock:
            return self.handles.get(handle)

    def consume(self, handle: bytes) -> None:
        with self.lock:
            h = self.handles.get(handle)
            if h:
                h["used"] = True


# ---------------------------------------------------------------------------------------------
# The server

class ServerState:
    def __init__(self, name: str, verifier: Verifier, ca: CredentialAuthority, vault: SecretVault,
                 expires_in: int = 300, hash_name: str = "sha512", legacy_binding: bool = False,
                 bundle_auth_mode: bool = True, log_path: str | None = None,
                 targets: dict[str, dict] | None = None, bell: EpochBell | None = None,
                 clock=time.time, clock_skew: int = 5):
        self.name = name                        # for logs only; the Evidence does not bind the EST Server
        # Target -> {"mechanism": "enroll" | "retrieve", "credential_types": {...},
        #            "freshness": one of the five kinds (default present-nonce), "max_age": seconds}:
        # how this server provisions credentials for the Target (TACRA Section 4.4, Sections 5.1-5.3)
        self.targets = targets or {}
        self.bell = bell or EpochBell()
        self.clock = clock                      # the Relying Party's clock, for absent-timestamp
        self.clock_skew = clock_skew            # seconds an Attester's clock may run ahead
        self.verifier = verifier
        self.ca = ca
        self.vault = vault
        self.expires_in = expires_in
        self.hash_name = hash_name
        self.legacy_binding = legacy_binding
        self.bundle_auth_mode = bundle_auth_mode
        # The Relying Party mints the Handle (the EST Server MUST NOT): the CA for Enrollment, the
        # Vault for Retrieval. The EST Server only forwards it and correlates the two legs.
        self.ca.freshness = FreshnessOriginator(expires_in)
        self.vault.freshness = FreshnessOriginator(expires_in)
        self.lock = threading.RLock()   # record() is also called while the lock is held
        self.log_path = log_path
        self.log: list[dict] = []

    def originator(self, mode: str) -> "FreshnessOriginator":
        return self.ca.freshness if mode == "enroll" else self.vault.freshness

    def rrp(self, mode: str):
        return self.ca if mode == "enroll" else self.vault

    def record(self, entry: dict) -> None:
        entry["t"] = time.time()
        with self.lock:
            self.log.append(entry)
            if self.log_path:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")

    def expected_binding(self, mode: str, handle: bytes, target: str, subject: bytes) -> bytes:
        if self.legacy_binding:
            # draft -00 shape: H(handle || subject); neither the RRP nor the Target is bound
            import hashlib as _h
            return _h.sha512(handle + subject).digest()
        return binding_value(handle, self.rrp(mode).rrp_id, target, subject, self.hash_name)


class Handler(BaseHTTPRequestHandler):
    server_version = "tacra-est/0.1"
    state: ServerState = None  # set per server

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code: int, body: dict | bytes, ctype: str):
        data = body if isinstance(body, bytes) else json.dumps(body, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, code: int, error: str, detail: str, corr: str):
        self._send(code, error_body(error, detail, corr), MEDIA["error"])

    def do_GET(self):
        st = self.state
        u = urlparse(self.path)
        if u.path != "/.well-known/est/attest-initiate":
            return self._error(404, "not-found", "no such resource", "")
        q = parse_qs(u.query)
        target = (q.get("target") or [""])[0]
        ctype = (q.get("credential_type") or [""])[0]
        if not target or not ctype:
            return self._error(400, "bad-request", "target and credential_type are required", "")
        policy = st.targets.get(target)
        if policy is None:
            return self._error(403, "unsupported-target", "target %r is not served here" % target, "")
        if ctype not in policy["credential_types"]:
            return self._error(403, "unsupported-credential-type", "credential type %r is not provisioned for %r" % (ctype, target), "")
        mode = policy["mechanism"]          # the server decides the mode, from its policy for the Target
        kind = policy.get("freshness", "present-nonce")
        if kind == "present-nonce":
            handle = st.originator(mode).issue(mode, target, ctype)  # minted by the Relying Party, not the EST Server
        elif kind == "present-epoch":
            handle = st.bell.current()
        else:
            handle = None                   # absent-*: no Handle is returned
        acceptable = ["ecdsa-p256-sha256"] if mode == "enroll" else ["DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"]
        resp = initiation_response(kind, handle, st.rrp(mode).rrp_id, mode,
                                   st.expires_in if kind.startswith("present-") else None, acceptable,
                                   acceptable_evidence=[PROFILE_SNP, PROFILE_MOCK],
                                   max_age=policy.get("max_age", 60) if kind == "absent-timestamp" else None)
        st.record({"resource": "attest-initiate", "mode": mode, "target": target, "credential_type": ctype,
                   "freshness_kind": kind, "handle": b64u(handle) if handle else None})
        self._send(200, resp, MEDIA["initiation"])

    def do_POST(self):
        st = self.state
        corr = uuid.uuid4().hex[:12]
        t0 = now_ms()
        u = urlparse(self.path)
        if u.path not in ("/.well-known/est/attest-enroll", "/.well-known/est/attest-retrieve"):
            return self._error(404, "not-found", "no such resource", corr)
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 1_000_000:
                return self._error(400, "bad-request", "body too large", corr)
            req = json.loads(self.rfile.read(n))
        except Exception as e:
            return self._error(400, "bad-request", "malformed envelope: %s" % e, corr)
        mode = "enroll" if u.path.endswith("attest-enroll") else "retrieve"
        target = req.get("target") or ""
        ctype = req.get("credential_type") or ""

        def refuse(code: int, error: str, detail: str):
            self._error(code, error, detail, corr)
            st.record({"resource": u.path, "corr": corr, "outcome": code, "reason": error})

        # 0. the Target, the mode and the Freshness Kind are the server's policy for the Target, whether
        #    or not attest-initiate reached this server (it may have been completed locally)
        policy = st.targets.get(target)
        if policy is None or policy["mechanism"] != mode:
            return refuse(403, "unsupported-target", "target %r is not provisioned by %s here" % (target, mode))
        if ctype not in policy["credential_types"]:
            return refuse(403, "unsupported-credential-type", "credential type %r is not provisioned for %r" % (ctype, target))
        kind = policy.get("freshness", "present-nonce")
        if req.get("freshness_kind") != kind:
            return refuse(400, "bad-request", "freshness_kind must be %s for this Target" % kind)
        handle = b64u_dec(req["handle"]) if req.get("handle") else b""
        # 1. freshness, by kind
        if kind == "present-nonce":
            # correlate the Handle with the one the Relying Party minted at attest-initiate
            if not handle:
                return refuse(400, "bad-request", "present-nonce requires the Handle")
            orig = st.originator(mode)
            with orig.lock:
                h = orig.lookup(handle)
                if h is None:
                    return refuse(403, "unknown-handle", "handle was not issued for this mode by this server")
                if h["used"]:
                    return refuse(409, "handle-replay", "Freshness Handle already used")
                if time.time() - h["issued"] > orig.expires_in:
                    # A nonce that is no longer valid: the Attester retries attest-initiate (TACRA 5.4).
                    return refuse(409, "handle-expired", "Freshness Handle expired; retry attest-initiate")
                if h["target"] != target or h["credential_type"] != ctype:
                    return refuse(403, "initiation-mismatch", "target and credential_type must match attest-initiate")
                h["used"] = True
        elif kind in ("present-epoch", "absent-epoch"):
            if handle != st.bell.current():
                return refuse(409, "epoch-moved", "the epoch marker is not the current one; retry attest-initiate")
        elif kind == "absent-timestamp":
            try:
                ts = decode_timestamp(handle)
            except ValueError as e:
                return refuse(400, "bad-request", str(e))
            now = int(st.clock())
            max_age = policy.get("max_age", 60)
            if ts < now - max_age or ts > now + st.clock_skew:
                return refuse(409, "timestamp-out-of-window",
                              "timestamp %d is outside [now - %d s, now + %d s]; produce fresh Evidence" % (ts, max_age, st.clock_skew))
        elif handle:                        # absent-none
            return refuse(400, "bad-request", "handle must be absent for absent-none")
        # 2. Verifier
        t1 = now_ms()
        if req.get("profile") not in (PROFILE_SNP, PROFILE_MOCK):
            return self._error(415, "unsupported-evidence", "profile %r not accepted" % req.get("profile"), corr)
        try:
            evidence = decode_evidence(b64u_dec(req.get("evidence") or ""))
        except Exception as e:
            return self._error(400, "bad-request", "evidence is not a %s object: %s" % (req.get("profile"), e), corr)
        results = st.verifier.appraise(evidence)
        t2 = now_ms()
        if not results.get("ok"):
            self._error(403, "attestation-failed", "Verifier: %s" % results.get("reason"), corr)
            st.record({"resource": u.path, "corr": corr, "outcome": 403, "reason": "attestation-failed", "verifier": results, "ms_verifier": t2 - t1})
            return
        # 3. Relying Party: recompute the binding, then issue or release
        subject = b64u_dec(req["csr"]) if mode == "enroll" else b64u_dec(req["cek_pub"])
        expected = st.expected_binding(mode, handle, target, subject)
        if results.get("binding_value") != expected.hex():
            self._error(403, "binding-mismatch", "Evidence binding value does not match handle, rrp_id, target and %s" % ("CSR" if mode == "enroll" else "CEKpub"), corr)
            st.record({"resource": u.path, "corr": corr, "outcome": 403, "reason": "binding-mismatch",
                       "expected": expected.hex()[:32], "got": (results.get("binding_value") or "")[:32], "ms_verifier": t2 - t1,
                       "platform_form": results.get("platform_form"), "chip_id": (results.get("chip_id") or "")[:16]})
            return
        hint = req.get("credential_hint")
        try:
            if mode == "enroll":
                cert = st.ca.issue(subject, results, hint, target)
                t3 = now_ms()
                body = pkcs7.serialize_certificates([cert], serialization.Encoding.DER)
                import base64
                self._send(200, base64.b64encode(body), "application/pkcs7-mime; smime-type=certs-only")
                st.record({"resource": u.path, "corr": corr, "outcome": 200, "freshness_kind": kind, "ms_verifier": t2 - t1, "ms_ca": t3 - t2, "ms_total": t3 - t0,
                           "platform": results.get("platform"), "platform_form": results.get("platform_form"),
                           "chip_id": (results.get("chip_id") or "")[:16], "report_id": (results.get("report_id") or "")[:16],
                           "measurement": (results.get("measurement") or "")[:16], "checks": results.get("checks")})
            else:
                bundle = st.vault.release(subject, results, handle, target, hint, auth_mode=st.bundle_auth_mode)
                t3 = now_ms()
                self._send(200, bundle, MEDIA["bundle"])
                st.record({"resource": u.path, "corr": corr, "outcome": 200, "freshness_kind": kind, "ms_verifier": t2 - t1, "ms_vault": t3 - t2, "ms_total": t3 - t0,
                           "platform": results.get("platform"), "platform_form": results.get("platform_form"),
                           "group_id": bundle["aad"]["group_id"][:16], "container": bundle["container"], "checks": results.get("checks")})
        except ValueError as e:
            self._error(403, "policy-denied", str(e), corr)
            st.record({"resource": u.path, "corr": corr, "outcome": 403, "reason": "policy-denied", "detail": str(e)})


def make_tls_cert(hostname: str) -> tuple[str, str]:
    """A self-signed TLS certificate for the server; returns (cert_pem_path, key_pem_path)."""
    import tempfile
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp(prefix="tacra-est-tls-")
    cp, kp = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp


def start_server(state: ServerState, host: str = "127.0.0.1", port: int = 0, tls_hostname: str = "localhost"):
    """Start an HTTPS server in a thread; returns (server, port, cert_pem_path)."""
    cp, kp = make_tls_cert(tls_hostname)
    handler = type("H", (Handler,), {"state": state})
    srv = ThreadingHTTPServer((host, port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cp, kp)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, srv.server_address[1], cp


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="est")
    ap.add_argument("--ca-id", required=True, help="rrp_id of the Credential Authority, e.g. https://ca.tacra.example")
    ap.add_argument("--vault-id", required=True, help="rrp_id of the Secret Vault, e.g. https://vault.tacra.example")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--mock-root-pem", help="PEM file of the mock TEE root to trust")
    ap.add_argument("--pinned-ark-pem", help="PEM file of AMD ARK-Milan to pin")
    ap.add_argument("--legacy-binding", action="store_true")
    ap.add_argument("--bundle-base-mode", action="store_true")
    ap.add_argument("--log", default=None)
    ap.add_argument("--target", action="append", default=[], metavar="URI=MECHANISM:TYPE[,TYPE][/FRESHNESS]",
                    help="a Target this server provisions, e.g. https://db.tacra.example=enroll:x509 or "
                         "https://metrics.tacra.example=enroll:x509/absent-timestamp (repeatable)")
    a = ap.parse_args()
    targets = {}
    for spec in a.target:
        uri, _, rest = spec.partition("=")
        mech, _, rest = rest.partition(":")
        types, _, kind = rest.partition("/")
        kind = kind or "present-nonce"
        if not uri or mech not in ("enroll", "retrieve") or not types or kind not in FRESHNESS_KINDS:
            ap.error("--target %r: expected URI=enroll|retrieve:TYPE[,TYPE][/FRESHNESS]" % spec)
        targets[uri] = {"mechanism": mech, "credential_types": set(types.split(",")), "freshness": kind}
    mock_root = open(a.mock_root_pem).read() if a.mock_root_pem else None
    ark = open(a.pinned_ark_pem, "rb").read() if a.pinned_ark_pem else None
    state = ServerState(a.name, Verifier(pinned_ark_pem=ark, mock_root_pem=mock_root),
                        CredentialAuthority("TACRA demo CA", {"workload.tacra.example"}, a.ca_id), SecretVault(a.vault_id),
                        legacy_binding=a.legacy_binding, bundle_auth_mode=not a.bundle_base_mode, log_path=a.log,
                        targets=targets)
    srv, port, cp = start_server(state, host="0.0.0.0", port=a.port)
    print("serving %s (CA %s, Vault %s) on port %d, TLS cert %s" % (a.name, a.ca_id, a.vault_id, port, cp))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass

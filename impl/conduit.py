"""The EST Client of draft-novak-lamps-tacra-est: a conduit between the Attester and the EST
Server. It has no RATS role and no keys of the Attester's. Two conduits are implemented:

  Conduit       the honest one: relays initiate/enroll/retrieve between the Attester and the
                server the Attester named.
  EvilConduit   the attacker of TACRA Section 7.2: the same code path, but it may carry the
                Attester's messages to a server fronting a different RRP (RRP substitution) or
                hand the Attester a bundle of its own making (bundle substitution).
"""
import base64
import http.client
import json
import ssl

from cryptography.hazmat.primitives import serialization
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from common import MEDIA, b64u, b64u_dec, canonical_json, now_ms
from attester import hpke_info

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)


class ServerEndpoint:
    def __init__(self, host: str, port: int, tls_cert_pem_path: str):
        self.host, self.port = host, port
        self.ctx = ssl.create_default_context(cafile=tls_cert_pem_path)
        self.ctx.check_hostname = False   # the reference servers use self-signed localhost certs

    def request(self, method: str, path: str, body: dict | None = None, ctype: str | None = None):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=60)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": ctype} if ctype else {}
        t0 = now_ms()
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        ms = now_ms() - t0
        conn.close()
        rctype = r.getheader("Content-Type", "")
        if rctype.startswith("application/pkcs7-mime"):
            payload = raw
        else:
            try:
                payload = json.loads(raw)
            except Exception:
                payload = raw
        return r.status, rctype, payload, ms


class Conduit:
    def __init__(self, endpoint: ServerEndpoint):
        self.ep = endpoint
        self.timings: dict[str, float] = {}

    def initiate(self, target: str, credential_type: str) -> dict:
        from urllib.parse import urlencode
        q = urlencode({"target": target, "credential_type": credential_type})
        st, ct, body, ms = self.ep.request("GET", "/.well-known/est/attest-initiate?" + q)
        self.timings["initiate_ms"] = ms
        if st != 200:
            raise RuntimeError("attest-initiate %d: %s" % (st, body))
        return body

    def enroll(self, req: dict):
        st, ct, body, ms = self.ep.request("POST", "/.well-known/est/attest-enroll", req, MEDIA["enroll"])
        self.timings["enroll_ms"] = ms
        return st, ct, body

    def retrieve(self, req: dict):
        st, ct, body, ms = self.ep.request("POST", "/.well-known/est/attest-retrieve", req, MEDIA["retrieve"])
        self.timings["retrieve_ms"] = ms
        return st, ct, body


class EvilConduit(Conduit):
    """Sits between the Attester and the servers, as the untrusted conduit may. The Handle comes
    from, and the request goes to, `self.ep`, a server fronting another RRP. If `pretend_rrp_id` is
    set, the conduit also rewrites the RRP identifier in the initiation response (the lie); if not,
    it passes that server's response on unchanged."""

    def __init__(self, endpoint: ServerEndpoint, pretend_rrp_id: str | None = None):
        super().__init__(endpoint)
        self.pretend = pretend_rrp_id

    def initiate(self, target: str, credential_type: str) -> dict:
        body = dict(super().initiate(target, credential_type))
        if self.pretend:
            body["rrp_id"] = self.pretend    # the lie: the Attester sees the RRP it intended
        return body

    @staticmethod
    def forge_bundle(cek_spki_der: bytes, rrp_id: str, handle: bytes, credential_hint: str | None,
                     group_id: str, attacker_items: dict, target: str = "") -> dict:
        """Bundle substitution: a well-formed container encrypted to CEKpub in base mode, made by
        someone who has only seen CEKpub in the Evidence. No Vault key is involved."""
        aad = {"group_id": group_id, "rrp_id": rrp_id, "target": target, "credential_hint": credential_hint}
        if handle:
            aad["handle"] = b64u(handle)
        pkr = KEMKey.from_pyca_cryptography_key(serialization.load_der_public_key(cek_spki_der))
        enc, ctx = SUITE.create_sender_context(pkr, info=hpke_info(rrp_id, handle))
        ct = ctx.seal(canonical_json(attacker_items), aad=canonical_json(aad))
        return {"container": "hpke-base", "suite": {"kem": "DHKEM(X25519, HKDF-SHA256)", "kdf": "HKDF-SHA256", "aead": "AES-256-GCM"},
                "enc": b64u(enc), "ciphertext": b64u(ct), "aad": aad, "sender_pub": None}


class TargetSwapConduit(Conduit):
    """Target substitution: the conduit initiates for a Target of its choosing instead of the one the
    Attester named, and presents the Attester's request under that Target. The server is the one
    the Attester intended, so the RRP identifier is genuine."""

    def __init__(self, endpoint: ServerEndpoint, substitute_target: str):
        super().__init__(endpoint)
        self.substitute = substitute_target

    def initiate(self, target: str, credential_type: str) -> dict:
        return super().initiate(self.substitute, credential_type)

    def enroll(self, req: dict):
        return super().enroll(dict(req, target=self.substitute))

    def retrieve(self, req: dict):
        return super().retrieve(dict(req, target=self.substitute))

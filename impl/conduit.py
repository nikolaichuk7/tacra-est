"""The EST Client of draft-novak-lamps-tacra-est: a conduit between the Attester and the EST
Server. It has no RATS role and no keys of the Attester's. Two conduits are implemented:

  Conduit       the honest one: relays initiate/enroll/retrieve between the Attester and the
                server the Attester named.
  EvilConduit   the attacker of TACRA Section 7.2: the same code path, but it may carry the
                Attester's messages to a different server (server substitution) or hand the
                Attester a bundle of its own making (bundle substitution).
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

    def initiate(self, mode: str) -> dict:
        st, ct, body, ms = self.ep.request("GET", "/.well-known/est/attest-initiate?mode=%s" % mode)
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
    """Sits between the Attester and the servers, as the untrusted conduit may. `pretend_server_id`
    is what it tells the Attester in the initiation response (the Attester's intended Target), while
    the Handle comes from, and the request goes to, `self.ep` (another server)."""

    def __init__(self, endpoint: ServerEndpoint, pretend_server_id: str):
        super().__init__(endpoint)
        self.pretend = pretend_server_id

    def initiate(self, mode: str) -> dict:
        body = super().initiate(mode)
        body = dict(body)
        body["server_id"] = self.pretend     # the lie: the Attester sees the server it intended
        return body

    @staticmethod
    def forge_bundle(cek_spki_der: bytes, server_id: str, handle: bytes, credential_hint: str | None,
                     group_id: str, attacker_items: dict) -> dict:
        """Bundle substitution: a well-formed container encrypted to CEKpub in base mode, made by
        someone who has only seen CEKpub in the Evidence. No Vault key is involved."""
        aad = {"group_id": group_id, "server_id": server_id, "credential_hint": credential_hint}
        if handle:
            aad["handle"] = b64u(handle)
        pkr = KEMKey.from_pyca_cryptography_key(serialization.load_der_public_key(cek_spki_der))
        enc, ctx = SUITE.create_sender_context(pkr, info=hpke_info(server_id, handle))
        ct = ctx.seal(canonical_json(attacker_items), aad=canonical_json(aad))
        return {"container": "hpke-base", "suite": {"kem": "DHKEM(X25519, HKDF-SHA256)", "kdf": "HKDF-SHA256", "aead": "AES-256-GCM"},
                "enc": b64u(enc), "ciphertext": b64u(ct), "aad": aad, "sender_pub": None}

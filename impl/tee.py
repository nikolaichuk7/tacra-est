"""The Attesting Environment behind the Attester: a real AMD SEV-SNP guest (through the Linux
sev-guest driver) or a mock for running the protocol without hardware.

Both produce Evidence in the same JSON shape:

  {"type": "sev-snp", "report": b64u(1184-byte report), "certs": {"VCEK": b64u(DER), ...},
   "chain": PEM (ASK + ARK from the AMD KDS), "platform_form": "direct"}

  {"type": "mock", "report": b64u(canonical JSON of the mock report), "sig": b64u(ECDSA-P256
   signature over those bytes), "pub": PEM (the mock root's public key), "platform_form": "direct"}

The only guest-chosen content of a SEV-SNP report is the 64-byte REPORT_DATA; that is where the
binding value goes (pull request, "Binding Input"). The mock mirrors that: it signs a report whose
report_data is the 64 bytes it was given, and nothing else in it is under the caller's control.
"""
import ctypes
import fcntl
import json
import os
import struct
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from common import SNP_REPORT_LEN, b64u, canonical_json, kds_vcek_url, parse_snp_report

# --- Linux sev-guest UAPI (include/uapi/linux/sev-guest.h) ---------------------------------

class _Req(ctypes.Structure):
    _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]


class _Resp(ctypes.Structure):
    _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32),
                ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]


class _Ioctl(ctypes.Structure):
    _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64),
                ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]


class _ExtReq(ctypes.Structure):
    _fields_ = [("data", _Req), ("certs_address", ctypes.c_uint64), ("certs_len", ctypes.c_uint32)]


SNP_GET_REPORT = 0xC0205300
SNP_GET_EXT_REPORT = 0xC0205302
CERT_GUIDS = {
    "63da758d-e664-4564-adc5-f4b93be8accd": "VCEK",
    "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK",
    "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK",
    "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK",
}
KDS_CHAIN = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
UA = {"User-Agent": "tacra-est/0.1 (+https://github.com/nikolaichuk7/tacra-est)"}


def _get(url: str, timeout: int = 40) -> bytes:
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


class SnpGuestTEE:
    """AMD SEV-SNP through /dev/sev-guest. KEY_SEL=1 asks for a VCEK-signed report (per-chip
    identity); on a host that only offers a VLEK the firmware answers with the VLEK and the
    Verifier reports the provider-scoped form."""

    def __init__(self, device: str = "/dev/sev-guest", product: str = "Milan", key_sel: int = 1):
        self.device = device
        self.product = product
        self.key_sel = key_sel
        self.platform_form = "direct"
        self._chain: str | None = None            # the KDS chain is fetched once per process
        self._vcek_cache: dict[bytes, bytes] = {}  # VCEK by chip id, when the host gives no table
        self.last_ioctl_ms: float | None = None

    def _ioctl(self, request: int, io: _Ioctl) -> str | None:
        fd = os.open(self.device, os.O_RDWR)
        try:
            fcntl.ioctl(fd, request, io)
            return None
        except OSError as e:
            return "errno %d %s" % (e.errno, e.strerror)
        finally:
            os.close(fd)

    def report(self, report_data: bytes) -> dict:
        assert len(report_data) == 64
        # Extended report first: the host's certificate table carries the VCEK (or VLEK), ASK, ARK.
        certs_buf = (ctypes.c_ubyte * 16384)()
        ereq = _ExtReq()
        ctypes.memmove(ereq.data.user_data, report_data, 64)
        ereq.data.vmpl = 0
        ereq.data.flags = self.key_sel
        ereq.certs_address = ctypes.addressof(certs_buf)
        ereq.certs_len = 16384
        eresp = _Resp()
        eio = _Ioctl(1, ctypes.addressof(ereq), ctypes.addressof(eresp), 0)
        import time as _t
        _t0 = _t.monotonic()
        err = self._ioctl(SNP_GET_EXT_REPORT, eio)
        self.last_ioctl_ms = (_t.monotonic() - _t0) * 1000.0
        certs: dict[str, bytes] = {}
        if err is None and eresp.report_size == SNP_REPORT_LEN:
            rep = bytes(eresp.report[:SNP_REPORT_LEN])
            buf = bytes(certs_buf)
            i = 0
            while i + 24 <= len(buf):
                g = buf[i:i + 16]
                if g == bytes(16):
                    break
                off, ln = struct.unpack_from("<II", buf, i + 16)
                name = CERT_GUIDS.get(str(uuid.UUID(bytes=g)), str(uuid.UUID(bytes=g)))
                certs[name] = buf[off:off + ln]
                i += 24
        else:
            # Plain report; the VCEK is fetched from the KDS by chip id and reported TCB.
            req = _Req()
            ctypes.memmove(req.user_data, report_data, 64)
            req.vmpl = 0
            req.flags = self.key_sel
            resp = _Resp()
            io = _Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0)
            err2 = self._ioctl(SNP_GET_REPORT, io)
            if err2 is not None or resp.report_size != SNP_REPORT_LEN:
                raise RuntimeError("SNP_GET_REPORT failed: %s (ext: %s, exitinfo2=%#x)" % (err2, err, io.exitinfo2))
            rep = bytes(resp.report[:SNP_REPORT_LEN])
        parsed = parse_snp_report(rep)
        if "VCEK" not in certs and parsed["signing_key"] == "VCEK":
            if parsed["chip_id"] not in self._vcek_cache:
                self._vcek_cache[parsed["chip_id"]] = _get(kds_vcek_url(self.product, parsed["chip_id"], parsed["reported_tcb"]))
            certs["VCEK"] = self._vcek_cache[parsed["chip_id"]]
        if self._chain is None:
            self._chain = _get(KDS_CHAIN).decode("ascii")
        chain = self._chain
        return {
            "type": "sev-snp",
            "report": b64u(rep),
            "certs": {k: b64u(v) for k, v in certs.items()},
            "chain": chain,
            "platform_form": "direct" if parsed["signing_key"] == "VCEK" and not parsed["mask_chip_key"] else "provider-scoped",
        }


class MockTEE:
    """A stand-in for hardware, for running the protocol on a laptop: an ECDSA P-256 key plays the
    attestation key, a fixed measurement plays the launch measurement. The Verifier for the mock
    trusts the mock root's public key exactly as it would trust AMD's root."""

    MEASUREMENT = bytes.fromhex("6d6f636b2d6d6561737572656d656e74" * 3)  # 48 bytes, "mock-measurement" x3

    def __init__(self, seed: bytes | None = None):
        if seed is not None:
            self.key = ec.derive_private_key(int.from_bytes(seed, "big") % ec.SECP256R1().key_size ** 8 or 1, ec.SECP256R1())
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
        self.platform_form = "direct"
        self.chip_id = bytes(range(64))
        self._report_counter = 0

    def root_pem(self) -> str:
        return self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def report(self, report_data: bytes) -> dict:
        assert len(report_data) == 64
        self._report_counter += 1
        body = {"version": "mock-1", "measurement": self.MEASUREMENT.hex(), "report_data": report_data.hex(),
                "report_id": os.urandom(32).hex(), "chip_id": self.chip_id.hex(), "counter": self._report_counter}
        raw = canonical_json(body)
        sig = self.key.sign(raw, ec.ECDSA(hashes.SHA256()))
        return {"type": "mock", "report": b64u(raw), "sig": b64u(sig), "pub": self.root_pem(), "platform_form": self.platform_form}


def make_tee(kind: str, **kw):
    if kind == "sev-snp":
        return SnpGuestTEE(**kw)
    if kind == "mock":
        return MockTEE(**kw)
    raise ValueError(kind)

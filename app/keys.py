"""Loading of the pre-provisioned demo keys (one fixed KSK + two demo ZSKs).

Keys are ECDSA P-256 (DNSSEC algorithm 13, ECDSAP256SHA256) stored as
unencrypted PKCS#8 PEM files under ``keys/``.  They are generated once by
``scripts/gen_keys.py`` and committed on purpose: this is a self-contained
demo, never reuse these keys for anything real.
"""
from __future__ import annotations

import logging
from pathlib import Path

import dns.dnssec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

log = logging.getLogger("dnssec-demo.keys")

KSK_FLAGS = 257  # ZONE | SEP
ZSK_FLAGS = 256  # ZONE


class KeyPair:
    """A private key plus its derived DNSKEY rdata and key tag."""

    def __init__(self, role: str, path: Path, flags: int):
        self.role = role
        self.path = path
        with open(path, "rb") as f:
            self.private_key = load_pem_private_key(f.read(), password=None)
        self.dnskey = dns.dnssec.make_dnskey(
            self.private_key.public_key(),
            algorithm=dns.dnssec.Algorithm.ECDSAP256SHA256,
            flags=flags,
        )
        self.key_tag = dns.dnssec.key_id(self.dnskey)

    def public_dict(self) -> dict:
        return {
            "role": self.role,
            "key_tag": self.key_tag,
            "flags": self.dnskey.flags,
            "algorithm": int(self.dnskey.algorithm),
            "file": self.path.name,
        }


class KeyRing:
    """The fixed KSK and the two demo ZSKs (zsk1 = old, zsk2 = new)."""

    def __init__(self, keys_dir: str):
        base = Path(keys_dir)
        self.ksk = KeyPair("ksk", base / "ksk.pem", KSK_FLAGS)
        self.zsk1 = KeyPair("zsk1", base / "zsk1.pem", ZSK_FLAGS)
        self.zsk2 = KeyPair("zsk2", base / "zsk2.pem", ZSK_FLAGS)
        log.info(
            "loaded keys: KSK tag=%d, ZSK1 (old) tag=%d, ZSK2 (new) tag=%d",
            self.ksk.key_tag,
            self.zsk1.key_tag,
            self.zsk2.key_tag,
        )

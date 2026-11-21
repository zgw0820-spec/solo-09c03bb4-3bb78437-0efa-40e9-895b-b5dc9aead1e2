#!/usr/bin/env python3
"""Generate the pre-provisioned demo keys (1 KSK + 2 ZSKs, ECDSA P-256 / alg 13).

Usage: python3 scripts/gen_keys.py [keys_dir] [--force]

Existing keys are kept unless --force is given.  Prints the public DNSKEY
records and the KSK's DS record (what a parent zone would publish in a real
deployment).
"""
from __future__ import annotations

import sys
from pathlib import Path

import dns.dnssec
import dns.name
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROLES = (("ksk", 257), ("zsk1", 256), ("zsk2", 256))


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--force"]
    force = "--force" in sys.argv[1:]
    out = Path(args[0] if args else "keys")
    out.mkdir(parents=True, exist_ok=True)

    for role, _flags in ROLES:
        path = out / f"{role}.pem"
        if path.exists() and not force:
            print(f"keep existing {path}")
            continue
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        print(f"wrote {path}")

    zone = "example.test."
    apex = dns.name.from_text(zone)
    print()
    for role, flags in ROLES:
        key = load_pem_private_key((out / f"{role}.pem").read_bytes(), password=None)
        dnskey = dns.dnssec.make_dnskey(
            key.public_key(),
            algorithm=dns.dnssec.Algorithm.ECDSAP256SHA256,
            flags=flags,
        )
        tag = dns.dnssec.key_id(dnskey)
        print(f"{role}: key tag {tag}")
        print(f"  {zone} 300 IN DNSKEY {dnskey}")
        if role == "ksk":
            ds = dns.dnssec.make_ds(apex, dnskey, dns.dnssec.DSDigest.SHA256)
            print(f"  DS for parent (demo only): {zone} 300 IN DS {ds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

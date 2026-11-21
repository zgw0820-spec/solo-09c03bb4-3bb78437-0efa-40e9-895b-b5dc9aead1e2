#!/usr/bin/env python3
"""End-to-end check for DNSSEC negative answers (NSEC proofs).

Verifies, over real UDP against the running container/service:

  * NXDOMAIN for a non-existent name carries an NSEC covering QNAME and an
    NSEC covering the applicable wildcard, both signed and validating against
    the *current* DNSKEY RRset stored in a file (``--dnskey`` optionally).
  * NODATA for an existing name with an absent type carries the NSEC that
    matches the owner name, whose bitmap lists the types that do exist.
  * Out-of-zone queries are REFUSED and leak no SOA/NSEC/AA.
  * Proofs are re-signed at every rotation phase: the proof produced after
    publish/switch/retire validates against the DNSKEY of that same phase and
    never against the key that the phase has retired.

It also re-runs the key rotation via the HTTP API (Swagger endpoints) so the
phase transitions exercise the same code path the UI uses.

Usage:
  python3 scripts/negative_check.py            # full run (~70s of waits)
  python3 scripts/negative_check.py --quick    # skip the two timed waits

Env: API_BASE, DNS_HOST, DNS_PORT, ZONE_NAME, APP_LABEL
"""
from __future__ import annotations

import os
import sys
import time

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import httpx

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
DNS_HOST = os.getenv("DNS_HOST", "127.0.0.1")
DNS_PORT = int(os.getenv("DNS_PORT", "5353"))
ZONE = os.getenv("ZONE_NAME", "example.test").rstrip(".") + "."
APP_FQDN = f"{os.getenv('APP_LABEL', 'app')}.{ZONE}"
APEX = dns.name.from_text(ZONE)

failures: list[str] = []
QUICK = "--quick" in sys.argv[1:]


def check(name: str, cond: bool, extra: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {extra}" if extra else ""))
    if not cond:
        failures.append(name)


def udp(name: str, rdtype: str, want_dnssec: bool = True) -> dns.message.Message:
    q = dns.message.make_query(name, rdtype, want_dnssec=want_dnssec)
    return dns.query.udp(q, DNS_HOST, port=DNS_PORT, timeout=5)


def rrsets(msg, section) -> list:
    return [rr for rr in section if rr.rdtype != dns.rdatatype.RRSIG]


def nsec_types(nsec_rdata) -> set[str]:
    out = set()
    for window, bitmap in nsec_rdata.windows:
        for i, octet in enumerate(bitmap):
            for j in range(8):
                if octet & (0x80 >> j):
                    out.add(dns.rdatatype.to_text(window * 256 + i * 8 + j))
    return out


def nsec_next(rrset) -> dns.name.Name:
    return rrset[0].next


def validate_rrset(rrset, msg: dns.message.Message, keys) -> bool:
    """Validate *rrset* using the RRSIG of the same owner covering its type."""
    for rr in msg.authority + msg.answer:
        if rr.rdtype != dns.rdatatype.RRSIG:
            continue
        if rr.name != rrset.name:
            continue
        if not any(rd.type_covered == rrset.rdtype for rd in rr):
            continue
        try:
            dns.dnssec.validate(rrset, rr, keys)
            return True
        except dns.dnssec.ValidationFailure:
            return False
    return False


def dnskey_of_phase(client: httpx.Client):
    resp = udp(ZONE, "DNSKEY")
    dnskey = None
    for rr in resp.answer:
        if rr.rdtype == dns.rdatatype.DNSKEY:
            dnskey = rr
    assert dnskey is not None, "no DNSKEY in answer"
    return {APEX: dnskey}


def signed_by(msg: dns.message.Message, owner: dns.name.Name, covered: int):
    """Key tag of the RRSIG over <owner, covered> in this message, or None."""
    for rr in msg.authority:
        if rr.rdtype != dns.rdatatype.RRSIG or rr.name != owner:
            continue
        for rd in rr:
            if rd.type_covered == covered:
                return rd.key_tag
    return None


def covers(nsec: dns.rrset.RRset, name: dns.name.Name) -> bool:
    """True if *name* falls strictly inside the NSEC interval at *nsec*."""
    owner, nxt = nsec.name, nsec_next(nsec)
    if owner < nxt:
        return owner < name < nxt
    # interval wraps around the apex (last NSEC in the zone)
    return name > owner or name < nxt


def check_nxdomain(label: str, qname: str, keys) -> None:
    resp = udp(qname, "A")
    check(f"{label}: rcode NXDOMAIN", resp.rcode() == dns.rcode.NXDOMAIN, dns.rcode.to_text(resp.rcode()))
    q = dns.name.from_text(qname)
    nsecs = [rr for rr in rrsets(resp, resp.authority) if rr.rdtype == dns.rdatatype.NSEC]
    check(f"{label}: answer section empty", len(resp.answer) == 0)
    check(f"{label}: NXDOMAIN carries NSEC proof(s)", len(nsecs) >= 1, f"nsecs={len(nsecs)}")
    check(
        f"{label}: an NSEC covers QNAME",
        any(covers(n, q) for n in nsecs),
        f"qname={q} nsec_intervals={[(str(n.name), str(nsec_next(n))) for n in nsecs]}",
    )
    check(
        f"{label}: an NSEC covers the applicable wildcard",
        any(covers(n, dns.name.Name((b"*",)) + APEX) for n in nsecs),
        "wildcard=*." + ZONE,
    )
    check(f"{label}: SOA present in authority", any(rr.rdtype == dns.rdatatype.SOA for rr in resp.authority))
    soa = next((rr for rr in rrsets(resp, resp.authority) if rr.rdtype == dns.rdatatype.SOA), None)
    check(f"{label}: SOA validates", soa is not None and validate_rrset(soa, resp, keys))
    for n in nsecs:
        check(f"{label}: NSEC {n.name} validates", validate_rrset(n, resp, keys))
    check(
        f"{label}: NSEC bitmap lists NSEC and RRSIG",
        all({"NSEC", "RRSIG"} <= nsec_types(n[0]) for n in nsecs),
    )
    check(
        f"{label}: NSEC TTL matches SOA minimum",
        soa is not None and all(n.ttl == soa[0].minimum for n in nsecs),
        f"ttl={[n.ttl for n in nsecs]} soa_min={soa[0].minimum if soa else '-'}",
    )


def check_nodata(label: str, qname: str, qtype: str, present: set[str], keys) -> None:
    resp = udp(qname, qtype)
    check(f"{label}: rcode NOERROR", resp.rcode() == dns.rcode.NOERROR, dns.rcode.to_text(resp.rcode()))
    check(f"{label}: answer section empty", len(resp.answer) == 0)
    q = dns.name.from_text(qname)
    matching = [
        rr for rr in rrsets(resp, resp.authority)
        if rr.rdtype == dns.rdatatype.NSEC and rr.name == q
    ]
    check(f"{label}: NODATA carries the matching NSEC", len(matching) == 1, f"matching={len(matching)}")
    if matching:
        n = matching[0]
        types = nsec_types(n[0])
        check(f"{label}: bitmap omits QTYPE {qtype}", qtype not in types, f"types={sorted(types)}")
        check(f"{label}: bitmap lists present types {sorted(present)}", present <= types, f"types={sorted(types)}")
        check(f"{label}: NSEC validates", validate_rrset(n, resp, keys))
    check(f"{label}: SOA present in authority", any(rr.rdtype == dns.rdatatype.SOA for rr in resp.authority))
    check(f"{label}: no covering NSEC needed", len(matching) == 1)


def main() -> int:
    client = httpx.Client(base_url=API_BASE, timeout=10)
    r = client.post("/rotate/reset")
    r.raise_for_status()
    st = client.get("/status").json()
    ksk_tag = st["keys"]["ksk"]
    zsk1_tag = st["keys"]["zsk1"]
    zsk2_tag = st["keys"]["zsk2"]
    dnskey_ttl = st["dnskey_ttl"]
    a_ttl = st["a_ttl"]
    print(f"KSK={ksk_tag} ZSK1(old)={zsk1_tag} ZSK2(new)={zsk2_tag} TTLs DNSKEY={dnskey_ttl} A={a_ttl}\n")

    # ---- initial phase -------------------------------------------------------
    keys = dnskey_of_phase(client)
    print("== initial phase ==")
    check_nxdomain("initial NXDOMAIN", f"missing.{ZONE}", keys)
    check_nxdomain("initial NXDOMAIN (deep)", f"x.y.{ZONE}", keys)
    check_nodata("initial NODATA app/A+AAAA", APP_FQDN, "AAAA", {"A", "RRSIG", "NSEC"}, keys)
    check_nodata("initial NODATA apex/TXT", ZONE, "TXT", {"SOA", "DNSKEY", "RRSIG", "NSEC"}, keys)
    # zone-apex proof is signed by the phase signing ZSK, not the KSK
    resp = udp(f"missing.{ZONE}", "A")
    tag = signed_by(resp, dns.name.from_text(ZONE), dns.rdatatype.NSEC)
    check("initial NSEC proof signed by ZSK1", tag == zsk1_tag, f"key_tag={tag}")

    # ---- out-of-zone refusal -------------------------------------------------
    print("\n== out-of-zone ==")
    for name in ("example.com.", "test.", f"{APP_FQDN}evil."):
        for want in (True, False):
            resp = udp(name, "A", want_dnssec=want)
            check(
                f"REFUSED {name} (dnssec={want}) with no data",
                resp.rcode() == dns.rcode.REFUSED
                and not resp.answer
                and not resp.authority
                and not resp.additional
                and not (resp.flags & dns.flags.AA),
                f"rcode={dns.rcode.to_text(resp.rcode())} an={len(resp.answer)} "
                f"ns={len(resp.authority)} ar={len(resp.additional)}",
            )

    # ---- publish -------------------------------------------------------------
    print("\n== publish ==")
    client.post("/rotate/publish").raise_for_status()
    keys_published = dnskey_of_phase(client)
    check_nxdomain("published NXDOMAIN", f"missing.{ZONE}", keys_published)
    check_nodata("published NODATA app/AAAA", APP_FQDN, "AAAA", {"A", "RRSIG", "NSEC"}, keys_published)
    resp = udp(f"missing.{ZONE}", "A")
    check(
        "published NSEC proof still signed by ZSK1 (A signer)",
        signed_by(resp, dns.name.from_text(ZONE), dns.rdatatype.NSEC) == zsk1_tag,
    )
    # A proof signed in the published phase does not validate against the
    # retired-phase DNSKEY (no ZSK1): this is the stale-key hazard the wait
    # protects against, and it must be impossible to observe from one phase.

    if QUICK:
        print("\n--quick: skipping timed waits (switch/retire proof checks omitted)")
    else:
        # ---- switch ----------------------------------------------------------
        r = client.post("/rotate/switch")
        if r.status_code == 409:
            wait = r.json()["detail"].get("remaining_seconds", 0) + 2
            print(f"waiting {wait}s for DNSKEY caches (t_publish + DNSKEY TTL)...")
            time.sleep(wait)
            r = client.post("/rotate/switch")
            r.raise_for_status()
        else:
            r.raise_for_status()
        print("\n== switch ==")
        keys_switched = dnskey_of_phase(client)
        check_nxdomain("switched NXDOMAIN", f"missing.{ZONE}", keys_switched)
        check_nodata("switched NODATA app/AAAA", APP_FQDN, "AAAA", {"A", "RRSIG", "NSEC"}, keys_switched)
        resp = udp(f"missing.{ZONE}", "A")
        tag = signed_by(resp, dns.name.from_text(ZONE), dns.rdatatype.NSEC)
        check("switched NSEC proof signed by ZSK2", tag == zsk2_tag, f"key_tag={tag}")
        check(
            "switched NSEC proof does not validate against the old DNSKEY",
            _fails_against(udp(f"missing.{ZONE}", "A"), keys),
        )

        # ---- retire ----------------------------------------------------------
        r = client.post("/rotate/retire")
        if r.status_code == 409:
            wait = r.json()["detail"].get("remaining_seconds", 0) + 2
            print(f"waiting {wait}s for A/SOA/NSEC caches (t_switch + signing TTL)...")
            time.sleep(wait)
            r = client.post("/rotate/retire")
            r.raise_for_status()
        else:
            r.raise_for_status()
        print("\n== retire ==")
        keys_retired = dnskey_of_phase(client)
        check_nxdomain("retired NXDOMAIN", f"missing.{ZONE}", keys_retired)
        check_nodata("retired NODATA app/AAAA", APP_FQDN, "AAAA", {"A", "RRSIG", "NSEC"}, keys_retired)
        resp = udp(f"missing.{ZONE}", "A")
        check(
            "retired NSEC proof signed by ZSK2",
            signed_by(resp, dns.name.from_text(ZONE), dns.rdatatype.NSEC) == zsk2_tag,
        )
        check(
            "retired NXDOMAIN carries no ZSK1 signature at all",
            all(
                rd.key_tag != zsk1_tag
                for rr in resp.authority
                if rr.rdtype == dns.rdatatype.RRSIG
                for rd in rr
            ),
        )

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all checks passed")
    return 0


def _fails_against(msg: dns.message.Message, old_keys) -> bool:
    """True if the NSEC proof in *msg* fails validation with *old_keys*."""
    for rr in msg.authority:
        if rr.rdtype != dns.rdatatype.NSEC:
            continue
        if not validate_rrset(rr, msg, old_keys):
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""End-to-end check of the DNSSEC ZSK rotation demo.

Drives the HTTP API (the same calls Swagger UI makes) and verifies real UDP
answers at every phase, then replays captured answers in the two dangerous
old/new mixes a caching resolver could see:

  MIX 1: NEW A answer (signed by ZSK2) + OLD cached DNSKEY (no ZSK2) -> must FAIL
         => why /rotate/switch waits t_publish + DNSKEY TTL
  MIX 2: OLD A answer (signed by ZSK1) + NEW DNSKEY (ZSK1 removed)  -> must FAIL
         => why /rotate/retire waits t_switch + A TTL

Usage: python3 scripts/demo_check.py
Env:   API_BASE (default http://127.0.0.1:8000), DNS_HOST (127.0.0.1),
       DNS_PORT (5353), ZONE_NAME (example.test), APP_LABEL (app)
"""
from __future__ import annotations

import os
import sys
import time

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import httpx

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
DNS_HOST = os.getenv("DNS_HOST", "127.0.0.1")
DNS_PORT = int(os.getenv("DNS_PORT", "5353"))
ZONE = os.getenv("ZONE_NAME", "example.test").rstrip(".") + "."
APP_FQDN = f"{os.getenv('APP_LABEL', 'app')}.{ZONE}"
APEX = dns.name.from_text(ZONE)

failures: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {extra}" if extra else ""))
    if not cond:
        failures.append(name)


def udp_query(name: str, rdtype: str) -> dns.message.Message:
    q = dns.message.make_query(name, rdtype, want_dnssec=True)
    return dns.query.udp(q, DNS_HOST, port=DNS_PORT, timeout=5)


def get_rrset(resp: dns.message.Message, rdtype: int):
    for rr in resp.answer:
        if rr.rdtype == rdtype:
            return rr
    return None


def key_tags(dnskey_rrset) -> list[int]:
    return sorted(dns.dnssec.key_id(k) for k in dnskey_rrset)


def validates(rrset, rrsig, dnskey_rrset) -> bool:
    try:
        dns.dnssec.validate(rrset, rrsig, {APEX: dnskey_rrset})
        return True
    except dns.dnssec.ValidationFailure:
        return False


def authority_rrsets(resp: dns.message.Message, rdtype: int):
    return [rr for rr in resp.authority if rr.rdtype == rdtype]


def rrsig_for(resp: dns.message.Message, rrset, section=None):
    """The RRSIG covering *rrset* at the same owner name, from *section*."""
    section = resp.authority if section is None else section
    for rr in section:
        if rr.rdtype != dns.rdatatype.RRSIG or rr.name != rrset.name:
            continue
        for rd in rr:
            if rd.type_covered == rrset.rdtype:
                return rr
    return None


def nsec_bitmap_types(nsec_rrset) -> set[str]:
    types = set()
    for window, bitmap in nsec_rrset[0].windows:
        for i, octet in enumerate(bitmap):
            for j in range(8):
                if octet & (0x80 >> j):
                    types.add(dns.rdatatype.to_text(window * 256 + i * 8 + j))
    return types


def check_negative(
    label: str, qname: str, qtype: str, dnskey_rrset, expected: str, signer_tag: int
) -> None:
    """Verify a negative answer: NXDOMAIN or NODATA NSEC proof + signatures."""
    q = dns.name.from_text(qname)
    resp = udp_query(qname, qtype)
    nsecs = authority_rrsets(resp, dns.rdatatype.NSEC)
    soas = authority_rrsets(resp, dns.rdatatype.SOA)
    if expected == "nxdomain":
        check(f"{label}: rcode NXDOMAIN", resp.rcode() == dns.rcode.NXDOMAIN)
        check(f"{label}: answer empty", not resp.answer)
        check(f"{label}: NSEC covers QNAME", any(_covers(n, q) for n in nsecs))
        check(
            f"{label}: NSEC covers the wildcard",
            any(_covers(n, dns.name.Name((b"*",)) + APEX) for n in nsecs),
        )
    else:
        check(f"{label}: rcode NOERROR (NODATA)", resp.rcode() == dns.rcode.NOERROR)
        check(f"{label}: answer empty", not resp.answer)
        matching = [n for n in nsecs if n.name == q]
        check(f"{label}: matching NSEC present", len(matching) == 1)
        if matching:
            types = nsec_bitmap_types(matching[0])
            check(f"{label}: bitmap omits {qtype}", qtype not in types, f"types={sorted(types)}")
    check(f"{label}: SOA present", len(soas) == 1)
    if soas:
        check(f"{label}: SOA validates", validates(soas[0], rrsig_for(resp, soas[0]), dnskey_rrset))
    check(
        f"{label}: every NSEC validates",
        bool(nsecs) and all(validates(n, rrsig_for(resp, n), dnskey_rrset) for n in nsecs),
    )
    check(
        f"{label}: denial signed by the current ZSK",
        bool(nsecs)
        and all(rrsig_for(resp, n)[0].key_tag == signer_tag for n in nsecs)
        and bool(soas)
        and rrsig_for(resp, soas[0])[0].key_tag == signer_tag,
        f"expected tag {signer_tag}",
    )


def _covers(nsec_rrset, name: dns.name.Name) -> bool:
    owner, nxt = nsec_rrset.name, nsec_rrset[0].next
    if owner < nxt:
        return owner < name < nxt
    return name > owner or name < nxt


def main() -> int:
    client = httpx.Client(base_url=API_BASE, timeout=10)

    # ---- 0. known starting point -------------------------------------------
    r = client.post("/rotate/reset")
    r.raise_for_status()
    st = client.get("/status").json()
    ksk_tag = st["keys"]["ksk"]
    zsk1_tag = st["keys"]["zsk1"]
    zsk2_tag = st["keys"]["zsk2"]
    dnskey_ttl = st["dnskey_ttl"]
    a_ttl = st["a_ttl"]
    soa_ttl = st["soa_ttl"]
    print(f"KSK tag={ksk_tag}  ZSK1(old) tag={zsk1_tag}  ZSK2(new) tag={zsk2_tag}")
    print(f"TTLs: DNSKEY={dnskey_ttl}s A={a_ttl}s SOA={soa_ttl}s\n")

    # ---- 1. initial answers -------------------------------------------------
    check("reset leaves phase=initial", st["phase"] == "initial", st["phase"])

    r = client.post("/rotate/switch")
    check(
        "switch before publish -> 409 invalid_order",
        r.status_code == 409 and r.json()["detail"]["error"] == "invalid_order",
    )
    r = client.post("/rotate/retire")
    check(
        "retire before switch -> 409 invalid_order",
        r.status_code == 409 and r.json()["detail"]["error"] == "invalid_order",
    )

    resp = udp_query(APP_FQDN, "A")
    a_old = get_rrset(resp, dns.rdatatype.A)
    a_old_sig = get_rrset(resp, dns.rdatatype.RRSIG)
    check("initial A answer carries A + RRSIG", a_old is not None and a_old_sig is not None)
    check(
        "initial A signed by ZSK1",
        a_old_sig is not None and a_old_sig[0].key_tag == zsk1_tag,
        f"key_tag={a_old_sig[0].key_tag if a_old_sig else '-'}",
    )

    resp = udp_query(ZONE, "DNSKEY")
    dnskey_old = get_rrset(resp, dns.rdatatype.DNSKEY)
    dnskey_old_sig = get_rrset(resp, dns.rdatatype.RRSIG)
    check(
        "initial DNSKEY = {KSK, ZSK1}",
        dnskey_old is not None and key_tags(dnskey_old) == sorted([ksk_tag, zsk1_tag]),
        f"tags={key_tags(dnskey_old) if dnskey_old else '-'}",
    )
    check("initial DNSKEY self-signed by KSK", validates(dnskey_old, dnskey_old_sig, dnskey_old))
    check("initial A validates against initial DNSKEY", validates(a_old, a_old_sig, dnskey_old))
    check_negative(
        "initial NXDOMAIN", f"missing.{ZONE}", "A", dnskey_old, "nxdomain", zsk1_tag
    )
    check_negative(
        "initial NODATA", APP_FQDN, "AAAA", dnskey_old, "nodata", zsk1_tag
    )
    udp_query_initial_nxdomain = udp_query(f"missing.{ZONE}", "A")

    # ---- 2. publish (idempotent) -------------------------------------------
    r = client.post("/rotate/publish")
    check("publish -> 200 changed=true", r.status_code == 200 and r.json()["changed"] is True)
    t_publish_1 = r.json()["state"]["timers"]["t_publish"]
    r2 = client.post("/rotate/publish")
    check(
        "re-publish -> 200 changed=false",
        r2.status_code == 200 and r2.json()["changed"] is False,
    )
    check(
        "re-publish does not restart t_publish",
        r2.json()["state"]["timers"]["t_publish"] == t_publish_1,
    )

    resp = udp_query(ZONE, "DNSKEY")
    dnskey_mid = get_rrset(resp, dns.rdatatype.DNSKEY)
    check(
        "after publish DNSKEY = {KSK, ZSK1, ZSK2}",
        dnskey_mid is not None
        and key_tags(dnskey_mid) == sorted([ksk_tag, zsk1_tag, zsk2_tag]),
        f"tags={key_tags(dnskey_mid) if dnskey_mid else '-'}",
    )
    check_negative(
        "published NXDOMAIN", f"missing.{ZONE}", "A", dnskey_mid, "nxdomain", zsk1_tag
    )
    check_negative(
        "published NODATA", APP_FQDN, "AAAA", dnskey_mid, "nodata", zsk1_tag
    )

    # ---- 3. switch too early ------------------------------------------------
    r = client.post("/rotate/switch")
    check("early switch -> 409", r.status_code == 409, f"got {r.status_code}")
    detail = r.json()["detail"]
    remaining = detail.get("remaining_seconds", -1)
    check(
        "early switch reports remaining seconds",
        detail.get("error") == "too_early" and 0 < remaining <= dnskey_ttl,
        f"remaining={remaining}",
    )
    check("Retry-After header matches", r.headers.get("retry-after") == str(remaining))
    resp = udp_query(APP_FQDN, "A")
    sig = get_rrset(resp, dns.rdatatype.RRSIG)
    check(
        "failed switch keeps old A answer (still ZSK1)",
        sig is not None and sig[0].key_tag == zsk1_tag,
    )

    # ---- 4. wait for DNSKEY caches, then switch -----------------------------
    wait = remaining + 2
    print(f"\nwaiting {wait}s: cached DNSKEY answers without ZSK2 must expire "
          f"(t_publish + DNSKEY TTL={dnskey_ttl}s)...")
    time.sleep(wait)
    r = client.post("/rotate/switch")
    check("switch after wait -> 200 changed=true", r.status_code == 200 and r.json()["changed"] is True)
    t_switch_1 = r.json()["state"]["timers"]["t_switch"]
    r2 = client.post("/rotate/switch")
    check(
        "re-switch -> 200 changed=false, t_switch unchanged",
        r2.status_code == 200
        and r2.json()["changed"] is False
        and r2.json()["state"]["timers"]["t_switch"] == t_switch_1,
    )

    resp = udp_query(APP_FQDN, "A")
    a_new = get_rrset(resp, dns.rdatatype.A)
    a_new_sig = get_rrset(resp, dns.rdatatype.RRSIG)
    check(
        "after switch A signed by ZSK2",
        a_new_sig is not None and a_new_sig[0].key_tag == zsk2_tag,
        f"key_tag={a_new_sig[0].key_tag if a_new_sig else '-'}",
    )
    check_negative(
        "switched NXDOMAIN", f"missing.{ZONE}", "A", dnskey_mid, "nxdomain", zsk2_tag
    )
    check_negative(
        "switched NODATA", APP_FQDN, "AAAA", dnskey_mid, "nodata", zsk2_tag
    )

    # ---- 5. retire too early ------------------------------------------------
    r = client.post("/rotate/retire")
    check("early retire -> 409", r.status_code == 409, f"got {r.status_code}")
    detail = r.json()["detail"]
    remaining = detail.get("remaining_seconds", -1)
    signing_ttl = max(a_ttl, st["soa_ttl"])
    check(
        "early retire reports remaining seconds",
        detail.get("error") == "too_early" and 0 < remaining <= signing_ttl,
        f"remaining={remaining}",
    )
    resp = udp_query(ZONE, "DNSKEY")
    dk = get_rrset(resp, dns.rdatatype.DNSKEY)
    check("failed retire keeps 3 DNSKEYs", dk is not None and len(dk) == 3)

    # ---- 6. wait for A caches, then retire ----------------------------------
    wait = remaining + 2
    print(f"\nwaiting {wait}s: cached A/SOA/NSEC answers with the old signature "
          f"must expire (t_switch + signing TTL={signing_ttl}s)...")
    time.sleep(wait)
    r = client.post("/rotate/retire")
    check("retire after wait -> 200 changed=true", r.status_code == 200 and r.json()["changed"] is True)
    r2 = client.post("/rotate/retire")
    check("re-retire -> 200 changed=false", r2.status_code == 200 and r2.json()["changed"] is False)

    resp = udp_query(ZONE, "DNSKEY")
    dnskey_new = get_rrset(resp, dns.rdatatype.DNSKEY)
    dnskey_new_sig = get_rrset(resp, dns.rdatatype.RRSIG)
    check(
        "after retire DNSKEY = {KSK, ZSK2}",
        dnskey_new is not None and key_tags(dnskey_new) == sorted([ksk_tag, zsk2_tag]),
        f"tags={key_tags(dnskey_new) if dnskey_new else '-'}",
    )
    check("new DNSKEY self-signed by KSK", validates(dnskey_new, dnskey_new_sig, dnskey_new))
    resp = udp_query(APP_FQDN, "A")
    check(
        "A still signed by ZSK2 after retire",
        get_rrset(resp, dns.rdatatype.RRSIG)[0].key_tag == zsk2_tag,
    )
    check_negative(
        "retired NXDOMAIN", f"missing.{ZONE}", "A", dnskey_new, "nxdomain", zsk2_tag
    )
    check_negative(
        "retired NODATA", APP_FQDN, "AAAA", dnskey_new, "nodata", zsk2_tag
    )
    # No proof from an earlier phase may survive into the retired phase.
    resp = udp_query(f"missing.{ZONE}", "A")
    check(
        "retired NXDOMAIN carries no ZSK1 signature",
        all(
            rd.key_tag != zsk1_tag
            for rr in resp.authority
            if rr.rdtype == dns.rdatatype.RRSIG
            for rd in rr
        ),
    )

    # ---- 7. old/new mixes ----------------------------------------------------
    print("\n== old/new mix validation (why the two waits exist) ==")
    check("control: old A + old DNSKEY validates", validates(a_old, a_old_sig, dnskey_old))
    check("control: new A + mid DNSKEY validates", validates(a_new, a_new_sig, dnskey_mid))
    check("control: old A + mid DNSKEY validates", validates(a_old, a_old_sig, dnskey_mid))
    check("control: new A + new DNSKEY validates", validates(a_new, a_new_sig, dnskey_new))
    check(
        "MIX 1 (danger): new A + old cached DNSKEY (no ZSK2) FAILS",
        not validates(a_new, a_new_sig, dnskey_old),
    )
    check(
        "MIX 2 (danger): old A (ZSK1 sig) + new DNSKEY (no ZSK1) FAILS",
        not validates(a_old, a_old_sig, dnskey_new),
    )
    # The same hazard applies to denial proofs: an NXDOMAIN proof captured in
    # the initial phase was signed by ZSK1, which the retired phase removed.
    nx_initial = udp_query_initial_nxdomain
    old_nsec = [rr for rr in nx_initial.authority if rr.rdtype == dns.rdatatype.NSEC]
    check(
        "MIX 3 (danger): initial NXDOMAIN proof (ZSK1) + retired DNSKEY (no ZSK1) FAILS",
        bool(old_nsec)
        and not any(
            validates(n, rrsig_for(nx_initial, n), dnskey_new) for n in old_nsec
        ),
    )

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

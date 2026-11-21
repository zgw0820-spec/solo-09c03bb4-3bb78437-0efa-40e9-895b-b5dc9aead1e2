"""Unit tests for the zone renderer's DNSSEC denial of existence.

No network: a ZoneRenderer is driven directly and each proof is validated
with dns.dnssec against the DNSKEY set rendered in the same phase.
"""
from __future__ import annotations

import dataclasses

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from app.config import load_settings
from app.keys import KeyRing
from app.zone import RotationState, ZoneRenderer

APEX = dns.name.from_text("example.test.")
APP = dns.name.from_text("app.example.test.")


@pytest.fixture(scope="module")
def keyring():
    return KeyRing(load_settings().keys_dir)


@pytest.fixture()
def env(keyring):
    settings = load_settings()
    state = RotationState(settings, keyring)
    return settings, state, ZoneRenderer(settings, keyring, state)


def dnskey_map(renderer, state):
    view = state.view()
    rr = renderer._dnskey_rrset(view)
    return {APEX: rr}


def nsec_types(nsec_rrset) -> set[str]:
    out = set()
    for window, bitmap in nsec_rrset[0].windows:
        for i, octet in enumerate(bitmap):
            for j in range(8):
                if octet & (0x80 >> j):
                    out.add(dns.rdatatype.to_text(window * 256 + i * 8 + j))
    return out


def sig_for(rrsets, rrset):
    for rr in rrsets:
        if rr.rdtype != dns.rdatatype.RRSIG or rr.name != rrset.name:
            continue
        if any(rd.type_covered == rrset.rdtype for rd in rr):
            return rr
    raise AssertionError(f"no RRSIG over {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}")


def assert_signed(rrsets, keys):
    for rr in rrsets:
        if rr.rdtype == dns.rdatatype.RRSIG:
            continue
        sig = sig_for(rrsets, rr)
        dns.dnssec.validate(rr, sig, keys)


def covers(nsec_rrset, name):
    owner, nxt = nsec_rrset.name, nsec_rrset[0].next
    if owner < nxt:
        return owner < name < nxt
    return name > owner or name < nxt


def test_chain_is_complete_and_canonical(env):
    _, state, renderer = env
    names = renderer._owner_names
    assert names == sorted(names)
    assert set(names) == {APEX, APP}
    # last NSEC points back at the apex
    assert renderer._nsec_rrsets[APP][0].next == APEX
    assert renderer._nsec_rrsets[APEX][0].next == APP


def test_chain_bitmaps(env):
    _, _, renderer = env
    apex_types = nsec_types(renderer._nsec_rrsets[APEX])
    assert {"SOA", "DNSKEY", "NSEC", "RRSIG"} <= apex_types
    assert "A" not in apex_types
    app_types = nsec_types(renderer._nsec_rrsets[APP])
    assert app_types == {"A", "NSEC", "RRSIG"}


def test_nsec_ttl_is_soa_minimum(env):
    settings, _, renderer = env
    for rr in renderer._nsec_rrsets.values():
        assert rr.ttl == settings.soa_ttl


def test_nodata_app_aaaa(env):
    settings, state, renderer = env
    rcode, answer, authority = renderer.lookup(APP, dns.rdatatype.AAAA)
    assert rcode == dns.rcode.NOERROR
    assert answer == []
    nsecs = [rr for rr in authority if rr.rdtype == dns.rdatatype.NSEC]
    assert len(nsecs) == 1
    assert nsecs[0].name == APP
    assert "AAAA" not in nsec_types(nsecs[0])
    assert "A" in nsec_types(nsecs[0])
    assert any(rr.rdtype == dns.rdatatype.SOA for rr in authority)
    assert_signed(authority, dnskey_map(renderer, state))


def test_nodata_apex_txt(env):
    settings, state, renderer = env
    rcode, answer, authority = renderer.lookup(APEX, dns.rdatatype.TXT)
    assert rcode == dns.rcode.NOERROR and answer == []
    nsecs = [rr for rr in authority if rr.rdtype == dns.rdatatype.NSEC]
    assert [n.name for n in nsecs] == [APEX]
    assert "TXT" not in nsec_types(nsecs[0])
    assert_signed(authority, dnskey_map(renderer, state))


@pytest.mark.parametrize(
    "qname",
    [
        "missing.example.test.",
        "zzz.example.test.",
        "x.y.example.test.",
        "a.example.test.",
        "0.example.test.",
        "*.example.test.",
    ],
)
def test_nxdomain_proves_name_and_wildcard(env, qname):
    settings, state, renderer = env
    q = dns.name.from_text(qname)
    rcode, answer, authority = renderer.lookup(q, dns.rdatatype.A)
    assert rcode == dns.rcode.NXDOMAIN
    assert answer == []
    nsecs = [rr for rr in authority if rr.rdtype == dns.rdatatype.NSEC]
    assert nsecs, "NXDOMAIN lacks an NSEC proof"
    assert any(covers(n, q) for n in nsecs), "no NSEC covers QNAME"
    wildcard = dns.name.Name((b"*",)) + APEX
    assert any(covers(n, wildcard) for n in nsecs), "no NSEC denies the wildcard"
    # no duplicate proof RRsets
    assert len({(n.name, n[0].next) for n in nsecs}) == len(nsecs)
    assert_signed(authority, dnskey_map(renderer, state))


def test_nxdomain_single_proof_when_same_interval(env):
    """When one NSEC covers both QNAME and the wildcard it is sent once.

    In this 2-name zone the wildcard ``*.example.test.`` falls in the
    apex -> app interval, as does ``a.example.test.``.
    """
    settings, state, renderer = env
    rcode, _, authority = renderer.lookup(
        dns.name.from_text("a.example.test."), dns.rdatatype.A
    )
    assert rcode == dns.rcode.NXDOMAIN
    nsecs = [rr for rr in authority if rr.rdtype == dns.rdatatype.NSEC]
    assert len(nsecs) == 1
    assert nsecs[0].name == APEX


def test_out_of_zone_is_refused_without_leaks(env, keyring):
    settings, state, renderer = env
    for qname in ("example.com.", "test.", "app.example.test.evil."):
        rcode, answer, authority = renderer.lookup(dns.name.from_text(qname), dns.rdatatype.A)
        assert rcode == dns.rcode.REFUSED
        assert answer == [] and authority == []
        assert not renderer.is_authoritative(dns.name.from_text(qname))
    assert renderer.is_authoritative(APEX)
    assert renderer.is_authoritative(APP)


def test_proofs_use_current_signer_at_every_phase(env, keyring, monkeypatch):
    """Each phase's denial proof validates against that phase's DNSKEY only."""
    settings, state, renderer = env
    expected = {"initial": keyring.zsk1, "published": keyring.zsk1,
                "switched": keyring.zsk2, "retired": keyring.zsk2}
    state.publish()
    state.publish()  # idempotent
    for phase_action, phase in [
        (lambda: None, "published"),
        (lambda: _force_switch(state), "switched"),
        (lambda: _force_retire(state), "retired"),
    ]:
        phase_action()
        view = state.view()
        assert view.phase == phase
        keys = {APEX: renderer._dnskey_rrset(view)}
        signer = expected[phase]
        _, _, authority = renderer.lookup(
            dns.name.from_text("missing.example.test."), dns.rdatatype.A
        )
        assert_signed(authority, keys)
        for rr in authority:
            if rr.rdtype == dns.rdatatype.RRSIG:
                assert rr[0].key_tag == signer.key_tag, (phase, rr[0].key_tag)
        # the A RRset and the NSEC proof are signed by the same ZSK
        _, a_answer, _ = renderer.lookup(APP, dns.rdatatype.A)
        a_sig = sig_for(a_answer, a_answer[0])
        assert a_sig[0].key_tag == signer.key_tag
        # after retire the old key must be gone from the DNSKEY set
        if phase == "retired":
            tags = {dns.dnssec.key_id(k) for k in keys[APEX]}
            assert keyring.zsk1.key_tag not in tags
            assert keyring.zsk2.key_tag in tags


def test_ent_answered_in_name_error_form():
    """A name that only exists as an empty non-terminal is NXDOMAIN + proofs."""
    base = load_settings()
    settings = dataclasses.replace(base, app_label="a.b")
    keyring = KeyRing(settings.keys_dir)
    state = RotationState(settings, keyring)
    renderer = ZoneRenderer(settings, keyring, state)
    ent = dns.name.from_text("b.example.test.")
    rcode, answer, authority = renderer.lookup(ent, dns.rdatatype.A)
    assert rcode == dns.rcode.NXDOMAIN
    nsecs = [rr for rr in authority if rr.rdtype == dns.rdatatype.NSEC]
    assert any(covers(n, ent) for n in nsecs)
    # the closest encloser is the ENT itself, so the wildcard is *.b.example...
    wildcard = dns.name.from_text("*.b.example.test.")
    assert any(covers(n, wildcard) for n in nsecs)
    # no NSEC is synthesised for the ENT (RFC 4035 2.3)
    assert ent not in renderer._nsec_rrsets


def _force_switch(state):
    """Bypass the cache wait for the unit test only."""
    state._t_publish = 0.0
    return state.switch()


def _force_retire(state):
    state._t_switch = 0.0
    return state.retire()

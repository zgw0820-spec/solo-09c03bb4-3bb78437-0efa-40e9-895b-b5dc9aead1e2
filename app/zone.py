"""Rotation state machine and on-the-fly DNSSEC signing.

Implements a pre-publish ZSK rollover (RFC 6781 style) for one fixed domain:

    initial    DNSKEY = {KSK, ZSK1}          A signed by ZSK1
    published  DNSKEY = {KSK, ZSK1, ZSK2}    A signed by ZSK1
    switched   DNSKEY = {KSK, ZSK1, ZSK2}    A signed by ZSK2
    retired    DNSKEY = {KSK, ZSK2}          A signed by ZSK2

Two cache-safety waits are enforced, both anchored at the last moment the
*old* answer could have been sent, plus that answer's TTL:

  * /rotate/switch is refused until t_publish + DNSKEY_TTL, because a resolver
    may still hold a DNSKEY answer that does not contain ZSK2 (a new A record
    signed by ZSK2 would not validate against it).
  * /rotate/retire is refused until t_switch + A_TTL, because a resolver may
    still hold an A answer carrying the ZSK1 signature (it would not validate
    once ZSK1 disappears from the DNSKEY set).

Failed operations never touch the state, so DNS answers stay exactly as they
were.  Repeating an already-successful operation is a no-op and, in
particular, does NOT restart any timer.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdata
import dns.rcode
import dns.rrset
import dns.rdatatype

from .config import Settings
from .keys import KeyPair, KeyRing

log = logging.getLogger("dnssec-demo.zone")

PHASE_INITIAL = "initial"  # ZSK1 published, ZSK1 signs A
PHASE_PUBLISHED = "published"  # ZSK1+ZSK2 published, ZSK1 signs A
PHASE_SWITCHED = "switched"  # ZSK1+ZSK2 published, ZSK2 signs A
PHASE_RETIRED = "retired"  # ZSK2 published, ZSK2 signs A

SOA_SERIAL = 2026112101


class RotationState:
    """Rotation phase plus the two wall-clock anchors (all times epoch secs).

    t_publish: last moment a DNSKEY answer *without* ZSK2 could have been sent.
    t_switch:  last moment an A answer signed with ZSK1 could have been sent.
    """

    def __init__(self, settings: Settings, keyring: KeyRing):
        self.settings = settings
        self.keyring = keyring
        self._lock = threading.RLock()
        self._phase = PHASE_INITIAL
        self._t_publish: float | None = None
        self._t_switch: float | None = None

    # ------------------------------------------------------------------ views

    def _published_zsks_locked(self) -> list[KeyPair]:
        if self._phase == PHASE_INITIAL:
            return [self.keyring.zsk1]
        if self._phase == PHASE_RETIRED:
            return [self.keyring.zsk2]
        return [self.keyring.zsk1, self.keyring.zsk2]

    def _signing_zsk_locked(self) -> KeyPair:
        if self._phase in (PHASE_INITIAL, PHASE_PUBLISHED):
            return self.keyring.zsk1
        return self.keyring.zsk2

    @dataclass(frozen=True)
    class View:
        """Consistent snapshot used to render one DNS answer."""

        phase: str
        published_zsks: tuple[KeyPair, ...]
        signing_zsk: KeyPair

    def view(self) -> "RotationState.View":
        with self._lock:
            return RotationState.View(
                phase=self._phase,
                published_zsks=tuple(self._published_zsks_locked()),
                signing_zsk=self._signing_zsk_locked(),
            )

    def status(self) -> dict:
        with self._lock:
            now = time.time()
            switch_not_before = (
                self._t_publish + self.settings.dnskey_ttl
                if self._t_publish is not None
                else None
            )
            retire_not_before = (
                self._t_switch + self.settings.a_ttl
                if self._t_switch is not None
                else None
            )
            signing = self._signing_zsk_locked()
            return {
                "zone": self.settings.apex,
                "domain": self.settings.app_fqdn,
                "phase": self._phase,
                "now": now,
                "keys": {
                    "ksk": self.keyring.ksk.key_tag,
                    "zsk1": self.keyring.zsk1.key_tag,
                    "zsk2": self.keyring.zsk2.key_tag,
                },
                "ksk": self.keyring.ksk.public_dict(),
                "published_zsks": [z.public_dict() for z in self._published_zsks_locked()],
                "a_record": {
                    "name": self.settings.app_fqdn,
                    "value": self.settings.a_value,
                    "ttl": self.settings.a_ttl,
                    "signed_by": {"role": signing.role, "key_tag": signing.key_tag},
                },
                "dnskey_ttl": self.settings.dnskey_ttl,
                "a_ttl": self.settings.a_ttl,
                "timers": {
                    "t_publish": self._t_publish,
                    "t_switch": self._t_switch,
                    "switch_not_before": switch_not_before,
                    "switch_remaining_seconds": _remaining(switch_not_before, now),
                    "retire_not_before": retire_not_before,
                    "retire_remaining_seconds": _remaining(retire_not_before, now),
                },
            }

    # -------------------------------------------------------------- operations

    def publish(self) -> dict:
        """Step 1: add ZSK2 to the DNSKEY RRset (starts the switch wait)."""
        with self._lock:
            if self._phase != PHASE_INITIAL:
                return self._ok(
                    "publish",
                    changed=False,
                    message="new ZSK already published; existing t_publish kept",
                )
            self._phase = PHASE_PUBLISHED
            self._t_publish = time.time()
            log.info(
                "PUBLISH: ZSK2 (tag %d) added to DNSKEY set; switch allowed in %ds",
                self.keyring.zsk2.key_tag,
                self.settings.dnskey_ttl,
            )
            return self._ok(
                "publish",
                changed=True,
                message=(
                    f"ZSK2 (key tag {self.keyring.zsk2.key_tag}) added to the DNSKEY "
                    f"set; /rotate/switch allowed after t_publish + DNSKEY TTL "
                    f"({self.settings.dnskey_ttl}s)"
                ),
            )

    def switch(self) -> dict:
        """Step 2: sign the A record with ZSK2 (starts the retire wait)."""
        with self._lock:
            if self._phase in (PHASE_SWITCHED, PHASE_RETIRED):
                return self._ok(
                    "switch",
                    changed=False,
                    message="A record already signed by the new ZSK; existing t_switch kept",
                )
            if self._phase == PHASE_INITIAL:
                return self._conflict(
                    "switch",
                    "invalid_order",
                    "new ZSK is not in the DNSKEY set yet; call /rotate/publish first",
                )
            not_before = self._t_publish + self.settings.dnskey_ttl
            now = time.time()
            if now < not_before:
                return self._conflict(
                    "switch",
                    "too_early",
                    "waiting for cached DNSKEY answers without the new ZSK to expire "
                    "(t_publish + DNSKEY TTL); state unchanged",
                    remaining=math.ceil(not_before - now),
                    not_before=not_before,
                )
            self._phase = PHASE_SWITCHED
            self._t_switch = now
            log.info(
                "SWITCH: A record now signed by ZSK2 (tag %d); retire allowed in %ds",
                self.keyring.zsk2.key_tag,
                self.settings.a_ttl,
            )
            return self._ok(
                "switch",
                changed=True,
                message=(
                    f"A record now signed by ZSK2 (key tag {self.keyring.zsk2.key_tag}); "
                    f"/rotate/retire allowed after t_switch + A TTL "
                    f"({self.settings.a_ttl}s)"
                ),
            )

    def retire(self) -> dict:
        """Step 3: remove ZSK1 from the DNSKEY RRset."""
        with self._lock:
            if self._phase == PHASE_RETIRED:
                return self._ok(
                    "retire",
                    changed=False,
                    message="old ZSK already retired",
                )
            if self._phase in (PHASE_INITIAL, PHASE_PUBLISHED):
                return self._conflict(
                    "retire",
                    "invalid_order",
                    "old ZSK still signs the A record; call /rotate/switch first",
                )
            not_before = self._t_switch + self.settings.a_ttl
            now = time.time()
            if now < not_before:
                return self._conflict(
                    "retire",
                    "too_early",
                    "waiting for cached A answers carrying the old ZSK signature to "
                    "expire (t_switch + A TTL); state unchanged",
                    remaining=math.ceil(not_before - now),
                    not_before=not_before,
                )
            self._phase = PHASE_RETIRED
            log.info(
                "RETIRE: ZSK1 (tag %d) removed from DNSKEY set",
                self.keyring.zsk1.key_tag,
            )
            return self._ok(
                "retire",
                changed=True,
                message=(
                    f"ZSK1 (key tag {self.keyring.zsk1.key_tag}) removed from the "
                    f"DNSKEY set; rotation complete"
                ),
            )

    def reset(self) -> dict:
        """Demo helper: back to the initial state (ZSK1 only, timers cleared)."""
        with self._lock:
            self._phase = PHASE_INITIAL
            self._t_publish = None
            self._t_switch = None
            log.info("RESET: back to initial state (ZSK1 only)")
            return self._ok("reset", changed=True, message="demo state reset to initial")

    # ----------------------------------------------------------------- helpers

    def _ok(self, operation: str, changed: bool, message: str) -> dict:
        return {
            "ok": True,
            "operation": operation,
            "changed": changed,
            "message": message,
            "state": self.status(),
        }

    @staticmethod
    def _conflict(
        operation: str,
        error: str,
        reason: str,
        remaining: int | None = None,
        not_before: float | None = None,
    ) -> dict:
        detail = {"error": error, "operation": operation, "reason": reason}
        if remaining is not None:
            detail["remaining_seconds"] = remaining
        if not_before is not None:
            detail["not_before"] = not_before
        return {"ok": False, "error": detail}


def _remaining(not_before: float | None, now: float) -> int | None:
    if not_before is None:
        return None
    return max(0, math.ceil(not_before - now))


class ZoneRenderer:
    """Builds signed RRsets for the zone from the current rotation state."""

    def __init__(self, settings: Settings, keyring: KeyRing, state: RotationState):
        self.settings = settings
        self.keyring = keyring
        self.state = state
        self.apex = dns.name.from_text(settings.apex)
        self.app_name = dns.name.from_text(settings.app_fqdn)
        self.a_rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.A, settings.a_value
        )
        self.soa_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            f"ns1.{settings.apex} hostmaster.{settings.apex} "
            f"{SOA_SERIAL} 7200 3600 1209600 {settings.soa_ttl}",
        )

    # ---------------------------------------------------------------- signing

    def _sign(self, rrset: dns.rrset.RRset, key: KeyPair) -> dns.rrset.RRset:
        now = int(time.time())
        rrsig = dns.dnssec.sign(
            rrset,
            key.private_key,
            self.apex,
            key.dnskey,
            inception=now - self.settings.sig_inception_skew,
            expiration=now + self.settings.sig_lifetime,
        )
        return dns.rrset.from_rdata(rrset.name, rrset.ttl, rrsig)

    def _soa_rrset(self) -> dns.rrset.RRset:
        rr = dns.rrset.RRset(self.apex, dns.rdataclass.IN, dns.rdatatype.SOA)
        rr.ttl = self.settings.soa_ttl
        rr.add(self.soa_rdata)
        return rr

    def _dnskey_rrset(self, view: RotationState.View) -> dns.rrset.RRset:
        rr = dns.rrset.RRset(self.apex, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        rr.ttl = self.settings.dnskey_ttl
        rr.add(self.keyring.ksk.dnskey)
        for zsk in view.published_zsks:
            rr.add(zsk.dnskey)
        return rr

    def _a_rrset(self) -> dns.rrset.RRset:
        rr = dns.rrset.RRset(self.app_name, dns.rdataclass.IN, dns.rdatatype.A)
        rr.ttl = self.settings.a_ttl
        rr.add(self.a_rdata)
        return rr

    # ---------------------------------------------------------------- lookups

    def lookup(self, qname: dns.name.Name, qtype: int):
        """Return (rcode, answer_rrsets, authority_rrsets) for a query."""
        view = self.state.view()
        refused = (dns.rcode.REFUSED, [], [])
        if not qname.is_subdomain(self.apex):
            return refused

        soa = self._soa_rrset()
        soa_signed = [soa, self._sign(soa, view.signing_zsk)]

        if qname not in (self.apex, self.app_name):
            return dns.rcode.NXDOMAIN, [], soa_signed

        answers: list[dns.rrset.RRset] = []
        if qname == self.apex:
            if qtype in (dns.rdatatype.SOA, dns.rdatatype.ANY):
                answers += soa_signed
            if qtype in (dns.rdatatype.DNSKEY, dns.rdatatype.ANY):
                dnskey = self._dnskey_rrset(view)
                answers += [dnskey, self._sign(dnskey, self.keyring.ksk)]
        elif qtype in (dns.rdatatype.A, dns.rdatatype.ANY):
            a = self._a_rrset()
            answers += [a, self._sign(a, view.signing_zsk)]

        if answers:
            return dns.rcode.NOERROR, answers, []
        # Known name, unknown type: NODATA.
        return dns.rcode.NOERROR, [], soa_signed

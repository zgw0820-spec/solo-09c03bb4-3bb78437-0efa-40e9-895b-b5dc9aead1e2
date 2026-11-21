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
  * /rotate/retire is refused until t_switch + max(A_TTL, SOA_TTL), because a
    resolver may still hold an answer carrying the ZSK1 signature -- A records,
    and also the SOA/NSEC material in negative answers -- which would not
    validate once ZSK1 disappears from the DNSKEY set.

Negative answers are signed too: NXDOMAIN carries NSEC proofs that QNAME and
the relevant wildcard do not exist, NODATA carries the NSEC for the queried
owner name.  Every RRset in a response is signed by the phase's signing ZSK
(DNSKEY by the KSK), from one state snapshot, so an answer never mixes
signatures or proofs from different rotation phases.

Failed operations never touch the state, so DNS answers stay exactly as they
were.  Repeating an already-successful operation is a no-op and, in
particular, does NOT restart any timer.
"""
from __future__ import annotations

import bisect
import logging
import math
import threading
import time
from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.NSEC import NSEC, Bitmap

from .config import Settings
from .keys import KeyPair, KeyRing

log = logging.getLogger("dnssec-demo.zone")

PHASE_INITIAL = "initial"  # ZSK1 published, ZSK1 signs A/SOA/NSEC
PHASE_PUBLISHED = "published"  # ZSK1+ZSK2 published, ZSK1 signs A/SOA/NSEC
PHASE_SWITCHED = "switched"  # ZSK1+ZSK2 published, ZSK2 signs A/SOA/NSEC
PHASE_RETIRED = "retired"  # ZSK2 published, ZSK2 signs A/SOA/NSEC

SOA_SERIAL = 2026112101


class RotationState:
    """Rotation phase plus the two wall-clock anchors (all times epoch secs).

    t_publish: last moment a DNSKEY answer *without* ZSK2 could have been sent.
    t_switch:  last moment an answer signed by ZSK1 could have been sent
               (A, SOA and NSEC all carry the signing ZSK's signature).
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

    def _signing_zsk_ttl_locked(self) -> int:
        """Longest TTL of any RRset signed by the current signing ZSK.

        The ZSK signs A as well as the negative-answer material (SOA and
        NSEC), so the retire wait must outlive every cached answer carrying
        an old-ZSK signature, not just the A RRset.
        """
        return max(self.settings.a_ttl, self.settings.soa_ttl)

    @dataclass(frozen=True)
    class View:
        """Consistent snapshot used to render one DNS answer."""

        phase: str
        published_zsks: tuple[KeyPair, ...]
        signing_zsk: KeyPair

    def view(self) -> RotationState.View:
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
                self._t_switch + self._signing_zsk_ttl_locked()
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
                "soa_ttl": self.settings.soa_ttl,
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
            signing_ttl = self._signing_zsk_ttl_locked()
            log.info(
                "SWITCH: A/SOA/NSEC now signed by ZSK2 (tag %d); retire allowed in %ds",
                self.keyring.zsk2.key_tag,
                signing_ttl,
            )
            return self._ok(
                "switch",
                changed=True,
                message=(
                    f"A/SOA/NSEC now signed by ZSK2 (key tag "
                    f"{self.keyring.zsk2.key_tag}); /rotate/retire allowed after "
                    f"t_switch + max(A TTL, SOA TTL) ({signing_ttl}s)"
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
                    "old ZSK still signs the A/SOA/NSEC data; call /rotate/switch first",
                )
            not_before = self._t_switch + self._signing_zsk_ttl_locked()
            now = time.time()
            if now < not_before:
                return self._conflict(
                    "retire",
                    "too_early",
                    "waiting for cached A/SOA/NSEC answers carrying the old ZSK "
                    "signature to expire (t_switch + signing TTL); state unchanged",
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
    """Builds signed RRsets for the zone from the current rotation state.

    The zone is unsigned in memory; every answer is signed on the fly with
    the *current* signing ZSK, so a proof can never carry a stale signature
    from an earlier rotation phase.  The zone also carries a full NSEC chain
    (one NSEC per authoritative owner name, in canonical order) used for
    authenticated denial of existence:

      * NXDOMAIN: NSEC(s) covering the queried name and the wildcard that
        could have synthesised it (RFC 4035 section 3.1.3.2);
      * NODATA:   the NSEC that exactly matches the queried owner name,
        whose type bitmap lists the types that do exist (section 3.1.3.1).

    NSEC RRsets use the SOA MINIMUM TTL (RFC 4035 section 2.3) and are
    signed by the same ZSK that signs the SOA/A data.
    """

    def __init__(self, settings: Settings, keyring: KeyRing, state: RotationState):
        self.settings = settings
        self.keyring = keyring
        self.state = state
        self.apex = dns.name.from_text(settings.apex)
        self.app_name = dns.name.from_text(settings.app_fqdn)
        if b"*" in self.app_name.labels:
            raise ValueError(
                "APP_LABEL must not contain a wildcard label: this zone has no "
                "wildcard synthesis, and denial proofs assume that"
            )
        self.a_rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.A, settings.a_value
        )
        self.soa_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            f"ns1.{settings.apex} hostmaster.{settings.apex} "
            f"{SOA_SERIAL} 7200 3600 1209600 {settings.soa_ttl}",
        )

        # Authoritative RRsets at each owner name (unsigned).  DNSKEY is
        # rendered per query because its contents depend on the phase.
        self._zone: dict[dns.name.Name, set[int]] = {
            self.apex: {dns.rdatatype.SOA, dns.rdatatype.DNSKEY},
            self.app_name: {dns.rdatatype.A},
        }
        self._owner_names: list[dns.name.Name] = sorted(self._zone)
        self._owner_set = set(self._owner_names)
        # Names that exist in the zone tree for closest-encloser purposes:
        # every owner name plus every ancestor up to the apex (empty
        # non-terminals).  ENTs get no NSEC of their own (RFC 4035 2.3) but a
        # query for one is answered in the Name Error form (RFC 4035 3.1.3.2).
        existing: set[dns.name.Name] = set()
        for owner in self._owner_names:
            name = owner
            while name.is_subdomain(self.apex):
                existing.add(name)
                if name == self.apex:
                    break
                name = name.parent()
        self._existing_names = existing
        self._nsec_rrsets = self._build_nsec_chain()

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

    def _signed(self, rrset: dns.rrset.RRset, key: KeyPair) -> list[dns.rrset.RRset]:
        return [rrset, self._sign(rrset, key)]

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

    # ------------------------------------------------------------- NSEC chain

    def _build_nsec_chain(self) -> dict[dns.name.Name, dns.rrset.RRset]:
        """One NSEC per authoritative owner name, chained in canonical order.

        The last NSEC points back at the apex (RFC 4034 section 4.1.1).  The
        type bitmap always lists the types that actually exist at the owner
        plus NSEC and RRSIG, which is mandatory (RFC 4035 section 2.3).
        """
        chain: dict[dns.name.Name, dns.rrset.RRset] = {}
        for i, owner in enumerate(self._owner_names):
            nxt = self._owner_names[(i + 1) % len(self._owner_names)]
            types = set(self._zone[owner]) | {
                dns.rdatatype.NSEC,
                dns.rdatatype.RRSIG,
            }
            nsec = NSEC(
                dns.rdataclass.IN,
                dns.rdatatype.NSEC,
                nxt,
                Bitmap.from_rdtypes(sorted(types)),
            )
            rr = dns.rrset.from_rdata(owner, self.settings.soa_ttl, nsec)
            chain[owner] = rr
        return chain

    def _nsec_rrsets_at(self, name: dns.name.Name) -> dns.rrset.RRset:
        return self._nsec_rrsets[name]

    def _covering_nsec(self, name: dns.name.Name) -> dns.rrset.RRset:
        """NSEC whose canonical interval contains *name* (which must not exist).

        With a sorted owner-name list, the predecessor of the insertion point
        owns that interval; the chain wraps from the last name back to apex.
        """
        idx = bisect.bisect_left(self._owner_names, name)
        pred = self._owner_names[(idx - 1) % len(self._owner_names)]
        return self._nsec_rrsets[pred]

    # ---------------------------------------------------------------- lookups

    def is_authoritative(self, qname: dns.name.Name) -> bool:
        """True if *qname* is inside the zone this renderer is authoritative for."""
        return qname.is_subdomain(self.apex)

    def _all_signed_rrsets_at(
        self, name: dns.name.Name, view: RotationState.View
    ) -> list[list[dns.rrset.RRset]]:
        """Every authoritative RRset at *name*, each followed by its RRSIG(s)."""
        groups: list[list[dns.rrset.RRset]] = []
        if name == self.apex:
            groups.append(self._signed(self._soa_rrset(), view.signing_zsk))
            groups.append(self._signed(self._dnskey_rrset(view), self.keyring.ksk))
            groups.append(self._signed(self._nsec_rrsets_at(name), view.signing_zsk))
        elif name == self.app_name:
            groups.append(self._signed(self._a_rrset(), view.signing_zsk))
            groups.append(self._signed(self._nsec_rrsets_at(name), view.signing_zsk))
        return groups

    def lookup(self, qname: dns.name.Name, qtype: int):
        """Return (rcode, answer_rrsets, authority_rrsets) for a query.

        One state snapshot is taken up front, so a single answer is always
        rendered from one rotation phase (no old/new proof mixing).
        """
        view = self.state.view()

        # Outside the zone: refuse, and leak nothing (no SOA, no NSEC).
        if not qname.is_subdomain(self.apex):
            return dns.rcode.REFUSED, [], []

        groups = self._all_signed_rrsets_at(qname, view) if qname in self._owner_set else []
        if groups:
            if qtype == dns.rdatatype.ANY:
                return dns.rcode.NOERROR, [rr for g in groups for rr in g], []
            if qtype == dns.rdatatype.RRSIG:
                # One RRSIG per covered RRset; RFC 4034 section 3 allows their
                # TTLs to differ when the covered RRsets' TTLs differ.
                return dns.rcode.NOERROR, [g[1] for g in groups], []
            for group in groups:
                if group[0].rdtype == qtype:
                    return dns.rcode.NOERROR, list(group), []
            # Known name, absent type: NODATA, proven by the matching NSEC.
            authority = self._negative_authority(view, [qname])
            return dns.rcode.NOERROR, [], authority

        # Name does not exist.  RFC 4035 section 3.1.3.2 needs an NSEC that
        # covers QNAME and an NSEC that covers the wildcard at the closest
        # encloser (often the same NSEC, which is then sent only once).
        closest = self._closest_encloser(qname)
        wildcard = dns.name.Name((b"*",)) + closest
        proof_owners = [self._covering_nsec(qname).name]
        if wildcard not in self._owner_set:
            wc_owner = self._covering_nsec(wildcard).name
            if wc_owner not in proof_owners:
                proof_owners.append(wc_owner)
        authority = self._negative_authority(view, proof_owners)
        return dns.rcode.NXDOMAIN, [], authority

    def _closest_encloser(self, qname: dns.name.Name) -> dns.name.Name:
        """Longest existing ancestor of *qname* (the apex always exists)."""
        name = qname
        while name not in self._existing_names:
            if name == self.apex:
                return self.apex
            name = name.parent()
        return name

    def _negative_authority(
        self, view: RotationState.View, nsec_owners: list[dns.name.Name]
    ) -> list[dns.rrset.RRset]:
        """Signed SOA plus the signed NSEC RRset(s) for a negative answer."""
        authority: list[dns.rrset.RRset] = self._signed(
            self._soa_rrset(), view.signing_zsk
        )
        for owner in nsec_owners:
            authority.extend(self._signed(self._nsec_rrsets_at(owner), view.signing_zsk))
        return authority

"""FastAPI control plane for the DNSSEC ZSK rotation demo.

Run:  uvicorn app.main:app --host 0.0.0.0 --port 8000
Then: http://127.0.0.1:8000/docs  (Swagger UI)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from .config import load_settings
from .dns_server import DNSServer
from .keys import KeyRing
from .zone import RotationState, ZoneRenderer


def _setup_logging() -> None:
    logger = logging.getLogger("dnssec-demo")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


_setup_logging()
log = logging.getLogger("dnssec-demo.main")

settings = load_settings()
keyring = KeyRing(settings.keys_dir)
state = RotationState(settings, keyring)
renderer = ZoneRenderer(settings, keyring, state)
dns_server = DNSServer(settings.dns_host, settings.dns_port, renderer)


@asynccontextmanager
async def lifespan(app: FastAPI):
    dns_server.start()  # raises (and aborts startup) if the UDP bind fails
    log.info(
        "serving zone %s (domain %s -> %s); KSK tag %d, ZSK1 tag %d, ZSK2 tag %d",
        settings.apex,
        settings.app_fqdn,
        settings.a_value,
        keyring.ksk.key_tag,
        keyring.zsk1.key_tag,
        keyring.zsk2.key_tag,
    )
    yield
    dns_server.stop()


app = FastAPI(
    title="DNSSEC ZSK rotation demo",
    version="1.0.0",
    description=(
        "Single-instance authoritative DNS (dnspython, UDP) serving a DNSSEC-signed "
        "zone (A + DNSKEY + SOA) with NSEC proofs for NXDOMAIN and NODATA, plus a "
        "control API for a pre-publish ZSK rollover.\n\n"
        "Negative answers: a non-existent name returns NXDOMAIN with NSEC(s) that "
        "cover QNAME and the applicable wildcard; an existing name without the "
        "queried type returns NODATA with the NSEC whose bitmap omits that type. "
        "NSEC and SOA are signed by the current signing ZSK, from one state "
        "snapshot, so proofs never mix rotation phases. Out-of-zone queries are "
        "REFUSED with no zone data.\n\n"
        "Rotation order: **publish** (add new ZSK to DNSKEY) → wait "
        "`t_publish + DNSKEY TTL` → **switch** (re-sign A/SOA/NSEC with new ZSK) → "
        "wait `t_switch + max(A TTL, SOA TTL)` → **retire** (remove old ZSK).\n\n"
        "Calling an operation too early returns **409** with `remaining_seconds` "
        "and a `Retry-After` header; the DNS answers stay unchanged. Repeating a "
        "completed operation is an idempotent no-op and does not restart timers."
    ),
    lifespan=lifespan,
)


def _result_or_409(result: dict) -> dict:
    if result["ok"]:
        return result
    error = result["error"]
    headers = {}
    if "remaining_seconds" in error:
        headers["Retry-After"] = str(error["remaining_seconds"])
    raise HTTPException(status_code=409, detail=error, headers=headers)


@app.get("/", summary="Service overview")
def root() -> dict:
    return {
        "service": "DNSSEC ZSK rotation demo",
        "zone": settings.apex,
        "domain": settings.app_fqdn,
        "dns_udp_port": settings.dns_port,
        "swagger_ui": "/docs",
        "status": "/status",
        "rotation_steps": ["/rotate/publish", "/rotate/switch", "/rotate/retire"],
    }


@app.get("/status", summary="Current rotation phase, keys, answers and timers")
def get_status() -> dict:
    return state.status()


@app.post(
    "/rotate/publish",
    summary="Step 1: publish the new ZSK in the DNSKEY set",
    responses={409: {"description": "Conflict (state unchanged)"}},
)
def rotate_publish() -> dict:
    return _result_or_409(state.publish())


@app.post(
    "/rotate/switch",
    summary="Step 2: sign the A record with the new ZSK",
    responses={409: {"description": "Too early / invalid order (state unchanged)"}},
)
def rotate_switch() -> dict:
    return _result_or_409(state.switch())


@app.post(
    "/rotate/retire",
    summary="Step 3: remove the old ZSK from the DNSKEY set",
    responses={409: {"description": "Too early / invalid order (state unchanged)"}},
)
def rotate_retire() -> dict:
    return _result_or_409(state.retire())


@app.post("/rotate/reset", summary="Demo helper: reset to the initial state")
def rotate_reset() -> dict:
    return _result_or_409(state.reset())

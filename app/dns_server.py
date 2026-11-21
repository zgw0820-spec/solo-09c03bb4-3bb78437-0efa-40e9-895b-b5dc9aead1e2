"""Minimal threaded UDP authoritative DNS server built on dnspython."""
from __future__ import annotations

import logging
import socketserver
import threading

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass

from .zone import ZoneRenderer

log = logging.getLogger("dnssec-demo.dns")

EDNS_PAYLOAD = 1232


def build_response(renderer: ZoneRenderer, query: dns.message.Message) -> dns.message.Message:
    resp = dns.message.make_response(query, our_payload=EDNS_PAYLOAD)
    if query.opcode() != dns.opcode.QUERY:
        resp.set_rcode(dns.rcode.NOTIMP)
        return resp
    if not query.question:
        resp.set_rcode(dns.rcode.FORMERR)
        return resp
    q = query.question[0]
    if q.rdclass != dns.rdataclass.IN:
        resp.set_rcode(dns.rcode.REFUSED)
        return resp
    rcode, answers, authority = renderer.lookup(q.name, q.rdtype)
    # AA only when we actually answered for our own zone.  Out-of-zone
    # queries are REFUSED with empty answer/authority/additional sections,
    # so nothing about the zone leaks.
    if renderer.is_authoritative(q.name):
        resp.flags |= dns.flags.AA
    resp.set_rcode(rcode)
    resp.answer.extend(answers)
    resp.authority.extend(authority)
    return resp


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        server: _ThreadedUDPServer = self.server  # type: ignore[assignment]
        try:
            query = dns.message.from_wire(data)
        except Exception:
            log.warning("dropping unparsable datagram from %s", self.client_address)
            return
        try:
            response = build_response(server.renderer, query)
        except Exception:
            log.exception("failed to build response; answering SERVFAIL")
            try:
                response = dns.message.make_response(query, our_payload=EDNS_PAYLOAD)
                response.set_rcode(dns.rcode.SERVFAIL)
            except Exception:
                return
        try:
            max_size = query.payload if query.edns >= 0 else 512
            try:
                wire = response.to_wire(max_size=max_size)
            except dns.exception.TooBig:
                response.flags |= dns.flags.TC
                response.answer = []
                response.authority = []
                response.additional = []
                wire = response.to_wire(max_size=max_size)
            sock.sendto(wire, self.client_address)
            if query.question:
                q = query.question[0]
                log.info(
                    "answered %s %s for %s -> %s (%d bytes)",
                    q.name.to_text(),
                    dns.rdatatype.to_text(q.rdtype),
                    self.client_address[0],
                    dns.rcode.to_text(response.rcode()),
                    len(wire),
                )
        except Exception:
            log.exception("failed to send response")


class _ThreadedUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    renderer: ZoneRenderer


class DNSServer:
    """Runs the UDP authoritative server in a daemon thread."""

    def __init__(self, host: str, port: int, renderer: ZoneRenderer):
        self.host = host
        self.port = port
        self.renderer = renderer
        self._server: _ThreadedUDPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        srv = _ThreadedUDPServer((self.host, self.port), _UDPHandler)
        srv.renderer = self.renderer
        self._server = srv
        self._thread = threading.Thread(
            target=srv.serve_forever,
            kwargs={"poll_interval": 0.5},
            daemon=True,
            name="dns-udp",
        )
        self._thread.start()
        log.info("authoritative DNS listening on udp/%s:%d", self.host, self.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

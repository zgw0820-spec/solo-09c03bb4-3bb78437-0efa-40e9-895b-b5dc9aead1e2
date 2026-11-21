"""Environment-driven settings for the DNSSEC rotation demo."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    zone_name: str
    app_label: str
    a_value: str
    a_ttl: int
    dnskey_ttl: int
    soa_ttl: int
    dns_host: str
    dns_port: int
    keys_dir: str
    sig_inception_skew: int
    sig_lifetime: int

    @property
    def apex(self) -> str:
        return self.zone_name.rstrip(".") + "."

    @property
    def app_fqdn(self) -> str:
        return f"{self.app_label}.{self.apex}"


def load_settings() -> Settings:
    return Settings(
        zone_name=os.getenv("ZONE_NAME", "example.test"),
        app_label=os.getenv("APP_LABEL", "app"),
        a_value=os.getenv("A_VALUE", "192.0.2.10"),
        a_ttl=_int_env("A_TTL", 30),
        dnskey_ttl=_int_env("DNSKEY_TTL", 30),
        soa_ttl=_int_env("SOA_TTL", 30),
        dns_host=os.getenv("DNS_HOST", "0.0.0.0"),
        dns_port=_int_env("DNS_PORT", 5353),
        keys_dir=os.getenv("KEYS_DIR", "keys"),
        sig_inception_skew=_int_env("SIG_INCEPTION_SKEW", 300),
        sig_lifetime=_int_env("SIG_LIFETIME", 30 * 24 * 3600),
    )

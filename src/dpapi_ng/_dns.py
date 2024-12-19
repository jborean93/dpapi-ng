# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

import dns.asyncresolver
import dns.rdtypes
import dns.resolver


class SrvRecord(t.NamedTuple):
    target: str
    port: int
    weight: int
    priority: int


def _get_highest_answer(
    answer: dns.resolver.Answer,
) -> SrvRecord:
    answers: t.List[SrvRecord] = []
    for a in answer:
        answers.append(
            SrvRecord(
                # The trailing . causes errors on Windows and the SPN lookup.
                target=str(a.target).rstrip("."),  # type: ignore[attr-defined]
                port=a.port,  # type: ignore[attr-defined]
                weight=a.weight,  # type: ignore[attr-defined]
                priority=a.priority,  # type: ignore[attr-defined]
            )
        )

    # Sorts the array by lowest priority then highest weight.
    return sorted(answers, key=lambda a: (a.priority, -a.weight))[0]


async def async_lookup_dc(
    domain_name: t.Optional[str] = None,
) -> SrvRecord:
    """Lookup DC for domain name

    Attempts to lookup LDAP server based on the domain name specified or the
    system's search domain if available. This is done through an SRV lookup for
    '_ldap._tcp.dc._msdcs.{domain_name}'.

    Args:
        domain_name: The domain to lookup the DC for.

    Returns:
        SrvRecord: The SRV record result.

    Raises:
        dns.exception.DNSException: DNS lookup error.
    """

    if domain_name:
        record = f"_ldap._tcp.dc._msdcs.{domain_name}"
    else:
        record = f"_ldap._tcp.dc._msdcs"

    answers = await dns.asyncresolver.resolve(record, "SRV", search=True)
    return _get_highest_answer(answers)


def lookup_dc(
    domain_name: t.Optional[str] = None,
) -> SrvRecord:
    """Lookup DC for domain name

    Attempts to lookup LDAP server based on the domain name specified or the
    system's search domain if available. This is done through an SRV lookup for
    '_ldap._tcp.dc._msdcs.{domain_name}'.

    Args:
        domain_name: The domain to lookup the DC for.

    Returns:
        SrvRecord: The SRV record result.

    Raises:
        dns.exception.DNSException: DNS lookup error.
    """

    if domain_name:
        record = f"_ldap._tcp.dc._msdcs.{domain_name}"
    else:
        record = f"_ldap._tcp.dc._msdcs"

    answers = dns.resolver.resolve(record, "SRV", search=True)
    return _get_highest_answer(answers)

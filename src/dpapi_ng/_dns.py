# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

import dns.asyncresolver
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
                target=str(a.target).rstrip("."),
                port=a.port,
                weight=a.weight,
                priority=a.priority,
            )
        )

    # Sorts the array by lowest priority then highest weight.
    return sorted(answers, key=lambda a: (a.priority, -a.weight))[0]


async def async_lookup_dc(
    domain_name: str,
) -> SrvRecord:
    """Lookup DC for domain name

    Attempts to lookup LDAP server based on the domain name specified. This is
    done through an SRV lookup for '_ldap._tcp.dc._msdcs.{domain_name}'.

    Args:
        domain_name: The domain to lookup the DC for.

    Returns:
        SrvRecord: The SRV record result.

    Raises:
        dns.exception.DNSException: DNS lookup error.
    """

    record = f"_ldap._tcp.dc._msdcs.{domain_name}"

    answers = await dns.asyncresolver.resolve(record, "SRV")
    return _get_highest_answer(answers)


def lookup_dc(
    domain_name: str,
) -> SrvRecord:
    """Lookup DC for domain name

    Attempts to lookup LDAP server based on the domain name specified. This is
    done through an SRV lookup for '_ldap._tcp.dc._msdcs.{domain_name}'.

    Args:
        domain_name: The domain to lookup the DC for.

    Returns:
        SrvRecord: The SRV record result.

    Raises:
        dns.exception.DNSException: DNS lookup error.
    """

    record = f"_ldap._tcp.dc._msdcs.{domain_name}"

    answers = dns.resolver.resolve(record, "SRV")
    return _get_highest_answer(answers)

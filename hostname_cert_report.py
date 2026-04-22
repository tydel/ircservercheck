#!/usr/bin/env python3
"""Report A/AAAA DNS records and TLS certificate SHA-256 fingerprints for IRC hosts."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import Iterable


@dataclass
class HostReport:
    hostname: str
    a_records: list[str]
    aaaa_records: list[str]
    cert_fingerprint: str | None
    cert_error: str | None


def unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def resolve_records(hostname: str) -> tuple[list[str], list[str]]:
    a_records: list[str] = []
    aaaa_records: list[str] = []

    try:
        for result in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            a_records.append(result[4][0])
    except socket.gaierror:
        pass

    try:
        for result in socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM):
            raw_addr = result[4][0]
            try:
                ip = ipaddress.ip_address(raw_addr)
            except ValueError:
                continue

            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                a_records.append(str(ip.ipv4_mapped))
                continue

            if isinstance(ip, ipaddress.IPv6Address):
                aaaa_records.append(ip.compressed)
            aaaa_records.append(result[4][0])
    except socket.gaierror:
        pass

    return unique_sorted(a_records), unique_sorted(aaaa_records)


def get_cert_sha256_fingerprint(hostname: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                if not cert_der:
                    return None, "no peer certificate presented"
                digest = hashlib.sha256(cert_der).hexdigest().upper()
                pretty = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
                return pretty, None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def inspect_host(hostname: str, port: int, timeout: float) -> HostReport:
    a_records, aaaa_records = resolve_records(hostname)
    fingerprint, cert_error = get_cert_sha256_fingerprint(hostname, port=port, timeout=timeout)
    return HostReport(
        hostname=hostname,
        a_records=a_records,
        aaaa_records=aaaa_records,
        cert_fingerprint=fingerprint,
        cert_error=cert_error,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read hostnames and print A/AAAA DNS records plus TLS certificate "
            "SHA-256 fingerprints from the target port."
        )
    )
    parser.add_argument(
        "hostnames",
        nargs="*",
        help="Hostnames to inspect. If omitted, hostnames are read from --input or stdin.",
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Path to a file containing one hostname per line.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=6697,
        help="TLS port to inspect (default: 6697).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Network timeout in seconds for DNS/TLS operations (default: 8.0).",
    )
    return parser.parse_args()


def load_hostnames(args: argparse.Namespace) -> list[str]:
    hostnames = list(args.hostnames)

    if args.input:
        with open(args.input, encoding="utf-8") as f:
            hostnames.extend(line.strip() for line in f)

    if not hostnames and not sys.stdin.isatty():
        hostnames.extend(line.strip() for line in sys.stdin)

    normalized = unique_sorted(h for h in hostnames if h and not h.startswith("#"))
    return normalized


def print_report(report: HostReport, port: int) -> None:
    print(f"hostname: {report.hostname}")
    print(f"  A: {', '.join(report.a_records) if report.a_records else '(none)'}")
    print(f"  AAAA: {', '.join(report.aaaa_records) if report.aaaa_records else '(none)'}")
    if report.cert_fingerprint:
        print(f"  cert_sha256_port_{port}: {report.cert_fingerprint}")
    else:
        print(f"  cert_sha256_port_{port}: ERROR ({report.cert_error})")


def main() -> int:
    args = parse_args()
    hostnames = load_hostnames(args)

    if not hostnames:
        print("No hostnames provided. Use positional args, --input, or stdin.", file=sys.stderr)
        return 1

    for idx, hostname in enumerate(hostnames):
        if idx:
            print()
        report = inspect_host(hostname, port=args.port, timeout=args.timeout)
        print_report(report, args.port)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

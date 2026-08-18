#!/usr/bin/env python3

import argparse
import smtplib
import socket

import dns.exception
import dns.resolver


VERSION = "1.2.0"
VERBOSE = False

RESET = "\033[0m"
BOLD = "\033[1m"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BLUE = "\033[94m"


def show_banner():
    print()
    print(f"{CYAN}{BOLD}")
    print(r"""
  ███╗   ███╗ █████╗ ██╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ████╗ ████║██╔══██╗██║██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██╔████╔██║███████║██║██║     ███████║██║   ██║██║  ██║██║   ██║
  ██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║   ██║██║  ██║██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝

                  ╔══════════════════════════════╗
                  ║        By MrDedSec           ║
                  ╚══════════════════════════════╝
""")
    print(f"{RESET}")
    print(f"  {GRAY}Email Security & Configuration Auditor{RESET}")
    print()


def print_header(title):
    print()
    print(f"{CYAN}{BOLD}{title}{RESET}")
    print(f"{GRAY}{'─' * 68}{RESET}")


def print_check(name, status, detail=None):
    if status is True:
        label = f"{GREEN}✓ PASS{RESET}"
    elif status is False:
        label = f"{RED}✗ FAIL{RESET}"
    elif status == "info":
        label = f"{BLUE}ℹ INFO{RESET}"
    else:
        label = f"{YELLOW}⚠ WARN{RESET}"

    print(
        f"  {label:<20} "
        f"{WHITE}{name:<22}{RESET}"
    )

    if detail:
        print(
            f"      {GRAY}{detail}{RESET}"
        )


def verbose(message):
    if VERBOSE:
        print(
            f"      {GRAY}[verbose] {message}{RESET}"
        )


def dns_txt(name):
    verbose(f"Querying TXT: {name}")

    try:
        answers = dns.resolver.resolve(
            name,
            "TXT"
        )

        records = []

        for answer in answers:
            value = b"".join(
                answer.strings
            ).decode(
                "utf-8",
                errors="replace"
            )

            records.append(value)

        verbose(
            f"TXT records returned: {len(records)}"
        )

        for record in records:
            verbose(
                f"TXT: {record}"
            )

        return records

    except dns.resolver.NXDOMAIN:
        verbose("DNS result: NXDOMAIN")
        return []

    except dns.resolver.NoAnswer:
        verbose("DNS result: NOANSWER")
        return []

    except dns.resolver.NoNameservers:
        verbose("DNS result: NO NAMESERVERS")
        return []

    except dns.exception.Timeout:
        verbose("DNS query timed out")
        return []


def check_spf(domain):
    records = dns_txt(domain)

    spf_records = [
        record
        for record in records
        if record.lower().startswith("v=spf1")
    ]

    verbose(
        f"SPF records detected: {len(spf_records)}"
    )

    if len(spf_records) == 1:
        return True, "SPF record found"

    if len(spf_records) > 1:
        return False, (
            f"Multiple SPF records found ({len(spf_records)})"
        )

    return False, "No SPF record found"


def parse_dmarc_record(record):
    tags = {}

    for part in record.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split(
            "=",
            1
        )

        tags[key.strip().lower()] = value.strip()

    return tags


def check_dmarc(domain):
    records = dns_txt(
        f"_dmarc.{domain}"
    )

    dmarc_records = [
        record
        for record in records
        if record.lower().startswith("v=dmarc1")
    ]

    verbose(
        f"DMARC records detected: {len(dmarc_records)}"
    )

    if not dmarc_records:
        return False, "No DMARC record found"

    if len(dmarc_records) > 1:
        return False, (
            f"Multiple DMARC records found ({len(dmarc_records)})"
        )

    record = dmarc_records[0]

    verbose(
        f"DMARC record: {record}"
    )

    tags = parse_dmarc_record(
        record
    )

    verbose(
        f"DMARC tags: {tags}"
    )

    policy = tags.get(
        "p",
        ""
    ).lower()

    if policy not in {
        "none",
        "quarantine",
        "reject",
    }:
        return False, "Invalid or missing DMARC policy"

    pct_raw = tags.get(
        "pct",
        "100"
    )

    try:
        pct = int(pct_raw)
    except ValueError:
        return False, f"Invalid pct value: {pct_raw}"

    if not 0 <= pct <= 100:
        return False, f"Invalid pct value: {pct}"

    if policy == "none":
        return None, (
            "Monitoring only: p=none"
        )

    if pct < 100:
        return None, (
            f"Enforced at {pct}%: p={policy}"
        )

    return True, (
        f"Full enforcement: p={policy}, pct=100"
    )


COMMON_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "google1",
    "google2",
    "k1",
    "k2",
    "mail",
    "dkim",
    "s1",
    "s2",
    "smtp",
    "zoho",
    "zmail",
]


def check_dkim(domain):
    found = []

    verbose(
        f"Testing {len(COMMON_DKIM_SELECTORS)} common DKIM selectors"
    )

    for selector in COMMON_DKIM_SELECTORS:
        name = (
            f"{selector}._domainkey.{domain}"
        )

        verbose(
            f"Checking DKIM selector: {selector}"
        )

        records = dns_txt(name)

        for record in records:
            if "p=" in record.lower():
                found.append(
                    selector
                )

                verbose(
                    f"DKIM selector found: {selector}"
                )

    if not found:
        return None, (
            "No common selector found; DKIM cannot be confirmed"
        )

    selectors = ", ".join(
        sorted(set(found))
    )

    return True, (
        f"DKIM selector found: {selectors}"
    )


def get_mx(domain):
    verbose(
        f"Querying MX records for {domain}"
    )

    try:
        answers = dns.resolver.resolve(
            domain,
            "MX"
        )

        mx_records = []

        for answer in answers:
            priority = answer.preference

            raw_hostname = str(
                answer.exchange
            )

            if raw_hostname == ".":
                hostname = "."
            else:
                hostname = raw_hostname.rstrip(".")

            mx_records.append(
                (
                    priority,
                    hostname
                )
            )

            verbose(
                f"MX: priority={priority}, host={hostname}"
            )

        return sorted(
            mx_records,
            key=lambda item: item[0]
        )

    except dns.resolver.NXDOMAIN:
        verbose("MX result: NXDOMAIN")
        return []

    except dns.resolver.NoAnswer:
        verbose("MX result: NOANSWER")
        return []

    except dns.resolver.NoNameservers:
        verbose("MX result: NO NAMESERVERS")
        return []

    except dns.exception.Timeout:
        verbose("MX query timed out")
        return []


def is_null_mx(mx_records):
    return (
        len(mx_records) == 1
        and mx_records[0][1] == "."
    )


def check_smtp_tls(
    mx_host,
    timeout
):
    if mx_host == ".":
        return "info", "Null MX — no SMTP server"

    verbose(
        f"Connecting to {mx_host}:25"
    )

    try:
        with smtplib.SMTP(
            timeout=timeout
        ) as smtp:

            smtp.connect(
                mx_host,
                25
            )

            verbose(
                f"SMTP extensions: {smtp.esmtp_features}"
            )

            smtp.ehlo()

            verbose(
                f"SMTP extensions after EHLO: {smtp.esmtp_features}"
            )

            if smtp.has_extn(
                "starttls"
            ):
                return True, "Start TLS advertised"

            return False, "Start TLS not advertised"

    except socket.timeout:
        verbose("SMTP connection timed out")
        return None, "Connection timed out"

    except ConnectionRefusedError:
        verbose("SMTP connection refused")
        return None, "Connection refused"

    except socket.gaierror:
        verbose("SMTP hostname resolution failed")
        return None, "DNS resolution failed"

    except OSError as error:
        verbose(
            f"SMTP network error: {error}"
        )

        return None, f"Network error: {error}"

    except Exception as error:
        verbose(
            f"SMTP test error: "
            f"{type(error).__name__}: {error}"
        )

        return None, (
            f"Unable to test ({type(error).__name__})"
        )


def check_smtp_relay(
    mx_host,
    domain,
    timeout
):
    if mx_host == ".":
        return "info", "Null MX — no SMTP server"

    sender = (
        f"security-check@{domain}"
    )

    recipient = (
        "relay-test@example.net"
    )

    verbose(
        f"Testing SMTP relay behavior on {mx_host}:25"
    )

    try:
        with smtplib.SMTP(
            timeout=timeout
        ) as smtp:

            smtp.connect(
                mx_host,
                25
            )

            smtp.ehlo()

            verbose(
                f"MAIL FROM:<{sender}>"
            )

            code, response = smtp.mail(
                sender
            )

            verbose(
                f"MAIL FROM response: {code} {response!r}"
            )

            if code >= 400:
                return True, (
                    "Relay closed — MAIL FROM rejected"
                )

            verbose(
                f"RCPT TO:<{recipient}>"
            )

            code, response = smtp.rcpt(
                recipient
            )

            verbose(
                f"RCPT TO response: {code} {response!r}"
            )

            if code in (
                250,
                251
            ):
                return False, (
                    "Relay open — external recipient accepted"
                )

            return True, (
                f"Relay closed — external recipient rejected ({code})"
            )

    except socket.timeout:
        verbose(
            "SMTP relay test timed out"
        )

        return None, (
            "Could not determine relay status — connection timed out"
        )

    except ConnectionRefusedError:
        verbose(
            "SMTP relay connection refused"
        )

        return None, (
            "Could not determine relay status — connection refused"
        )

    except socket.gaierror:
        verbose(
            "SMTP relay hostname resolution failed"
        )

        return None, (
            "Could not determine relay status — DNS resolution failed"
        )

    except OSError as error:
        verbose(
            f"SMTP relay network error: {error}"
        )

        return None, (
            "Could not determine relay status — network error"
        )

    except Exception as error:
        verbose(
            f"SMTP relay test error: "
            f"{type(error).__name__}: {error}"
        )

        return None, (
            "Could not determine relay status"
        )


def print_summary(results):
    print_header(
        "AUDIT SUMMARY"
    )

    passed = sum(
        result is True
        for result in results
    )

    failed = sum(
        result is False
        for result in results
    )

    warnings = sum(
        result is None
        for result in results
    )

    info = sum(
        result == "info"
        for result in results
    )

    print()

    print(
        f"  {GREEN}{passed} passed{RESET}   "
        f"{RED}{failed} failed{RESET}   "
        f"{YELLOW}{warnings} warnings{RESET}   "
        f"{BLUE}{info} info{RESET}"
    )

    print()

    if failed:
        print(
            f"  {RED}{BOLD}"
            "✗ Action recommended: review the failed checks."
            f"{RESET}"
        )

    elif warnings:
        print(
            f"  {YELLOW}{BOLD}"
            "⚠ Review the warnings above."
            f"{RESET}"
        )

    else:
        print(
            f"  {GREEN}{BOLD}"
            "✓ No security issues were detected by the checks performed."
            f"{RESET}"
        )

    print()


def audit(
    domain,
    timeout
):
    domain = domain.lower().strip()

    print_header(
        f"DOMAIN: {domain}"
    )

    print(
        f"  {GRAY}"
        "Checking DNS email authentication and "
        "mail delivery configuration..."
        f"{RESET}"
    )

    print_header(
        "EMAIL AUTHENTICATION"
    )

    spf_status, spf_detail = check_spf(
        domain
    )

    print_check(
        "SPF",
        spf_status,
        spf_detail
    )

    dmarc_status, dmarc_detail = check_dmarc(
        domain
    )

    print_check(
        "DMARC",
        dmarc_status,
        dmarc_detail
    )

    dkim_status, dkim_detail = check_dkim(
        domain
    )

    print_check(
        "DKIM",
        dkim_status,
        dkim_detail
    )

    mx_records = get_mx(
        domain
    )

    print_header(
        "MAIL DELIVERY"
    )

    if not mx_records:
        print_check(
            "MX RECORD",
            False,
            "No MX records found"
        )

        print_summary([
            spf_status,
            dmarc_status,
            dkim_status,
            False
        ])

        return

    if is_null_mx(
        mx_records
    ):
        print_check(
            "MX RECORD",
            "info",
            "Null MX — domain does not accept email"
        )

        print(
            f"\n  {GRAY}"
            "SMTP tests skipped because the domain "
            "has no mail server."
            f"{RESET}"
        )

        print_summary([
            spf_status,
            dmarc_status,
            dkim_status,
            "info"
        ])

        return

    print_check(
        "MX RECORD",
        True,
        f"{len(mx_records)} mail server(s) found"
    )

    print_header(
        "SMTP SECURITY"
    )

    tls_results = []
    relay_results = []

    for priority, mx_host in mx_records:

        print()

        print(
            f"  {WHITE}{BOLD}"
            f"{mx_host}"
            f"{RESET}"
            f" {GRAY}"
            f"(priority {priority})"
            f"{RESET}"
        )

        tls_status, tls_detail = check_smtp_tls(
            mx_host,
            timeout
        )

        print_check(
            "Start TLS",
            tls_status,
            tls_detail
        )

        tls_results.append(
            tls_status
        )

        relay_status, relay_detail = check_smtp_relay(
            mx_host,
            domain,
            timeout
        )

        print_check(
            "SMTP RELAY",
            relay_status,
            relay_detail
        )

        relay_results.append(
            relay_status
        )

    if all(
        result is True
        for result in tls_results
    ):
        tls_overall = True

    elif any(
        result is False
        for result in tls_results
    ):
        tls_overall = False

    else:
        tls_overall = None

    if all(
        result is True
        for result in relay_results
    ):
        relay_overall = True

    elif any(
        result is False
        for result in relay_results
    ):
        relay_overall = False

    else:
        relay_overall = None

    print_summary([
        spf_status,
        dmarc_status,
        dkim_status,
        tls_overall,
        relay_overall
    ])


def build_parser():
    parser = argparse.ArgumentParser(
        prog="MailAudit",
        description=(
            "Email security and configuration auditor. "
            "Checks DNS authentication records, MX configuration, "
            "and basic SMTP security."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
CHECKS
  SPF             Verify SPF configuration.
  DMARC           Check policy and enforcement level.
  DKIM            Check common DKIM selectors.
  MX              Inspect mail exchanger configuration.
  Start TLS       Check SMTP Start TLS support.
  SMTP RELAY      Verify that unauthorized external relay
                  attempts are rejected.

OPTIONS
  -v, --verbose   Show detailed DNS queries, DNS responses,
                  DKIM selectors, MX records, and SMTP activity.

STATUS
  PASS            The security check passed.
  FAIL            A security or configuration problem was detected.
  WARN            The result needs review.
  INFO            Informational result, not necessarily a problem.

SMTP RELAY
  PASS            Relay is closed; external mail was rejected.
  FAIL            Relay is open; external mail was accepted.
  WARN            Relay status could not be determined.

EXAMPLES
  %(prog)s example.com
  %(prog)s example.com -v
  %(prog)s -d example.com
  %(prog)s -d example.com --verbose
  %(prog)s example.com --timeout 15
  %(prog)s --version

NOTES
  DKIM selectors cannot be reliably discovered from DNS alone.
  MailAudit checks common selectors and reports a warning when
  none can be confirmed.

  A Null MX record (MX 0 .) means the domain does not accept
  email. SMTP tests are skipped for Null MX domains.

Version: {VERSION}
"""
    )

    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain to audit, for example: example.com"
    )

    parser.add_argument(
        "-d",
        "--domain",
        dest="domain_option",
        help="Domain to audit"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="SMTP connection timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed DNS and SMTP diagnostic information"
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    return parser


def main():
    global VERBOSE

    parser = build_parser()
    args = parser.parse_args()

    domain = (
        args.domain_option
        or args.domain
    )

    if not domain:
        parser.error(
            "a domain is required; use "
            "'MailAudit example.com' or "
            "'MailAudit -d example.com'"
        )

    if args.timeout <= 0:
        parser.error(
            "--timeout must be greater than 0"
        )

    VERBOSE = args.verbose

    show_banner()

    audit(
        domain,
        args.timeout
    )


if __name__ == "__main__":
    main()
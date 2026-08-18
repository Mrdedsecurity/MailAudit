# MailAudit

```text
  ███╗   ███╗ █████╗ ██╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ████╗ ████║██╔══██╗██║██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██╔████╔██║███████║██║██║     ███████║██║   ██║██║  ██║██║   ██║
  ██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║   ██║██║  ██║██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝

                  ╔══════════════════════════════╗
                  ║        By MrDedSec           ║
                  ╚══════════════════════════════╝
```

## Installation

MailAudit requires **Python 3.8+** and `dnspython`.

Install the required dependency:

```bash
sudo apt install dnspython
```

## Usage

Run MailAudit against a domain:

```bash
python mailaudit.py example.com
```

### Verbose Mode

Enable verbose output:

```bash
python mailaudit.py example.com -v
```

### Custom Timeout

Specify a custom timeout in seconds:

```bash
python mailaudit.py example.com -t 15
```

### Help / Version

Display the help menu:

```bash
python mailaudit.py -h
```

Display the current version:

```bash
python mailaudit.py --version
```

## Checks

MailAudit performs several checks against the target domain's email infrastructure:

| Check          | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| **SPF**        | Checks the SPF record and identifies duplicate SPF records. |
| **DMARC**      | Checks the DMARC policy and enforcement configuration.      |
| **DKIM**       | Checks common DKIM selectors.                               |
| **MX**         | Checks mail servers and identifies Null MX records.         |
| **STARTTLS**   | Checks SMTP TLS support.                                    |
| **SMTP Relay** | Checks for unauthorised SMTP relay.                         |

## SMTP Relay

SMTP relay results are interpreted as follows:

```text
Closed = PASS
Open   = FAIL
```

An open SMTP relay may indicate that the mail server allows unauthorised users to relay email.

## Status

| Status   | Meaning                  |
| -------- | ------------------------ |
| **PASS** | Expected / secure result |
| **FAIL** | Security issue detected  |
| **WARN** | Needs review             |
| **INFO** | Informational            |

## Example

```bash
python mailaudit.py example.com -v
```

MailAudit will run the available email security and configuration checks and report the results using the status levels above.


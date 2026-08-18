MailAudit
  ███╗   ███╗ █████╗ ██╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ████╗ ████║██╔══██╗██║██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██╔████╔██║███████║██║██║     ███████║██║   ██║██║  ██║██║   ██║
  ██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║   ██║██║  ██║██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝


                  ╔══════════════════════════════╗
                  ║        By MrDedSec           ║
                  ╚══════════════════════════════╝


          Email Security & Configuration Auditor


Installation
git clone <repository-url>
pip install dnspython

Usage
python mailaudit.py example.com

Verbose mode:

python mailaudit.py example.com -v

Custom SMTP timeout:

python mailaudit.py example.com -t 15

Help:

python mailaudit.py -h

Version:

python mailaudit.py --version

Checks
SPF — Checks SPF records and duplicates.
DMARC — Checks policy and enforcement.
DKIM — Checks common DKIM selectors.
MX — Checks mail exchanger configuration and Null MX.
Start TLS — Checks SMTP Start TLS support.
SMTP Relay — Verifies unauthorized external relay is rejected.
SMTP Relay

A closed relay is PASS:

✓ PASS   SMTP RELAY
         Relay closed — external recipient rejected

An open relay is FAIL:

✗ FAIL   SMTP RELAY
         Relay open — external recipient accepted
         
Status
Status	Meaning
PASS	Desired security configuration detected
FAIL	Security/configuration problem detected
WARN	Needs review or cannot be fully confirmed
INFO	Informational result

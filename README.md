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
Installation

Requires Python 3.8+ and dnspython.

pip install dnspython
Usage
python mailaudit.py example.com

Verbose mode:

python mailaudit.py example.com -v

Custom timeout:

python mailaudit.py example.com -t 15

Help/version:

python mailaudit.py -h
python mailaudit.py --version
Checks
SPF — SPF record and duplicates
DMARC — Policy and enforcement
DKIM — Common selectors
MX — Mail servers and Null MX
Start TLS — SMTP TLS support
SMTP Relay — Unauthorized relay detection

SMTP Relay: Closed = PASS · Open = FAIL

Status
Status	Meaning
PASS	Expected/secure result
FAIL	Security issue detected
WARN	Needs review
INFO	Informational

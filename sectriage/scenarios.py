"""Demo alerts and the fault plan used to exercise every failure path."""
from __future__ import annotations

ALERTS = [
    {"alert_id": "A-001", "source": "email-gateway",
     "raw": "Email gateway: user reported 'Urgent: verify your CQU password' from it-support@cqu-helpdesk.example.net"},
    {"alert_id": "A-002", "source": "sshd",
     "raw": "sshd[2211]: Failed password for root from 203.0.113.45 port 52144 ssh2 (attempts=57 in 120s)"},
    {"alert_id": "A-003", "source": "edr",
     "raw": "EDR: powershell.exe -enc JABzAD0ATgBlAHcA spawned by winword.exe on host LAB-PC-07"},
    {"alert_id": "A-004", "source": "ids",
     "raw": "IDS: nmap scan detected from 192.0.2.50 against 10.0.0.0/24"},
    {"alert_id": "A-005", "source": "auth",
     "raw": "Info: user alice logged in successfully from 10.0.0.23 at 09:02"},
    {"alert_id": "A-006", "source": "proxy",
     "raw": "Proxy: unusual outbound transfer of 4.2 GB from host SRV-DB-01 to 192.0.2.77"},
    {"alert_id": "A-007", "source": "edr",
     "raw": "EDR: ransom note README_DECRYPT.txt created on host FIN-PC-02"},
    {"alert_id": "A-008", "source": "firewall",
     "raw": "FW: 198.51.100.9 probed 12 ports on 10.0.0.5 within 30s"},
    {"alert_id": "A-009", "source": "sshd",
     "raw": "sshd[3310]: Failed password for admin from 198.51.100.77 port 40022 ssh2 (attempts=120 in 60s)"},
]

# alert -> faults the classifier will suffer (consumed one per attempt)
DEFAULT_FAULTS = {
    "A-003": ["timeout"],
    "A-004": ["malformed_json"],
    "A-005": ["bad_receiver"],
    "A-006": ["hallucinated_indicator"],
    "A-007": ["stubborn"],
    "A-008": ["wrong_category"],
    "A-009": ["ignore_feedback"],
}

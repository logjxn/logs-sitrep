# logs-sitrep

Security incident reports and write-ups from hands-on labs, written to a
professional standard: evidence-backed timelines, defanged IOCs, MITRE ATT&CK
mapping, and specific containment and remediation steps.

All scenarios are training environments (TryHackMe, CyberDefenders).

## Reports

| Date | Report | Platform | Highlights |
|------|--------|----------|------------|
| 2026-09-30 | [JetBrains TeamCity Compromise](incident-reports/2026-09-30-jetbrains-CyD.md) | CyberDefenders | PCAP analysis, CVE-2024-27198 auth bypass, webshell, container escape |
| 2026-09-27 | [Snapped Phishing Line](incident-reports/2026-09-27-snapped-phished-line.md) | TryHackMe | Phishing kit analysis, exposed credential log, 4 compromised accounts |
| 2026-09-26 | [Greenholt Phish](incident-reports/2026-09-26-the-greenholt-phish.md) | TryHackMe | Header analysis, SPF/DMARC failure, Loki-family attachment |
| 2026-09-23 | [Summit](incident-reports/2026-09-23-summit.md) | TryHackMe | Pyramid of Pain, Sigma rules for evasion, beaconing, exfiltration |
| 2026-09-20 | [Intro to Phishing](incident-reports/2026-09-20-intro-to-phishing.md) | TryHackMe | SIEM alert triage, FP/TP disposition, L2 escalation |

## Report Formats

- **Incident report**: blue-team investigations ([template](templates/incident-report.md))
- **Pentest finding**: CVSS-scored, reproduction-focused ([template](templates/pentest-finding.md))
- **CTF report**: methodology narrative ([template](templates/ctf-report.md))

## In Progress

- TryHackMe SOC Level 1
- TryHackMe Jr Penetration Tester (next)

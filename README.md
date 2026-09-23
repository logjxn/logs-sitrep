# logs-sitrep
Structured reports from TryHackMe paths, CTF challenges, and bug bounty research.

## Structure

```
.
├── templates/
│   ├── incident-report.md
│   ├── pentest-finding.md
│   └── ctf-report.md

├── incident-reports/
│   └── YYYY-MM-DD-room-or-scenario-name.md
├── pentest-findings/
│   └── YYYY-MM-DD-room-or-scenario-name.md
├── ctf-reports/
│   └── YYYY-MM-DD-challenge-name.md
└── README.md
```

## Report Types

| Type | Source | Format |
|------|--------|--------|
| Blue-Team | SOC rooms, detection/defensive scenarios | Incident reports (timeline/IOC), detection-engineering |
| Red-Team | TryHackMe pen-test rooms, offensive labs | CVSS-scored, reproduction-focused |
| CTF Report | Standalone challenges, competitions | Methodology narrative |

## Paths in Progress

- [ ] TryHackMe SOC Level 1
- [ ] TryHackMe Jr Penetration Tester

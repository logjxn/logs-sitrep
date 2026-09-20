# logs-sitrep
Structured reports from TryHackMe paths, CTF challenges, and bug bounty research.

## Structure

```
.
├── templates/
│   ├── incident-report.md
│   ├── pentest-findings.md
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
| Incident Report | TryHackMe SOC rooms, blue team scenarios | Timeline-based, IOC-focused |
| Pentest Finding | TryHackMe pen-test rooms, offensive labs | CVSS-scored, reproduction-focused |
| CTF Report | Standalone challenges, competitions | Methodology narrative |

## Paths in Progress

- [ ] TryHackMe SOC Level 1
- [ ] TryHackMe Jr Penetration Tester

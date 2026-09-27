# Incident Report: Greenholt Phish

## Metadata

| Field | Value |
|-------|-------|
| Date | 2026-09-26 |
| Analyst | Logan J. |
| Severity | Medium |
| Platform | TryHackMe |
| Room/Scenario | SOC L1 Path - Greenholt Phish |
| Status | Closed |

## Executive Summary

A phishing email posing as a payment confirmation was delivered to the `webmaster@redacted[.]org` mailbox on June 10th, 2020. The email claimed a bank transfer had been processed and pressed the recipient to open an attached transfer document.

The message came from a commercial hosting server that the real domain does not authorize to send on its behalf, with replies being routed to a free webmail account.

The attachment is a disguised archive that security vendors widely identify as malware, with multiple detections associating it with the Loki family.

The email is classified as a **true positive phishing attempt**. The available evidence does not show whether the recipient opened the attachment. Priority actions are to remove the message from all mailboxes, block the associated indicators, and confirm with the mailbox owner whether the attachment was opened.

## Timeline of Events

| Timestamp (UTC) | Event | Source |
|-----------------|-------|--------|
| Not visible in captured evidence | `hwsrv-737338.hostwindsdns[.]com` (192.119.71[.]157) connects to the `sub.redacted.com` relay (Exim 4.80), announcing itself as `helo=mutawamarine[.]com` | Email header (Received) |
| 2020-06-10 05:58:54 | Message received from `sub.redacted.com` by `mta4212.mail.bf1.yahoo.com` | Email header (Received) |
| 2020-06-10 05:58:55 | Message received by `atlas125.free.mail.bf1.yahoo.com`; SPF result `fail`, DMARC result `unknown`; message delivered to mailbox | Email header (Received, Authentication-Results) |

## Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| IP Address | `192.119.71[.]157` | Originating mail server |
| Hostname | `hwsrv-737338.hostwindsdns[.]com` | Reverse DNS of the originating IP, per the Received header |
| Email Address | `info@mutawamarine[.]com` | Spoofed From / Return-Path address |
| Email Address | `info.mutawamarine@mail[.]com` | Reply-To address |
| Subject | `Transfer Reference Number:(09674321)` | Email subject line |
| File Name | `SWT_#09674321____PDF__.CAB` | Malicious attachment |
| File Hash (SHA256) | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` | Malicious attachment |

## Analysis

### Sender Impersonation

The email was presented as coming from "Mr. James Jackson" at `info@mutawamarine[.]com`, but replies were directed to `info.mutawamarine@mail[.]com`. It's unusual for a corporate sender to route replies to a free webmail account. The Reply-To address resembles the legitimate address while using a free webmail domain, creating a discrepancy between the displayed sender and the address used for replies.

The final Received header shows the originating server, `hwsrv-737338.hostwindsdns[.]com` at 192.119.71[.]157, announcing itself as `helo=mutawamarine[.]com`. This behavior of a hosting server announcing itself as a corporate identity is consistent with sender impersonation.

### Email Authentication

The spoofed domain publishes the following records:

- SPF: `v=spf1 include:spf.protection.outlook.com -all`
- DMARC: `v=DMARC1; p=quarantine; fo=1`

The SPF record authorizes only Microsoft 365 infrastructure to send mail for `mutawamarine.com`, with -all to deny any other domains. The originating IP, 192.119.71[.]157, resolves to a Hostwinds/Hostpapa server rather than Microsoft. It is therefore not an authorized sender, and the message fails SPF.

The domain's DMARC policy is `p=quarantine`, yet the receiving server recorded `dmarc=unknown` and delivered the message. 

The relay's own filter flagged the message as spam in its `X-Ham-Report` header.

### Attachment

The attachment `SWT_#09674321____PDF__.CAB` is disguised through two extensions.

1. The name includes "PDF" to suggest a transfer document.
2. It also carries a `.CAB` extension, but VirusTotal identifies the actual file type as a **RAR archive**.

The SHA-256 hash `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` returned the following on VirusTotal:

- **49 / 64** vendors flagged the file as malicious.
- Popular threat label: `trojan.msil/loki`. Family labels: `msil`, `loki`, `agensla`.
- Several vendors (e.g., Avast, AVG) labeled it `MalwareX-gen [Pws]`, a password-stealer designation.
- Some vendors (e.g., ALYac, Arcabit, BitDefender) used ransomware-style names (`Gen:Variant.Ransom.Loki`).
- Tags: `rar`, `attachment`, `spreader`.

The consistent Loki namings point to a credential stealer. However, no sandbox or dynamic analysis was performed, so the malware's actual behavior is unconfirmed.

### MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access (TA0001) | T1566.001 - Phishing: Spearphishing Attachment | Malicious archive delivered as an email attachment |
| Defense Evasion (TA0005) | T1036.008 - Masquerading: Masquerade File Type | RAR archive given a `.CAB` extension and "PDF" in its name |

## Containment & Recovery

| Action | Target | Purpose |
|--------|--------|---------|
| Search all mailboxes and purge matches | Subject `Transfer Reference Number:(09674321)`, attachment hash, sender `info@mutawamarine[.]com`, Reply-To `info.mutawamarine@mail[.]com` | Identify and remove other copies of this campaign |
| Block the sender address and Reply-To address | Mail gateway | Stop further delivery and prevent replies from reaching the attacker |
| Block the file hash | EDR / endpoint protection | Prevent execution if the file is saved elsewhere |
| Block or monitor the originating IP | Mail gateway | Prevent further delivery from this infrastructure |
| Confirm with the mailbox owner(s) | Users with access to `webmaster@redacted[.]org` | Determine whether the attachment was opened |
| If opened: isolate the endpoint and reset credentials | Affected device and accounts | Loki-family stealers target saved browser, email and FTP credentials. Isolate the device, review it for execution and outbound connections, and reset every credential stored on or entered from that device. |

## Recommendations

1. **Block archive attachments from external senders.** Configure the mail gateway to quarantine `.cab`, `.rar`, `.7z` and `.zip` attachments from external senders.
2. **Detect file-type mismatches.** Enable rules that compare an attachment's true file type (magic bytes) against its extension and quarantine mismatches, such as a RAR archive named `.CAB`.
3. **Review DMARC Enforcement.** The sender's domain published p=quarantine, but the message was delivered with dmarc=unknown. Review the receiving mail system's DMARC evaluation and enforcement behavior to determine why the message was delivered.
4. **Review the relay path.** The relay flagged this message as spam in `X-Ham-Report` and forwarded it anyway. Configure the relay to quarantine or tag spam-classified mail rather than forwarding it.
5. **Flag Reply-To mismatches.** Add a visible warning banner when the Reply-To domain differs from the From domain.
6. **Train users on invoice and payment lures.** Focus on unexpected payment notices that carry attachments, and on checking the reply address before responding.

## Evidence Appendix

### E1: Email Header Excerpt

Source: `challenge.eml`, viewed as source in Thunderbird.

![Email Headers](assets/Greenholt-Phish-P1.png)

### E2: SPF and DMARC Records for mutawamarine.com

Source: online SPF/DMARC lookup tool

```
SPF:   v=spf1 include:spf.protection.outlook.com -all
DMARC: v=DMARC1; p=quarantine; fo=1
```

### E3: Attachment Hash

```
$ sha256sum SWT_#09674321____PDF__.CAB
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f  SWT_#09674321____PDF__.CAB
```

### E4: VirusTotal Result

Source: VirusTotal, lookup 2026-09-26

![VirusTotal](assets/Greenholt-Phish-P2.png)

### E5: Cisco Talos IP Lookup

Source: Cisco Talos Intelligence, lookup 2026-09-26

![Talos](assets/Greenholt-Phish-P3.png)

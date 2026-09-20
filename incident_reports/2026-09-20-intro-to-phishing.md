# Incident Report: Introduction to Phishing 

## Metadata

| Field | Value |
|-------|-------|
| Date | 2026-09-20 |
| Analyst | Logan J. |
| Platform | TryHackMe |
| Room/Scenario | SOC L1 Path - Simulation - Introduction to Phishing |
| Status | Closed, Alert 4 escalated to L2 |

## Executive Summary

During the window of 16:34:00 - 16:42:00 on 09/20/2026, four phishing alerts were generated in the SIEM and triaged: one false positive (legitimate HR onboarding email), three true positive alerts.
The Amazon-themed phishing email reached H. Harris's inbox, but when the user clicked the malicious link the firewall blocked the connection, and no further access attempts were observed in the available logs. However, alert four was escalated to L2 and should be
looked into further. The user C. Allen received a phishing attempt from an attacker posing as Microsoft, and the user visited a malicious website from the email, to
which the connection was allowed by our security controls. There is potential risk that the user entered their credentials; however, available evidence does not confirm credential submission or account compromise. 

## Timeline of Events

| Timestamp (UTC) | Event | Source | Disposition | 
|-----------------|-------|--------|-------------|
| 09/20/2026 16:34:56.095 | Potential Phishing Attempt | SIEM | FP |
| 09/20/2026 16:38:09.095 | Potential Phishing Attempt | SIEM | TP |
| 09/20/2026 16:39:23.095 | Blacklisted External URL Attempted Access | SIEM | TP |
| 09/20/2026 16:40:27.095 | Potential Phishing Attempt | SIEM | TP |

## Attack Indicators

Alerts 2 and 3
| Type | Value | Context |
|------|-------|---------|
| IP Address | 67.199.248[.]11:80 | IP of the blacklisted URL |
| URL | hxxp://bit[.]ly/3sHkX3da12340 | The blacklisted website |
| Email Address | urgents@amazon[.]biz | The sender of the phishing email |

Alert 4
| Type | Value | Context |
|------|-------|---------|
| URL | hxxps://m1crosoftsupport[.]co/login | The false Microsoft website |
| Email Address | no-reply@m1crosoftsupport[.]co | The sender of the phishing email |

## Affected Systems

H. Harris - 10.20.2[.]17:34257 - h.harris@trydaily[.]thm
C. Allen - c.allen@thetrydaily[.]thm 

## Analysis
Alerts 2 & 3 - Chained together due to alert three being a direct result of alert two's outcome. The user H. Harris received a phishing email from urgents@amazon[.]biz,
posing as Amazon informing the user that their package was not delivered, and that they needed to access an external URL to re-enter shipping information. The URL
(hxxp://bit[.]ly/3sHkX3da12340) is a known bad website, blacklisted internally by the organization. At 09/20/2026 16:39:23.095, the user attempted to access the
website, indicating interaction with the phishing attempt, but was denied by the organization's firewall. No further logs indicate that the user continued to try and access
this website after being initially denied.

Alert 4 - The user C. Allen received an "urgent" email at 09/20/2026 16:40:27.095, encouraging them that there was a malicious attempt to access their Microsoft 
account, and that they need to review account activity immediately. The sender, no-reply@m1crosoftsupport[.]co, is not a legitimate Microsoft email (notice the 1 instead
of an I). Combined with the urgency and typo-squatting, these traits are consistent with phishing attempts. The email contained a link to hxxps://m1crosoftsupport[.]co/login, to which the user
accessed, and the internal firewall did not block this request. This alert deserves escalation to L2 to further investigate whether the credentials were compromised, and reviewing any further authentication on the user account.

## Recommendations 

Alert 1 - False Positive - Closed

Alerts 2 & 3 - True Positives - Firewall blocked access to the malicious URL, ensuring the blacklist is working effectively. To prevent this in the future, the email
filtering rules should be tightened to detect illegitimate domains, such as amazon[.]biz, and auto-filter to spam so the user is not persuaded to urgently enter their information.
Furthermore, users should be trained to recognize phishing attempts and signs.

Alert 4 - True Positive - The phishing attempt reached the user, and the malicious URL was accessed without intervention. First priority should be to contact the user and determine whether credentials 
or other sensitive information were entered into the site. As a precaution, credentials should be reset if credential submission cannot be ruled out. L2 should also review authentication logs for suspicious sign-ins,
token activity, MFA changes, and other indicators of account compromise. Furthermore, the domain should be added to a blacklist in an attempt to prevent future access. Email filters should be tuned to identify suspicious typosquatting domains and 
impersonation attempts, and users should be trained to recognize false domains more efficiently.


## Evidence Appendix

### E1: Alert 1 - Onboarding email (hrconnex) + internal FP confirmation

Source: SIEM alert view; internal confirmation via email thread (H. Harris, HR)

Alert (as-seen):
  Time:      09/20/2026 16:34:56.095
  Sender:    onboarding@hrconnex[.]thm
  Recipient: j.garcia@thetrydaily[.]thm
  URL:       hxxps://hrconnex[.]thm/onboarding/15400654060/j.garcia

FP confirmation:
  09/20/26 15:36:29.095 - H. Harris (HR) confirmed hrconnex[.]thm is the
  org's third-party onboarding provider and that J. Garcia is a pending new
  hire awaiting onboarding.

### E2: Alert 2 - Amazon-themed phishing email to H. Harris

Source: SIEM alert view

  Time:      09/20/2026 16:38:09.095
  Sender:    urgents@amazon[.]biz
  Recipient: h.harris@trydaily[.]thm
  URL:       hxxp://bit[.]ly/3sHkX3da12340
  Phish:      Fake failed-delivery notice; prompts user to re-enter shipping info

### E3: Alert 3 - Firewall log, blocked access to blacklisted URL

Source: SIEM firewall log 

  Time:      09/20/2026 16:39:23.095
  Source IP: 10.20.2[.]17:34257  (H. Harris)
  Dest IP:   67.199.248[.]11:80
  URL:       hxxp://bit[.]ly/3sHkX3da12340
  Action:    Blocked (blacklist match)

Note: Same event as E2 (Harris/Amazon), second event. No further access attempts to this URL in logs after.

### E4: Alert 4 - Microsoft-themed phishing email to C. Allen

Source: SIEM alert view; URL-access confirmed via SIEM logs

  Time (email):  09/20/2026 16:40:27.095
  Sender:        no-reply@m1crosoftsupport[.]co
  Recipient:     c.allen@thetrydaily[.]thm
  URL:           hxxps://m1crosoftsupport[.]co/login
  Phish:          Fake "suspicious sign-in" alert; prompts credential review
  Outcome:       User accessed URL at 09/20/2026 16:41:36.095; firewall ALLOWED

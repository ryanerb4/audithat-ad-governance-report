<h1 align="center">AuditHat — Active Directory Governance Report</h1>

<p align="center">
  <b>Active Directory and Group Policy governance reporting for bank and credit union IT Committees.</b><br>
  One PowerShell script. A committee report, a control mapping, and a 30-day administrative change report.
</p>

<p align="center">
  <a href="https://audithat.com"><b>audithat.com</b></a>
</p>

<p align="center">
  <sub>
    FFIEC IT Examination Handbook · NIST CSF 2.0 · CRI Profile (Cyber Risk Institute) · CIS Controls v8 &amp; CIS Benchmarks (Center for Internet Security) · GLBA 501(b) · IT Steering Committee review · Examiner and IT audit preparation
  </sub>
</p>

<p align="center">
  <b><a href="examples/">→ See a complete sample report</a></b> — both HTML files, generated against a fictional lab domain
</p>

---

Community banks and credit unions have to show their IT Committee — and then their examiner and their IT auditor — that Active Directory is configured the way policy says it is, and that they know what changed since the last review.

Run one read-only PowerShell script on a domain controller. You get two HTML files: a detailed technical report for the administrator, and a print-ready **IT Committee report** for the board packet, including an **administrative change report** covering the last 30 days.

No modules to install beyond RSAT. No agents. Nothing is sent anywhere — the script is read-only and writes only to the output folder you choose.

---

## Who this is for

- **Community bank and credit union IT Committees / IT Steering Committees** preparing the quarterly or annual system review
- **Internal auditors and ISOs** assembling evidence for an FFIEC IT examination, an NCUA or FDIC/OCC exam, or a third-party IT audit
- **MSPs and vCISOs** who have to produce the same Active Directory review across many institutions on a schedule
- **Anyone** who has been asked for "the AD change report" or "the admin access review" and does not want to build it by hand again

---

## What it produces

Every run creates a dated folder containing:

| File | Audience |
|---|---|
| `AD-Report-<domain>-YYYYMMDD.html` | Administrators and auditors — full detail, searchable, sortable |
| `AD-Committee-Review-<domain>-YYYYMMDD.html` | IT Committee / IT Steering Committee — cover sheet, summary, change report, findings, sign-off |
| `Drift-Changes.csv` | Every change in the review window, one row each — evidence and ticketing |
| `PasswordProducts.csv` / `PasswordFilters.csv` / `PasswordBannedWords.csv` | Detected password-restriction products, registered filters, and any readable banned word list |
| `PerGPO\*.html` | The native GPMC report for each individual GPO |
| `*.csv` | Flat exports for pivoting, ticketing, or evidence retention |
| `ad-snapshot.json` | Machine-readable state, used to compute change on the next run |

### The detailed report

A left-nav application in a single HTML file:

- **Focus areas (A–F)** — which GPOs configure password policy, account lockout, audit policy, inactivity/screen lock, USB and removable storage, and the logon banner. Expand a GPO to see its scope and the exact settings it contributes.
- **Password restrictions** — what actually restricts the *content* of a password: which password-restriction product is in place (Microsoft Entra Password Protection, Enzoic, Specops, Lithnet, PassFiltEx, nFront, Netwrix/Anixis and others), detected four ways, whether it is **enforcing or only auditing**, and **the banned word list itself** wherever it is stored as a readable file.
- **Privileged groups** — effective membership of Administrators, Domain Admins, Enterprise Admins and Schema Admins, including accounts inherited through nested groups.
- **Logon restrictions** — per-user logon hours as a 7×24 weekly grid in local time, plus workstation restrictions and account expiry.
- **All GPOs** — the full nested inventory: every configured setting, grouped by container path, with each GPO's scope, security filtering and WMI filter.
- **Scope index / Unlinked GPOs** — every link in the domain by container, and the GPOs that are applying nowhere.
- **Cleanup** — disabled users, users idle beyond a threshold, and computers that have not checked in, each flagged when the account holds privileged group membership.

### The committee report

A print-ready document, not an application:

- Cover sheet with domain, review date, preparer, and the exact period covered
- Executive summary in plain language
- **Change over the last 30 days** — five differential tables (below)
- Control review and mapping table
- Open items sorted by severity
- Committee sign-off block

---

## The change report

This is the part committees and examiners actually ask about: *what changed, and what stayed the same.*

Drift is measured against **the state recorded 30 days ago — not against the previous run.** If you run the report weekly, the committee still gets a clean 30-day picture rather than a week's worth of noise. The window is set with `-DriftDays`. The report always states the exact baseline date and the actual number of days covered, and says so plainly when no snapshot that old exists yet.

Five tables, each of which reports **no change** affirmatively rather than going silent:

| # | Table | Reports |
|---|---|---|
| 1 | Control areas | Each of the six areas: changed, or confirmed unchanged, with before and after |
| 2 | Group Policy setting changes | Every setting added, removed or modified — **with the old value and the new value**, and the GPO it came from |
| 3 | Privileged group membership changes | Every account added to or removed from Administrators, Domain Admins, Enterprise Admins, Schema Admins |
| 4 | User account changes | Accounts created, deleted, enabled, disabled, moved between OUs, and changes to password-never-expires or account expiry |
| 5 | Computer account changes | Machines joined, removed, enabled, disabled or moved |

The HTML tables are capped for print; the complete, uncapped list is always written to `Drift-Changes.csv` with the baseline date, comparison date and window length on every row.

```
Area              Setting                    Change    Was                Now
A. Password       MinimumPasswordLength      Modified  14 characters      12 characters
B. Lockout        LockoutBadCount            Removed   5 failed attempts  (not set)

Group             Account      Change                 Was     Now
Domain Admins     legacysvc    Removed from group     Member  Not a member

Account           Change                   Was       Now
bnhire            Account created          —         Enabled
rickadmin         Password never expires   No        Yes
```

Point every run at the same `-OutputPath` and the comparison happens automatically. The first run states that it is establishing the baseline. Keep the report folders and you keep the history.

---

## Password restrictions

"Do you ban the bank's own name as a password?" is a question with no answer in Group Policy — length, age, history and complexity are all a GPO knows about. Anything that restricts what a password *contains* is a **password filter DLL** registered with the LSA on every domain controller, and it is invisible in GPMC.

### Products detected

Each product is looked for **four independent ways**, because vendors rename their DLLs and not every filter name is publicly documented:

1. the DLL registered in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`
2. the product's own registry key
3. the product's Windows service
4. for Entra Password Protection, its DC agent event log

Any one is enough, and the report prints **which signals actually fired** — so an undocumented DLL name never becomes a false "not installed."

| Product | Detected by | Notes |
|---|---|---|
| **Microsoft Entra Password Protection** | filter DLL, registry key, DC agent service, agent event log | Reports **Audit vs Enforce mode** — see below |
| **Enzoic for Active Directory** | `EnzoicFilter` DLL, service, registry | Breach screening, fuzzy/leet matching, root-word detection, custom dictionary |
| **Specops Password Policy** | Sentinel service, `HKLM\SOFTWARE\Specopssoft\Specops Password Policy`, filter | Custom dictionaries, banned word lists, passphrase rules, breached-password screening |
| **Lithnet Password Protection** | `lithnetpwdf` DLL, registry | Banned word store, compromised-password store, normalised matching |
| **PassFiltEx** | `PassFiltEx` DLL, registry | Plain-text blacklist — **printed in full** |
| **nFront Password Filter** | `PPRO` DLL, registry | Dictionary and banned word lists per policy |
| **Netwrix / Anixis Password Policy Enforcer** | `PPE` DLL, registry, service | Dictionary, banned word and pattern rules |
| **ManageEngine ADSelfService Plus**, **Safepass.me**, **OpenPasswordFilter** | DLL, service | Dictionary and breached-password restrictions |

### Audit mode is not enforcement

A Microsoft Entra Password Protection deployment left in **audit-only** mode logs banned passwords and then *accepts them*. The report reads the DC agent's own event log (event 30006, `AuditOnly`), prints the mode in the product table, and raises it as a **High** finding if nothing is actually being blocked. That distinction is the difference between a control and a report about a control.

### What else the section shows

- **The banned word list**, printed in full, wherever the product stores it as a readable file. Where it is encrypted or proprietary — Entra caches the tenant custom list encrypted in SYSVOL, Enzoic keeps its settings in Active Directory — the report says so and names where to export it from, per product.
- **Each product's configuration** straight out of its own registry key.
- **Any GPO setting** referencing a dictionary, a banned or prohibited word list, a passphrase rule or a breached-password check.
- **What the built-in rule actually does** — with complexity enabled, Windows blocks the account name and three-or-more character tokens of the display name and requires three of five character categories. No word list, no dictionary, no breach check. If that is all you have, the report says so in those words.
- **An unrecognised filter** in the password path is a finding in its own right. Something is loading into LSASS and reading every password change; it should be identified and covered by change control.

A product or filter appearing, disappearing, or dropping into audit mode between runs shows up in the change report, because a banned-word product being uninstalled is exactly the kind of drift nobody notices.

If the registry cannot be read — running off a domain controller without remote registry rights — the section says **NOT CHECKED** rather than reporting "none configured." The difference matters when the output is evidence.

---

## See it before you run it

[**`examples/`**](examples/) holds a complete pair of reports — the detailed report and the committee report — generated against a fictional "Example Bank" lab domain. The generator that produced them is in the same folder, so you can confirm the data is synthetic and reproduce them yourself.

GitHub does not render HTML from a repository; download the files and open them, or paste their URLs into <https://htmlpreview.github.io/>.

---

## Quick start

```powershell
# On a domain controller, or any domain-joined machine with RSAT
.\Export-ADAuditReport.ps1 -ShowWhenDone
```

That's it. Output lands in `C:\GPOReports\` by default.

```powershell
# Quarterly review window, tighter thresholds, specific DC
.\Export-ADAuditReport.ps1 -OutputPath D:\Audit -DriftDays 90 `
                           -StaleUserDays 45 -StaleComputerDays 90 `
                           -Server DC02 -ShowWhenDone
```

---

## Requirements

| | |
|---|---|
| **PowerShell** | 5.1 or later (ships with Windows Server) |
| **GroupPolicy module** | `Install-WindowsFeature GPMC` — required |
| **ActiveDirectory module** | `Install-WindowsFeature RSAT-AD-PowerShell` — optional, see below |
| **Permissions** | Read access to the GPOs and to Active Directory. No write access is used. |

The script is **read-only**. It creates and modifies nothing in the directory or in SYSVOL.

### ADWS is not required

The `ActiveDirectory` module talks to Active Directory Web Services on TCP 9389, which is frequently stopped or firewalled even on a healthy domain controller. When ADWS is unavailable the script falls back to **LDAP on TCP 389** — the same transport the Group Policy inventory already uses — and produces every section anyway. The report header records which route was used.

If neither route works, the Group Policy inventory is still produced and the directory sections are clearly marked **NOT CHECKED** rather than silently reporting zero.

---

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-Domain` | Current domain | FQDN of the domain to report on |
| `-Server` | Auto-discovered | Specific domain controller to query |
| `-OutputPath` | `C:\GPOReports` | Root folder for the dated report folder. Keep it the same between runs — it is where the history lives |
| `-Name` | All | Wildcard filter on GPO display name, e.g. `'*Baseline*'` |
| `-DriftDays` | `30` | Size of the change window, in days. Use `90` for a quarterly committee cycle |
| `-StaleUserDays` | `30` | A user with no logon in this many days is listed as stale |
| `-StaleComputerDays` | `60` | A computer with no check-in in this many days is listed as stale |
| `-UtcOffsetHours` | Machine offset | Offset used to draw logon-hour grids in local time |
| `-SkipUserDrift` | Off | Skip the per-account differential tables (4 and 5) and the account roster in the snapshot |
| `-SkipPerGpoHtml` | Off | Skip the per-GPO GPMC reports (much faster on large domains) |
| `-SkipPrivilegedGroups` | Off | Skip privileged group membership collection |
| `-SkipCleanup` | Off | Skip the disabled/stale account views |
| `-SkipPasswordRestrictions` | Off | Skip the password filter / banned word check (no registry read) |
| `-SkipCommitteeReport` | Off | Produce only the detailed report |
| `-NoCsv` | Off | Skip the CSV exports |
| `-ShowWhenDone` | Off | Open the report when finished |

---

## Control mapping

Each reviewed area carries a control reference in the committee report:

| Area | FFIEC IT Examination Handbook | NIST CSF 2.0 | CRI Profile | CIS Controls v8 |
|---|---|---|---|---|
| Password policy | IS II.C.7 User Security Controls; II.C.15 Logical Security | PR.AA | PR.AA | 5.2, 6.3 |
| Account lockout | IS II.C.7 User Security Controls | PR.AA | PR.AA | 6.3 |
| Audit policy and event logs | IS II.C Risk Mitigation; Audit booklet | DE.CM, PR.PS | DE.CM, PR.PS | 8.2, 8.5, 8.11 |
| Inactivity / session lock | IS II.C.7; II.C.15 | PR.AA | PR.AA, PR.PS | 4.3 |
| USB and removable storage | IS II.C.13 Control of Information | PR.DS, PR.PS | PR.DS, PR.PS | 3.6, 10.3 |
| Logon banner | IS II.C.15 Logical Security | PR.AT, GV.PO | PR.AT, PR.PS | 4.1 |
| Privileged group membership | IS II.C.7 (least privilege) | PR.AA | PR.AA | 5.4, 6.8 |
| Account provisioning and dormancy | IS II.C.7 (provisioning and deprovisioning) | PR.AA, ID.AM | PR.AA, ID.AM | 5.1, 5.3 |
| User logon restrictions | IS II.C.7; II.C.15 | PR.AA | PR.AA | 6.1, 6.2 |
| Password content restrictions | IS II.C.7 (authentication strength) | PR.AA | PR.AA | 5.2 |
| Group Policy configuration | IS II.C.2; Architecture, Infrastructure and Operations booklet | PR.PS | PR.PS | 4.1, 4.2 |

**FFIEC** references are to the current [IT Examination Handbook](https://ithandbook.ffiec.gov/) booklets.

**NIST CSF 2.0** gives the Function and Category for institutions reporting against the Framework directly.

**CRI Profile** references are to the [Cyber Risk Institute](https://cyberriskinstitute.org/) Profile v2.x at the *Category* level. The Profile identifies individual requirements as **diagnostic statements** in the form `FUNCTION.CATEGORY-##.##` (for example `GV.OC-01.01`). Category-level mapping is provided because the statement text is licensed material — if your institution reports against specific diagnostic statements, add those numbers from your own Profile workbook. Note that CRI v2.x restructures the GOVERN function relative to CSF 2.0, which is why the CSF and CRI columns differ on the logon banner row.

**CIS Controls v8** safeguards are included for institutions whose hardening standard is the [Center for Internet Security](https://www.cisecurity.org/controls) Benchmarks. The CIS Windows Server and Windows 10/11 Benchmarks *set* the password, lockout, audit, session-lock, removable-media and interactive-logon-message values that this report reads back out of Group Policy — so the same output doubles as CIS Benchmark conformance evidence.

The same evidence also supports a GLBA 501(b) information security program review and the access-control workpapers in most third-party bank IT audit programs.

**These are defaults, not authority.** Confirm them against your own control set and your examiner's expectations. They live in one editable hashtable near the top of the script:

```powershell
$script:ControlMap = @{
    'pwd'     = 'Your citation here'
    'lockout' = 'Your citation here'
    # ...
}
```

Edit once and every report your organization produces inherits your house citations.

*Framework and vendor names are used for mapping and identification only. No endorsement, certification or affiliation is implied by any organization named here.*

---

## Handling the output

**Reports contain sensitive directory data** — account names, organizational units, descriptions, privileged group membership, and logon schedules. Treat a generated report the same way you would treat any other audit work product:

- Do not commit generated reports to source control. The included `.gitignore` blocks the usual filenames, but check before you push.
- Store them where your evidence retention policy says audit work product belongs.
- Redact or generate against a lab domain before using a report as a public example.

---

## Limitations

- Reports **configured** settings only. The GPO XML report does not contain settings left "Not Configured," so absence in this report means absence from Group Policy — not that a setting is unset on the endpoint.
- `LastLogonDate` derives from `lastLogonTimestamp`, which replicates lazily and can lag by up to 14 days. Day counts are approximate by design; the thresholds are deliberately loose because of it.
- The change report compares **snapshots**, not the security event log. It tells you an account was added to Domain Admins between two dates; it does not tell you who added it or exactly when. Pair it with your SIEM or event-log retention for attribution.
- Account-level tables (4 and 5) need a baseline snapshot that also recorded account detail. A baseline written by an older version, or with `-SkipUserDrift`, is reported as *not measured* rather than as *no change*.
- Logon hours are stored in UTC and rendered in local time. Generating during daylight saving shifts the grid by an hour relative to a schedule authored under standard time. Use `-UtcOffsetHours` to pin it.
- Focus areas match on setting names and category paths. A control implemented through an unusual custom ADMX or a preference item may not be matched — open an issue with the setting name and it can be added.
- This tool reports configuration. **It is not an audit, a risk assessment, or a substitute for either.**

---

## Questions, suggestions, or something it missed?

Visit **[audithat.com](https://audithat.com)** and fill out the contact form. Feature requests, unmatched settings, and control-mapping corrections are all welcome there — or as a GitHub issue if you prefer.

---

## If you like this, you will love Pulse

This script gives you a point-in-time baseline of one domain and, on the next run, the drift against it. That is the manual, quarterly version of what **[Pulse by AuditHat](https://audithat.com)** does continuously — and Pulse does not stop at Active Directory.

Pulse adds reporting and change tracking across:

- **Microsoft 365** — Entra ID, Exchange Online, Intune
- **Firewalls** and perimeter configuration
- **Threat protection** and endpoint security posture
- **Software inventory** and patch state
- **Network devices**

…in the same committee-ready format, mapped to the same frameworks, without the calendar reminder. If you find this script useful once a quarter, Pulse is the same idea running all the time. [Talk to us at audithat.com](https://audithat.com).

---

## Contributing

Issues and pull requests are welcome, particularly:

- **Unmatched settings.** If a control in your environment is implemented in a way the focus areas do not catch, open an issue with the setting name and container path and it can be added to the matcher.
- **Control mapping.** Corrections to the FFIEC, NIST CSF 2.0, CRI Profile or CIS Controls v8 references, with a citation.
- **Directory shapes.** Multi-domain forests, unusual OU structures, and non-English domains are where edge cases live.

Please do not attach a real report to an issue. Redact it, or reproduce against a lab domain.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Provided on an "AS IS" basis, without warranties or conditions of any kind. Output is a configuration report for review by qualified personnel. It does not constitute an audit opinion, a compliance determination, or legal advice.

---

<sub>
<b>Topics:</b> active-directory · group-policy · gpo-report · ad-audit · ad-change-report · admin-change-report · it-committee-report · it-steering-committee · governance · banking · community-bank · credit-union · ffiec · ffiec-compliance · nist-csf · nist-csf-2 · cri-profile · cyber-risk-institute · cis-controls · cis-controls-v8 · cis-benchmarks · center-for-internet-security · cis-hardening · glba · ncua · fdic · occ · sox-itgc · powershell · windows-server-2022 · domain-controller · privileged-access-review · user-access-review · configuration-drift · security-baseline · examiner-preparation · it-audit · msp
</sub>

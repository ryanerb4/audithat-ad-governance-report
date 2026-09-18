<h1 align="center">AuditHat — Active Directory Governance Report</h1>

<p align="center">
  <b>Active Directory and Group Policy governance reporting for bank and credit union IT Committees.</b><br>
  One PowerShell script. Committee-ready HTML, control mapping, and quarter-over-quarter drift tracking.
</p>

<p align="center">
  <a href="https://audithat.com"><b>audithat.com</b></a>
</p>

<p align="center">
  <sub>
    FFIEC IT Examination Handbook · NIST CSF 2.0 · IT Steering Committee review · Examiner preparation
  </sub>
</p>

---

Run one PowerShell script on a domain controller. Get two HTML files: a detailed technical report for the administrator, and a print-ready committee review for the packet.

No modules to install beyond RSAT. No agents. Nothing is sent anywhere — the script is read-only and writes only to the output folder you choose.

---

## What it produces

Every run creates a dated folder containing:

| File | Audience |
|---|---|
| `AD-Report-<domain>-YYYYMMDD.html` | Administrators and auditors — full detail, searchable, sortable |
| `AD-Committee-Review-<domain>-YYYYMMDD.html` | IT Committee / IT Steering Committee — cover sheet, summary, findings, sign-off |
| `PerGPO\*.html` | The native GPMC report for each individual GPO |
| `*.csv` | Flat exports for pivoting, ticketing, or evidence retention |
| `ad-snapshot.json` | Machine-readable state, used to compute change on the next run |

### The detailed report

A left-nav application in a single HTML file:

- **Focus areas (A–F)** — which GPOs configure password policy, account lockout, audit policy, inactivity/screen lock, USB and removable storage, and the logon banner. Expand a GPO to see its scope and the exact settings it contributes.
- **Privileged groups** — effective membership of Administrators, Domain Admins, Enterprise Admins and Schema Admins, including accounts inherited through nested groups.
- **Logon restrictions** — per-user logon hours as a 7×24 weekly grid in local time, plus workstation restrictions and account expiry.
- **All GPOs** — the full nested inventory: every configured setting, grouped by container path, with each GPO's scope, security filtering and WMI filter.
- **Scope index / Unlinked GPOs** — every link in the domain by container, and the GPOs that are applying nowhere.
- **Cleanup** — disabled users, users idle beyond a threshold, and computers that have not checked in, each flagged when the account holds privileged group membership.

### The committee review

A print-ready document, not an application:

- Cover sheet with domain, review date, preparer, and period covered
- Executive summary in plain language
- **Change since last review** — what moved since the previous run, tagged better / worse / neutral
- Control review and mapping table
- Open items sorted by severity
- Committee sign-off block

---

## Quick start

```powershell
# On a domain controller, or any domain-joined machine with RSAT
.\Export-ADAuditReport.ps1 -ShowWhenDone
```

That's it. Output lands in `C:\GPOReports\` by default.

```powershell
# Narrow the scope, change thresholds, pick a DC
.\Export-ADAuditReport.ps1 -OutputPath D:\Audit `
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
| `-OutputPath` | `C:\GPOReports` | Root folder for the dated report folder |
| `-Name` | All | Wildcard filter on GPO display name, e.g. `'*Baseline*'` |
| `-StaleUserDays` | `30` | A user with no logon in this many days is listed as stale |
| `-StaleComputerDays` | `60` | A computer with no check-in in this many days is listed as stale |
| `-UtcOffsetHours` | Machine offset | Offset used to draw logon-hour grids in local time |
| `-SkipPerGpoHtml` | Off | Skip the per-GPO GPMC reports (much faster on large domains) |
| `-SkipPrivilegedGroups` | Off | Skip privileged group membership collection |
| `-SkipCleanup` | Off | Skip the disabled/stale account views |
| `-SkipCommitteeReport` | Off | Produce only the detailed report |
| `-NoCsv` | Off | Skip the CSV exports |
| `-ShowWhenDone` | Off | Open the report when finished |

---

## Tracking change over time

The committee review compares each run against the previous one and reports what moved:

```
BETTER   Logon banner: now configured by an applying GPO (was not configured)
BETTER   Domain Admins: removed jsmith
WORSE    Administrators (built-in): added contractor01
WORSE    Stale users: 4 -> 9
NEUTRAL  Configured settings: 412 -> 418
```

This is what turns a one-time snapshot into a standing agenda item. Point every run at the same `-OutputPath` and the comparison happens automatically — the first run states that it is establishing the baseline.

Comparison is driven by `ad-snapshot.json` in each report folder. Keep the folders and you keep the history.

---

## Control mapping

Each reviewed area carries a control reference in the committee report:

| Area | Reference |
|---|---|
| Password policy | FFIEC IS II.C.7 User Security Controls; II.C.15 Logical Security · NIST CSF 2.0 PR.AA |
| Account lockout | FFIEC IS II.C.7 User Security Controls · NIST CSF 2.0 PR.AA |
| Audit policy and event logs | FFIEC IS II.C Risk Mitigation; Audit booklet · NIST CSF 2.0 DE.CM, PR.PS |
| Inactivity / session lock | FFIEC IS II.C.7; II.C.15 · NIST CSF 2.0 PR.AA |
| USB and removable storage | FFIEC IS II.C.13 Control of Information · NIST CSF 2.0 PR.DS, PR.PS |
| Logon banner | FFIEC IS II.C.15 Logical Security · NIST CSF 2.0 PR.AT, GV.PO |
| Privileged group membership | FFIEC IS II.C.7 (least privilege) · NIST CSF 2.0 PR.AA |
| Account provisioning and dormancy | FFIEC IS II.C.7 (provisioning and deprovisioning) · NIST CSF 2.0 PR.AA, ID.AM |

FFIEC references are to the current [IT Examination Handbook](https://ithandbook.ffiec.gov/) booklets. NIST CSF 2.0 categories are provided as a cross-reference for institutions aligned to the CRI Profile or to CSF directly.

**These are defaults, not authority.** Confirm them against your own control set and your examiner's expectations. They live in one editable hashtable near the top of the script:

```powershell
$script:ControlMap = @{
    'pwd'     = 'Your citation here'
    'lockout' = 'Your citation here'
    # ...
}
```

Edit once and every report your organization produces inherits your house citations.

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
- Logon hours are stored in UTC and rendered in local time. Generating during daylight saving shifts the grid by an hour relative to a schedule authored under standard time. Use `-UtcOffsetHours` to pin it.
- Focus areas match on setting names and category paths. A control implemented through an unusual custom ADMX or a preference item may not be matched — open an issue with the setting name and it can be added.
- This tool reports configuration. **It is not an audit, a risk assessment, or a substitute for either.**

---

## From a quarterly snapshot to continuous monitoring

This script gives you a point-in-time baseline and, on the next run, the drift against it. That is the manual version of what [AuditHat](https://audithat.com) does continuously — tracking change and drift from the security baseline, and turning it into the executive reporting an IT Committee and an examiner expect.

If you find this useful once a quarter, the continuous version is the same idea without the calendar reminder.

---

## Contributing

Issues and pull requests are welcome, particularly:

- **Unmatched settings.** If a control in your environment is implemented in a way the focus areas do not catch, open an issue with the setting name and container path and it can be added to the matcher.
- **Control mapping.** Corrections to the FFIEC or NIST CSF references, with a citation.
- **Directory shapes.** Multi-domain forests, unusual OU structures, and non-English domains are where edge cases live.

Please do not attach a real report to an issue. Redact it, or reproduce against a lab domain.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Provided on an "AS IS" basis, without warranties or conditions of any kind. Output is a configuration report for review by qualified personnel. It does not constitute an audit opinion, a compliance determination, or legal advice.

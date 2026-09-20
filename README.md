# Sample reports

Two complete reports, exactly as the script produces them.

| File | What it is |
|---|---|
| [`AD-Report-examplebank.local-SAMPLE.html`](AD-Report-examplebank.local-SAMPLE.html) | The **detailed report** — left-nav application for the administrator and the auditor |
| [`AD-Committee-Review-examplebank.local-SAMPLE.html`](AD-Committee-Review-examplebank.local-SAMPLE.html) | The **IT Committee report** — print-ready, with the 30-day change report and control mapping |

GitHub will not render HTML from the repository itself. Either **download the file and open it in a browser**, or view it through a third-party HTML previewer by pasting the file's URL into <https://htmlpreview.github.io/>.

---

## Everything here is fictional

There is no Example Bank. The domain, every user and computer account, the privileged group membership, the GPO names and all of the findings were invented for this sample and generated in a container — **no real directory was read, and no institution's data appears in these files.** Both reports carry a banner saying so.

`sample-harness.ps1` in this folder is the generator. It mocks `Get-GPO`, `Get-GPOReport`, the `ActiveDirectory` cmdlets and the password-filter readers, then dot-sources the real `Export-ADAuditReport.ps1` unmodified. You can read it to confirm the data is synthetic, and run it yourself:

```powershell
$env:SAMPLE_OUT = 'C:\Temp\Samples'
pwsh -File sample-harness.ps1          # baseline run
# backdate the snapshot, then:
$env:SAMPLE_RUN2 = '1'
pwsh -File sample-harness.ps1          # second run, 35 days later
```

The published samples are the **second** run, so the change tables have something to report.

---

## What the sample is set up to show

The fictional institution is in reasonable shape with a realistic set of problems — the point is to show what the report does with both.

**Working well**

- Domain password policy and lockout configured at the domain root, with two fine-grained policies (PSOs) for privileged and service accounts
- Advanced audit subcategories and a 1 GB security log on the servers
- Removable storage denied on workstations and teller stations
- A logon banner (title *and* text — both are required, and the report checks for both)
- Teller accounts restricted to weekday hours and to named workstations, shown as a 7×24 grid
- Microsoft Entra Password Protection and PassFiltEx both detected, with the institution-specific banned word list printed in full

**Open items the report raises**

- **Entra Password Protection dropped from Enforced to Audit-only** during the window — logged, not blocked. Raised as a High finding and as the first headline in the change report.
- A contractor account added to **Domain Admins** and **Administrators** inside the window
- A service account in Domain Admins with a non-expiring password
- Minimum password length weakened from 14 to 12; machine inactivity limit relaxed from 15 to 30 minutes
- Disabled accounts still present, a stale user, stale computers, and one unlinked GPO

**The 30-day change report** shows all five differential tables populated: control areas (changed *and* confirmed unchanged), setting-level changes with old → new values, privileged group movement, user account changes (created, disabled, moved OU, password-never-expires), and computer accounts (joined, disabled, removed).

---

← [Back to the project README](../README.md) · [audithat.com](https://audithat.com)

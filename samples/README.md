# Sample reports

Two complete sample reports, exactly as `Export-ADAuditReport.ps1` writes them to disk.

| File | What it is |
|---|---|
| `sample-detailed-report.html` | The detailed review — left-nav application with focus areas, privileged groups, logon restrictions, service accounts, the full user inventory, the GPO inventory and the cleanup views |
| `sample-committee-review.html` | The IT Committee report — cover sheet, executive summary, change tracking, control mapping, open items with management response boxes, sign-off block and exhibits |

**How to view them:** download the file and open it in any browser. Both are self-contained single
HTML files — no server, no internet connection, no dependencies. GitHub will not render them in the
browser from this page; it shows the source instead.

## About the data

Every domain name, account name, computer name, organizational unit and Group Policy Object in these
samples is **fictional**. They describe an invented domain, `corp.examplebank.local`, belonging to an
invented institution. No real organization's directory was used.

The sample domain was built to show the kinds of findings the script reports — lockout disabled,
unrestricted service accounts, no inactivity policy, a half-configured logon banner, a disabled
account still in Domain Admins, and a removable-media GPO whose link was turned off. A healthy domain
produces a much shorter report.

## Things worth clicking

In `sample-detailed-report.html`:

- The **stat tiles** on *All users* and *User logon restrictions* are filters — click one.
- **Export this view to CSV** exports what is currently filtered, not the whole table.
- **Print this view** prints without the navigation sidebar.
- Column headers sort.
- Expand a GPO under *Focus areas* to see its scope panel — who it applies to, and whether it is
  actually applying.

In `sample-committee-review.html`:

- The **management response / action** boxes under each open item are editable in the browser — click
  in and type, then print or save to PDF.
- Each open item links to its **exhibit** at the back of the report.
- Each exhibit has a **Copy** button on the change request, ready to paste into a ticket.
- Print the page (Ctrl+P / Cmd+P) to see the committee packet as it goes in the board binder.

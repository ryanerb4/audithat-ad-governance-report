# Security

## What this tool does and does not do

`Export-ADAuditReport.ps1` is **read-only**. It queries Group Policy and Active
Directory and writes HTML and CSV files to a path you specify. It creates,
modifies and deletes nothing in the directory, in SYSVOL, or in the registry.

It makes **no outbound network connections**. All traffic is to your own domain
controllers over LDAP (TCP 389) or ADWS (TCP 9389), and to SYSVOL over SMB.

## Handling generated reports

Reports contain sensitive directory data: account names, sAMAccountNames,
organizational units, account descriptions, privileged group membership, logon
schedules and last-logon dates. Treat them as audit work product.

- Do not commit a generated report to any repository.
- Store them according to your evidence retention policy.
- Redact, or generate against a lab domain, before sharing publicly.

## Reporting a vulnerability

If you find a security issue in this script, please report it privately rather
than opening a public issue. Contact: security@audithat.com

Please include the script version (shown in the console banner and in the report
footer), what you observed, and how to reproduce it.

# AD Hygiene Audit

A read-only PowerShell audit for Active Directory, with optional Entra ID guest checks. It finds the accounts, groups and computers that tend to cause audit findings, and writes a CSV and a self-contained HTML report.

Everything here is free: Windows PowerShell 5.1, the RSAT Active Directory tools, the free Microsoft.Graph module, and a free Windows Server evaluation VM for testing. No paid licence is needed.

## What it checks

| Area | Finding | Severity |
| --- | --- | --- |
| Users | Disabled account still in a privileged group | High |
| Users | Enabled privileged account with no logon for 90+ days | High |
| Users | Privileged account whose password never expires | High |
| Users | Enabled account with no logon for 90+ days | Medium |
| Users | Enabled account that has never logged on (older than 30 days) | Medium |
| Users | Password never expires | Medium |
| Users | Password older than 365 days | Low |
| Groups | Privileged group with more than 10 members | Medium |
| Groups | Group with no members | Low |
| Computers | Operating system out of support (XP, Vista, 7, Server 2003, 2008, 2012) | Medium |
| Computers | Enabled computer with no logon for 90+ days | Low |
| Entra guests | Guest invitation pending for 30+ days (optional) | Medium |

Privileged groups: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators. Membership is resolved recursively, so nested groups count. All day counts can be changed with parameters.

## Run it

```powershell
# Try it with fictional data. Touches no directory.
.\Invoke-ADHygieneAudit.ps1 -Demo

# Your domain (run from a domain-joined machine with RSAT Active Directory tools)
.\Invoke-ADHygieneAudit.ps1 -StaleDays 60 -OutputPath .\report

# Add Entra ID guest checks (free tier data only)
Connect-MgGraph -Scopes User.Read.All
.\Invoke-ADHygieneAudit.ps1 -IncludeEntra
```

The script only reads. It never changes, disables or deletes anything.

## Test it

```powershell
.\Tests.ps1
```

The tests use fictional data and mocked AD cmdlets, so they need no domain. They cover every check above, the privileged-membership logic, the group counts and the report output.

## Design

- **Collection is separate from checks.** The checks work on plain objects, so they are easy to test and to reuse.
- **Findings are explained.** Each row says what was found and what to do about it.
- **Free-tier only.** The Entra check uses guest type and invitation state, which the free tier provides. It does not use sign-in activity, which needs a paid licence.

## Limits

- **Tested with mocks and demo data, not against a live domain.** I wrote and tested this without access to a domain. Try it in a lab domain before using it on a production one.
- Last logon dates come from lastLogonTimestamp, which can lag by up to 14 days.
- It reports only. Review each finding before you change anything.
- The out-of-support operating system list is built in. Verify dates against the Microsoft Lifecycle site.
- Service accounts and break-glass accounts may be flagged on purpose. Treat the report as a review list, not a to-do list.

## Files

- Invoke-ADHygieneAudit.ps1: the tool
- Tests.ps1: self-test
- sample-report.html: output from -Demo

MIT licensed.

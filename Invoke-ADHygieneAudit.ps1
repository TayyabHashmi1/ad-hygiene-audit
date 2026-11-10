<#
.SYNOPSIS
    Read-only hygiene audit for Active Directory, with optional Entra ID guest checks.

.DESCRIPTION
    Finds stale and risky accounts, empty or oversized privileged groups, stale computers
    and out-of-support operating systems. Writes a CSV and a self-contained HTML report.
    It never changes anything in the directory.

    Data collection is separate from the checks. The checks work on plain objects, so they
    can be tested with fictional data (see Tests.ps1 and the -Demo switch).

.PARAMETER Demo
    Build the report from fictional sample data. No directory is contacted.

.PARAMETER StaleDays
    Enabled user accounts with no logon for this many days are flagged. Default 90.

.PARAMETER ComputerStaleDays
    Enabled computer accounts with no logon for this many days are flagged. Default 90.

.PARAMETER PasswordMaxAgeDays
    Enabled users whose password is older than this are flagged. Default 365.

.PARAMETER GuestPendingDays
    Entra guests whose invitation has not been accepted after this many days are flagged.
    Default 30.

.PARAMETER IncludeEntra
    Also check Entra ID guests. Needs the free Microsoft.Graph.Users module and a signed-in
    Connect-MgGraph session with the User.Read.All scope. It uses only data available on the
    free Entra ID tier (guest type and invitation state), so no paid licence is needed.

.PARAMETER OutputPath
    Folder for the report files. Created if missing.

.EXAMPLE
    .\Invoke-ADHygieneAudit.ps1 -Demo

.EXAMPLE
    .\Invoke-ADHygieneAudit.ps1 -StaleDays 60 -OutputPath .\report
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [int]$StaleDays = 90,
    [int]$ComputerStaleDays = 90,
    [int]$PasswordMaxAgeDays = 365,
    [int]$GuestPendingDays = 30,
    [switch]$IncludeEntra,
    [string]$OutputPath = (Join-Path (Get-Location) 'ADHygieneReport')
)

Set-StrictMode -Version 2.0

$script:PrivilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators')
$script:LargePrivilegedGroupSize = 10

function New-Finding {
    param($Category, $Severity, $Object, $Finding, $Recommendation)
    [pscustomobject]@{
        Severity       = $Severity
        Category       = $Category
        Object         = $Object
        Finding        = $Finding
        Recommendation = $Recommendation
    }
}

function Test-AdhUser {
    param($Users, [datetime]$Now, [int]$StaleDays, [int]$PasswordMaxAgeDays)
    foreach ($u in $Users) {
        $priv = [bool]$u.IsPrivileged
        if (-not $u.Enabled) {
            if ($priv) {
                New-Finding 'Users' 'High' $u.SamAccountName 'Disabled account is still a member of a privileged group' 'Remove it from the privileged group.'
            }
            continue
        }
        if ($null -eq $u.LastLogonDate) {
            if (($Now - $u.WhenCreated).TotalDays -gt 30) {
                $sev = if ($priv) { 'High' } else { 'Medium' }
                New-Finding 'Users' $sev $u.SamAccountName 'Enabled account has never logged on' 'Confirm it is needed, then disable it.'
            }
        }
        elseif (($Now - $u.LastLogonDate).TotalDays -gt $StaleDays) {
            $days = [int]($Now - $u.LastLogonDate).TotalDays
            $sev = if ($priv) { 'High' } else { 'Medium' }
            New-Finding 'Users' $sev $u.SamAccountName ("No logon for {0} days" -f $days) 'Disable the account if it is no longer used.'
        }
        if ($u.PasswordNeverExpires) {
            $sev = if ($priv) { 'High' } else { 'Medium' }
            New-Finding 'Users' $sev $u.SamAccountName 'Password never expires' 'Use a managed service account or add a rotation process.'
        }
        elseif ($null -ne $u.PasswordLastSet -and ($Now - $u.PasswordLastSet).TotalDays -gt $PasswordMaxAgeDays) {
            $days = [int]($Now - $u.PasswordLastSet).TotalDays
            New-Finding 'Users' 'Low' $u.SamAccountName ("Password is {0} days old" -f $days) 'Require a password change.'
        }
    }
}

function Test-AdhGroup {
    param($Groups)
    foreach ($g in $Groups) {
        $isPriv = $script:PrivilegedGroups -contains $g.Name
        if ($g.MemberCount -eq 0 -and -not $isPriv) {
            New-Finding 'Groups' 'Low' $g.Name 'Group has no members' 'Delete the group if it is unused.'
        }
        if ($isPriv -and $g.MemberCount -gt $script:LargePrivilegedGroupSize) {
            New-Finding 'Groups' 'Medium' $g.Name ("Privileged group has {0} members" -f $g.MemberCount) 'Review membership and remove anyone who does not need it.'
        }
    }
}

function Test-AdhComputer {
    param($Computers, [datetime]$Now, [int]$StaleDays)
    # Operating system names that are past or near end of support. Verify dates on the Microsoft Lifecycle site.
    $oldOs = 'Windows XP|Vista|Windows 7|Server 2003|Server 2008|Server 2012'
    foreach ($c in $Computers) {
        if (-not $c.Enabled) { continue }
        if ($null -ne $c.LastLogonDate -and ($Now - $c.LastLogonDate).TotalDays -gt $StaleDays) {
            $days = [int]($Now - $c.LastLogonDate).TotalDays
            New-Finding 'Computers' 'Low' $c.Name ("No logon for {0} days" -f $days) 'Disable and move the account if the machine is retired.'
        }
        if ($c.OperatingSystem -and $c.OperatingSystem -match $oldOs) {
            New-Finding 'Computers' 'Medium' $c.Name ("Operating system out of support: {0}" -f $c.OperatingSystem) 'Upgrade or replace the system.'
        }
    }
}

function Test-AdhEntraGuest {
    # Uses only free-tier data: guest type, creation date and invitation state.
    param($EntraUsers, [datetime]$Now, [int]$GuestPendingDays)
    foreach ($e in $EntraUsers) {
        if ($e.UserType -ne 'Guest') { continue }
        if ($e.ExternalUserState -eq 'PendingAcceptance') {
            $days = [int]($Now - $e.CreatedDateTime).TotalDays
            if ($days -gt $GuestPendingDays) {
                New-Finding 'Entra guests' 'Medium' $e.UserPrincipalName ("Guest invitation pending for {0} days" -f $days) 'Cancel the invitation or resend it if the access is still needed.'
            }
        }
    }
}

# ---- data collection (needs the ActiveDirectory module; mocked in Tests.ps1) ----

function Get-AdhDirectoryData {
    $privSam = @{}
    foreach ($name in $script:PrivilegedGroups) {
        $grp = Get-ADGroup -Filter ("Name -eq '{0}'" -f $name) -ErrorAction SilentlyContinue
        if ($grp) {
            foreach ($m in (Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue)) {
                if ($m.objectClass -eq 'user') { $privSam[$m.SamAccountName] = $true }
            }
        }
    }
    $users = foreach ($u in (Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, WhenCreated)) {
        [pscustomobject]@{
            SamAccountName       = $u.SamAccountName
            Enabled              = [bool]$u.Enabled
            LastLogonDate        = $u.LastLogonDate
            PasswordLastSet      = $u.PasswordLastSet
            PasswordNeverExpires = [bool]$u.PasswordNeverExpires
            WhenCreated          = $u.WhenCreated
            IsPrivileged         = $privSam.ContainsKey($u.SamAccountName)
        }
    }
    $groups = foreach ($g in (Get-ADGroup -Filter * -Properties Members)) {
        [pscustomobject]@{ Name = $g.Name; MemberCount = @($g.Members).Count }
    }
    $computers = foreach ($c in (Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem)) {
        [pscustomobject]@{ Name = $c.Name; Enabled = [bool]$c.Enabled; LastLogonDate = $c.LastLogonDate; OperatingSystem = $c.OperatingSystem }
    }
    [pscustomobject]@{ Users = @($users); Groups = @($groups); Computers = @($computers) }
}

function Get-AdhEntraData {
    # Needs Connect-MgGraph -Scopes User.Read.All first. These properties are available on the free tier.
    $mg = Get-MgUser -All -Filter "userType eq 'Guest'" -Property UserPrincipalName, UserType, CreatedDateTime, ExternalUserState
    foreach ($m in $mg) {
        [pscustomobject]@{
            UserPrincipalName = $m.UserPrincipalName
            UserType          = $m.UserType
            CreatedDateTime   = $m.CreatedDateTime
            ExternalUserState = $m.ExternalUserState
        }
    }
}

function Get-AdhDemoData {
    param([datetime]$Now)
    $d = $Now.Date
    $users = @(
        [pscustomobject]@{ SamAccountName = 'a.khan';      Enabled = $true;  LastLogonDate = $d.AddDays(-2);   PasswordLastSet = $d.AddDays(-40);  PasswordNeverExpires = $false; WhenCreated = $d.AddDays(-800); IsPrivileged = $false }
        [pscustomobject]@{ SamAccountName = 'j.martin';    Enabled = $true;  LastLogonDate = $d.AddDays(-210); PasswordLastSet = $d.AddDays(-500); PasswordNeverExpires = $false; WhenCreated = $d.AddDays(-900); IsPrivileged = $false }
        [pscustomobject]@{ SamAccountName = 'svc-backup';  Enabled = $true;  LastLogonDate = $d.AddDays(-1);   PasswordLastSet = $d.AddDays(-1200); PasswordNeverExpires = $true; WhenCreated = $d.AddDays(-1500); IsPrivileged = $true }
        [pscustomobject]@{ SamAccountName = 'adm-lopez';   Enabled = $true;  LastLogonDate = $d.AddDays(-150); PasswordLastSet = $d.AddDays(-30);  PasswordNeverExpires = $false; WhenCreated = $d.AddDays(-600); IsPrivileged = $true }
        [pscustomobject]@{ SamAccountName = 'old-contractor'; Enabled = $false; LastLogonDate = $d.AddDays(-400); PasswordLastSet = $d.AddDays(-420); PasswordNeverExpires = $false; WhenCreated = $d.AddDays(-700); IsPrivileged = $true }
        [pscustomobject]@{ SamAccountName = 'new.hire';    Enabled = $true;  LastLogonDate = $null;           PasswordLastSet = $d.AddDays(-60);  PasswordNeverExpires = $false; WhenCreated = $d.AddDays(-60);  IsPrivileged = $false }
    )
    $groups = @(
        [pscustomobject]@{ Name = 'Domain Admins';  MemberCount = 14 }
        [pscustomobject]@{ Name = 'Finance-Share';  MemberCount = 22 }
        [pscustomobject]@{ Name = 'Project-Falcon'; MemberCount = 0 }
        [pscustomobject]@{ Name = 'Printers-Old';   MemberCount = 0 }
    )
    $computers = @(
        [pscustomobject]@{ Name = 'SRV-WEB01';   Enabled = $true; LastLogonDate = $d.AddDays(-1);   OperatingSystem = 'Windows Server 2019 Standard' }
        [pscustomobject]@{ Name = 'SRV-OLDAPP';  Enabled = $true; LastLogonDate = $d.AddDays(-5);   OperatingSystem = 'Windows Server 2012 R2 Standard' }
        [pscustomobject]@{ Name = 'WS-RETIRED7'; Enabled = $true; LastLogonDate = $d.AddDays(-300); OperatingSystem = 'Windows 7 Professional' }
    )
    $entra = @(
        [pscustomobject]@{ UserPrincipalName = 'partner1_vendor.example#EXT#'; UserType = 'Guest';  CreatedDateTime = $d.AddDays(-500); ExternalUserState = 'Accepted' }
        [pscustomobject]@{ UserPrincipalName = 'auditor_firm.example#EXT#';    UserType = 'Guest';  CreatedDateTime = $d.AddDays(-120); ExternalUserState = 'PendingAcceptance' }
        [pscustomobject]@{ UserPrincipalName = 'm.silva@corp.example';        UserType = 'Member'; CreatedDateTime = $d.AddDays(-900); ExternalUserState = $null }
    )
    [pscustomobject]@{ Users = $users; Groups = $groups; Computers = $computers; Entra = $entra }
}

function Export-AdhReport {
    param($Findings, [string]$OutputPath, [datetime]$Now, [bool]$IsDemo)
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $stamp = $Now.ToString('yyyyMMdd-HHmm')
    $csvPath = Join-Path $OutputPath ("ad-hygiene-{0}.csv" -f $stamp)
    $htmPath = Join-Path $OutputPath ("ad-hygiene-{0}.html" -f $stamp)
    $order = @{ High = 0; Medium = 1; Low = 2 }
    $sorted = @($Findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Object)
    $sorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $hi = @($sorted | Where-Object { $_.Severity -eq 'High' }).Count
    $me = @($sorted | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lo = @($sorted | Where-Object { $_.Severity -eq 'Low' }).Count
    $rows = foreach ($f in $sorted) {
        $cls = $f.Severity.ToLower()
        $cells = @($cls, (& $enc $f.Severity), (& $enc $f.Category), (& $enc $f.Object), (& $enc $f.Finding), (& $enc $f.Recommendation))
        $tpl = '<tr><td><span class="pill {0}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>'
        $tpl -f $cells
    }
    $css = @'
body{font-family:Segoe UI,system-ui,sans-serif;margin:32px;color:#14202b;background:#f6f8fa}
h1{margin:0 0 4px}p.sub{color:#5a6b7b;margin:0 0 24px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{background:#fff;border:1px solid #d8e0e8;border-radius:10px;padding:14px 18px;min-width:140px}
.card b{display:block;font-size:28px}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #d8e0e8}
th,td{padding:9px 12px;border-bottom:1px solid #e6ecf1;text-align:left;font-size:14px;vertical-align:top}
th{background:#eef2f6}
.pill{display:inline-block;min-width:64px;text-align:center;border-radius:999px;padding:2px 10px;font-weight:600;color:#fff}
.high{background:#c0392b}.medium{background:#b8740a}.low{background:#4a6a8a}
.note{color:#5a6b7b;font-size:13px;margin-top:16px}
'@
    $demoNote = if ($IsDemo) { ' from fictional demo data' } else { '' }
    $html = @(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AD hygiene report</title><style>' + $css + '</style></head><body>'
        '<h1>AD hygiene report</h1>'
        ('<p class="sub">Generated {0}{1}. {2} findings.</p>' -f $Now.ToString('yyyy-MM-dd HH:mm'), $demoNote, $sorted.Count)
        ('<div class="cards"><div class="card"><b>{0}</b>High</div><div class="card"><b>{1}</b>Medium</div><div class="card"><b>{2}</b>Low</div></div>' -f $hi, $me, $lo)
        '<table><thead><tr><th>Severity</th><th>Area</th><th>Object</th><th>Finding</th><th>Suggested action</th></tr></thead><tbody>'
        ($rows -join [Environment]::NewLine)
        '</tbody></table>'
        '<p class="note">Read-only audit. Last logon dates come from lastLogonTimestamp, which can lag by up to 14 days. Review each finding before changing anything.</p>'
        '</body></html>'
    ) -join [Environment]::NewLine
    Set-Content -Path $htmPath -Value $html -Encoding UTF8
    [pscustomobject]@{ Csv = $csvPath; Html = $htmPath; High = $hi; Medium = $me; Low = $lo }
}

function Invoke-ADHygieneAudit {
    $now = Get-Date
    if ($Demo) {
        $data = Get-AdhDemoData -Now $now
        $entra = $data.Entra
    }
    else {
        if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
            throw 'The ActiveDirectory module is not available. Install RSAT: Active Directory tools, or use -Demo.'
        }
        $data = Get-AdhDirectoryData
        $entra = $null
        if ($IncludeEntra) { $entra = @(Get-AdhEntraData) }
    }
    $findings = @()
    $findings += @(Test-AdhUser -Users $data.Users -Now $now -StaleDays $StaleDays -PasswordMaxAgeDays $PasswordMaxAgeDays)
    $findings += @(Test-AdhGroup -Groups $data.Groups)
    $findings += @(Test-AdhComputer -Computers $data.Computers -Now $now -StaleDays $ComputerStaleDays)
    if ($entra) { $findings += @(Test-AdhEntraGuest -EntraUsers $entra -Now $now -GuestPendingDays $GuestPendingDays) }

    $result = Export-AdhReport -Findings $findings -OutputPath $OutputPath -Now $now -IsDemo ([bool]$Demo)
    Write-Host ("Findings: {0} high, {1} medium, {2} low" -f $result.High, $result.Medium, $result.Low)
    Write-Host ("CSV : {0}" -f $result.Csv)
    Write-Host ("HTML: {0}" -f $result.Html)
}

# Run only when executed, not when dot-sourced by the tests.
if ($MyInvocation.InvocationName -ne '.') { Invoke-ADHygieneAudit }

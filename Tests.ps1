<#
.SYNOPSIS
    Self-test for Invoke-ADHygieneAudit.ps1. Uses fictional data and mocked AD cmdlets.
    Needs no domain and no extra modules. Run: .\Tests.ps1
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Invoke-ADHygieneAudit.ps1')

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) }
    else { $script:fail++; Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red }
}
function Find-Item {
    param($Findings, $Object, $Text)
    # The leading comma keeps the result an array even when there is exactly one match.
    , @($Findings | Where-Object { $_.Object -eq $Object -and $_.Finding -like $Text })
}

$now = [datetime]'2026-11-09 12:00'
$data = Get-AdhDemoData -Now $now

Write-Host 'Users'
$u = @(Test-AdhUser -Users $data.Users -Now $now -StaleDays 90 -PasswordMaxAgeDays 365)
Assert-True ((Find-Item $u 'j.martin' 'No logon*').Count -eq 1 -and (Find-Item $u 'j.martin' 'No logon*')[0].Severity -eq 'Medium') 'stale ordinary user is Medium'
Assert-True ((Find-Item $u 'j.martin' 'Password is*').Count -eq 1) 'old password is flagged'
Assert-True ((Find-Item $u 'svc-backup' 'Password never expires')[0].Severity -eq 'High') 'privileged never-expires is High'
Assert-True ((Find-Item $u 'adm-lopez' 'No logon*')[0].Severity -eq 'High') 'stale privileged user is High'
Assert-True ((Find-Item $u 'old-contractor' 'Disabled*')[0].Severity -eq 'High') 'disabled privileged user is High'
Assert-True ((Find-Item $u 'new.hire' 'Enabled account has never logged on').Count -eq 1) 'never-logged-on account older than 30 days is flagged'
Assert-True (@($u | Where-Object { $_.Object -eq 'a.khan' }).Count -eq 0) 'healthy user has no findings'

Write-Host 'Groups'
$g = @(Test-AdhGroup -Groups $data.Groups)
Assert-True ((Find-Item $g 'Domain Admins' 'Privileged group has*')[0].Severity -eq 'Medium') 'oversized privileged group is Medium'
Assert-True ((Find-Item $g 'Project-Falcon' 'Group has no members').Count -eq 1) 'empty group is flagged'
Assert-True (@($g | Where-Object { $_.Object -eq 'Finance-Share' }).Count -eq 0) 'normal group has no findings'

Write-Host 'Computers'
$c = @(Test-AdhComputer -Computers $data.Computers -Now $now -StaleDays 90)
Assert-True ((Find-Item $c 'SRV-OLDAPP' 'Operating system out of support*').Count -eq 1) 'Server 2012 R2 is flagged as out of support'
Assert-True ((Find-Item $c 'WS-RETIRED7' 'No logon*').Count -eq 1) 'stale computer is flagged'
Assert-True (@($c | Where-Object { $_.Object -eq 'SRV-WEB01' }).Count -eq 0) 'current computer has no findings'

Write-Host 'Entra guests (free-tier data only)'
$e = @(Test-AdhEntraGuest -EntraUsers $data.Entra -Now $now -GuestPendingDays 30)
Assert-True ($e.Count -eq 1 -and $e[0].Object -like 'auditor_firm*') 'only the long-pending guest invitation is flagged'

Write-Host 'Collection with mocked AD cmdlets'
function Get-ADGroup {
    [CmdletBinding()] param($Filter, $Properties)
    $all = @(
        [pscustomobject]@{ Name = 'Domain Admins'; Members = @('CN=a,DC=x', 'CN=b,DC=x') }
        [pscustomobject]@{ Name = 'Empty-Group'; Members = @() }
    )
    if ($Filter -is [string] -and $Filter -match "Name -eq '(.+)'") {
        $all | Where-Object { $_.Name -eq $Matches[1] }
    }
    else { $all }
}
function Get-ADGroupMember {
    [CmdletBinding()] param($Identity, [switch]$Recursive)
    [pscustomobject]@{ SamAccountName = 'adm-lopez'; objectClass = 'user' }
    [pscustomobject]@{ SamAccountName = 'SRV-TEST$'; objectClass = 'computer' }
}
function Get-ADUser {
    [CmdletBinding()] param($Filter, $Properties)
    [pscustomobject]@{ SamAccountName = 'adm-lopez'; Enabled = $true; LastLogonDate = $now.AddDays(-5); PasswordLastSet = $now.AddDays(-10); PasswordNeverExpires = $false; WhenCreated = $now.AddDays(-300) }
    [pscustomobject]@{ SamAccountName = 'a.khan'; Enabled = $true; LastLogonDate = $now.AddDays(-1); PasswordLastSet = $now.AddDays(-10); PasswordNeverExpires = $false; WhenCreated = $now.AddDays(-300) }
}
function Get-ADComputer {
    [CmdletBinding()] param($Filter, $Properties)
    [pscustomobject]@{ Name = 'SRV01'; Enabled = $true; LastLogonDate = $now; OperatingSystem = 'Windows Server 2022 Standard' }
}
$col = Get-AdhDirectoryData
Assert-True (@($col.Users).Count -eq 2) 'collection returns both users'
Assert-True (($col.Users | Where-Object { $_.SamAccountName -eq 'adm-lopez' }).IsPrivileged -eq $true) 'privileged membership is resolved (users only)'
Assert-True (($col.Users | Where-Object { $_.SamAccountName -eq 'a.khan' }).IsPrivileged -eq $false) 'ordinary user is not privileged'
Assert-True ((($col.Groups | Where-Object { $_.Name -eq 'Domain Admins' }).MemberCount) -eq 2) 'group member count is read'

Write-Host 'Report'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('adh-test-' + [guid]::NewGuid().ToString('N'))
$all = @($u) + @($g) + @($c) + @($e)
$r = Export-AdhReport -Findings $all -OutputPath $tmp -Now $now -IsDemo $true
Assert-True ((Test-Path $r.Csv) -and (Test-Path $r.Html)) 'CSV and HTML are written'
Assert-True ((Get-Content $r.Html -Raw) -match 'fictional demo data') 'demo report is labelled as fictional'
Assert-True ($r.High -gt 0 -and $r.Medium -gt 0 -and $r.Low -gt 0) 'all three severities are counted'
Remove-Item $tmp -Recurse -Force

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }

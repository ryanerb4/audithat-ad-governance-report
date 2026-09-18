#Requires -Version 5.1
<#
.SYNOPSIS
    AuditHat - Active Directory and Group Policy audit report.
    https://audithat.com

    Produces a detailed HTML review of every GPO in the domain, plus a separate
    print-ready committee review with control mapping and change tracking.

.DESCRIPTION
    Read-only. Run on a domain controller, or any domain-joined machine with RSAT.

    Output lands in <OutputPath>\AD-Report-<domain>-YYYYMMDD\ :
      AD-Report-<domain>-YYYYMMDD.html            <- detailed review (left-nav app)
      AD-Committee-Review-<domain>-YYYYMMDD.html  <- committee packet document
      PerGPO\<gpo name>.html                      <- native GPMC report per GPO
      GPO-Settings.csv / GPO-Scope.csv            <- every setting, every link
      Cleanup-*.csv                               <- disabled / stale accounts
      LogonRestrictions.csv                       <- per-user logon limits
      ad-snapshot.json                            <- state, for the next run's comparison

    The detailed report has a left navigation with separate views:
      Focus areas       - which GPOs configure each area auditors ask about
      Privileged groups - Administrators / Domain / Enterprise / Schema Admins
      Logon restrictions- per-user logon hours (7x24 grid), workstations, expiry
      All GPOs          - the full nested inventory with search
      Scope index       - every link in the domain, by container
      Unlinked GPOs     - GPOs that are not applying anywhere
      Cleanup           - disabled users, stale users, stale computers

    The committee review is a separate, print-ready document: cover sheet,
    executive summary, change since the last review, control mapping and
    sign-off block.

    The focus areas cover what auditors ask for by name:
        A. Password policy (users and administrators, incl. fine-grained PSOs)
        B. Account lockout
        C. Audit policy (basic, advanced and event log)
        D. Inactivity / screen lock / idle session limits
        E. USB and removable-storage restrictions
        F. Logon banner (legal notice text and title)

    Active Directory is read through the ActiveDirectory module when ADWS is
    reachable, and falls back to LDAP (TCP 389) when it is not.

.PARAMETER Domain
    FQDN of the domain to inventory. Defaults to the current computer's domain.

.PARAMETER Server
    Specific DC to read from. Defaults to whatever the GroupPolicy module picks (PDCe).

.PARAMETER OutputPath
    Root folder for the report. Defaults to C:\GPOReports. A timestamped subfolder is created.

.PARAMETER Name
    Optional wildcard filter(s) on GPO display name, e.g. -Name 'Server*','*Baseline*'

.PARAMETER SkipPerGpoHtml
    Skip generating the individual GPMC HTML reports (much faster on big domains).

.PARAMETER SkipPrivilegedGroups
    Skip the privileged-group membership section (Administrators, Domain Admins,
    Enterprise Admins, Schema Admins). That section needs the ActiveDirectory module.

.PARAMETER UtcOffsetHours
    UTC offset used to draw the logon-hour grids. logonHours is stored in UTC;
    the grids are drawn in local time. Default: this machine's current offset.

.PARAMETER SkipCommitteeReport
    Skip the separate committee review HTML (AD-Committee-Review-<domain>-YYYYMMDD.html).

.PARAMETER SkipCleanup
    Skip the AD cleanup views (disabled users, stale users, stale computers).

.PARAMETER StaleUserDays
    A user with no logon in this many days is listed as stale. Default 30.

.PARAMETER StaleComputerDays
    A computer with no check-in in this many days is listed as stale. Default 60.

.PARAMETER NoCsv
    Skip the flat CSV exports.

.PARAMETER ShowWhenDone
    Open index.html in the default browser when finished.

.EXAMPLE
    .\Export-ADAuditReport.ps1

.EXAMPLE
    .\Export-ADAuditReport.ps1 -OutputPath D:\Audit -Name '*Baseline*' -ShowWhenDone

.NOTES
    Read-only. Requires GPO Read permission on every GPO you want reported
    (Domain Admins / GPO readers). Run in an elevated-ish context that can read SYSVOL.
#>
[CmdletBinding()]
param(
    [string]   $Domain,
    [string]   $Server,
    [string]   $OutputPath = (Join-Path $env:SystemDrive 'GPOReports'),
    [string[]] $Name,
    [switch]   $SkipPerGpoHtml,
    [switch]   $SkipPrivilegedGroups,
    [switch]   $SkipCleanup,
    [switch]   $SkipCommitteeReport,
    [int]      $UtcOffsetHours = 9999,
    [int]      $StaleUserDays = 30,
    [int]      $StaleComputerDays = 60,
    [switch]   $NoCsv,
    [switch]   $ShowWhenDone
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:ScriptVersion = '3.3.0'
$script:ScriptName    = 'Export-ADAuditReport.ps1'
$script:Brand         = 'AuditHat'
$script:BrandUrl      = 'https://audithat.com'
$script:BrandTag      = 'Baseline and drift reporting for financial institutions'

# ------------------------------------------------------------------ helpers --

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function HtmlEnc { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function Get-Elem {
    param($Node)
    if ($null -eq $Node) { return @() }
    return @($Node.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
}

function Get-ChildText {
    param($Node, [string]$LocalName)
    $c = Get-Elem $Node | Where-Object { $_.LocalName -eq $LocalName } | Select-Object -First 1
    if ($c) { return ([string]$c.InnerText).Trim() }
    return $null
}

function Get-ChildNode {
    param($Node, [string]$LocalName)
    Get-Elem $Node | Where-Object { $_.LocalName -eq $LocalName } | Select-Object -First 1
}

$script:SkipAttrs = @('clsid', 'uid', 'image', 'changed', 'bypassErrors', 'userContext', 'removePolicy', 'desc', 'status')

function Format-Attrs {
    param($Node, [string[]]$Exclude = @())
    $parts = @()
    if ($null -eq $Node -or $null -eq $Node.Attributes) { return , $parts }
    foreach ($a in $Node.Attributes) {
        if ($a.NamespaceURI -like '*XMLSchema-instance*') { continue }
        if ($a.Prefix -eq 'xmlns' -or $a.LocalName -eq 'xmlns') { continue }
        if ($script:SkipAttrs -contains $a.LocalName) { continue }
        if ($Exclude -contains $a.LocalName) { continue }
        if ([string]::IsNullOrWhiteSpace($a.Value)) { continue }
        $parts += ('{0}={1}' -f $a.LocalName, $a.Value)
    }
    return , $parts
}

function New-Setting {
    param([string]$Side, [string]$Container, [string]$Name, [string]$Value)
    [pscustomobject]@{
        Side      = $Side
        Container = $Container
        Name      = $Name
        Value     = $Value
    }
}

function Format-Hours {
    param([double]$Minutes)
    $h = [math]::Round($Minutes / 60, 2)
    if ($h -eq [math]::Floor($h)) { return ('{0} hour{1}' -f [long]$h, $(if ([long]$h -eq 1) { '' } else { 's' })) }
    return ('{0} hours' -f $h)
}

function Format-TimeSpanAsHours {
    param($Value)
    if ($null -eq $Value) { return '' }
    try {
        $t = [timespan]$Value
        return ('{0} ({1})' -f (Format-Hours $t.TotalMinutes), $t.ToString())
    }
    catch { return "$Value" }
}

function Format-TimeSpanAsDays {
    param($Value)
    if ($null -eq $Value) { return '' }
    try {
        $t = [timespan]$Value
        if ($t.TotalDays -ge 1) { return ('{0} days' -f [math]::Round($t.TotalDays, 2)) }
        return (Format-Hours $t.TotalMinutes)
    }
    catch { return "$Value" }
}

function Format-AccountPolicyValue {
    <#
      Account Policy values arrive as bare numbers. GptTmpl.inf stores lockout
      timers in MINUTES and password ages in DAYS - render them with units so a
      reader does not have to know that.

      -1 means "never / forever" and is reported by the GPO XML in its unsigned
      form, 4294967295. Never cast these to Int32.
    #>
    param([string]$SettingName, $Value)

    $raw = "$Value"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $raw }

    $n = 0.0
    if (-not [double]::TryParse($raw, [ref]$n)) { return $raw }

    # -1, or its unsigned spelling, is the "never / forever" sentinel
    $never = ($n -lt 0) -or ($n -ge 4294967295)

    try {
        switch -Regex ($SettingName) {

            '^LockoutDuration$' {
                if ($never -or $n -le 0) { return 'Until an administrator unlocks the account' }
                return ('{0}  ({1} minutes)' -f (Format-Hours $n), [long]$n)
            }
            '^(ResetLockoutCount|LockoutObservationWindow)$' {
                if ($never) { return 'Never resets automatically' }
                if ($n -le 0) { return '0 minutes' }
                return ('{0}  ({1} minutes)' -f (Format-Hours $n), [long]$n)
            }
            '^LockoutBadCount$' {
                if ($never) { return $raw }
                if ($n -le 0) { return '0 - account lockout is DISABLED' }
                return ('{0} failed attempts' -f [long]$n)
            }
            '^MaximumPasswordAge$' {
                if ($never -or $n -le 0) { return 'Passwords never expire' }
                return ('{0} days' -f [long]$n)
            }
            '^MinimumPasswordAge$' {
                if ($never) { return $raw }
                if ($n -le 0) { return '0 days - users may change their password immediately' }
                return ('{0} day{1}' -f [long]$n, $(if ([long]$n -eq 1) { '' } else { 's' }))
            }
            '^MinimumPasswordLength$' {
                if ($never) { return $raw }
                return ('{0} characters' -f [long]$n)
            }
            '^PasswordHistorySize$' {
                if ($never) { return $raw }
                return ('{0} passwords remembered' -f [long]$n)
            }
            '^(PasswordComplexity|ClearTextPassword|RequireLogonToChangePassword|ForceLogoffWhenHourExpire)$' {
                return $(if ($n -eq 1) { 'Enabled' } else { 'Disabled' })
            }
            '^MaxTicketAge$'  { if ($never) { return $raw }; return ('{0} hours' -f [long]$n) }
            '^MaxRenewAge$'   { if ($never) { return $raw }; return ('{0} days' -f [long]$n) }
            '^MaxServiceAge$' { if ($never) { return $raw }; return ('{0} minutes  ({1})' -f [long]$n, (Format-Hours $n)) }
            '^MaxClockSkew$'  { if ($never) { return $raw }; return ('{0} minutes' -f [long]$n) }
            default           { return $raw }
        }
    }
    catch { return $raw }
}

function Convert-AuditValue {
    param($Value)
    switch ("$Value") {
        '0'       { 'No auditing' }
        '1'       { 'Success' }
        '2'       { 'Failure' }
        '3'       { 'Success, Failure' }
        default   { "$Value" }
    }
}

# ---------------------------------------------------------- control map ----
# Default control references used by the committee review. EDIT THESE to match
# your institution's own control set / house citations.
#   FFIEC = IT Examination Handbook, Information Security booklet (current)
#   CSF   = NIST Cybersecurity Framework 2.0 category, as a cross-reference for
#           institutions aligned to the CRI Profile or to CSF directly
$script:ControlMap = @{
    'pwd'        = 'FFIEC IS II.C.7 User Security Controls; II.C.15 Logical Security | NIST CSF 2.0 PR.AA'
    'lockout'    = 'FFIEC IS II.C.7 User Security Controls | NIST CSF 2.0 PR.AA'
    'audit'      = 'FFIEC IS II.C Risk Mitigation (logging and monitoring); Audit booklet | NIST CSF 2.0 DE.CM, PR.PS'
    'inactivity' = 'FFIEC IS II.C.7 User Security Controls; II.C.15 Logical Security | NIST CSF 2.0 PR.AA'
    'usb'        = 'FFIEC IS II.C.13 Control of Information | NIST CSF 2.0 PR.DS, PR.PS'
    'banner'     = 'FFIEC IS II.C.15 Logical Security | NIST CSF 2.0 PR.AT, GV.PO'
    'privileged' = 'FFIEC IS II.C.7 User Security Controls (least privilege, access rights administration) | NIST CSF 2.0 PR.AA'
    'stale'      = 'FFIEC IS II.C.7 User Security Controls (provisioning and deprovisioning) | NIST CSF 2.0 PR.AA, ID.AM'
    'logon'      = 'FFIEC IS II.C.7 User Security Controls; II.C.15 Logical Security | NIST CSF 2.0 PR.AA'
    'gpo'        = 'FFIEC IS II.C.2 Technology Design; Architecture, Infrastructure and Operations booklet | NIST CSF 2.0 PR.PS'
}

# Recommended logon banner, offered when the domain has none configured.
# Deliberately generic so it can be used as a standard configuration anywhere.
$script:BannerTitle = 'AUTHORIZED USE NOTICE'
$script:BannerText = @'
This computer system is provided for authorized business use only.

By continuing, you acknowledge and agree to comply with the organization's Information Security, Acceptable Use, and Computer Use Policies.

Use of this system may be monitored, recorded, and reviewed by authorized personnel. Users should have no expectation of privacy when using organization-owned systems, networks, email, internet access, or other technology resources.

Unauthorized access or misuse of this system is prohibited and may result in disciplinary, civil, or criminal action.

By continuing to log on, you acknowledge and consent to these conditions.
'@

# Extension display name -> root container path shown in the report.
$script:ExtRootMap = @{
    'Security'                       = 'Policies\Windows Settings\Security Settings'
    'Audit Policy Configuration'     = 'Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration'
    'Public Key'                     = 'Policies\Windows Settings\Security Settings\Public Key Policies'
    'Windows Firewall'               = 'Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security'
    'Wireless Group Policy'          = 'Policies\Windows Settings\Security Settings\Wireless Network (802.11) Policies'
    '802.3 Group Policy'             = 'Policies\Windows Settings\Security Settings\Wired Network (802.3) Policies'
    'Software Restriction'           = 'Policies\Windows Settings\Security Settings\Software Restriction Policies'
    'Application Control'            = 'Policies\Windows Settings\Security Settings\Application Control Policies (AppLocker)'
    'IP Security'                    = 'Policies\Windows Settings\Security Settings\IP Security Policies'
    'Scripts'                        = 'Policies\Windows Settings\Scripts'
    'Folder Redirection'             = 'Policies\Windows Settings\Folder Redirection'
    'Deployed Printer Connections'   = 'Policies\Windows Settings\Deployed Printers'
    'Software Installation'          = 'Policies\Software Settings\Software installation'
    'Internet Explorer Maintenance'  = 'Policies\Windows Settings\Internet Explorer Maintenance'
    'Central Access Policy'          = 'Policies\Windows Settings\Security Settings\File System\Central Access Policy'
    'Registry'                       = 'Preferences\Windows Settings\Registry'
    'Files'                          = 'Preferences\Windows Settings\Files'
    'Folders'                        = 'Preferences\Windows Settings\Folders'
    'Ini Files'                      = 'Preferences\Windows Settings\Ini Files'
    'Shortcuts'                      = 'Preferences\Windows Settings\Shortcuts'
    'Network Shares'                 = 'Preferences\Windows Settings\Network Shares'
    'Environment'                    = 'Preferences\Windows Settings\Environment'
    'Applications'                   = 'Preferences\Windows Settings\Applications'
    'Drive Maps'                     = 'Preferences\Windows Settings\Drive Maps'
    'Data Sources'                   = 'Preferences\Control Panel Settings\Data Sources'
    'Devices'                        = 'Preferences\Control Panel Settings\Devices'
    'Folder Options'                 = 'Preferences\Control Panel Settings\Folder Options'
    'Internet Settings'              = 'Preferences\Control Panel Settings\Internet Settings'
    'Local Users and Groups'         = 'Preferences\Control Panel Settings\Local Users and Groups'
    'Network Options'                = 'Preferences\Control Panel Settings\Network Options'
    'Power Options'                  = 'Preferences\Control Panel Settings\Power Options'
    'Printers'                       = 'Preferences\Control Panel Settings\Printers'
    'Regional Options'               = 'Preferences\Control Panel Settings\Regional Options'
    'Scheduled Tasks'                = 'Preferences\Control Panel Settings\Scheduled Tasks'
    'Services'                       = 'Preferences\Control Panel Settings\Services'
    'Start Menu'                     = 'Preferences\Control Panel Settings\Start Menu'
}

# ------------------------------------------------------- auditor focus ------
# Each area is matched (case-insensitively) against "<container> | <setting> | <value>"
# of every configured setting found in every GPO.
$script:FocusAreas = @(
    [pscustomobject]@{
        Key = 'pwd'; Letter = 'A'; Title = 'Password policy - users and administrators'
        Hint = 'Domain password policy comes from a GPO linked at the DOMAIN root. Separate rules for admins are normally fine-grained password policies (PSOs), listed underneath.'
        Pattern = 'Account Policies\\Password Policy|Minimum password|Maximum password|Enforce password history|Password must meet complexity|reversible encryption|Do not store LAN Manager hash|Prompt user to change password|MinimumPasswordAge|MaximumPasswordAge|MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|ClearTextPassword'
    }
    [pscustomobject]@{
        Key = 'lockout'; Letter = 'B'; Title = 'Account lockout'
        Hint = 'Threshold, duration and reset counter. Also applied at the domain root.'
        Pattern = 'Account Lockout Policy|Machine account lockout threshold|LockoutBadCount|LockoutDuration|ResetLockoutCount|Account lockout'
    }
    [pscustomobject]@{
        Key = 'audit'; Letter = 'C'; Title = 'Audit policy and event logs'
        Hint = 'Basic audit policy, advanced audit subcategories, and event log size / retention.'
        Pattern = 'Local Policies\\Audit Policy|Advanced Audit Policy Configuration|Event Log|Audit:|Audit Credential|Audit Logon|Audit Account|Audit Policy Configuration|Force audit policy subcategory|unable to log security audits|MaximumLogSize|RetentionDays|AuditLog'
    }
    [pscustomobject]@{
        Key = 'inactivity'; Letter = 'D'; Title = 'Inactivity - screen lock and idle sessions'
        Hint = 'Machine inactivity limit, screen saver lock, and RDP / SMB idle session timeouts.'
        Pattern = 'Machine inactivity limit|InactivityTimeoutSecs|screen ?saver|ScreenSave|idle time required before suspending|time limit for active but idle|time limit for disconnected|Idle session limit|Set time limit for active|Lock Screen|Interactive logon: Machine inactivity'
    }
    [pscustomobject]@{
        Key = 'usb'; Letter = 'E'; Title = 'USB and removable storage restrictions'
        Hint = 'Removable Storage Access policies, device installation restrictions, and the USBSTOR service.'
        Pattern = 'Removable Storage|Removable Disk|USBSTOR|\bUSB\b|Device Installation|WPD Devices|CD and DVD: Deny|Floppy Drives: Deny|Tape Drives: Deny|Allowed to format and eject removable media|Restrict CD-ROM access|Restrict floppy access|Portable Operating System|Custom Classes: Deny'
    }
    [pscustomobject]@{
        Key = 'banner'; Letter = 'F'; Title = 'Logon banner - legal notice'
        Hint = 'Both the message TEXT and the message TITLE must be set, or no banner is displayed.'
        Pattern = 'Message text for users attempting to log on|Message title for users attempting to log on|legalnotice|Logon Banner|Interactive logon: Message'
    }
)

# ---------------------------------------------------- setting extractors ----

function Convert-AdmPolicy {
    param($PolicyNode, [string]$Side, [string]$RootPath)

    $category = Get-ChildText $PolicyNode 'Category'
    $name     = Get-ChildText $PolicyNode 'Name'
    $state    = Get-ChildText $PolicyNode 'State'
    if ($category) { $category = $category -replace '/', '\' }
    $container = if ($category) { "$RootPath\$category" } else { $RootPath }

    $valueTypes = @('EditText', 'DropDownList', 'Numeric', 'ListBox', 'CheckBox', 'Text', 'Boolean', 'MultiTextBox')
    $extras = @()

    foreach ($c in (Get-Elem $PolicyNode)) {
        if ($valueTypes -notcontains $c.LocalName) { continue }

        $subName = Get-ChildText $c 'Name'
        if (-not $subName) { $subName = $c.LocalName }
        $subName = $subName.TrimEnd(':', ' ')

        $valNode = Get-ChildNode $c 'Value'
        if (-not $valNode) { $valNode = Get-ChildNode $c 'State' }
        $v = $null
        if ($valNode) {
            $kids = @(Get-Elem $valNode)
            if ($kids.Count -gt 0) {
                $v = (($kids | ForEach-Object {
                    $gk = @(Get-Elem $_)
                    if ($gk.Count -gt 0) { (($gk | ForEach-Object { ([string]$_.InnerText).Trim() }) -join ' = ') }
                    else { ([string]$_.InnerText).Trim() }
                }) -join '; ')
            }
            else { $v = ([string]$valNode.InnerText).Trim() }
        }
        if ($null -eq $v -or $v -eq '') { $v = ([string]$c.InnerText).Trim() }
        $extras += ('{0}: {1}' -f $subName, $v)
    }

    $value = $state
    if ($extras.Count -gt 0) { $value = ($state + '  |  ' + ($extras -join '  |  ')) }
    return (New-Setting $Side $container $name $value)
}

function Convert-SecurityNode {
    param($Node, [string]$Side, [string]$RootPath, [System.Collections.ArrayList]$Out)

    $ln = $Node.LocalName
    $sub = $null
    $name = $null
    $value = $null

    switch ($ln) {

        'Account' {
            $mode = ''
            try { $mode = [string]$Node.GetAttribute('mode') } catch { $mode = '' }
            $sub = switch ($mode) {
                'Password' { 'Account Policies\Password Policy' }
                'Lockout'  { 'Account Policies\Account Lockout Policy' }
                'Kerberos' { 'Account Policies\Kerberos Policy' }
                default    { 'Account Policies' }
            }
            $name  = Get-ChildText $Node 'Name'
            $value = Get-ChildText $Node 'SettingNumber'
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingBoolean' }
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingString' }
            $value = Format-AccountPolicyValue -SettingName $name -Value $value
        }

        'EventAudit' {
            $sub   = 'Local Policies\Audit Policy'
            $name  = Get-ChildText $Node 'Name'
            $value = Convert-AuditValue (Get-ChildText $Node 'SettingValue')
        }

        'AuditSetting' {
            $target = Get-ChildText $Node 'PolicyTarget'
            $sub    = if ($target) { $target } else { 'System' }
            $name   = Get-ChildText $Node 'SubcategoryName'
            $value  = Convert-AuditValue (Get-ChildText $Node 'SettingValue')
        }

        'UserRightsAssignment' {
            $sub  = 'Local Policies\User Rights Assignment'
            $name = Get-ChildText $Node 'Name'
            $members = @(Get-Elem $Node | Where-Object { $_.LocalName -eq 'Member' } | ForEach-Object {
                $mn = Get-ChildText $_ 'Name'
                if (-not $mn) { $mn = ([string]$_.InnerText).Trim() }
                $mn
            })
            $value = if ($members.Count) { $members -join '; ' } else { '(no members defined)' }
        }

        'SecurityOptions' {
            $sub = 'Local Policies\Security Options'
            $disp = Get-ChildNode $Node 'Display'
            if ($disp) {
                $name = Get-ChildText $disp 'Name'
                $value = Get-ChildText $disp 'DisplayString'
                if ($null -eq $value) { $value = Get-ChildText $disp 'DisplayBoolean' }
                if ($null -eq $value) { $value = Get-ChildText $disp 'DisplayNumber' }
                if ($null -eq $value) {
                    $ds = Get-ChildNode $disp 'DisplayStrings'
                    if ($ds) { $value = ((Get-Elem $ds | ForEach-Object { ([string]$_.InnerText).Trim() }) -join '; ') }
                }
                if ($null -eq $value) {
                    $dl = Get-ChildNode $disp 'DisplayFields'
                    if ($dl) {
                        $value = ((Get-Elem $dl | ForEach-Object {
                            (('{0}: {1}' -f (Get-ChildText $_ 'Name'), (Get-ChildText $_ 'Value')))
                        }) -join '; ')
                    }
                }
            }
            if (-not $name) { $name = Get-ChildText $Node 'KeyName' }
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingString' }
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingNumber' }
            if ($null -eq $value) {
                $sn = Get-ChildNode $Node 'SettingStrings'
                if ($sn) { $value = ((Get-Elem $sn | ForEach-Object { ([string]$_.InnerText).Trim() }) -join '; ') }
            }
        }

        'RestrictedGroups' {
            $sub = 'Restricted Groups'
            $gn  = Get-ChildNode $Node 'GroupName'
            $name = if ($gn) { Get-ChildText $gn 'Name' } else { $null }
            $mem = @(Get-Elem $Node | Where-Object { $_.LocalName -eq 'Member' } | ForEach-Object { Get-ChildText $_ 'Name' })
            $memOf = @(Get-Elem $Node | Where-Object { $_.LocalName -eq 'Memberof' } | ForEach-Object { Get-ChildText $_ 'Name' })
            $bits = @()
            if ($mem.Count)   { $bits += ('Members: '   + ($mem   -join '; ')) }
            if ($memOf.Count) { $bits += ('Member of: ' + ($memOf -join '; ')) }
            $value = if ($bits.Count) { $bits -join '  |  ' } else { 'Members: (none)' }
        }

        'SystemServices' {
            $sub   = 'System Services'
            $name  = Get-ChildText $Node 'Name'
            $value = 'Startup mode: ' + (Get-ChildText $Node 'StartupMode')
        }

        'RegistrySetting' {
            $sub  = 'Registry'
            $name = Get-ChildText $Node 'KeyName'
            $vals = @(Get-Elem $Node | Where-Object { $_.LocalName -eq 'SettingString' -or $_.LocalName -eq 'SettingNumber' } |
                        ForEach-Object { ([string]$_.InnerText).Trim() })
            $value = if ($vals.Count) { $vals -join '; ' } else { '(permissions only)' }
        }

        'RegistryValue' {
            $sub  = 'Registry'
            $name = Get-ChildText $Node 'KeyName'
            $value = Get-ChildText $Node 'SettingString'
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingNumber' }
        }

        'File' {
            $sub  = 'File System'
            $name = Get-ChildText $Node 'Path'
            $value = 'Mode: ' + (Get-ChildText $Node 'PropagationMode')
        }

        { $_ -eq 'EventLog' -or $_ -eq 'LogSettings' } {
            $sub  = 'Event Log'
            $name = (Get-ChildText $Node 'Log') + ' - ' + (Get-ChildText $Node 'Name')
            $value = Get-ChildText $Node 'SettingNumber'
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingBoolean' }
            if ($null -eq $value) { $value = Get-ChildText $Node 'SettingString' }
        }

        default { return $false }
    }

    if (-not $name) { $name = $ln }
    if ($null -eq $value) { $value = '' }
    [void]$Out.Add((New-Setting $Side "$RootPath\$sub" $name $value))
    return $true
}

function Convert-GenericNode {
    param($Node, [string]$Side, [string]$Path, [int]$Depth, [System.Collections.ArrayList]$Out)

    if ($Depth -gt 12) { return }

    $children = @(Get-Elem $Node)
    $complex  = @($children | Where-Object { @(Get-Elem $_).Count -gt 0 })
    $simple   = @($children | Where-Object { @(Get-Elem $_).Count -eq 0 })
    $attrs    = Format-Attrs $Node

    $label = ''
    try { $label = [string]$Node.GetAttribute('name') } catch { $label = '' }
    if (-not $label) { $label = Get-ChildText $Node 'Name' }
    if (-not $label) {
        foreach ($alt in @('Command', 'Path', 'KeyName', 'DisplayName', 'SubcategoryName', 'Log', 'Location', 'Id')) {
            $v = Get-ChildText $Node $alt
            if ($v) { $label = $v; break }
        }
    }
    if (-not $label) { $label = $Node.LocalName }

    if ($simple.Count -gt 0 -or $attrs.Count -gt 0) {

        $parts = @()
        $parts += @($attrs | Where-Object { $_ -notlike 'name=*' })

        foreach ($s in $simple) {
            if ($s.LocalName -eq 'Name') { continue }
            $sa  = Format-Attrs $s
            $txt = ([string]$s.InnerText).Trim()
            $seg = $s.LocalName
            if ($sa.Count -gt 0) { $seg += ' (' + ($sa -join ', ') + ')' }
            if ($txt)            { $seg += ': ' + $txt }
            $parts += $seg
        }

        $parts = @($parts | Where-Object { $_ -and $_.Trim() })

        if ($parts.Count -eq 0 -and $complex.Count -gt 0) {
            # pure grouping node - do not emit a row, just descend
        }
        else {
            [void]$Out.Add((New-Setting $Side $Path $label (($parts -join '  |  '))))
        }

        foreach ($c in $complex) { Convert-GenericNode $c $Side "$Path\$label" ($Depth + 1) $Out }
    }
    else {
        foreach ($c in $children) { Convert-GenericNode $c $Side $Path ($Depth + 1) $Out }
    }
}

function Get-GpoSettings {
    param($Xml, [string]$Side)

    $out = New-Object System.Collections.ArrayList
    $root = Get-Elem $Xml.DocumentElement | Where-Object { $_.LocalName -eq $Side } | Select-Object -First 1
    if (-not $root) { return @() }

    foreach ($ed in (Get-Elem $root | Where-Object { $_.LocalName -eq 'ExtensionData' })) {

        $extName = Get-ChildText $ed 'Name'
        if (-not $extName) { $extName = 'Unknown extension' }

        $ext = Get-ChildNode $ed 'Extension'
        if (-not $ext) { continue }

        $children = @(Get-Elem $ext)
        if ($children.Count -eq 0) { continue }

        $isAdm = @($children | Where-Object { $_.LocalName -eq 'Policy' -and (Get-ChildText $_ 'Category') }).Count -gt 0

        if ($isAdm) { $rootPath = 'Policies\Administrative Templates' }
        elseif ($script:ExtRootMap.ContainsKey($extName)) { $rootPath = $script:ExtRootMap[$extName] }
        else { $rootPath = $extName }

        $isSecurity = ($extName -eq 'Security' -or $extName -eq 'Audit Policy Configuration')

        foreach ($c in $children) {

            if ($isAdm -and $c.LocalName -eq 'Policy') {
                [void]$out.Add((Convert-AdmPolicy $c $Side $rootPath))
                continue
            }

            if ($isSecurity) {
                $handled = Convert-SecurityNode $c $Side $rootPath $out
                if ($handled) { continue }
                Convert-GenericNode $c $Side ("$rootPath\" + $c.LocalName) 0 $out
                continue
            }

            Convert-GenericNode $c $Side $rootPath 0 $out
        }
    }

    return $out.ToArray()
}

# --------------------------------------------------------- scope extractor --

function Get-GpoScope {
    param($Gpo, $Xml, [hashtable]$GpParams)

    $links = @()
    foreach ($l in (Get-Elem $Xml.DocumentElement | Where-Object { $_.LocalName -eq 'LinksTo' })) {
        $links += [pscustomobject]@{
            SOMName  = (Get-ChildText $l 'SOMName')
            SOMPath  = (Get-ChildText $l 'SOMPath')
            Enabled  = (Get-ChildText $l 'Enabled')
            Enforced = (Get-ChildText $l 'NoOverride')
        }
    }

    $applyTo   = @()
    $denyApply = @()
    $editors   = @()
    try {
        $perms = Get-GPPermission -Guid $Gpo.Id -All @GpParams
        foreach ($p in $perms) {
            $trustee = $p.Trustee.Name
            if (-not $trustee) { $trustee = $p.Trustee.Sid.Value }
            switch -Wildcard ("$($p.Permission)") {
                'GpoApply' {
                    if ($p.Denied) { $denyApply += $trustee } else { $applyTo += $trustee }
                }
                'GpoEdit*' { if (-not $p.Denied) { $editors += $trustee } }
            }
        }
    }
    catch {
        $applyTo = @('(could not read permissions: ' + $_.Exception.Message + ')')
    }

    $wmi = $null
    try { if ($Gpo.WmiFilter) { $wmi = $Gpo.WmiFilter.Name } } catch { $wmi = $null }

    [pscustomobject]@{
        Links        = $links
        ApplyTo      = $applyTo
        DenyApply    = $denyApply
        Editors      = ($editors | Select-Object -Unique)
        WmiFilter    = $wmi
        Status       = "$($Gpo.GpoStatus)"
        Owner        = "$($Gpo.Owner)"
        Created      = $Gpo.CreationTime
        Modified     = $Gpo.ModificationTime
        CompVersion  = ('AD {0} / SYSVOL {1}' -f $Gpo.Computer.DSVersion, $Gpo.Computer.SysvolVersion)
        UserVersion  = ('AD {0} / SYSVOL {1}' -f $Gpo.User.DSVersion,     $Gpo.User.SysvolVersion)
    }
}

# =============================================================== AD ACCESS ==
# Two ways in:
#   Module - the ActiveDirectory cmdlets, which require ADWS (TCP 9389)
#   LDAP   - System.DirectoryServices against TCP 389, which is what the
#            GroupPolicy module already uses, so it works whenever GPOs do
# $script:AdMode is set during the prerequisite check and everything below
# dispatches on it, so the rest of the script never cares which one is live.

function Get-LdapEscapedDn {
    param([string]$Dn)
    return ($Dn -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a')
}

function Get-LdapSidFilter {
    <#
      Builds the escaped-binary objectSid filter by hand rather than via
      System.Security.Principal.SecurityIdentifier, which is Windows-only.
      SID binary layout: revision(1) + subAuthorityCount(1) +
      identifierAuthority(6, big-endian) + subAuthorities(4 each, little-endian).
    #>
    param([string]$Sid)

    $parts = "$Sid".Split('-')
    if ($parts.Count -lt 3 -or $parts[0] -ne 'S') { throw "Not a SID: $Sid" }

    $rev  = [byte]$parts[1]
    $auth = [uint64]$parts[2]
    $subs = @()
    for ($i = 3; $i -lt $parts.Count; $i++) { $subs += [uint32]$parts[$i] }

    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add($rev)
    $bytes.Add([byte]$subs.Count)
    for ($i = 5; $i -ge 0; $i--) { $bytes.Add([byte](($auth -shr (8 * $i)) -band 0xFF)) }
    foreach ($sa in $subs) {
        foreach ($b in [System.BitConverter]::GetBytes([uint32]$sa)) { $bytes.Add($b) }
    }

    return ('(objectSid=' + ((($bytes | ForEach-Object { '\{0:x2}' -f $_ }) -join '')) + ')')
}

function Invoke-LdapSearch {
    <# Returns raw SearchResult objects. Kept as its own function so it can be stubbed. #>
    param([string]$Root, [string]$Filter, [string[]]$Props)

    $entry = New-Object System.DirectoryServices.DirectoryEntry($Root)
    $ds = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $ds.Filter     = $Filter
    $ds.PageSize   = 1000
    $ds.SizeLimit  = 0
    $ds.SearchScope = 'Subtree'
    foreach ($p in $Props) { [void]$ds.PropertiesToLoad.Add($p) }
    try   { return @($ds.FindAll()) }
    finally { $ds.Dispose(); $entry.Dispose() }
}

function Get-LdapVal {
    param($Result, [string]$Name)
    try {
        if ($Result.Properties.Contains($Name) -and @($Result.Properties[$Name]).Count -gt 0) {
            return $Result.Properties[$Name][0]
        }
    }
    catch { }
    return $null
}

function ConvertFrom-AdFileTime {
    <# AD stores these as 100-ns ticks since 1601. 0 and the max value both mean "never". #>
    param($Value)
    if ($null -eq $Value) { return $null }
    $l = 0L
    if (-not [int64]::TryParse("$Value", [ref]$l)) { return $null }
    if ($l -le 0 -or $l -ge 9223372036854775807) { return $null }
    try { return [datetime]::FromFileTime($l) } catch { return $null }
}

function ConvertFrom-AdInterval {
    <# msDS-* durations are stored as NEGATIVE 100-ns intervals. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    $l = 0L
    if (-not [int64]::TryParse("$Value", [ref]$l)) { return $null }
    if ($l -eq 0) { return [timespan]::Zero }
    try { return [timespan]::FromTicks([math]::Abs($l)) } catch { return $null }
}

# ------------------------------------------------------------------ users --

$script:DirUserCache = $null
$script:DirCompCache = $null

function Get-DirUsers {
    <# Every user account, normalised to the shape the rest of the script expects. #>
    param([string]$Server)

    if ($null -ne $script:DirUserCache) { return $script:DirUserCache }

    $out = @()

    if ($script:AdMode -eq 'Module') {
        $adp = @{}
        if ($Server) { $adp['Server'] = $Server }
        $props = @('Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
                   'whenCreated', 'Description', 'logonHours', 'LogonWorkstations', 'AccountExpirationDate')
        $out = @(Get-ADUser -Filter * -Properties $props @adp)
    }
    elseif ($script:AdMode -eq 'LDAP') {
        $props = @('samaccountname', 'name', 'displayname', 'distinguishedname', 'useraccountcontrol',
                   'lastlogontimestamp', 'pwdlastset', 'accountexpires', 'whencreated', 'description',
                   'logonhours', 'userworkstations')
        $filter = '(&(objectCategory=person)(objectClass=user))'
        foreach ($r in (Invoke-LdapSearch -Root $script:LdapRoot -Filter $filter -Props $props)) {

            $uac = 0
            $uacRaw = Get-LdapVal $r 'useraccountcontrol'
            if ($null -ne $uacRaw) { [void][int]::TryParse("$uacRaw", [ref]$uac) }

            $nm = Get-LdapVal $r 'displayname'
            if (-not $nm) { $nm = Get-LdapVal $r 'name' }

            $out += [pscustomobject]@{
                Name                  = [string]$nm
                SamAccountName        = [string](Get-LdapVal $r 'samaccountname')
                DistinguishedName     = [string](Get-LdapVal $r 'distinguishedname')
                Enabled               = (($uac -band 0x2) -eq 0)          # ACCOUNTDISABLE
                PasswordNeverExpires  = (($uac -band 0x10000) -ne 0)      # DONT_EXPIRE_PASSWORD
                LastLogonDate         = (ConvertFrom-AdFileTime (Get-LdapVal $r 'lastlogontimestamp'))
                PasswordLastSet       = (ConvertFrom-AdFileTime (Get-LdapVal $r 'pwdlastset'))
                AccountExpirationDate = (ConvertFrom-AdFileTime (Get-LdapVal $r 'accountexpires'))
                whenCreated           = (Get-LdapVal $r 'whencreated')
                Description           = [string](Get-LdapVal $r 'description')
                logonHours            = (Get-LdapVal $r 'logonhours')
                LogonWorkstations     = [string](Get-LdapVal $r 'userworkstations')
            }
        }
    }

    $script:DirUserCache = @($out)
    return $script:DirUserCache
}

function Get-DirComputers {
    param([string]$Server)

    if ($null -ne $script:DirCompCache) { return $script:DirCompCache }

    $out = @()

    if ($script:AdMode -eq 'Module') {
        $adp = @{}
        if ($Server) { $adp['Server'] = $Server }
        $props = @('Enabled', 'LastLogonDate', 'PasswordLastSet', 'OperatingSystem', 'whenCreated', 'Description')
        $out = @(Get-ADComputer -Filter * -Properties $props @adp)
    }
    elseif ($script:AdMode -eq 'LDAP') {
        $props = @('name', 'distinguishedname', 'useraccountcontrol', 'lastlogontimestamp',
                   'pwdlastset', 'operatingsystem', 'whencreated', 'description')
        foreach ($r in (Invoke-LdapSearch -Root $script:LdapRoot -Filter '(objectCategory=computer)' -Props $props)) {

            $uac = 0
            $uacRaw = Get-LdapVal $r 'useraccountcontrol'
            if ($null -ne $uacRaw) { [void][int]::TryParse("$uacRaw", [ref]$uac) }

            $out += [pscustomobject]@{
                Name              = [string](Get-LdapVal $r 'name')
                DistinguishedName = [string](Get-LdapVal $r 'distinguishedname')
                Enabled           = (($uac -band 0x2) -eq 0)
                OperatingSystem   = [string](Get-LdapVal $r 'operatingsystem')
                LastLogonDate     = (ConvertFrom-AdFileTime (Get-LdapVal $r 'lastlogontimestamp'))
                PasswordLastSet   = (ConvertFrom-AdFileTime (Get-LdapVal $r 'pwdlastset'))
                whenCreated       = (Get-LdapVal $r 'whencreated')
                Description       = [string](Get-LdapVal $r 'description')
            }
        }
    }

    $script:DirCompCache = @($out)
    return $script:DirCompCache
}

# ------------------------------------------------------- privileged groups --

function Get-LdapPrivilegedGroupReport {
    <# Same output shape as Get-PrivilegedGroupReport, built over LDAP. #>

    $targets = @(
        [pscustomobject]@{ Label = 'Administrators (built-in)'; Sid = 'S-1-5-32-544';          Root = $script:LdapRoot;     Scope = $script:LdapDomainName }
        [pscustomobject]@{ Label = 'Domain Admins';             Sid = "$($script:DomainSid)-512"; Root = $script:LdapRoot; Scope = $script:LdapDomainName }
        [pscustomobject]@{ Label = 'Enterprise Admins';         Sid = "$($script:RootSid)-519";   Root = $script:LdapRootRoot; Scope = "$($script:LdapRootName) (forest root)" }
        [pscustomobject]@{ Label = 'Schema Admins';             Sid = "$($script:RootSid)-518";   Root = $script:LdapRootRoot; Scope = "$($script:LdapRootName) (forest root)" }
    )

    $out = @()
    foreach ($t in $targets) {

        $entry = [pscustomobject]@{
            Label = $t.Label; Scope = $t.Scope; Group = $null
            Members = @(); Nested = @(); Error = $null
        }

        try {
            $g = @(Invoke-LdapSearch -Root $t.Root -Filter (Get-LdapSidFilter $t.Sid) -Props @('name', 'distinguishedname')) |
                    Select-Object -First 1
            if (-not $g) { throw "Group with SID $($t.Sid) not found." }

            $entry.Group = [string](Get-LdapVal $g 'name')
            $gDn = [string](Get-LdapVal $g 'distinguishedname')
            $esc = Get-LdapEscapedDn $gDn

            # direct members - a search avoids member-attribute range retrieval entirely
            $direct = @(Invoke-LdapSearch -Root $t.Root -Filter "(memberOf=$esc)" -Props @('samaccountname', 'distinguishedname', 'objectclass', 'name'))
            $directDns = @($direct | ForEach-Object { [string](Get-LdapVal $_ 'distinguishedname') })
            $entry.Nested = @($direct | Where-Object {
                                @($_.Properties['objectclass']) -contains 'group'
                            } | ForEach-Object { [string](Get-LdapVal $_ 'name') })

            # effective users, expanded through nesting (LDAP_MATCHING_RULE_IN_CHAIN)
            $chain = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$esc))"
            $all = @(Invoke-LdapSearch -Root $t.Root -Filter $chain `
                        -Props @('samaccountname', 'name', 'displayname', 'distinguishedname',
                                 'useraccountcontrol', 'lastlogontimestamp', 'pwdlastset'))

            $members = @()
            foreach ($m in $all) {
                $uac = 0
                $uacRaw = Get-LdapVal $m 'useraccountcontrol'
                if ($null -ne $uacRaw) { [void][int]::TryParse("$uacRaw", [ref]$uac) }

                $nm = Get-LdapVal $m 'displayname'
                if (-not $nm) { $nm = Get-LdapVal $m 'name' }

                $members += [pscustomobject]@{
                    Name            = [string]$nm
                    Sam             = [string](Get-LdapVal $m 'samaccountname')
                    Direct          = ($directDns -contains [string](Get-LdapVal $m 'distinguishedname'))
                    Enabled         = (($uac -band 0x2) -eq 0)
                    PwdNeverExpires = (($uac -band 0x10000) -ne 0)
                    PwdLastSet      = (ConvertFrom-AdFileTime (Get-LdapVal $m 'pwdlastset'))
                    LastLogon       = (ConvertFrom-AdFileTime (Get-LdapVal $m 'lastlogontimestamp'))
                }
            }
            $entry.Members = @($members | Sort-Object Name)
        }
        catch { $entry.Error = $_.Exception.Message }

        $out += $entry
    }
    return $out
}

# --------------------------------------------- fine-grained password policy --

function Get-LdapPsos {
    $container = "LDAP://CN=Password Settings Container,CN=System,$($script:DomainDn)"
    $props = @('name', 'msds-passwordsettingsprecedence', 'msds-minimumpasswordlength',
               'msds-passwordcomplexityenabled', 'msds-passwordhistorylength',
               'msds-maximumpasswordage', 'msds-minimumpasswordage', 'msds-lockoutthreshold',
               'msds-lockoutduration', 'msds-lockoutobservationwindow',
               'msds-passwordreversibleencryptionenabled', 'msds-psoappliesto')

    $out = @()
    foreach ($r in (Invoke-LdapSearch -Root $container -Filter '(objectClass=msDS-PasswordSettings)' -Props $props)) {
        $applies = @()
        try {
            if ($r.Properties.Contains('msds-psoappliesto')) {
                $applies = @($r.Properties['msds-psoappliesto'] | ForEach-Object { (("$_" -split ',', 2)[0] -replace '^CN=', '') })
            }
        }
        catch { }

        $out += [pscustomobject]@{
            Name         = [string](Get-LdapVal $r 'name')
            Precedence   = (Get-LdapVal $r 'msds-passwordsettingsprecedence')
            MinLength    = (Get-LdapVal $r 'msds-minimumpasswordlength')
            Complexity   = (Get-LdapVal $r 'msds-passwordcomplexityenabled')
            History      = (Get-LdapVal $r 'msds-passwordhistorylength')
            MaxAge       = (ConvertFrom-AdInterval (Get-LdapVal $r 'msds-maximumpasswordage'))
            MinAge       = (ConvertFrom-AdInterval (Get-LdapVal $r 'msds-minimumpasswordage'))
            LockThresh   = (Get-LdapVal $r 'msds-lockoutthreshold')
            LockDuration = (ConvertFrom-AdInterval (Get-LdapVal $r 'msds-lockoutduration'))
            LockWindow   = (ConvertFrom-AdInterval (Get-LdapVal $r 'msds-lockoutobservationwindow'))
            Reversible   = (Get-LdapVal $r 'msds-passwordreversibleencryptionenabled')
            AppliesTo    = ($applies -join ', ')
        }
    }
    return $out
}

# ------------------------------------------------------------ AD cleanup ----

function Get-Prop {
    param($Obj, [string]$PropName)
    if ($null -eq $Obj) { return $null }
    $pp = $Obj.PSObject.Properties[$PropName]
    if ($pp) { return $pp.Value }
    return $null
}

function Get-CleanupData {
    <#
      Disabled users, users with no logon in $UserDays, computers with no
      check-in in $ComputerDays. Accounts that have NEVER logged on are only
      listed once they are older than the same threshold, so freshly created
      accounts are not flagged.
    #>
    param([string]$Server, [int]$UserDays, [int]$ComputerDays)

    $now     = Get-Date
    $userCut = $now.AddDays(-$UserDays)
    $compCut = $now.AddDays(-$ComputerDays)

    $allUsers = @(Get-DirUsers -Server $Server)
    $allComps = @(Get-DirComputers -Server $Server)

    $disabled  = @()
    $staleU    = @()
    $unknownEn = 0

    foreach ($u in $allUsers) {
        $ll = Get-Prop $u 'LastLogonDate'
        $wc = Get-Prop $u 'whenCreated'

        # tri-state: $true / $false / unknown. Only an explicit $false is disabled.
        $enRaw   = Get-Prop $u 'Enabled'
        $enKnown = ($null -ne $enRaw)
        $en      = if ($enKnown) { [bool]$enRaw } else { $true }
        if (-not $enKnown) { $unknownEn++ }

        $row = [pscustomobject]@{
            Name        = $u.Name
            Sam         = $u.SamAccountName
            OU          = ($u.DistinguishedName -split ',', 2)[1]
            Enabled     = $en
            LastLogon   = $ll
            DaysIdle    = $(if ($ll) { [int]($now - $ll).TotalDays } elseif ($wc) { [int]($now - $wc).TotalDays } else { $null })
            PwdLastSet  = (Get-Prop $u 'PasswordLastSet')
            PwdNever    = [bool](Get-Prop $u 'PasswordNeverExpires')
            Created     = $wc
            Description = (Get-Prop $u 'Description')
        }

        if ($enKnown -and -not $en) { $disabled += $row; continue }

        if ($ll) { if ($ll -lt $userCut) { $staleU += $row } }
        elseif ($wc -and $wc -lt $userCut) { $staleU += $row }
    }

    # Self-check: nothing but explicitly disabled accounts may sit on this list.
    $leaked = @($disabled | Where-Object { $_.Enabled -ne $false })
    if ($leaked.Count -gt 0) {
        Write-Warn ("Disabled-user list validation FAILED: {0} account(s) are not disabled - {1}" -f `
            $leaked.Count, (($leaked | ForEach-Object { $_.Sam }) -join ', '))
    }
    if ($unknownEn -gt 0) {
        Write-Warn ("{0} account(s) did not return an Enabled value and were treated as enabled, not disabled." -f $unknownEn)
    }

    $staleC = @()
    foreach ($c in $allComps) {
        $ll = Get-Prop $c 'LastLogonDate'
        $wc = Get-Prop $c 'whenCreated'
        $stale = $false
        if ($ll) { $stale = ($ll -lt $compCut) }
        elseif ($wc) { $stale = ($wc -lt $compCut) }

        if (-not $stale) { continue }

        $staleC += [pscustomobject]@{
            Name        = $c.Name
            OU          = ($c.DistinguishedName -split ',', 2)[1]
            Enabled     = [bool](Get-Prop $c 'Enabled')
            OS          = (Get-Prop $c 'OperatingSystem')
            LastLogon   = $ll
            DaysIdle    = $(if ($ll) { [int]($now - $ll).TotalDays } elseif ($wc) { [int]($now - $wc).TotalDays } else { $null })
            PwdLastSet  = (Get-Prop $c 'PasswordLastSet')
            Created     = $wc
            Description = (Get-Prop $c 'Description')
        }
    }

    [pscustomobject]@{
        Checked          = $true
        DisabledVerified = ($leaked.Count -eq 0)
        UnknownEnabled   = $unknownEn
        TotalUsers       = $allUsers.Count
        TotalComputers   = $allComps.Count
        Disabled       = @($disabled | Sort-Object Name)
        StaleUsers     = @($staleU   | Sort-Object { $_.DaysIdle } -Descending)
        StaleComputers = @($staleC   | Sort-Object { $_.DaysIdle } -Descending)
    }
}

$script:DayNames = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
$script:DayShort = @('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')

function ConvertFrom-LogonHours {
    <#
      logonHours is 21 bytes = 168 bits, one per hour of the week, in UTC.
      Bit 0 of byte 0 = Sunday 00:00-00:59 UTC, least-significant-bit first.
      Returns [bool[]] of 168 entries indexed (day * 24 + hour) in LOCAL time.
    #>
    param([byte[]]$Bytes, [int]$OffsetHours)

    $utc = [bool[]]::new(168)
    for ($i = 0; $i -lt 168; $i++) {
        $b = $Bytes[[int][math]::Floor($i / 8)]
        $utc[$i] = ((([int]$b -shr ($i % 8)) -band 1) -eq 1)
    }
    $local = [bool[]]::new(168)
    for ($i = 0; $i -lt 168; $i++) {
        $j = ((($i + $OffsetHours) % 168) + 168) % 168
        $local[$j] = $utc[$i]
    }
    return , $local
}

function Get-DayRangeText {
    param([bool[]]$Map, [int]$Day)
    $hours = @(0..23 | Where-Object { $Map[($Day * 24) + $_] })
    if ($hours.Count -eq 0)  { return 'None' }
    if ($hours.Count -eq 24) { return 'All day' }
    $ranges = @()
    $start = $hours[0]; $prev = $hours[0]
    foreach ($h in ($hours | Select-Object -Skip 1)) {
        if ($h -eq ($prev + 1)) { $prev = $h; continue }
        $ranges += ('{0:00}:00-{1:00}:00' -f $start, ($prev + 1))
        $start = $h; $prev = $h
    }
    $ranges += ('{0:00}:00-{1:00}:00' -f $start, ($prev + 1))
    return ($ranges -join ', ')
}

function Get-ScheduleSummary {
    param([bool[]]$Map)
    $perDay = @(0..6 | ForEach-Object { Get-DayRangeText -Map $Map -Day $_ })
    $parts = @()
    $i = 0
    while ($i -lt 7) {
        $j = $i
        while (($j + 1) -lt 7 -and $perDay[$j + 1] -eq $perDay[$i]) { $j++ }
        $label = if ($j -gt $i) { ('{0}-{1}' -f $script:DayShort[$i], $script:DayShort[$j]) } else { $script:DayShort[$i] }
        $parts += ('{0} {1}' -f $label, $perDay[$i])
        $i = $j + 1
    }
    return ($parts -join ' &middot; ')
}

function Get-UserLogonRestrictions {
    <#
      Every user account that is limited in WHEN it may sign in (logonHours),
      WHERE it may sign in from (logonWorkstations), or UNTIL when the account
      is valid (accountExpires). Users with none of the three are counted but
      not listed.
    #>
    param([string]$Server, [int]$OffsetHours)

    $users = @(Get-DirUsers -Server $Server)
    $rows = @()

    foreach ($u in $users) {

        # --- when may this account sign in?
        $bytes = $null
        $pp = $u.PSObject.Properties['logonHours']
        if ($pp -and $pp.Value) { try { $bytes = [byte[]]$pp.Value } catch { $bytes = $null } }

        $map = $null
        $allowed = 168
        if ($bytes -and $bytes.Length -ge 21) {
            $m = ConvertFrom-LogonHours -Bytes $bytes -OffsetHours $OffsetHours
            $a = @($m | Where-Object { $_ }).Count
            if ($a -lt 168) { $map = $m; $allowed = $a }
        }

        # --- where from, and until when?
        $ws = ''
        $wp = $u.PSObject.Properties['LogonWorkstations']
        if ($wp -and $wp.Value) { $ws = [string]$wp.Value }

        $exp = $null
        $ep = $u.PSObject.Properties['AccountExpirationDate']
        if ($ep -and $ep.Value) { $exp = $ep.Value }

        if ($null -eq $map -and -not $ws -and $null -eq $exp) { continue }

        $rows += [pscustomobject]@{
            Name           = $u.Name
            Sam            = $u.SamAccountName
            Enabled        = [bool]$u.Enabled
            OU             = ($u.DistinguishedName -split ',', 2)[1]
            Map            = $map
            AllowedHours   = $allowed
            HourRestricted = ($null -ne $map)
            NeverAllowed   = (($null -ne $map) -and ($allowed -eq 0))
            Workstations   = $ws
            Expires        = $exp
            LastLogon      = (Get-Prop $u 'LastLogonDate')
            Summary        = $(if ($map) { Get-ScheduleSummary -Map $map } else { 'Any hour of any day' })
        }
    }

    [pscustomobject]@{ Total = $users.Count; Rows = @($rows | Sort-Object Name) }
}

# ------------------------------------------------- privileged group report --

function Get-PrivilegedGroupReport {
    param([string]$Server)

    $adp = @{}
    if ($Server) { $adp['Server'] = $Server }

    $domain = Get-ADDomain @adp
    $forest = Get-ADForest @adp
    $rootSrv = $forest.RootDomain
    $rootDom = Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain

    $dsid = $domain.DomainSID.Value
    $rsid = $rootDom.DomainSID.Value
    $thisSrv = if ($Server) { $Server } else { $domain.DNSRoot }

    $targets = @(
        [pscustomobject]@{ Label = 'Administrators (built-in)'; Sid = 'S-1-5-32-544'; Srv = $thisSrv; Scope = $domain.DNSRoot }
        [pscustomobject]@{ Label = 'Domain Admins';             Sid = "$dsid-512";    Srv = $thisSrv; Scope = $domain.DNSRoot }
        [pscustomobject]@{ Label = 'Enterprise Admins';         Sid = "$rsid-519";    Srv = $rootSrv; Scope = "$rootSrv (forest root)" }
        [pscustomobject]@{ Label = 'Schema Admins';             Sid = "$rsid-518";    Srv = $rootSrv; Scope = "$rootSrv (forest root)" }
    )

    $out = @()
    foreach ($t in $targets) {

        $entry = [pscustomobject]@{
            Label   = $t.Label
            Scope   = $t.Scope
            Group   = $null
            Members = @()
            Nested  = @()
            Error   = $null
        }

        try {
            $grp = Get-ADGroup -Identity $t.Sid -Server $t.Srv -ErrorAction Stop
            $entry.Group = $grp.Name

            $direct = @()
            try { $direct = @(Get-ADGroupMember -Identity $grp -Server $t.Srv -ErrorAction Stop) } catch { }
            $directDns = @($direct | ForEach-Object { $_.distinguishedName })
            $entry.Nested = @($direct | Where-Object { $_.objectClass -eq 'group' } | ForEach-Object { $_.name })

            $all = @()
            try { $all = @(Get-ADGroupMember -Identity $grp -Recursive -Server $t.Srv -ErrorAction Stop) }
            catch { $all = @($direct | Where-Object { $_.objectClass -ne 'group' }) }

            $members = @()
            foreach ($m in ($all | Sort-Object name -Unique)) {
                $u = $null
                try {
                    $u = Get-ADUser -Identity $m.distinguishedName -Server $t.Srv `
                            -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, Description -ErrorAction Stop
                }
                catch { }

                $members += [pscustomobject]@{
                    Name            = $m.name
                    Sam             = $(if ($u) { $u.SamAccountName } else { $m.SamAccountName })
                    Direct          = ($directDns -contains $m.distinguishedName)
                    Enabled         = $(if ($u) { [bool]$u.Enabled } else { $null })
                    PwdNeverExpires = $(if ($u) { [bool]$u.PasswordNeverExpires } else { $null })
                    PwdLastSet      = $(if ($u) { $u.PasswordLastSet } else { $null })
                    LastLogon       = $(if ($u) { $u.LastLogonDate } else { $null })
                }
            }
            $entry.Members = $members
        }
        catch {
            $entry.Error = $_.Exception.Message
        }

        $out += $entry
    }
    return $out
}

# ------------------------------------------------------------------- setup --

Write-Host ''
Write-Host ("  {0}  " -f $script:Brand) -ForegroundColor Black -BackgroundColor White -NoNewline
Write-Host ("  {0}" -f $script:BrandUrl) -ForegroundColor DarkGray
Write-Host ("  {0} v{1}" -f $script:ScriptName, $script:ScriptVersion) -ForegroundColor DarkGray
Write-Host ("  {0}" -f $script:BrandTag) -ForegroundColor DarkGray
Write-Host ''
Write-Step 'Checking prerequisites'

if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    throw "The GroupPolicy PowerShell module is not present. Install it with: Install-WindowsFeature GPMC   (server)  or  Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0   (client)"
}
Import-Module GroupPolicy -ErrorAction Stop

if ($UtcOffsetHours -eq 9999) {
    $rawOffset = [System.TimeZoneInfo]::Local.GetUtcOffset([datetime]::Now).TotalHours
    $UtcOffsetHours = [int][math]::Round($rawOffset)
    $script:TzLabel = ('{0} (UTC{1}{2})' -f [System.TimeZoneInfo]::Local.Id, $(if ($UtcOffsetHours -ge 0) { '+' } else { '-' }), [math]::Abs($UtcOffsetHours))
}
else {
    $script:TzLabel = ('UTC{0}{1} (set with -UtcOffsetHours)' -f $(if ($UtcOffsetHours -ge 0) { '+' } else { '-' }), [math]::Abs($UtcOffsetHours))
}

# Two possible routes into AD. The ActiveDirectory module needs ADWS (TCP 9389),
# which is often stopped or blocked; LDAP (TCP 389) is what the GroupPolicy module
# already uses, so it works whenever the GPO half of this report works.
$script:AdMode = 'None'
$adError       = $null

function Initialize-LdapContext {
    param([string]$PreferredServer)
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $dn      = [string]$rootDse.Properties['defaultNamingContext'][0]
        $rootDn  = [string]$rootDse.Properties['rootDomainNamingContext'][0]
        if (-not $dn) { return $false }
        if (-not $rootDn) { $rootDn = $dn }

        $script:DomainDn     = $dn
        $script:LdapRoot     = if ($PreferredServer) { "LDAP://$PreferredServer/$dn" } else { "LDAP://$dn" }
        $script:LdapRootRoot = if ($PreferredServer -and ($rootDn -eq $dn)) { "LDAP://$PreferredServer/$rootDn" } else { "LDAP://$rootDn" }

        $dom = New-Object System.DirectoryServices.DirectoryEntry($script:LdapRoot)
        $script:DomainSid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$dom.Properties['objectSid'][0]), 0)).Value

        if ($rootDn -eq $dn) { $script:RootSid = $script:DomainSid }
        else {
            $rt = New-Object System.DirectoryServices.DirectoryEntry($script:LdapRootRoot)
            $script:RootSid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$rt.Properties['objectSid'][0]), 0)).Value
        }

        $script:LdapDomainName = ($dn     -replace 'DC=', '' -replace ',', '.')
        $script:LdapRootName   = ($rootDn -replace 'DC=', '' -replace ',', '.')
        return $true
    }
    catch {
        $script:LdapError = $_.Exception.Message
        return $false
    }
}

# --- route 1: the ActiveDirectory module over ADWS
if (Get-Module -ListAvailable -Name ActiveDirectory) {

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    $candidates = @()
    if ($Server) { $candidates += $Server }
    $candidates += ''
    try { $candidates += ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name } catch { }
    $candidates += $env:COMPUTERNAME

    foreach ($cand in ($candidates | Select-Object -Unique)) {
        try {
            if ($cand) { $null = Get-ADDomain -Server $cand -ErrorAction Stop }
            else       { $null = Get-ADDomain -ErrorAction Stop }
            $script:AdMode = 'Module'
            if ($cand -and -not $Server) { $Server = $cand }
            break
        }
        catch { $adError = $_.Exception.Message }
    }
}

# --- route 2: straight LDAP, no ADWS required
if ($script:AdMode -eq 'None') {
    if (Initialize-LdapContext -PreferredServer $Server) { $script:AdMode = 'LDAP' }
}

switch ($script:AdMode) {
    'Module' {
        if ($Server) { Write-Step "AD access   : ActiveDirectory module via $Server" }
        else         { Write-Step 'AD access   : ActiveDirectory module (ADWS)' }
    }
    'LDAP' {
        Write-Warn 'Active Directory Web Services (ADWS, TCP 9389) is not reachable - falling back to LDAP.'
        Write-Step ("AD access   : LDAP fallback on {0}" -f $script:LdapRoot)
        Write-Step '              All AD sections are still produced. To use the faster ActiveDirectory'
        Write-Step '              module instead, start the ADWS service on a DC (Get-Service ADWS).'
    }
    default {
        Write-Warn 'Could not reach Active Directory by either route:'
        Write-Warn '  - ActiveDirectory module / ADWS on TCP 9389'
        Write-Warn '  - LDAP on TCP 389'
        Write-Warn 'The GPO inventory is unaffected. Privileged groups, logon restrictions, fine-grained'
        Write-Warn 'password policies and the cleanup views will be marked NOT CHECKED.'
    }
}

$adAvailable = ($script:AdMode -ne 'None')

# why the AD-backed sections are missing, shown in the report itself
$script:AdSkipReason = ''
if (-not $adAvailable) {
    $script:AdSkipReason = 'Active Directory could not be reached from the machine that produced this report - neither Active Directory Web Services (ADWS, TCP 9389) nor LDAP (TCP 389) responded, so this section was not checked. Re-run from a domain-joined machine that can reach a domain controller, or pass -Server naming one.'
    if ($adError) { $script:AdSkipReason += ' Reported error: ' + $adError }
}

if (-not $Domain) {
    if ($env:USERDNSDOMAIN) { $Domain = $env:USERDNSDOMAIN }
    else { $Domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain }
}
if (-not $Domain -or $Domain -eq 'WORKGROUP') { throw 'Could not determine a domain. Pass -Domain <fqdn>.' }

$gpParams = @{ Domain = $Domain }
if ($Server) { $gpParams['Server'] = $Server }

# AD-Report-<domain>-YYYYMMDD  - the folder and the HTML share the same name.
# A second run on the same day gets -HHmm appended so it never overwrites the first.
$script:ReportName = ('AD-Report-{0}-{1}' -f ($Domain -replace '[^\w\.\-]', '_'), (Get-Date -Format 'yyyyMMdd'))
$reportDir = Join-Path $OutputPath $script:ReportName
if (Test-Path -LiteralPath $reportDir) {
    $script:ReportName = ('{0}-{1}' -f $script:ReportName, (Get-Date -Format 'HHmm'))
    $reportDir = Join-Path $OutputPath $script:ReportName
}
$perGpoDir = Join-Path $reportDir 'PerGPO'

New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
if (-not $SkipPerGpoHtml) { New-Item -ItemType Directory -Path $perGpoDir -Force | Out-Null }

Write-Step "Domain      : $Domain"
Write-Step "Output      : $reportDir"

Write-Step 'Enumerating GPOs'
$allGpos = @(Get-GPO -All @gpParams | Sort-Object DisplayName)

if ($Name) {
    $allGpos = @($allGpos | Where-Object {
        $g = $_
        ($Name | Where-Object { $g.DisplayName -like $_ }).Count -gt 0
    })
}

if ($allGpos.Count -eq 0) { throw 'No GPOs matched.' }
Write-Step ("Found {0} GPO(s)" -f $allGpos.Count)

# ------------------------------------------------------------ data gather --

$records      = New-Object System.Collections.ArrayList
$flatSettings = New-Object System.Collections.ArrayList
$flatScope    = New-Object System.Collections.ArrayList
$usedFiles    = @{}
$i = 0

foreach ($gpo in $allGpos) {

    $i++
    $pct = [int](($i / $allGpos.Count) * 100)
    Write-Progress -Activity 'Reading GPOs' -Status ("[{0}/{1}] {2}" -f $i, $allGpos.Count, $gpo.DisplayName) -PercentComplete $pct

    try {
        [xml]$xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml @gpParams
    }
    catch {
        Write-Warn ("Could not read '{0}': {1}" -f $gpo.DisplayName, $_.Exception.Message)
        continue
    }

    try { $scope = Get-GpoScope -Gpo $gpo -Xml $xml -GpParams $gpParams }
    catch {
        Write-Warn ("Could not read scope for '{0}': {1}" -f $gpo.DisplayName, $_.Exception.Message)
        $scope = [pscustomobject]@{
            Links = @(); ApplyTo = @(); DenyApply = @(); Editors = @(); WmiFilter = $null
            Status = "$($gpo.GpoStatus)"; Owner = ''; Created = $null; Modified = $null
            CompVersion = ''; UserVersion = ''
        }
    }

    $compSet = @()
    $userSet = @()
    try { $compSet = @(Get-GpoSettings -Xml $xml -Side 'Computer') }
    catch { Write-Warn ("Could not parse Computer settings in '{0}': {1}" -f $gpo.DisplayName, $_.Exception.Message) }
    try { $userSet = @(Get-GpoSettings -Xml $xml -Side 'User') }
    catch { Write-Warn ("Could not parse User settings in '{0}': {1}" -f $gpo.DisplayName, $_.Exception.Message) }

    # per-GPO native GPMC HTML
    $htmlFile = $null
    if (-not $SkipPerGpoHtml) {
        $safe = ($gpo.DisplayName -replace '[\\/:*?"<>|]', '_').Trim()
        if ($safe.Length -gt 90) { $safe = $safe.Substring(0, 90) }
        if ($usedFiles.ContainsKey($safe.ToLower())) { $safe = "$safe`_$($gpo.Id.ToString().Substring(0,8))" }
        $usedFiles[$safe.ToLower()] = $true
        $htmlFile = "$safe.html"
        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Html -Path (Join-Path $perGpoDir $htmlFile) @gpParams | Out-Null
        }
        catch {
            Write-Warn ("HTML export failed for '{0}': {1}" -f $gpo.DisplayName, $_.Exception.Message)
            $htmlFile = $null
        }
    }

    $liveLinks = @($scope.Links | Where-Object { $_.Enabled -eq 'true' })

    [void]$records.Add([pscustomobject]@{
        Gpo       = $gpo
        Scope     = $scope
        Computer  = $compSet
        User      = $userSet
        HtmlFile  = $htmlFile
        Anchor    = ('gpo-' + $gpo.Id.ToString())
        Applying  = (($liveLinks.Count -gt 0) -and ($scope.Status -ne 'AllSettingsDisabled'))
        LinkPaths = (($liveLinks | ForEach-Object { $_.SOMPath }) -join '; ')
    })

    foreach ($s in ($compSet + $userSet)) {
        [void]$flatSettings.Add([pscustomobject]@{
            GPO       = $gpo.DisplayName
            GUID      = $gpo.Id
            Side      = $s.Side
            Container = $s.Container
            Setting   = $s.Name
            Value     = $s.Value
        })
    }

    if ($scope.Links.Count -eq 0) {
        [void]$flatScope.Add([pscustomobject]@{
            GPO = $gpo.DisplayName; GUID = $gpo.Id; SOMPath = '(not linked)'
            LinkEnabled = ''; Enforced = ''; GpoStatus = $scope.Status
            SecurityFiltering = ($scope.ApplyTo -join '; '); WmiFilter = $scope.WmiFilter
        })
    }
    else {
        foreach ($l in $scope.Links) {
            [void]$flatScope.Add([pscustomobject]@{
                GPO = $gpo.DisplayName; GUID = $gpo.Id; SOMPath = $l.SOMPath
                LinkEnabled = $l.Enabled; Enforced = $l.Enforced; GpoStatus = $scope.Status
                SecurityFiltering = ($scope.ApplyTo -join '; '); WmiFilter = $scope.WmiFilter
            })
        }
    }
}
Write-Progress -Activity 'Reading GPOs' -Completed

# ----------------------------------------------------- collect focus areas --

Write-Step 'Collecting auditor focus areas'

$focus = @{}
foreach ($fa in $script:FocusAreas) { $focus[$fa.Key] = New-Object System.Collections.ArrayList }

foreach ($r in $records) {
    foreach ($sx in (@($r.Computer) + @($r.User))) {
        $hay = ('{0} | {1} | {2}' -f $sx.Container, $sx.Name, $sx.Value)
        foreach ($fa in $script:FocusAreas) {
            if ($hay -match $fa.Pattern) {
                [void]$focus[$fa.Key].Add([pscustomobject]@{
                    Gpo       = $r.Gpo.DisplayName
                    Anchor    = $r.Anchor
                    Applying  = $r.Applying
                    LinkPaths = $r.LinkPaths
                    Scope     = $r.Scope
                    Side      = $sx.Side
                    Container = $sx.Container
                    Name      = $sx.Name
                    Value     = $sx.Value
                })
            }
        }
    }
}

# Fine-grained password policies (PSOs) - how admins usually get a stricter policy
$psos = @()
if ($adAvailable) {
    try {
        if ($script:AdMode -eq 'LDAP') { $psos = @(Get-LdapPsos) }
        else {
        $psoParams = @{}
        if ($Server) { $psoParams['Server'] = $Server }
        foreach ($pso in @(Get-ADFineGrainedPasswordPolicy -Filter * @psoParams)) {
            $applies = @()
            try { $applies = @($pso.AppliesTo | ForEach-Object { ($_ -split ',', 2)[0] -replace '^CN=', '' }) } catch { }
            $psos += [pscustomobject]@{
                Name         = $pso.Name
                Precedence   = $pso.Precedence
                MinLength    = $pso.MinPasswordLength
                Complexity   = $pso.ComplexityEnabled
                History      = $pso.PasswordHistoryCount
                MaxAge       = $pso.MaxPasswordAge
                MinAge       = $pso.MinPasswordAge
                LockThresh   = $pso.LockoutThreshold
                LockDuration = $pso.LockoutDuration
                LockWindow   = $pso.LockoutObservationWindow
                Reversible   = $pso.ReversibleEncryptionEnabled
                AppliesTo    = ($applies -join ', ')
            }
        }
        }
    }
    catch { Write-Warn ("Could not read fine-grained password policies: {0}" -f $_.Exception.Message) }
}

# ------------------------------------------------- privileged group report --

$privGroups = @()
if (-not $SkipPrivilegedGroups -and $adAvailable) {
    Write-Step 'Reading privileged group membership'
    try {
        if ($script:AdMode -eq 'LDAP') { $privGroups = @(Get-LdapPrivilegedGroupReport) }
        else                           { $privGroups = @(Get-PrivilegedGroupReport -Server $Server) }
    }
    catch { Write-Warn ("Privileged group report failed: {0}" -f $_.Exception.Message) }
}

$script:PrivChecked = ($privGroups.Count -gt 0)

# sAMAccountName -> the privileged groups that account is effectively a member of
$script:PrivMap = @{}
foreach ($pg in $privGroups) {
    if ($pg.Error) { continue }
    foreach ($pm in @($pg.Members)) {
        $key = "$($pm.Sam)".ToLower()
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $lbl = ($pg.Label -replace ' \(built-in\)', '')
        if (-not $script:PrivMap.ContainsKey($key)) { $script:PrivMap[$key] = @() }
        if ($script:PrivMap[$key] -notcontains $lbl) { $script:PrivMap[$key] += $lbl }
    }
}

# --------------------------------------------------------------- cleanup ---

$cleanup = [pscustomobject]@{
    Checked = $false; DisabledVerified = $false; UnknownEnabled = 0
    TotalUsers = 0; TotalComputers = 0
    Disabled = @(); StaleUsers = @(); StaleComputers = @()
}
if (-not $SkipCleanup -and $adAvailable) {
    Write-Step ("Scanning for cleanup candidates (users idle > {0}d, computers idle > {1}d)" -f $StaleUserDays, $StaleComputerDays)
    try { $cleanup = Get-CleanupData -Server $Server -UserDays $StaleUserDays -ComputerDays $StaleComputerDays }
    catch { Write-Warn ("Cleanup scan failed: {0}" -f $_.Exception.Message) }
}

# ---------------------------------------------------------- logon hours ----

$logonScan = $null
if ($adAvailable) {
    Write-Step 'Checking user logon restrictions'
    try { $logonScan = Get-UserLogonRestrictions -Server $Server -OffsetHours $UtcOffsetHours }
    catch { Write-Warn ("Logon-hours check failed: {0}" -f $_.Exception.Message) }
}

# ------------------------------------------------------------ html builder --

Write-Step 'Building master report'


$css = @'
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--mut:#5c6673;--line:#dfe3e8;--accent:#0b5fff;--onacc:#fff;--warn:#b45309;--bad:#b91c1c;--ok:#15803d;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#181c21;--ink:#e6e9ee;--mut:#98a2b0;--line:#2a3038;--accent:#6ea8fe;--onacc:#0d1117;--warn:#f0b429;--bad:#f87171;--ok:#4ade80;--chip:#232931}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
a{color:var(--accent)}
.shell{display:flex;align-items:flex-start;min-height:100vh}
nav.side{width:242px;flex:0 0 242px;background:var(--card);border-right:1px solid var(--line);padding:16px 12px;position:sticky;top:0;height:100vh;overflow:auto}
nav.side .brand{font-weight:700;font-size:15px;padding:0 8px 12px;line-height:1.3}
nav.side .brand small{display:block;font-weight:400;color:var(--mut);font-size:11.5px;margin-top:3px}
nav.side a.brandmark{display:inline-block;margin:0 0 10px 8px;padding:3px 9px;border-radius:4px;background:var(--accent);color:var(--onacc);font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;text-decoration:none}
nav.side a.brandmark:hover{opacity:.85}
nav.side a.nav{display:flex;justify-content:space-between;gap:8px;align-items:center;padding:8px 10px;margin:1px 0;border-radius:6px;color:var(--ink);text-decoration:none;font-size:13.5px;cursor:pointer}
nav.side a.nav:hover{background:var(--chip)}
nav.side a.nav.on{background:var(--accent);color:var(--onacc)}
nav.side a.nav.on .n{color:var(--onacc);opacity:.85}
nav.side .n{color:var(--mut);font-size:11.5px;font-variant-numeric:tabular-nums;white-space:nowrap}
nav.side .grouplbl{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;padding:14px 10px 4px;font-weight:700}
nav.side hr{border:none;border-top:1px solid var(--line);margin:12px 4px}
nav.side .navnote{color:var(--mut);font-size:11.5px;padding:4px 10px;line-height:1.45}
main{flex:1 1 auto;min-width:0;padding:20px 26px 60px;max-width:1400px}
section.view{display:none}
section.view.on{display:block}
h1{margin:0 0 4px;font-size:20px}
h2{margin:26px 0 10px;font-size:16px}
.sub{color:var(--mut);font-size:13px}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;position:sticky;top:0;background:var(--bg);padding:12px 0;margin-bottom:6px;z-index:5;border-bottom:1px solid var(--line)}
.toolbar input[type=search]{flex:1 1 300px;min-width:200px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink)}
.toolbar select,.toolbar button{padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink);cursor:pointer}
.toolbar label{color:var(--mut);display:flex;gap:5px;align-items:center;cursor:pointer}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px}
.stat b{display:block;font-size:20px}
.stat span{color:var(--mut);font-size:12px}
.badge{font:600 11px/1 "Segoe UI",sans-serif;padding:4px 7px;border-radius:999px;background:var(--chip);color:var(--mut);white-space:nowrap}
.badge.warn{color:var(--warn)} .badge.bad{color:var(--bad)} .badge.ok{color:var(--ok)}

/* ---- focus areas: links to GPOs only ---- */
.area{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:12px;padding:14px 16px}
.area>h3{margin:0;font-size:15px;display:flex;flex-wrap:wrap;gap:9px;align-items:center}
.area .letter{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:6px;background:var(--accent);color:var(--onacc);font-size:12.5px;font-weight:700;flex:0 0 auto}
.area .hint{color:var(--mut);font-size:12.5px;margin:7px 0 10px 33px}
.gpolist{margin:0 0 0 33px;display:flex;flex-direction:column;gap:6px}
details.grow{border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--bg)}
details.grow>summary{display:flex;flex-wrap:wrap;gap:9px;align-items:center;padding:7px 10px;cursor:pointer;list-style:none}
details.grow>summary::-webkit-details-marker{display:none}
details.grow>summary::before{content:"\25B8";color:var(--mut);transition:transform .12s;flex:0 0 auto}
details.grow[open]>summary::before{transform:rotate(90deg)}
details.grow[open]>summary{background:var(--chip)}
details.grow .gname{font-weight:600;color:var(--accent)}
details.grow .jump{margin-left:auto;font-size:11.5px;white-space:nowrap;text-decoration:none}
details.grow .jump:hover{text-decoration:underline}
.where{color:var(--mut);font-size:12px;font-family:Consolas,"Cascadia Mono",monospace}
.fbody{border-top:1px solid var(--line);background:var(--card);padding:10px 12px 4px}
.fsechead{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:700;margin:4px 0 6px}
.fbody .scope{margin:0 0 12px}
.fbody .scope th{width:190px;padding:6px 9px}
table.focustbl{width:100%;border-collapse:collapse;font-size:12.5px;background:var(--card);margin-bottom:8px;border-top:1px solid var(--line)}
table.focustbl td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
table.focustbl tr:last-child td{border-bottom:none}
table.focustbl td.k{width:46%}
table.focustbl td.v{font-family:Consolas,"Cascadia Mono",monospace;color:var(--mut);word-break:break-word}
.missing{margin-left:33px;padding:9px 11px;border-radius:6px;background:var(--chip);color:var(--bad);font-weight:600;font-size:12.5px}
.note{margin:9px 0 0 33px;padding:9px 11px;border-radius:6px;background:var(--chip);color:var(--warn);font-weight:600;font-size:12.5px}
.psotbl{width:100%;border-collapse:collapse;font-size:12.5px;margin:10px 0 0 33px;max-width:calc(100% - 33px)}
.psotbl th{text-align:left;padding:5px 8px;color:var(--mut);border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.psotbl td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}

/* ---- gpo cards ---- */
details.gpo{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;overflow:hidden}
details.gpo>summary{padding:11px 14px;cursor:pointer;font-weight:600;font-size:15px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;list-style:none}
details.gpo>summary::-webkit-details-marker{display:none}
details.gpo>summary::before{content:"\25B8";color:var(--mut);font-weight:400;display:inline-block;transition:transform .12s}
details.gpo[open]>summary::before{transform:rotate(90deg)}
.gpmc{margin-left:auto;font-weight:400;font-size:12px;white-space:nowrap}
.body{padding:0 14px 14px}
.scope{border:1px solid var(--line);border-radius:6px;margin:4px 0 12px;overflow:hidden}
.scope table{width:100%;border-collapse:collapse;font-size:13px}
.scope th{text-align:left;width:210px;padding:8px 10px;color:var(--ink);font-weight:600;vertical-align:top;background:var(--chip)}
.scope th .hint{font-weight:400;font-size:11px;color:var(--mut);line-height:1.3;margin:0}
.scope td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.links{margin:0;padding-left:18px}
.links li{margin:2px 0}
details.side{margin:0 0 8px;border-left:3px solid var(--accent);padding-left:10px}
details.side>summary{cursor:pointer;font-weight:600;padding:5px 0;color:var(--accent)}
details.cont{margin:2px 0 2px 12px}
details.cont>summary{cursor:pointer;padding:4px 0;color:var(--ink);font-size:13px}
details.cont>summary .path{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px}
details.cont>summary .cnt{color:var(--mut);font-size:11.5px;margin-left:6px}
table.settings{width:100%;border-collapse:collapse;margin:4px 0 8px 14px;font-size:13px}
table.settings td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
table.settings td.k{width:42%;font-weight:500}
table.settings td.v{color:var(--mut);font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px;word-break:break-word}
.empty{color:var(--mut);font-style:italic;padding:6px 0}

/* ---- privileged groups ---- */
.grp{border:1px solid var(--line);border-radius:8px;margin-bottom:12px;overflow:hidden;background:var(--card)}
.grp>h3{margin:0;padding:10px 14px;font-size:14px;background:var(--chip);display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.grp table{width:100%;border-collapse:collapse;font-size:12.5px}
.grp th{text-align:left;padding:6px 10px;color:var(--mut);border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.grp td{padding:6px 10px;border-bottom:1px solid var(--line)}
.grp .nested{padding:8px 14px;color:var(--mut);font-size:12.5px}
.mono{font-family:Consolas,"Cascadia Mono",monospace}
.mut{color:var(--mut)}
.verified{margin:12px 0 0;padding:9px 11px;border-radius:6px;background:var(--chip);color:var(--ok);font-weight:600;font-size:12.5px}
th.sortable{cursor:pointer;user-select:none;white-space:nowrap}
th.sortable:hover{color:var(--ink)}
th.sortable::after{content:"\2195";margin-left:5px;opacity:.3;font-weight:400}
th.sortable[data-dir="asc"]::after{content:"\25B2";opacity:.85}
th.sortable[data-dir="desc"]::after{content:"\25BC";opacity:.85}
th.sortable[data-dir]{color:var(--accent)}
details.sugg{margin:10px 0 0 33px;border:1px solid var(--accent);border-radius:7px;overflow:hidden}
details.sugg>summary{cursor:pointer;list-style:none;padding:9px 13px;font-weight:600;font-size:13px;color:var(--onacc);background:var(--accent);display:flex;gap:8px;align-items:center}
details.sugg>summary::-webkit-details-marker{display:none}
details.sugg>summary::before{content:"\25B8";transition:transform .12s}
details.sugg[open]>summary::before{transform:rotate(90deg)}
.suggbody{padding:13px 15px;background:var(--card)}
.suggbody p{margin:0 0 10px;font-size:13px;line-height:1.5}
.suggbody h5{margin:16px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.suggbody ol{margin:0 0 10px;padding-left:20px;font-size:13px;line-height:1.6}
.suggbody code{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;background:var(--chip);padding:1px 4px;border-radius:3px}
pre.snippet{background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:11px 13px;margin:0;font:12px/1.5 Consolas,"Cascadia Mono",monospace;white-space:pre-wrap;word-break:break-word;color:var(--ink);max-height:340px;overflow:auto}
.copyrow{display:flex;gap:8px;align-items:center;margin:6px 0 0}
button.btn{padding:5px 11px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);cursor:pointer;font-size:12px}
button.btn:hover{border-color:var(--accent);color:var(--accent)}
.cite{font-size:12px;color:var(--mut);border-left:3px solid var(--line);padding-left:10px;margin:10px 0}
.tbl{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;font-size:12.5px}
.tbl th{text-align:left;padding:8px 10px;background:var(--chip);color:var(--mut);border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.03em;position:sticky;top:0}
.tbl td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.tblbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:14px 0 12px}
.tblbar input[type=search]{flex:1 1 280px;min-width:200px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink)}
.days{font-variant-numeric:tabular-nums;white-space:nowrap}
.lhuser{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;padding:12px 14px;display:flex;flex-wrap:wrap;gap:18px}
.lhwho{flex:1 1 300px;min-width:260px}
.lhwho h4{margin:0 0 2px;font-size:14.5px;display:flex;flex-wrap:wrap;gap:7px;align-items:center}
.lhwho .sam{color:var(--mut);font-size:12.5px;font-family:Consolas,"Cascadia Mono",monospace}
.lhmeta{margin-top:8px;font-size:12.5px}
.lhmeta div{margin:3px 0}
.lhmeta b{color:var(--mut);font-weight:600;display:inline-block;min-width:110px;padding-right:8px}
.lhgrid{display:grid;grid-template-columns:34px repeat(24,14px);gap:2px;align-items:center;flex:0 0 auto}
.lhgrid .hr{font-size:10px;color:var(--mut);text-align:center;font-family:Consolas,monospace}
.lhgrid .day{font-size:11px;color:var(--mut);text-align:right;padding-right:4px}
.lhgrid i{display:block;width:14px;height:14px;border-radius:2px;background:var(--chip)}
.lhgrid i.on{background:var(--accent)}
.lhlegend{display:flex;gap:16px;align-items:center;color:var(--mut);font-size:12px;margin:0 0 14px}
.lhlegend i{display:inline-block;width:12px;height:12px;border-radius:2px;vertical-align:-2px;margin-right:5px}
.lhnohours{flex:0 0 auto;align-self:center;color:var(--mut);font-size:12.5px;font-style:italic;padding-right:8px}

/* ---- appendix tables ---- */
.appendix table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;font-size:13px}
.appendix th{text-align:left;padding:8px 10px;background:var(--chip);color:var(--mut);border-bottom:1px solid var(--line)}
.appendix td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
footer{color:var(--mut);font-size:12px;padding:24px 0 0;text-align:center}
'@

$js = @'
function norm(s){return (s||'').toLowerCase();}
function show(v){
  document.querySelectorAll('nav.side a.nav').forEach(function(a){ a.classList.toggle('on', a.dataset.view === v); });
  document.querySelectorAll('section.view').forEach(function(s){ s.classList.toggle('on', s.id === 'view-' + v); });
  window.scrollTo(0, 0);
}
function gotoGpo(anchor){
  document.getElementById('q').value = '';
  document.getElementById('fLink').value = 'all';
  document.getElementById('fSet').checked = false;
  applyFilter();
  show('gpos');
  var el = document.getElementById(anchor);
  if (el) { el.open = true; el.scrollIntoView({block:'start'}); }
  return false;
}
function applyFilter(){
  var term = norm(document.getElementById('q').value).trim();
  var onlySet = document.getElementById('fSet').checked;
  var linkMode = document.getElementById('fLink').value;
  var shown = 0;
  document.querySelectorAll('details.gpo').forEach(function(g){
    var nameHit = (term === '') || norm(g.dataset.name).indexOf(term) >= 0;
    var total = 0;
    g.querySelectorAll('details.cont').forEach(function(c){
      var contHit = nameHit || norm(c.dataset.k).indexOf(term) >= 0;
      var vis = 0;
      c.querySelectorAll('tr.setting').forEach(function(r){
        var hit = contHit || norm(r.dataset.k).indexOf(term) >= 0;
        r.style.display = hit ? '' : 'none';
        if (hit) vis++;
      });
      c.style.display = vis > 0 ? '' : 'none';
      if (term && vis > 0) c.open = true;
      total += vis;
    });
    g.querySelectorAll('details.side').forEach(function(s){
      var any = 0;
      s.querySelectorAll('details.cont').forEach(function(c){ if (c.style.display !== 'none') any++; });
      s.style.display = any > 0 ? '' : 'none';
      if (term && any > 0) s.open = true;
    });
    var ok = (term === '') ? true : (nameHit || total > 0);
    if (onlySet && g.dataset.settings === '0') ok = false;
    if (linkMode === 'linked' && g.dataset.linked !== '1') ok = false;
    if (linkMode === 'unlinked' && g.dataset.linked === '1') ok = false;
    g.style.display = ok ? '' : 'none';
    if (ok) shown++;
    if (term && ok && total > 0) g.open = true;
  });
  document.getElementById('shown').textContent = shown;
}
function applyFocusFilter(){
  var inc = document.getElementById('fApply').checked;
  document.querySelectorAll('.area').forEach(function(a){
    var shown = 0, hidden = 0;
    a.querySelectorAll('details.grow').forEach(function(d){
      var ok = inc || d.dataset.applying === '1';
      d.style.display = ok ? '' : 'none';
      if (ok) { shown++; } else { hidden++; d.open = false; }
    });
    var badge = a.querySelector('.cnt');
    if (badge) {
      badge.textContent = shown > 0 ? (shown + ' GPO(s)') : 'Nothing applying';
      badge.className = shown > 0 ? 'badge ok cnt' : 'badge bad cnt';
    }
    var none = a.querySelector('.noneMsg');
    if (none) {
      if (shown > 0) { none.style.display = 'none'; }
      else {
        none.style.display = '';
        none.textContent = hidden > 0
          ? (hidden + ' GPO(s) configure this area but none of them are applying (unlinked, link disabled, or settings disabled). Tick "Include GPOs that are not applying" above to see them.')
          : 'No GPO in this domain configures anything in this area.';
      }
    }
  });
}
function applyLogonFilter(){
  var q = document.getElementById('qLogon');
  if (!q) return;
  var term = norm(q.value).trim();
  var mode = document.getElementById('fLogon').value;
  var incDisabled = document.getElementById('fLogonDis').checked;
  var n = 0;
  document.querySelectorAll('#tbl-logon .lhuser').forEach(function(u){
    var ok = (term === '') || norm(u.dataset.k).indexOf(term) >= 0;
    if (ok && !incDisabled && u.dataset.enabled === '0') ok = false;
    if (ok) {
      if (mode === 'hours' && u.dataset.hours !== '1') ok = false;
      if (mode === 'never' && u.dataset.never !== '1') ok = false;
      if (mode === 'ws'    && u.dataset.ws    !== '1') ok = false;
      if (mode === 'exp'   && u.dataset.exp   !== '1') ok = false;
    }
    u.style.display = ok ? '' : 'none';
    if (ok) n++;
  });
  document.getElementById('cnt-logon').textContent = n;
}
function copyFallback(text, done){
  var ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch (e) { }
  document.body.removeChild(ta);
}
function copyFrom(id, btn){
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.textContent;
  var done = function(){
    var old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(function(){ btn.textContent = old; }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function(){ copyFallback(text, done); });
  } else {
    copyFallback(text, done);
  }
}
/* ---- click-to-sort on any table with a header row ---- */
function sortKey(td){
  if (!td) return '';
  if (td.dataset && td.dataset.s !== undefined) return td.dataset.s;
  return (td.textContent || '').trim();
}
function cmpVals(a, b){
  var isoA = /^\d{4}-\d{2}-\d{2}/.test(a), isoB = /^\d{4}-\d{2}-\d{2}/.test(b);
  if (isoA && isoB) {
    var ta = Date.parse(a), tb = Date.parse(b);
    if (!isNaN(ta) && !isNaN(tb)) return ta - tb;
    return a.localeCompare(b);
  }
  if (isoA !== isoB) return isoA ? -1 : 1;
  var na = parseFloat(a), nb = parseFloat(b);
  var numA = /^-?[\d.]/.test(a) && !isNaN(na);
  var numB = /^-?[\d.]/.test(b) && !isNaN(nb);
  if (numA && numB) return na - nb;
  if (numA !== numB) return numA ? -1 : 1;
  return a.toLowerCase().localeCompare(b.toLowerCase());
}
function makeSortable(table){
  var head = table.querySelector('tr');
  if (!head) return;
  var cells = [].slice.call(head.children);
  if (!cells.length || cells[0].tagName !== 'TH') return;
  cells.forEach(function(th, idx){
    th.classList.add('sortable');
    th.addEventListener('click', function(){
      var asc = (th.dataset.dir !== 'asc');
      cells.forEach(function(h){ h.removeAttribute('data-dir'); });
      th.dataset.dir = asc ? 'asc' : 'desc';
      var body = table.tBodies[0];
      if (!body) return;
      var rows = [].slice.call(body.rows).filter(function(r){ return r !== head; });
      rows.sort(function(r1, r2){
        return (asc ? 1 : -1) * cmpVals(sortKey(r1.cells[idx]), sortKey(r2.cells[idx]));
      });
      rows.forEach(function(r){ body.appendChild(r); });
    });
  });
}
function setAll(open){ document.querySelectorAll('#view-gpos details').forEach(function(d){ d.open = open; }); }
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('nav.side a.nav').forEach(function(a){
    a.addEventListener('click', function(e){ e.preventDefault(); show(a.dataset.view); });
  });
  document.getElementById('q').addEventListener('input', applyFilter);
  document.getElementById('fSet').addEventListener('change', applyFilter);
  document.getElementById('fLink').addEventListener('change', applyFilter);
  document.getElementById('fApply').addEventListener('change', applyFocusFilter);
  if (document.getElementById('qLogon')) {
    document.getElementById('qLogon').addEventListener('input', applyLogonFilter);
    document.getElementById('fLogon').addEventListener('change', applyLogonFilter);
    document.getElementById('fLogonDis').addEventListener('change', applyLogonFilter);
    applyLogonFilter();
  }
  document.querySelectorAll('input.tblq').forEach(function(inp){
    inp.addEventListener('input', function(){
      var t = document.querySelector(inp.dataset.target);
      if (!t) return;
      var term = norm(inp.value).trim();
      var n = 0;
      t.querySelectorAll('.row').forEach(function(r){
        var ok = (term === '') || norm(r.dataset.k).indexOf(term) >= 0;
        r.style.display = ok ? '' : 'none';
        if (ok) n++;
      });
      var c = document.getElementById(inp.dataset.count);
      if (c) c.textContent = n;
    });
  });
  document.getElementById('bExpand').addEventListener('click', function(){ setAll(true); });
  document.getElementById('bCollapse').addEventListener('click', function(){ setAll(false); });
  document.querySelectorAll('table.tbl, .grp table, .appendix table, table.psotbl').forEach(makeSortable);
  applyFilter();
  applyFocusFilter();
  show('focus');
});
'@

$sb = New-Object System.Text.StringBuilder
function A { param([string]$Text) [void]$sb.AppendLine($Text) }

function Add-BannerSuggestion {
    <# Offered in focus area F when no applying GPO displays a complete logon banner. #>
    param([switch]$PartiallySet)

    $domainDn = ('DC=' + (($Domain -split '\.') -join ',DC='))
    $regKey   = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'

    A '<details class="sugg">'
    A ("<summary>Recommendation &ndash; {0}</summary>" -f `
        $(if ($PartiallySet) { 'complete the logon banner' } else { 'implement a logon banner' }))
    A '<div class="suggbody">'

    A '<p>I recommend implementing a standard logon banner across the domain. This supports the FFIEC IT Examination Handbook&rsquo;s guidance under <b>Information Security &ndash; Section II.C.15, Logical Security</b>, which addresses acceptable-use policies and requiring users to acknowledge and agree to those requirements.</p>'
    A '<p>Keeping the wording generic lets the same banner serve as a standard configuration across institutions.</p>'

    if ($PartiallySet) {
        A '<p><b>Note:</b> one half of the banner is already configured. Windows displays nothing unless <i>both</i> the message title and the message text are set, so the missing half needs to be filled in.</p>'
    }

    A '<h5>Suggested banner title</h5>'
    A ("<pre class='snippet' id='bannerTitle'>{0}</pre>" -f (HtmlEnc $script:BannerTitle))
    A '<div class="copyrow"><button class="btn" type="button" onclick="copyFrom(''bannerTitle'', this)">Copy title</button></div>'

    A '<h5>Suggested banner text</h5>'
    A ("<pre class='snippet' id='bannerText'>{0}</pre>" -f (HtmlEnc $script:BannerText))
    A '<div class="copyrow"><button class="btn" type="button" onclick="copyFrom(''bannerText'', this)">Copy banner text</button></div>'

    A '<h5>Where to set it in Group Policy</h5>'
    A '<ol>'
    A '<li>Create or edit a GPO linked at the domain root (or the OU covering the workstations in scope).</li>'
    A '<li>Browse to <code>Computer Configuration &rarr; Policies &rarr; Windows Settings &rarr; Security Settings &rarr; Local Policies &rarr; Security Options</code>.</li>'
    A '<li>Set <code>Interactive logon: Message title for users attempting to log on</code> to the title above.</li>'
    A '<li>Set <code>Interactive logon: Message text for users attempting to log on</code> to the text above.</li>'
    A '<li>Both entries are required &ndash; setting only one displays no banner at all.</li>'
    A '</ol>'

    A '<h5>Or configure it with PowerShell</h5>'
    $ps = @"
# Run on a domain controller with the GroupPolicy module
`$GpoName = 'Corp - Logon Banner'
`$Key     = '$regKey'

`$Banner = @'
$($script:BannerText.TrimEnd())
'@

if (-not (Get-GPO -Name `$GpoName -ErrorAction SilentlyContinue)) { New-GPO -Name `$GpoName | Out-Null }

Set-GPRegistryValue -Name `$GpoName -Key `$Key -ValueName 'legalnoticecaption' -Type String -Value '$($script:BannerTitle)'
Set-GPRegistryValue -Name `$GpoName -Key `$Key -ValueName 'legalnoticetext'    -Type String -Value `$Banner

# Link it (adjust the target if you scope this to an OU instead of the domain)
New-GPLink -Name `$GpoName -Target '$domainDn' -ErrorAction SilentlyContinue | Out-Null

# Verify on a client afterwards:  gpupdate /force  then sign out and back in
"@
    A ("<pre class='snippet' id='bannerPs'>{0}</pre>" -f (HtmlEnc $ps))
    A '<div class="copyrow"><button class="btn" type="button" onclick="copyFrom(''bannerPs'', this)">Copy PowerShell</button></div>'

    A '<div class="cite">Reference: FFIEC IT Examination Handbook, Information Security booklet, Section II.C.15 &ldquo;Logical Security&rdquo;. Have your own legal or compliance function review the wording before deployment &ndash; banner language can carry legal weight in your jurisdiction.</div>'

    A '</div></details>'
}

function Test-Privileged {
    param([string]$Sam)
    $key = "$Sam".ToLower()
    return ($script:PrivMap.Count -gt 0 -and $script:PrivMap.ContainsKey($key))
}

function Get-PrivCell {
    <# Badges naming every privileged group this account lands in, directly or nested. #>
    param([string]$Sam)
    if (-not $script:PrivChecked) { return '<span class="badge warn">not checked</span>' }
    $key = "$Sam".ToLower()
    if (-not $script:PrivMap.ContainsKey($key)) { return '<span class="mut">&ndash;</span>' }
    return ((@($script:PrivMap[$key]) | ForEach-Object { '<span class="badge bad">{0}</span>' -f (HtmlEnc $_) }) -join ' ')
}

function Add-ScopePanel {
    <# Is this GPO applying, where, and to whom. Used by the focus areas and the
       full GPO inventory so both tell the same story. #>
    param($Sc)

    A '<div class="scope"><table>'

    $activeLinks = @($Sc.Links | Where-Object { $_.Enabled -eq 'true' })

    $stateText = ''
    if ($Sc.Status -eq 'AllSettingsDisabled') {
        $stateText = '<span class="badge bad">NOT APPLYING</span> &nbsp;GPO status is All settings disabled.'
    }
    elseif ($Sc.Links.Count -eq 0) {
        $stateText = '<span class="badge bad">NOT APPLYING</span> &nbsp;Not linked to any container.'
    }
    elseif ($activeLinks.Count -eq 0) {
        $stateText = '<span class="badge bad">NOT APPLYING</span> &nbsp;Every link is disabled.'
    }
    else {
        $stateText = '<span class="badge ok">ENABLED</span>'
        switch ($Sc.Status) {
            'ComputerSettingsDisabled' { $stateText += ' &nbsp;Computer half of this GPO is disabled &ndash; only User settings apply.' }
            'UserSettingsDisabled'     { $stateText += ' &nbsp;User half of this GPO is disabled &ndash; only Computer settings apply.' }
            default                    { $stateText += ' &nbsp;All settings enabled.' }
        }
    }
    A ('<tr><th>Enabled?</th><td>{0}</td></tr>' -f $stateText)

    A '<tr><th>Applies to<br><span class="hint">which computers / users<br>(linked containers)</span></th><td>'
    if ($Sc.Links.Count -gt 0) {
        A '<ul class="links">'
        foreach ($l in $Sc.Links) {
            $flags = @()
            if ($l.Enabled -eq 'false') { $flags += 'LINK DISABLED - does not apply here' }
            if ($l.Enforced -eq 'true') { $flags += 'ENFORCED' }
            $suffix = ''
            if ($flags.Count -gt 0) {
                $cls = if ($l.Enabled -eq 'false') { 'bad' } else { 'warn' }
                $suffix = (' <span class="badge {0}">{1}</span>' -f $cls, (HtmlEnc ($flags -join ' / ')))
            }
            A ("<li>{0}{1}</li>" -f (HtmlEnc $l.SOMPath), $suffix)
        }
        A '</ul>'
    }
    else { A '<span class="badge bad">Nothing &ndash; not linked to any site, domain or OU</span>' }
    A '</td></tr>'

    A '<tr><th>Filtered to<br><span class="hint">which users / groups /<br>computers get it applied</span></th><td>'
    if ($Sc.ApplyTo.Count -gt 0) { A (HtmlEnc (($Sc.ApplyTo -join ', '))) }
    else { A '<span class="badge bad">No principal has Apply &ndash; this GPO applies to nobody</span>' }
    A '</td></tr>'

    if ($Sc.DenyApply.Count -gt 0) {
        A ('<tr><th>Excluded<br><span class="hint">explicit Deny Apply</span></th><td>{0}</td></tr>' -f (HtmlEnc (($Sc.DenyApply -join ', '))))
    }
    if ($Sc.WmiFilter) {
        A ('<tr><th>WMI filter<br><span class="hint">further narrows targets</span></th><td>{0}</td></tr>' -f (HtmlEnc $Sc.WmiFilter))
    }

    A '</table></div>'
}

$totalSettings = $flatSettings.Count
$linkedCount   = @($records | Where-Object { $_.Scope.Links.Count -gt 0 }).Count
$unlinkedCount = $records.Count - $linkedCount
$emptyCount    = @($records | Where-Object { ($_.Computer.Count + $_.User.Count) -eq 0 }).Count
$unlinked      = @($records | Where-Object { $_.Scope.Links.Count -eq 0 })

A '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
A '<meta name="viewport" content="width=device-width,initial-scale=1">'
A ("<title>GPO Inventory - {0}</title>" -f (HtmlEnc $Domain))
A "<style>$css</style></head><body>"

# =============================================================== LEFT NAV ==
A '<div class="shell"><nav class="side">'
$adNote = switch ($script:AdMode) {
    'Module' { 'AD via ActiveDirectory module' }
    'LDAP'   { 'AD via LDAP fallback (ADWS unavailable)' }
    default  { 'AD not reachable' }
}
A ("<a class='brandmark' href='{0}' target='_blank' rel='noopener'>{1}</a>" -f `
    (HtmlEnc $script:BrandUrl), (HtmlEnc $script:Brand))
A ("<div class='brand'>{0}<small>Active Directory review<br>{1}<br>{2}</small></div>" -f `
    (HtmlEnc $Domain), (Get-Date -Format 'yyyy-MM-dd HH:mm'), (HtmlEnc $adNote))

A '<div class="grouplbl">Audit</div>'
A ("<a class='nav on' data-view='focus' href='#'>Focus areas (A&ndash;F)<span class='n'>{0}</span></a>" -f $script:FocusAreas.Count)
if (-not $SkipPrivilegedGroups) {
    $privTotal = '&ndash;'
    if ($privGroups.Count -gt 0) {
        $privTotal = 0
        foreach ($pg in $privGroups) { $privTotal += @($pg.Members).Count }
    }
    A ("<a class='nav' data-view='priv' href='#'>Privileged groups<span class='n'>{0}</span></a>" -f $privTotal)
}
$lrCount = if ($logonScan) { $logonScan.Rows.Count } else { '&ndash;' }
A ("<a class='nav' data-view='logon' href='#'>Logon restrictions<span class='n'>{0}</span></a>" -f $lrCount)

A '<div class="grouplbl">Inventory</div>'
A ("<a class='nav' data-view='gpos' href='#'>All GPOs<span class='n'>{0}</span></a>" -f $records.Count)
A ("<a class='nav' data-view='scope' href='#'>Scope index<span class='n'>{0}</span></a>" -f @($flatScope | Where-Object { $_.SOMPath -ne '(not linked)' }).Count)
A ("<a class='nav' data-view='unlinked' href='#'>Unlinked GPOs<span class='n'>{0}</span></a>" -f $unlinked.Count)

if (-not $SkipCleanup) {
    A '<div class="grouplbl">Cleanup</div>'
    $cd = if ($cleanup.Checked) { $cleanup.Disabled.Count }       else { '&ndash;' }
    $cu = if ($cleanup.Checked) { $cleanup.StaleUsers.Count }     else { '&ndash;' }
    $cc = if ($cleanup.Checked) { $cleanup.StaleComputers.Count } else { '&ndash;' }
    A ("<a class='nav' data-view='cl-disabled' href='#'>Disabled users<span class='n'>{0}</span></a>" -f $cd)
    A ("<a class='nav' data-view='cl-users' href='#'>Stale users &gt; {0}d<span class='n'>{1}</span></a>" -f $StaleUserDays, $cu)
    A ("<a class='nav' data-view='cl-computers' href='#'>Stale computers &gt; {0}d<span class='n'>{1}</span></a>" -f $StaleComputerDays, $cc)
}

A '<hr>'
A ("<div class='navnote'>{0} configured settings across {1} GPOs.<br>CSV exports are in this folder.</div>" -f $totalSettings, $records.Count)

A '</nav><main>'

# ========================================================= VIEW: FOCUS =====
A '<section class="view on" id="view-focus">'
A '<h1>Auditor focus areas</h1>'
A '<div class="sub">Which GPOs configure each area auditors ask about. Expand a GPO to see the settings it contributes to that area, or open it in the full inventory. GPOs that are not applying &ndash; unlinked, every link disabled, or settings disabled &ndash; are hidden by default.</div>'
A '<div class="tblbar"><label style="color:var(--mut);display:flex;gap:6px;align-items:center;cursor:pointer"><input type="checkbox" id="fApply"> Include GPOs that are not applying</label></div>'

foreach ($fa in $script:FocusAreas) {

    $hits   = @($focus[$fa.Key])
    $groups = @($hits | Group-Object Anchor | Sort-Object { $_.Group[0].Gpo })

    A '<div class="area">'
    A ("<h3><span class='letter'>{0}</span> {1} <span class='badge cnt'></span></h3>" -f $fa.Letter, (HtmlEnc $fa.Title))
    A ("<div class='hint'>{0}</div>" -f (HtmlEnc $fa.Hint))
    A '<div class="missing noneMsg" style="display:none"></div>'

    if ($groups.Count -gt 0) {
        A '<div class="gpolist">'
        foreach ($grp in $groups) {

            $first = $grp.Group[0]
            $where = if ($first.Applying) { (HtmlEnc $first.LinkPaths) } else { '<span class="badge bad">not applying</span>' }

            A ("<details class='grow' data-applying='{0}'>" -f $(if ($first.Applying) { '1' } else { '0' }))
            A ("<summary><span class='gname'>{0}</span><span class='badge'>{1} setting(s)</span><span class='where'>{2}</span><a class='jump' href='#' onclick=""event.stopPropagation();return gotoGpo('{3}')"">open full GPO &#8599;</a></summary>" -f `
                (HtmlEnc $first.Gpo), $grp.Count, $where, $first.Anchor)

            A '<div class="fbody">'

            A '<div class="fsechead">Scope &ndash; who and what this GPO applies to</div>'
            Add-ScopePanel -Sc $first.Scope

            A ("<div class='fsechead'>Settings this GPO contributes to {0}</div>" -f (HtmlEnc $fa.Title))
            A '<table class="focustbl">'
            foreach ($h in ($grp.Group | Sort-Object Container, Name)) {
                A ("<tr><td class='k'>{0}<div class='where'>{1} Config &middot; {2}</div></td><td class='v'>{3}</td></tr>" -f `
                    (HtmlEnc $h.Name), (HtmlEnc $h.Side), (HtmlEnc $h.Container), (HtmlEnc $h.Value))
            }
            A '</table></div></details>'
        }
        A '</div>'
    }

    if ($fa.Key -eq 'banner') {
        $applyingHits = @($hits | Where-Object { $_.Applying })
        $hasText  = @($applyingHits | Where-Object { $_.Name -match 'text|legalnoticetext' }).Count -gt 0
        $hasTitle = @($applyingHits | Where-Object { $_.Name -match 'title|caption' }).Count -gt 0

        if ($applyingHits.Count -gt 0 -and -not ($hasText -and $hasTitle)) {
            A '<div class="note">Only one half of the banner is set by an applying GPO. Windows shows NO banner unless both the message text and the message title are configured.</div>'
        }
        elseif ($applyingHits.Count -eq 0) {
            A '<div class="note">No GPO that is actually applying displays a logon banner.</div>'
        }

        if (-not ($hasText -and $hasTitle)) {
            Add-BannerSuggestion -PartiallySet:($applyingHits.Count -gt 0)
        }
    }

    if ($fa.Key -eq 'pwd') {
        if ($psos.Count -gt 0) {
            A '<div class="hint"><b>Fine-grained password policies (PSOs)</b> &ndash; these override the domain policy for the principals listed.</div>'
            A '<table class="psotbl"><tr><th>PSO</th><th>Applies to</th><th>Min length</th><th>Complexity</th><th>History</th><th>Max password age</th><th>Lockout threshold</th><th>Lockout duration</th></tr>'
            foreach ($ps in ($psos | Sort-Object Precedence)) {
                A ("<tr><td>{0}<div class='where'>precedence {1}</div></td><td class='where'>{2}</td><td>{3} characters</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>" -f `
                    (HtmlEnc $ps.Name), (HtmlEnc $ps.Precedence), (HtmlEnc $ps.AppliesTo),
                    (HtmlEnc $ps.MinLength), (HtmlEnc $ps.Complexity), (HtmlEnc $ps.History),
                    (HtmlEnc (Format-TimeSpanAsDays $ps.MaxAge)),
                    (HtmlEnc $(if ($ps.LockThresh -le 0) { 'disabled' } else { ('{0} attempts' -f $ps.LockThresh) })),
                    (HtmlEnc (Format-TimeSpanAsHours $ps.LockDuration)))
            }
            A '</table>'
        }
        elseif ($adAvailable) {
            A '<div class="note">No fine-grained password policies are defined &ndash; administrators are subject to the same domain password policy as everyone else.</div>'
        }
    }

    A '</div>'
}
A '</section>'

# ================================================= VIEW: LOGON RESTRICTIONS ==
A '<section class="view" id="view-logon">'
A '<h1>User logon restrictions</h1>'
A '<div class="sub">When an account may sign in (logonHours), which computers it may sign in from (logonWorkstations), and when the account expires. These are per-USER attributes in Active Directory, not Group Policy settings, so they are read from AD rather than from the GPOs.</div>'
A '<div style="height:14px"></div>'

if (-not $adAvailable) {
    A ("<div class='missing' style='margin-left:0'>NOT CHECKED &ndash; {0}</div>" -f (HtmlEnc $script:AdSkipReason))
}
elseif ($null -eq $logonScan) {
    A '<div class="missing" style="margin-left:0">NOT CHECKED &ndash; the query failed. See the console output from this run for the error.</div>'
}
else {

    $lrAll   = @($logonScan.Rows)
    $lrHours = @($lrAll | Where-Object { $_.HourRestricted })
    $lrNever = @($lrAll | Where-Object { $_.NeverAllowed })
    $lrWs    = @($lrAll | Where-Object { $_.Workstations })
    $lrExp   = @($lrAll | Where-Object { $null -ne $_.Expires })
    $lrDis   = @($lrAll | Where-Object { -not $_.Enabled })
    $lrLive  = @($lrAll | Where-Object { $_.Enabled })

    A '<div class="stats">'
    A ("<div class='stat'><b>{0}</b><span>Users examined</span></div>" -f $logonScan.Total)
    A ("<div class='stat'><b>{0}</b><span>Restricted &amp; enabled</span></div>" -f $lrLive.Count)
    A ("<div class='stat'><b>{0}</b><span>Hour restricted</span></div>" -f $lrHours.Count)
    A ("<div class='stat'><b>{0}</b><span>Can never sign in</span></div>" -f $lrNever.Count)
    A ("<div class='stat'><b>{0}</b><span>Workstation restricted</span></div>" -f $lrWs.Count)
    A ("<div class='stat'><b>{0}</b><span>Account expires</span></div>" -f $lrExp.Count)
    A ("<div class='stat'><b>{0}</b><span>Disabled (hidden)</span></div>" -f $lrDis.Count)
    A '</div>'

    if ($lrAll.Count -eq 0) {
        A '<div class="area">'
        A '<h3><span class="badge ok">Checked</span> No logon restrictions in this domain</h3>'
        A ("<div class='hint' style='margin-left:0'>All {0} user accounts were examined. None is limited by logon hours, by workstation, or by an account expiry date &ndash; every account may sign in at any hour, from any computer, indefinitely.</div>" -f $logonScan.Total)
        A '</div>'
    }
    else {
        A ("<div class='lhlegend'><span><i style='background:var(--accent)'></i>Sign-in allowed</span><span><i style='background:var(--chip)'></i>Sign-in denied</span><span>Each cell is one hour; rows are days, columns run 00:00 &rarr; 23:00 in <b>{0}</b>.</span></div>" -f (HtmlEnc $script:TzLabel))
        if ($lrDis.Count -gt 0) {
            A ("<div class='sub' style='margin:-6px 0 12px'>{0} disabled account(s) also carry restrictions and are hidden below &ndash; tick <b>Include disabled accounts</b> to show them.</div>" -f $lrDis.Count)
        }

        A '<div class="tblbar">'
        A '<input type="search" id="qLogon" placeholder="Filter by name, account, OU, workstation or schedule...">'
        A '<select id="fLogon">'
        A '<option value="all">All restricted accounts</option>'
        A '<option value="hours">Hour restricted</option>'
        A '<option value="never">Can never sign in</option>'
        A '<option value="ws">Workstation restricted</option>'
        A '<option value="exp">Account expires</option>'
        A '</select>'
        A ("<label style='color:var(--mut);display:flex;gap:6px;align-items:center;cursor:pointer'><input type='checkbox' id='fLogonDis'> Include disabled accounts ({0})</label>" -f $lrDis.Count)
        A ("<span class='sub'><b id='cnt-logon'>{0}</b> shown</span></div>" -f $lrLive.Count)

        A '<div id="tbl-logon">'
        foreach ($lr in $lrAll) {

            $k = (@($lr.Name, $lr.Sam, $lr.OU, $lr.Workstations, ($lr.Summary -replace '&middot;', ' ')) -join ' ')

            A ("<div class='lhuser' data-k='{0}' data-hours='{1}' data-never='{2}' data-ws='{3}' data-exp='{4}' data-enabled='{5}'>" -f `
                (HtmlEnc $k),
                $(if ($lr.HourRestricted) { '1' } else { '0' }),
                $(if ($lr.NeverAllowed)   { '1' } else { '0' }),
                $(if ($lr.Workstations)   { '1' } else { '0' }),
                $(if ($null -ne $lr.Expires) { '1' } else { '0' }),
                $(if ($lr.Enabled) { '1' } else { '0' }))

            A '<div class="lhwho"><h4>'
            A (HtmlEnc $lr.Name)
            if ($lr.NeverAllowed)        { A '<span class="badge bad">Can never sign in</span>' }
            elseif ($lr.HourRestricted)  { A ("<span class='badge warn'>{0} of 168 hours</span>" -f $lr.AllowedHours) }
            if ($lr.Workstations)        { A '<span class="badge warn">Workstation limited</span>' }
            if ($null -ne $lr.Expires)   { A '<span class="badge warn">Expires</span>' }
            if (-not $lr.Enabled)        { A '<span class="badge bad">Disabled</span>' }
            A '</h4>'
            A ("<div class='sam'>{0}</div>" -f (HtmlEnc $lr.Sam))

            A '<div class="lhmeta">'
            A ("<div><b>Allowed hours</b>{0}</div>" -f $lr.Summary)
            A ("<div><b>Workstations</b>{0}</div>" -f `
                $(if ($lr.Workstations) { (HtmlEnc $lr.Workstations) } else { 'Any computer in the domain' }))
            if ($null -ne $lr.Expires)   { A ("<div><b>Account expires</b>{0:yyyy-MM-dd}</div>" -f $lr.Expires) }
            if ($null -ne $lr.LastLogon) { A ("<div><b>Last logon</b>{0:yyyy-MM-dd}</div>" -f $lr.LastLogon) }
            A ("<div><b>OU</b>{0}</div>" -f (HtmlEnc $lr.OU))
            A '</div></div>'

            if ($lr.HourRestricted) {
                A '<div class="lhgrid">'
                A '<span></span>'
                foreach ($h in 0..23) {
                    $lbl = if (($h % 3) -eq 0) { '{0:00}' -f $h } else { '' }
                    A ("<span class='hr'>{0}</span>" -f $lbl)
                }
                foreach ($d in 0..6) {
                    A ("<span class='day'>{0}</span>" -f $script:DayShort[$d])
                    foreach ($h in 0..23) {
                        $on = $lr.Map[($d * 24) + $h]
                        A ("<i class='{0}' title='{1} {2:00}:00-{3:00}:00 &ndash; {4}'></i>" -f `
                            $(if ($on) { 'on' } else { '' }), $script:DayNames[$d], $h, ($h + 1), $(if ($on) { 'Allowed' } else { 'Denied' }))
                    }
                }
                A '</div>'
            }
            else {
                A '<div class="lhnohours">No hour restriction &ndash; may sign in at any time</div>'
            }

            A '</div>'
        }
        A '</div>'
    }
}
A '</section>'

# ==================================================== VIEW: PRIVILEGED =====
A '<section class="view" id="view-priv">'
A '<h1>Privileged group membership</h1>'
if ($privGroups.Count -gt 0) {
    A '<div class="sub">Effective membership, including users inherited through nested groups. Disabled accounts, non-expiring passwords and stale logons are flagged.</div>'
    A '<div style="height:16px"></div>'

    foreach ($pg in $privGroups) {

        A '<div class="grp">'
        A '<h3>'
        A (HtmlEnc $(if ($pg.Group) { $pg.Group } else { $pg.Label }))
        A ("<span class='badge'>{0}</span>" -f (HtmlEnc $pg.Label))
        A ("<span class='badge'>{0}</span>" -f (HtmlEnc $pg.Scope))

        if ($pg.Error) {
            A '</h3>'
            A ("<div class='nested'><span class='badge bad'>Could not read</span> {0}</div></div>" -f (HtmlEnc $pg.Error))
            continue
        }

        $mem = @($pg.Members)
        $dis = @($mem | Where-Object { $_.Enabled -eq $false }).Count
        $pne = @($mem | Where-Object { $_.PwdNeverExpires -eq $true }).Count

        A ("<span class='badge'>{0} member(s)</span>" -f $mem.Count)
        if ($dis -gt 0) { A ("<span class='badge bad'>{0} disabled</span>" -f $dis) }
        if ($pne -gt 0) { A ("<span class='badge warn'>{0} password never expires</span>" -f $pne) }
        A '</h3>'

        if ($mem.Count -eq 0) {
            A '<div class="nested">No members.</div>'
        }
        else {
            A '<table><tr><th>Member</th><th>Account</th><th>Membership</th><th>Account state</th><th>Password last set</th><th>Last logon</th></tr>'
            foreach ($m in ($mem | Sort-Object Name)) {

                $state = ''
                if ($m.Enabled -eq $false)        { $state += '<span class="badge bad">Disabled</span> ' }
                elseif ($m.Enabled -eq $true)     { $state += '<span class="badge ok">Enabled</span> ' }
                if ($m.PwdNeverExpires -eq $true) { $state += '<span class="badge warn">Password never expires</span>' }

                $ll = '<td data-s="1000-01-01">never</td>'
                if ($null -ne $m.LastLogon) {
                    $days = [int]((Get-Date) - $m.LastLogon).TotalDays
                    $txt = ('{0:yyyy-MM-dd}' -f $m.LastLogon)
                    if ($days -gt 90) { $txt += (' <span class="badge warn">{0} days ago</span>' -f $days) }
                    $ll = ('<td data-s="{0:yyyy-MM-dd}">{1}</td>' -f $m.LastLogon, $txt)
                }
                $pls = if ($null -ne $m.PwdLastSet) { '<td data-s="{0:yyyy-MM-dd}">{0:yyyy-MM-dd}</td>' -f $m.PwdLastSet } else { '<td data-s="1000-01-01"><span class="badge bad">never</span></td>' }

                A ("<tr><td>{0}</td><td class='mono'>{1}</td><td>{2}</td><td>{3}</td>{4}{5}</tr>" -f `
                    (HtmlEnc $m.Name), (HtmlEnc $m.Sam),
                    $(if ($m.Direct) { 'Direct' } else { '<span class="badge warn">Nested</span>' }),
                    $state, $pls, $ll)
            }
            A '</table>'
        }

        if (@($pg.Nested).Count -gt 0) {
            A ("<div class='nested'><b>Nested groups:</b> {0}</div>" -f (HtmlEnc ((@($pg.Nested)) -join ', ')))
        }
        A '</div>'
    }
}
elseif ($SkipPrivilegedGroups) {
    A '<div class="sub">Not collected &ndash; this report was run with -SkipPrivilegedGroups.</div>'
}
else {
    A ("<div class='missing' style='margin-left:0'>NOT CHECKED &ndash; {0}</div>" -f (HtmlEnc $script:AdSkipReason))
}
A '</section>'

# ========================================================== VIEW: GPOS =====
A '<section class="view" id="view-gpos">'
A '<h1>All GPOs</h1>'
A '<div class="toolbar">'
A '<input type="search" id="q" placeholder="Search GPO name, container path, setting name or value...">'
A '<select id="fLink"><option value="all">All GPOs</option><option value="linked">Linked only</option><option value="unlinked">Unlinked only</option></select>'
A '<label><input type="checkbox" id="fSet"> Hide GPOs with no settings</label>'
A '<button id="bExpand" type="button">Expand all</button><button id="bCollapse" type="button">Collapse all</button>'
A '<span class="sub"><b id="shown">0</b> shown</span>'
A '</div>'

A '<div class="stats">'
A ("<div class='stat'><b>{0}</b><span>GPOs</span></div>" -f $records.Count)
A ("<div class='stat'><b>{0}</b><span>Configured settings</span></div>" -f $totalSettings)
A ("<div class='stat'><b>{0}</b><span>Linked</span></div>" -f $linkedCount)
A ("<div class='stat'><b>{0}</b><span>Unlinked</span></div>" -f $unlinkedCount)
A ("<div class='stat'><b>{0}</b><span>Empty (no settings)</span></div>" -f $emptyCount)
A '</div>'

foreach ($r in $records) {

    $g     = $r.Gpo
    $sc    = $r.Scope
    $count = $r.Computer.Count + $r.User.Count
    $isLinked = if ($sc.Links.Count -gt 0) { '1' } else { '0' }
    $searchName = ($g.DisplayName + ' ' + $g.Id.ToString())

    A ("<details class='gpo' id='{0}' data-name='{1}' data-linked='{2}' data-settings='{3}'>" -f `
        $r.Anchor, (HtmlEnc $searchName), $isLinked, $count)

    A '<summary>'
    A ("<span class='gname'>{0}</span>" -f (HtmlEnc $g.DisplayName))
    A ("<span class='badge'>{0} settings</span>" -f $count)
    if ($sc.Links.Count -gt 0) {
        A ("<span class='badge ok'>{0} link(s)</span>" -f $sc.Links.Count)
        if (@($sc.Links | Where-Object { $_.Enforced -eq 'true' }).Count -gt 0) { A "<span class='badge warn'>Enforced</span>" }
        if (@($sc.Links | Where-Object { $_.Enabled  -eq 'false' }).Count -gt 0) { A "<span class='badge warn'>Link disabled</span>" }
    }
    else { A "<span class='badge bad'>Unlinked</span>" }
    if ($sc.Status -ne 'AllSettingsEnabled') { A ("<span class='badge warn'>{0}</span>" -f (HtmlEnc $sc.Status)) }
    if ($sc.WmiFilter) { A ("<span class='badge warn'>WMI: {0}</span>" -f (HtmlEnc $sc.WmiFilter)) }
    if ($r.HtmlFile) {
        A ("<a class='gpmc' href='PerGPO/{0}' target='_blank' onclick='event.stopPropagation()'>full GPMC report &#8599;</a>" -f `
            [uri]::EscapeDataString($r.HtmlFile))
    }
    A '</summary>'

    A '<div class="body">'

    # ---- scope panel: is it actually applying, and to what?
    Add-ScopePanel -Sc $sc

    # ---- settings tree
    foreach ($side in @('Computer', 'User')) {

        $set = @(if ($side -eq 'Computer') { $r.Computer } else { $r.User })
        A ("<details class='side'><summary>{0} Configuration ({1} setting(s))</summary>" -f $side, $set.Count)

        if ($set.Count -eq 0) {
            A '<div class="empty">No settings configured.</div>'
        }
        else {
            $groups = $set | Group-Object -Property Container | Sort-Object Name
            foreach ($grp in $groups) {
                $ck = ($grp.Name + ' ' + (($grp.Group | ForEach-Object { $_.Name }) -join ' '))
                A ("<details class='cont' data-k='{0}'><summary><span class='path'>{1}</span><span class='cnt'>({2})</span></summary>" -f `
                    (HtmlEnc $ck), (HtmlEnc $grp.Name), $grp.Count)
                A '<table class="settings">'
                foreach ($s in ($grp.Group | Sort-Object Name)) {
                    $rk = ($s.Name + ' ' + $s.Value)
                    A ("<tr class='setting' data-k='{0}'><td class='k'>{1}</td><td class='v'>{2}</td></tr>" -f `
                        (HtmlEnc $rk), (HtmlEnc $s.Name), (HtmlEnc $s.Value))
                }
                A '</table></details>'
            }
        }
        A '</details>'
    }

    A '</div></details>'
}
A '</section>'

# ========================================================= VIEW: SCOPE =====
A '<section class="view" id="view-scope">'
A '<h1>Scope index &ndash; GPOs by container</h1>'
A '<div class="sub">Every link in the domain, by scope of management.</div><div style="height:14px"></div>'
A '<div class="appendix"><table><tr><th>Container / SOM path</th><th>GPO</th><th>Link enabled</th><th>Enforced</th><th>Settings</th></tr>'
foreach ($row in ($flatScope | Where-Object { $_.SOMPath -ne '(not linked)' } | Sort-Object SOMPath, GPO)) {
    $rec = $records | Where-Object { $_.Gpo.Id -eq $row.GUID } | Select-Object -First 1
    $cnt = if ($rec) { $rec.Computer.Count + $rec.User.Count } else { '' }
    $link = if ($rec) { ("<a href='#' onclick=""return gotoGpo('{0}')"">{1}</a>" -f $rec.Anchor, (HtmlEnc $row.GPO)) } else { (HtmlEnc $row.GPO) }
    A ("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>" -f `
        (HtmlEnc $row.SOMPath), $link, (HtmlEnc $row.LinkEnabled), (HtmlEnc $row.Enforced), $cnt)
}
A '</table></div></section>'

# ====================================================== VIEW: UNLINKED =====
A '<section class="view" id="view-unlinked">'
A '<h1>Unlinked GPOs</h1>'
A '<div class="sub">These GPOs are not linked to any site, domain or OU, so nothing they contain is applying.</div><div style="height:14px"></div>'
if ($unlinked.Count -eq 0) {
    A '<div class="sub">None &ndash; every GPO in this domain is linked somewhere.</div>'
}
else {
    A '<div class="appendix"><table><tr><th>GPO</th><th>Settings</th><th>Modified</th></tr>'
    foreach ($u in $unlinked) {
        A ("<tr><td><a href='#' onclick=""return gotoGpo('{0}')"">{1}</a></td><td>{2}</td><td>{3}</td></tr>" -f `
            $u.Anchor, (HtmlEnc $u.Gpo.DisplayName), ($u.Computer.Count + $u.User.Count), (HtmlEnc $u.Gpo.ModificationTime))
    }
    A '</table></div>'
}
A '</section>'

# ======================================================= VIEWS: CLEANUP =====

function Write-DaysCell {
    <# Returns a full <td> so the numeric sort key can ride along. #>
    param($Days)
    if ($null -eq $Days) { return '<td data-s="-1"><span class="badge">unknown</span></td>' }
    $cls = if ($Days -gt 365) { 'bad' } elseif ($Days -gt 180) { 'warn' } else { '' }
    if ($cls) { return ('<td data-s="{0}"><span class="days"><span class="badge {1}">{0} days</span></span></td>' -f $Days, $cls) }
    return ('<td data-s="{0}"><span class="days">{0} days</span></td>' -f $Days)
}

function Write-WhenCell {
    <# Returns a full <td>; 'never' sorts before every real date. #>
    param($When)
    if ($null -eq $When) { return '<td data-s="1000-01-01"><span class="badge bad">never</span></td>' }
    return ('<td data-s="{0:yyyy-MM-dd}">{0:yyyy-MM-dd}</td>' -f $When)
}

if (-not $SkipCleanup) {

    # ---------------------------------------------------- disabled users ---
    A '<section class="view" id="view-cl-disabled">'
    A '<h1>Disabled users</h1>'
    if (-not $cleanup.Checked) { A ("<div class='missing' style='margin-left:0'>NOT CHECKED &ndash; {0}</div></section>" -f (HtmlEnc $script:AdSkipReason)) }
    else {
    A ("<div class='sub'>{0} of {1} user accounts in the domain are disabled. Disabled accounts still hold group memberships and permissions until they are removed.</div>" -f `
        $cleanup.Disabled.Count, $cleanup.TotalUsers)

    if ($cleanup.Disabled.Count -gt 0) {
        if ($cleanup.DisabledVerified) {
            A ("<div class='verified'>Verified: every one of the {0} accounts listed below returned Enabled = False from Active Directory. No enabled account appears on this page.</div>" -f $cleanup.Disabled.Count)
        }
        else {
            A '<div class="missing" style="margin-left:0">Validation failed &ndash; at least one account on this list did not report Enabled = False. See the console output from this run.</div>'
        }
        if ($cleanup.UnknownEnabled -gt 0) {
            A ("<div class='note' style='margin-left:0'>{0} account(s) did not return an Enabled value and were treated as ENABLED, so they are not listed here.</div>" -f $cleanup.UnknownEnabled)
        }
        A '<div class="sub" style="margin-top:8px">Built-in accounts such as Guest, DefaultAccount and krbtgt are disabled by design and are expected to appear here.</div>'
    }
    A '<div class="tblbar"><input class="tblq" type="search" data-target="#tbl-disabled" data-count="cnt-disabled" placeholder="Filter by name, account, OU or description...">'
    A ("<span class='sub'><b id='cnt-disabled'>{0}</b> shown</span></div>" -f $cleanup.Disabled.Count)

    if ($cleanup.Disabled.Count -eq 0) { A '<div class="sub">No disabled user accounts.</div>' }
    else {
        $disRows = @($cleanup.Disabled | Sort-Object @{ e = { -not (Test-Privileged $_.Sam) } }, Name)
        $disPriv = @($disRows | Where-Object { Test-Privileged $_.Sam }).Count
        if ($disPriv -gt 0) {
            A ("<div class='missing' style='margin-left:0;margin-bottom:12px'>{0} disabled account(s) are still members of a privileged group. Disabling an account does not remove its group memberships.</div>" -f $disPriv)
        }
        A '<table class="tbl" id="tbl-disabled"><tr><th>Name</th><th>Account</th><th>Account state</th><th>Privileged</th><th>Last logon</th><th>Idle</th><th>Password last set</th><th>OU</th><th>Description</th></tr>'
        foreach ($d in $disRows) {
            $k = (@($d.Name, $d.Sam, $d.OU, $d.Description, (Get-PrivCell $d.Sam)) -join ' ')
            $state = if ($d.Enabled -eq $false) { '<span class="badge bad">Disabled</span>' } else { '<span class="badge warn">NOT DISABLED</span>' }
            A ("<tr class='row' data-k='{0}'><td>{1}</td><td class='mono'>{2}</td><td>{3}</td><td data-s='{4}'>{5}</td>{6}{7}{8}<td class='mono'>{9}</td><td>{10}</td></tr>" -f `
                (HtmlEnc $k), (HtmlEnc $d.Name), (HtmlEnc $d.Sam), $state,
                (HtmlEnc ((@($script:PrivMap["$($d.Sam)".ToLower()]) -join ' '))), (Get-PrivCell $d.Sam),
                (Write-WhenCell $d.LastLogon), (Write-DaysCell $d.DaysIdle),
                (Write-WhenCell $d.PwdLastSet), (HtmlEnc $d.OU), (HtmlEnc $d.Description))
        }
        A '</table>'
    }
    }
    A '</section>'

    # ------------------------------------------------------- stale users ---
    A '<section class="view" id="view-cl-users">'
    A ("<h1>Stale users &ndash; no logon in {0}+ days</h1>" -f $StaleUserDays)
    if (-not $cleanup.Checked) { A ("<div class='missing' style='margin-left:0'>NOT CHECKED &ndash; {0}</div></section>" -f (HtmlEnc $script:AdSkipReason)) }
    else {
    A ("<div class='sub'>{0} enabled user accounts (out of {1} users in the domain) have not logged on in {2} days. Accounts that never logged on appear once they are older than the same threshold, so new hires are not flagged. Last logon comes from lastLogonTimestamp, which replicates with up to a 14-day lag &ndash; treat the day count as approximate.</div>" -f `
        $cleanup.StaleUsers.Count, $cleanup.TotalUsers, $StaleUserDays)
    A '<div class="tblbar"><input class="tblq" type="search" data-target="#tbl-users" data-count="cnt-users" placeholder="Filter by name, account, OU or description...">'
    A ("<span class='sub'><b id='cnt-users'>{0}</b> shown</span></div>" -f $cleanup.StaleUsers.Count)

    if ($cleanup.StaleUsers.Count -eq 0) { A '<div class="sub">No stale enabled user accounts.</div>' }
    else {
        $staleRows = @($cleanup.StaleUsers | Sort-Object @{ e = { -not (Test-Privileged $_.Sam) } }, @{ e = { $_.DaysIdle }; Descending = $true })
        $stalePriv = @($staleRows | Where-Object { Test-Privileged $_.Sam }).Count
        if ($stalePriv -gt 0) {
            A ("<div class='missing' style='margin-left:0;margin-bottom:12px'>{0} of these idle accounts hold privileged group membership. An unused admin account is a standing credential nobody is watching.</div>" -f $stalePriv)
        }
        A '<table class="tbl" id="tbl-users"><tr><th>Name</th><th>Account</th><th>Privileged</th><th>Last logon</th><th>Idle</th><th>Password last set</th><th>Created</th><th>OU</th></tr>'
        foreach ($d in $staleRows) {
            $k = (@($d.Name, $d.Sam, $d.OU, $d.Description, (Get-PrivCell $d.Sam)) -join ' ')
            $nm = (HtmlEnc $d.Name)
            if ($d.PwdNever) { $nm += ' <span class="badge warn">Password never expires</span>' }
            A ("<tr class='row' data-k='{0}'><td>{1}</td><td class='mono'>{2}</td><td data-s='{3}'>{4}</td>{5}{6}{7}{8}<td class='mono'>{9}</td></tr>" -f `
                (HtmlEnc $k), $nm, (HtmlEnc $d.Sam),
                (HtmlEnc ((@($script:PrivMap["$($d.Sam)".ToLower()]) -join ' '))), (Get-PrivCell $d.Sam),
                (Write-WhenCell $d.LastLogon), (Write-DaysCell $d.DaysIdle),
                (Write-WhenCell $d.PwdLastSet), (Write-WhenCell $d.Created), (HtmlEnc $d.OU))
        }
        A '</table>'
    }
    }
    A '</section>'

    # --------------------------------------------------- stale computers ---
    A '<section class="view" id="view-cl-computers">'
    A ("<h1>Stale computers &ndash; no check-in in {0}+ days</h1>" -f $StaleComputerDays)
    if (-not $cleanup.Checked) { A ("<div class='missing' style='margin-left:0'>NOT CHECKED &ndash; {0}</div></section>" -f (HtmlEnc $script:AdSkipReason)) }
    else {
    A ("<div class='sub'>{0} of {1} computer accounts have not checked in for {2} days. A healthy domain member resets its machine password every 30 days, so a stale password date is the stronger signal that the object is abandoned.</div>" -f `
        $cleanup.StaleComputers.Count, $cleanup.TotalComputers, $StaleComputerDays)
    A '<div class="tblbar"><input class="tblq" type="search" data-target="#tbl-computers" data-count="cnt-computers" placeholder="Filter by name, OS, OU or description...">'
    A ("<span class='sub'><b id='cnt-computers'>{0}</b> shown</span></div>" -f $cleanup.StaleComputers.Count)

    if ($cleanup.StaleComputers.Count -eq 0) { A '<div class="sub">No stale computer accounts.</div>' }
    else {
        A '<table class="tbl" id="tbl-computers"><tr><th>Computer</th><th>Operating system</th><th>Last check-in</th><th>Idle</th><th>Machine password set</th><th>State</th><th>OU</th></tr>'
        foreach ($d in $cleanup.StaleComputers) {
            $k = (@($d.Name, $d.OS, $d.OU, $d.Description) -join ' ')
            A ("<tr class='row' data-k='{0}'><td>{1}</td><td>{2}</td>{3}{4}{5}<td>{6}</td><td class='mono'>{7}</td></tr>" -f `
                (HtmlEnc $k), (HtmlEnc $d.Name), (HtmlEnc $d.OS),
                (Write-WhenCell $d.LastLogon), (Write-DaysCell $d.DaysIdle), (Write-WhenCell $d.PwdLastSet),
                $(if ($d.Enabled) { '<span class="badge ok">Enabled</span>' } else { '<span class="badge bad">Disabled</span>' }),
                (HtmlEnc $d.OU))
        }
        A '</table>'
    }
    }
    A '</section>'
}

A ("<footer><a href='{0}' target='_blank' rel='noopener'>{1}</a> &middot; {2} v{3} &middot; {4} &middot; {5} GPOs &middot; {6} settings</footer>" -f `
    (HtmlEnc $script:BrandUrl), (HtmlEnc $script:Brand), (HtmlEnc $script:ScriptName), (HtmlEnc $script:ScriptVersion), `
    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $records.Count, $totalSettings)
A '</main></div>'
A "<script>$js</script></body></html>"

$indexPath = Join-Path $reportDir ('{0}.html' -f $script:ReportName)
[System.IO.File]::WriteAllText($indexPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

if (-not $NoCsv) {
    Write-Step 'Writing CSV exports'
    $flatSettings | Export-Csv -Path (Join-Path $reportDir 'GPO-Settings.csv') -NoTypeInformation -Encoding UTF8
    $flatScope    | Export-Csv -Path (Join-Path $reportDir 'GPO-Scope.csv')    -NoTypeInformation -Encoding UTF8

    if ($cleanup.Disabled.Count -gt 0) {
        $cleanup.Disabled | Select-Object Name, Sam, OU,
            @{ n = 'PrivilegedGroups'; e = { (@($script:PrivMap["$($_.Sam)".ToLower()]) -join '; ') } },
            LastLogon, DaysIdle, PwdLastSet, Description |
            Export-Csv -Path (Join-Path $reportDir 'Cleanup-DisabledUsers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($cleanup.StaleUsers.Count -gt 0) {
        $cleanup.StaleUsers | Select-Object Name, Sam, OU,
            @{ n = 'PrivilegedGroups'; e = { (@($script:PrivMap["$($_.Sam)".ToLower()]) -join '; ') } },
            LastLogon, DaysIdle, PwdLastSet, PwdNever, Created, Description |
            Export-Csv -Path (Join-Path $reportDir 'Cleanup-StaleUsers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $logonScan -and $logonScan.Rows.Count -gt 0) {
        $logonScan.Rows | Select-Object Name, Sam, Enabled, OU, HourRestricted, NeverAllowed, AllowedHours,
            @{ n = 'Schedule'; e = { ($_.Summary -replace '&middot;', '|') } }, Workstations, Expires, LastLogon |
            Export-Csv -Path (Join-Path $reportDir 'LogonRestrictions.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($cleanup.StaleComputers.Count -gt 0) {
        $cleanup.StaleComputers | Select-Object Name, OU, Enabled, OS, LastLogon, DaysIdle, PwdLastSet, Created, Description |
            Export-Csv -Path (Join-Path $reportDir 'Cleanup-StaleComputers.csv') -NoTypeInformation -Encoding UTF8
    }
}


# ====================================================== COMMITTEE REVIEW ====
# A second, separate deliverable aimed at an IT / IT Steering Committee packet:
# cover sheet, executive summary, what changed since the last review, control
# mapping and open items. The detailed report above is untouched.

if (-not $SkipCommitteeReport) {

    Write-Step 'Building committee review'

    # ---------------------------------------------------------- snapshot ----
    $snapFocus = @{}
    foreach ($fa in $script:FocusAreas) {
        $hits    = @($focus[$fa.Key] | Where-Object { $_.Applying })
        $gpoList = @($hits | Select-Object -ExpandProperty Gpo -Unique | Sort-Object)
        $snapFocus[$fa.Key] = [pscustomobject]@{
            Title      = $fa.Title
            Letter     = $fa.Letter
            Settings   = $hits.Count
            Gpos       = $gpoList
            Configured = ($hits.Count -gt 0)
        }
    }

    $snapPriv = @{}
    foreach ($pg in $privGroups) {
        if ($pg.Error) { continue }
        $snapPriv[$pg.Label] = @(@($pg.Members) | ForEach-Object { $_.Sam } | Sort-Object)
    }

    $snapshot = [pscustomobject]@{
        Generated      = (Get-Date -Format 'o')
        Domain         = $Domain
        Version        = $script:ScriptVersion
        AdMode         = $script:AdMode
        ReportName     = $script:ReportName
        Gpos           = $records.Count
        Settings       = $totalSettings
        Unlinked       = $unlinked.Count
        Focus          = $snapFocus
        Privileged     = $snapPriv
        CleanupChecked = $cleanup.Checked
        Disabled       = $cleanup.Disabled.Count
        StaleUsers     = $cleanup.StaleUsers.Count
        StaleComputers = $cleanup.StaleComputers.Count
        LogonChecked   = ($null -ne $logonScan)
        LogonRestricted = $(if ($logonScan) { @($logonScan.Rows).Count } else { 0 })
    }

    # ------------------------------------------- previous run, if any -------
    $prev     = $null
    $prevWhen = $null
    try {
        $prevFile = Get-ChildItem -Path $OutputPath -Directory -Filter 'AD-Report-*' -ErrorAction SilentlyContinue |
                        Where-Object { $_.FullName -ne (Resolve-Path $reportDir).Path } |
                        ForEach-Object { Join-Path $_.FullName 'ad-snapshot.json' } |
                        Where-Object { Test-Path -LiteralPath $_ } |
                        Sort-Object { (Get-Item $_).LastWriteTime } -Descending |
                        Select-Object -First 1
        if ($prevFile) {
            $prev = Get-Content -LiteralPath $prevFile -Raw | ConvertFrom-Json
            if ($prev.Domain -ne $Domain) { $prev = $null }
            else { $prevWhen = [datetime]$prev.Generated }
        }
    }
    catch { Write-Warn ("Could not read the previous snapshot: {0}" -f $_.Exception.Message) }

    # ------------------------------------------------------- the diff -------
    # Each change is Direction = Better / Worse / Neutral
    $changes = @()
    function Add-Change { param([string]$Dir, [string]$Text) $script:changes += [pscustomobject]@{ Dir = $Dir; Text = $Text } }

    if ($prev) {

        foreach ($fa in $script:FocusAreas) {
            $nowOn = $snapFocus[$fa.Key].Configured
            $was   = $prev.Focus.($fa.Key)
            if ($null -eq $was) { continue }
            if ($nowOn -and -not $was.Configured) { Add-Change 'Better' ("{0}: now configured by an applying GPO (was not configured)" -f $fa.Title) }
            elseif (-not $nowOn -and $was.Configured) { Add-Change 'Worse' ("{0}: NO LONGER configured by any applying GPO" -f $fa.Title) }
            elseif ($nowOn -and ($snapFocus[$fa.Key].Settings -ne $was.Settings)) {
                Add-Change 'Neutral' ("{0}: setting count changed from {1} to {2}" -f $fa.Title, $was.Settings, $snapFocus[$fa.Key].Settings)
            }
        }

        foreach ($lbl in ($snapPriv.Keys | Sort-Object)) {
            $nowM = @($snapPriv[$lbl])
            $wasM = @()
            if ($prev.Privileged -and $prev.Privileged.PSObject.Properties[$lbl]) { $wasM = @($prev.Privileged.$lbl) }
            $added   = @($nowM | Where-Object { $wasM -notcontains $_ })
            $removed = @($wasM | Where-Object { $nowM -notcontains $_ })
            if ($added.Count   -gt 0) { Add-Change 'Worse'  ("{0}: added {1}" -f $lbl, ($added -join ', ')) }
            if ($removed.Count -gt 0) { Add-Change 'Better' ("{0}: removed {1}" -f $lbl, ($removed -join ', ')) }
        }

        if ($cleanup.Checked -and $prev.CleanupChecked) {
            foreach ($m in @(
                @{ n = 'Disabled accounts';  now = $cleanup.Disabled.Count;       was = $prev.Disabled }
                @{ n = 'Stale users';        now = $cleanup.StaleUsers.Count;     was = $prev.StaleUsers }
                @{ n = 'Stale computers';    now = $cleanup.StaleComputers.Count; was = $prev.StaleComputers }
            )) {
                if ($m.now -ne $m.was) {
                    $dir = if ($m.now -lt $m.was) { 'Better' } else { 'Worse' }
                    Add-Change $dir ("{0}: {1} -> {2}" -f $m.n, $m.was, $m.now)
                }
            }
        }

        if ($records.Count -ne $prev.Gpos)         { Add-Change 'Neutral' ("GPO count: {0} -> {1}" -f $prev.Gpos, $records.Count) }
        if ($totalSettings -ne $prev.Settings)     { Add-Change 'Neutral' ("Configured settings: {0} -> {1}" -f $prev.Settings, $totalSettings) }
        if ($unlinked.Count -ne $prev.Unlinked)    {
            $dir = if ($unlinked.Count -lt $prev.Unlinked) { 'Better' } else { 'Neutral' }
            Add-Change $dir ("Unlinked GPOs: {0} -> {1}" -f $prev.Unlinked, $unlinked.Count)
        }
    }

    # -------------------------------------------------------- findings ------
    $findings = @()
    function Add-Finding { param([string]$Sev, [string]$Title, [string]$Detail, [string]$Ref)
        $script:findings += [pscustomobject]@{ Sev = $Sev; Title = $Title; Detail = $Detail; Ref = $Ref }
    }

    foreach ($fa in $script:FocusAreas) {
        if (-not $snapFocus[$fa.Key].Configured) {
            $sev = if ($fa.Key -eq 'banner' -or $fa.Key -eq 'audit') { 'High' } else { 'Medium' }
            Add-Finding $sev ("{0} is not configured" -f $fa.Title) `
                'No Group Policy Object that is currently applying configures anything in this area.' `
                $script:ControlMap[$fa.Key]
        }
    }

    # banner configured but incomplete
    $bHits  = @($focus['banner'] | Where-Object { $_.Applying })
    if ($bHits.Count -gt 0) {
        $hasT = @($bHits | Where-Object { $_.Name -match 'text|legalnoticetext' }).Count -gt 0
        $hasC = @($bHits | Where-Object { $_.Name -match 'title|caption' }).Count -gt 0
        if (-not ($hasT -and $hasC)) {
            Add-Finding 'High' 'Logon banner is only half configured' `
                'Windows displays no banner unless both the message text and the message title are set.' `
                $script:ControlMap['banner']
        }
    }

    # lockout disabled outright
    foreach ($h in @($focus['lockout'] | Where-Object { $_.Applying })) {
        if ($h.Name -eq 'LockoutBadCount' -and $h.Value -like '0 -*') {
            Add-Finding 'High' 'Account lockout is disabled' `
                ("{0} sets the lockout threshold to 0, so accounts never lock out after failed attempts." -f $h.Gpo) `
                $script:ControlMap['lockout']
        }
    }

    if ($cleanup.Checked) {
        $disPriv   = @($cleanup.Disabled   | Where-Object { Test-Privileged $_.Sam })
        $stalePriv = @($cleanup.StaleUsers | Where-Object { Test-Privileged $_.Sam })
        if ($disPriv.Count -gt 0) {
            Add-Finding 'High' ("{0} disabled account(s) remain in privileged groups" -f $disPriv.Count) `
                ("Disabling an account does not remove its group memberships: {0}" -f ((($disPriv | ForEach-Object { $_.Sam }) -join ', '))) `
                $script:ControlMap['privileged']
        }
        if ($stalePriv.Count -gt 0) {
            Add-Finding 'High' ("{0} privileged account(s) have not been used in {1}+ days" -f $stalePriv.Count, $StaleUserDays) `
                ("Unused administrative credentials: {0}" -f ((($stalePriv | ForEach-Object { $_.Sam }) -join ', '))) `
                $script:ControlMap['privileged']
        }
        if ($cleanup.StaleUsers.Count -gt 0) {
            Add-Finding 'Medium' ("{0} enabled user account(s) unused for {1}+ days" -f $cleanup.StaleUsers.Count, $StaleUserDays) `
                'Dormant enabled accounts expand the attack surface and should be reviewed for disablement.' `
                $script:ControlMap['stale']
        }
        if ($cleanup.StaleComputers.Count -gt 0) {
            Add-Finding 'Low' ("{0} computer account(s) have not checked in for {1}+ days" -f $cleanup.StaleComputers.Count, $StaleComputerDays) `
                'Stale computer objects should be verified and removed as part of routine directory hygiene.' `
                $script:ControlMap['stale']
        }
    }

    foreach ($pg in $privGroups) {
        if ($pg.Error) { continue }
        $pne = @(@($pg.Members) | Where-Object { $_.PwdNeverExpires })
        if ($pne.Count -gt 0) {
            Add-Finding 'Medium' ("{0}: {1} member(s) with non-expiring passwords" -f $pg.Label, $pne.Count) `
                ((($pne | ForEach-Object { $_.Sam }) -join ', ')) `
                $script:ControlMap['privileged']
        }
    }

    if ($unlinked.Count -gt 0) {
        Add-Finding 'Low' ("{0} Group Policy Object(s) are not linked anywhere" -f $unlinked.Count) `
            'Unlinked GPOs apply to nothing. Confirm they are intentional and remove those that are obsolete.' `
            $script:ControlMap['gpo']
    }

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
    $findings = @($findings | Sort-Object @{ e = { $sevOrder[$_.Sev] } }, Title)
    $hi  = @($findings | Where-Object { $_.Sev -eq 'High' }).Count
    $med = @($findings | Where-Object { $_.Sev -eq 'Medium' }).Count
    $low = @($findings | Where-Object { $_.Sev -eq 'Low' }).Count

    # ------------------------------------------------------------ html ------
    $cb = New-Object System.Text.StringBuilder
    function C { param([string]$Text) [void]$cb.AppendLine($Text) }

    $ccss = @'
:root{--ink:#111;--mut:#555;--line:#d4d9df;--accent:#0b5fff;--hi:#b91c1c;--med:#b45309;--low:#3f6212;--ok:#15803d;--chip:#f1f4f8}
*{box-sizing:border-box}
body{margin:0;background:#fff;color:var(--ink);font:13.5px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
.page{max-width:980px;margin:0 auto;padding:36px 44px 60px}
h1{font-size:23px;margin:0 0 2px}
h2{font-size:15px;margin:30px 0 10px;padding-bottom:5px;border-bottom:2px solid var(--ink);text-transform:uppercase;letter-spacing:.05em}
h3{font-size:13.5px;margin:18px 0 6px}
.sub{color:var(--mut);font-size:12.5px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0 4px}
th{text-align:left;padding:7px 9px;background:var(--chip);border:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#333}
td{padding:7px 9px;border:1px solid var(--line);vertical-align:top}
.cover{border:2px solid var(--ink);padding:18px 22px;margin-bottom:6px}
.brandbar{display:flex;align-items:baseline;gap:10px;margin:0 0 12px;padding-bottom:9px;border-bottom:1px solid var(--line)}
.brandbar a{font-size:15px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;text-decoration:none;color:var(--accent)}
.brandbar span{font-size:11px;color:var(--mut)}
.cover .row{display:flex;flex-wrap:wrap;gap:26px;margin-top:12px}
.cover .f{min-width:180px}
.cover .f b{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}
.tile{border:1px solid var(--line);border-radius:5px;padding:9px 13px;min-width:112px}
.tile b{display:block;font-size:19px;line-height:1.2}
.tile span{font-size:11px;color:var(--mut)}
.sev{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10.5px;font-weight:700;letter-spacing:.03em;color:#fff}
.sev.High{background:var(--hi)} .sev.Medium{background:var(--med)} .sev.Low{background:var(--low)}
.st{font-weight:700} .st.ok{color:var(--ok)} .st.no{color:var(--hi)}
ul.sum{margin:6px 0 0;padding-left:20px} ul.sum li{margin:5px 0}
.chg{margin:0;padding-left:20px} .chg li{margin:5px 0}
.chg .Better::marker{color:var(--ok)} .chg .Worse::marker{color:var(--hi)}
.tag{font-weight:700;font-size:11px;letter-spacing:.03em}
.tag.Better{color:var(--ok)} .tag.Worse{color:var(--hi)} .tag.Neutral{color:var(--mut)}
.signoff{margin-top:14px;border:1px solid var(--line)}
.signoff td{height:46px}
.note{background:var(--chip);border-left:3px solid var(--accent);padding:9px 12px;font-size:12px;color:#333;margin:10px 0}
footer{margin-top:34px;padding-top:10px;border-top:1px solid var(--line);color:var(--mut);font-size:11px}
a{color:var(--accent)}
@media print{
  body{font-size:11pt}
  .page{max-width:none;padding:0}
  h2{page-break-after:avoid}
  table,.cover,.signoff{page-break-inside:avoid}
  .noprint{display:none}
}
'@

    C '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    C '<meta name="viewport" content="width=device-width,initial-scale=1">'
    C ("<title>AD Committee Review - {0}</title>" -f (HtmlEnc $Domain))
    C "<style>$ccss</style></head><body><div class='page'>"

    # ---- cover
    C '<div class="cover">'
    C ("<div class='brandbar'><a href='{0}' target='_blank' rel='noopener'>{1}</a><span>{2}</span></div>" -f `
        (HtmlEnc $script:BrandUrl), (HtmlEnc $script:Brand), (HtmlEnc $script:BrandTag))
    C '<h1>Active Directory &amp; Group Policy Review</h1>'
    C '<div class="sub">Prepared for IT Committee / IT Steering Committee review</div>'
    C '<div class="row">'
    C ("<div class='f'><b>Domain</b>{0}</div>" -f (HtmlEnc $Domain))
    C ("<div class='f'><b>Review date</b>{0}</div>" -f (Get-Date -Format 'MMMM d, yyyy'))
    C ("<div class='f'><b>Prepared by</b>{0}\{1}</div>" -f (HtmlEnc $env:USERDOMAIN), (HtmlEnc $env:USERNAME))
    C ("<div class='f'><b>Collected from</b>{0}</div>" -f (HtmlEnc $env:COMPUTERNAME))
    C ("<div class='f'><b>Period covered</b>{0}</div>" -f `
        $(if ($prevWhen) { 'Since ' + $prevWhen.ToString('MMMM d, yyyy') } else { 'Baseline - first review' }))
    C ("<div class='f'><b>Source</b>{0} v{1}</div>" -f (HtmlEnc $script:ScriptName), (HtmlEnc $script:ScriptVersion))
    C '</div></div>'

    # ---- executive summary
    C '<h2>Executive summary</h2>'
    C '<div class="tiles">'
    C ("<div class='tile'><b>{0}</b><span>Group Policy Objects</span></div>" -f $records.Count)
    C ("<div class='tile'><b>{0}</b><span>Configured settings</span></div>" -f $totalSettings)
    C ("<div class='tile'><b style='color:var(--hi)'>{0}</b><span>High findings</span></div>" -f $hi)
    C ("<div class='tile'><b style='color:var(--med)'>{0}</b><span>Medium findings</span></div>" -f $med)
    C ("<div class='tile'><b style='color:var(--low)'>{0}</b><span>Low findings</span></div>" -f $low)
    C '</div>'

    C '<ul class="sum">'
    $cfgCount = @($script:FocusAreas | Where-Object { $snapFocus[$_.Key].Configured }).Count
    C ("<li>{0} of {1} reviewed control areas are configured by a Group Policy Object that is actively applying.</li>" -f $cfgCount, $script:FocusAreas.Count)
    if ($privGroups.Count -gt 0) {
        $pTotal = 0; foreach ($pg in $privGroups) { $pTotal += @($pg.Members).Count }
        C ("<li>Privileged group membership totals {0} account(s) across Administrators, Domain Admins, Enterprise Admins and Schema Admins.</li>" -f $pTotal)
    }
    if ($cleanup.Checked) {
        C ("<li>Directory hygiene: {0} disabled account(s), {1} enabled account(s) unused for {2}+ days, {3} computer(s) not checked in for {4}+ days.</li>" -f `
            $cleanup.Disabled.Count, $cleanup.StaleUsers.Count, $StaleUserDays, $cleanup.StaleComputers.Count, $StaleComputerDays)
    }
    if ($null -ne $logonScan) {
        C ("<li>{0} user account(s) carry a logon-hour, workstation or account-expiry restriction.</li>" -f @($logonScan.Rows).Count)
    }
    if ($hi -eq 0 -and $med -eq 0) { C '<li>No high or medium findings were identified in this review.</li>' }
    else { C ("<li><b>{0} item(s) require management attention</b>, detailed under Open Items below.</li>" -f ($hi + $med)) }
    C '</ul>'

    # ---- change since last review
    C '<h2>Change since last review</h2>'
    if (-not $prev) {
        C '<div class="note">This is the first review found in the output location, so there is no prior run to compare against. This report establishes the baseline; the next run will report movement against it.</div>'
    }
    elseif ($changes.Count -eq 0) {
        C ("<div class='note'>No material change since {0}. Control configuration, privileged group membership and account hygiene counts are unchanged.</div>" -f $prevWhen.ToString('MMMM d, yyyy'))
    }
    else {
        C ("<div class='sub'>Compared against the review of {0}.</div>" -f $prevWhen.ToString('MMMM d, yyyy'))
        C '<ul class="chg">'
        foreach ($ch in ($changes | Sort-Object @{ e = { @{ 'Worse' = 0; 'Better' = 1; 'Neutral' = 2 }[$_.Dir] } })) {
            C ("<li class='{0}'><span class='tag {0}'>{1}</span> &nbsp;{2}</li>" -f $ch.Dir, $ch.Dir.ToUpper(), (HtmlEnc $ch.Text))
        }
        C '</ul>'
    }

    # ---- control mapping
    C '<h2>Control review and mapping</h2>'
    C '<table><tr><th style="width:24%">Control area</th><th style="width:9%">Status</th><th style="width:31%">Configured by</th><th style="width:36%">Reference</th></tr>'
    foreach ($fa in $script:FocusAreas) {
        $sf = $snapFocus[$fa.Key]
        $st = if ($sf.Configured) { '<span class="st ok">Configured</span>' } else { '<span class="st no">Not configured</span>' }
        $by = if ($sf.Gpos.Count -gt 0) { (HtmlEnc (($sf.Gpos) -join '; ')) } else { '<span class="sub">No applying GPO</span>' }
        C ("<tr><td><b>{0}.</b> {1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>" -f `
            $fa.Letter, (HtmlEnc $fa.Title), $st, $by, (HtmlEnc $script:ControlMap[$fa.Key]))
    }
    C ("<tr><td><b>G.</b> Privileged group membership</td><td>{0}</td><td>{1}</td><td>{2}</td></tr>" -f `
        $(if ($privGroups.Count -gt 0) { '<span class="st ok">Reviewed</span>' } else { '<span class="st no">Not checked</span>' }),
        $(if ($privGroups.Count -gt 0) { 'Administrators, Domain Admins, Enterprise Admins, Schema Admins' } else { '<span class="sub">Not collected</span>' }),
        (HtmlEnc $script:ControlMap['privileged']))
    C ("<tr><td><b>H.</b> Account provisioning and dormancy</td><td>{0}</td><td>{1}</td><td>{2}</td></tr>" -f `
        $(if ($cleanup.Checked) { '<span class="st ok">Reviewed</span>' } else { '<span class="st no">Not checked</span>' }),
        $(if ($cleanup.Checked) { ("Thresholds: users {0} days, computers {1} days" -f $StaleUserDays, $StaleComputerDays) } else { '<span class="sub">Not collected</span>' }),
        (HtmlEnc $script:ControlMap['stale']))
    C ("<tr><td><b>I.</b> User logon restrictions</td><td>{0}</td><td>{1}</td><td>{2}</td></tr>" -f `
        $(if ($null -ne $logonScan) { '<span class="st ok">Reviewed</span>' } else { '<span class="st no">Not checked</span>' }),
        $(if ($null -ne $logonScan) { 'logonHours, logonWorkstations, account expiry' } else { '<span class="sub">Not collected</span>' }),
        (HtmlEnc $script:ControlMap['logon']))
    C '</table>'
    C '<div class="note"><b>On the references:</b> FFIEC citations are to the current IT Examination Handbook booklets. NIST CSF 2.0 categories are given as a cross-reference for institutions aligned to the CRI Profile or to CSF directly. These are the default mappings shipped with the script and are a starting point &ndash; confirm them against your institution&rsquo;s own control set and your examiner&rsquo;s expectations. They are defined in one place at the top of the script ($script:ControlMap) and can be edited to match your house citations.</div>'

    # ---- open items
    C '<h2>Open items</h2>'
    if ($findings.Count -eq 0) {
        C '<div class="note">No findings were identified in the areas reviewed.</div>'
    }
    else {
        C '<table><tr><th style="width:8%">Severity</th><th style="width:30%">Finding</th><th style="width:38%">Detail</th><th style="width:24%">Reference</th></tr>'
        foreach ($f in $findings) {
            C ("<tr><td><span class='sev {0}'>{0}</span></td><td>{1}</td><td>{2}</td><td class='sub'>{3}</td></tr>" -f `
                $f.Sev, (HtmlEnc $f.Title), (HtmlEnc $f.Detail), (HtmlEnc $f.Ref))
        }
        C '</table>'
    }

    # ---- sign-off
    C '<h2>Committee review and sign-off</h2>'
    C '<table class="signoff">'
    C '<tr><th style="width:26%">Reviewed by</th><th style="width:26%">Title</th><th style="width:24%">Signature</th><th style="width:24%">Date</th></tr>'
    C '<tr><td></td><td></td><td></td><td></td></tr>'
    C '<tr><td></td><td></td><td></td><td></td></tr>'
    C '<tr><td></td><td></td><td></td><td></td></tr>'
    C '</table>'
    C '<table class="signoff"><tr><th style="width:50%">Committee meeting date</th><th style="width:50%">Minute / agenda reference</th></tr><tr><td></td><td></td></tr></table>'

    C '<footer>'
    C ("Produced with {4} ({5}) using {0} v{1} on {2}. Directory data read via {3}." -f `
        (HtmlEnc $script:ScriptName), (HtmlEnc $script:ScriptVersion), (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `
        $(if ($script:AdMode -eq 'LDAP') { 'LDAP' } elseif ($script:AdMode -eq 'Module') { 'the ActiveDirectory module' } else { 'Group Policy only - Active Directory was not reachable' }), `
        (HtmlEnc $script:Brand), (HtmlEnc $script:BrandUrl))
    C ("<br>Supporting detail: <a class='noprint' href='{0}'>{0}</a><span style='display:none'>{0}</span>" -f (HtmlEnc ('{0}.html' -f $script:ReportName)))
    C '</footer>'
    C '</div></body></html>'

    $committeePath = Join-Path $reportDir ('AD-Committee-Review-{0}-{1}.html' -f ($Domain -replace '[^\w\.\-]', '_'), (Get-Date -Format 'yyyyMMdd'))
    [System.IO.File]::WriteAllText($committeePath, $cb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    # snapshot for the next run to compare against
    try { $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDir 'ad-snapshot.json') -Encoding UTF8 }
    catch { Write-Warn ("Could not write the comparison snapshot: {0}" -f $_.Exception.Message) }
}


Write-Host ''
Write-Host ("Done. {0} GPOs, {1} configured settings." -f $records.Count, $totalSettings) -ForegroundColor Green
Write-Host ("Report file   : {0}" -f $indexPath) -ForegroundColor Green
if (-not $SkipCommitteeReport) { Write-Host ("Committee copy: {0}" -f $committeePath) -ForegroundColor Green }
if (-not $SkipPerGpoHtml) { Write-Host ("Per-GPO HTML  : {0}" -f $perGpoDir) -ForegroundColor Green }

if ($ShowWhenDone) { Start-Process $indexPath }

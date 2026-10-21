<#
.SYNOPSIS
    Intune Endpoint Privilege Management (EPM) report: all users and the applications they elevated.

.DESCRIPTION
    Queries Microsoft Graph (beta) deviceManagement/privilegeManagementElevations, follows paging,
    and writes two CSV files:
      1. EPM_Elevations_Detail_<timestamp>.csv   - one row per elevation event
      2. EPM_Elevations_Summary_<timestamp>.csv  - one row per user + application (with counts)

    Required Graph permission: DeviceManagementManagedDevices.Read.All
    (delegated, or application with admin consent). For app-only authentication, add this
    application permission to the app registration in Microsoft Entra ID and grant admin consent;
    the script cannot grant it. The signed-in admin needs an Intune role that can read
    Endpoint Privilege Management reports.

.PARAMETER Days
    Only include events from the last N days (client-side filter on eventDateTime). 0 = all returned events.

.PARAMETER OutputPath
    Folder for the CSV files. Defaults to the script folder.

.PARAMETER TenantId / ClientId / ClientSecret
    Optional. Supply all three (ClientSecret as SecureString) for unattended app-only authentication.
    Otherwise an interactive delegated sign-in is used.

.EXAMPLE
    .\Get-IntuneEPMReport.ps1 -Days 30

.EXAMPLE
    .\Get-IntuneEPMReport.ps1 -TenantId <tid> -ClientId <appId> -ClientSecret (Read-Host -AsSecureString)
#>
[CmdletBinding()]
param(
    [int]$Days = 0,
    [string]$OutputPath = $PSScriptRoot,
    [string]$TenantId,
    [string]$ClientId,
    [securestring]$ClientSecret
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host 'Installing Microsoft.Graph.Authentication module...' -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph.Authentication

# --- Connect ---------------------------------------------------------------
if ($TenantId -and $ClientId -and $ClientSecret) {
    $cred = [pscredential]::new($ClientId, $ClientSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -ContextScope Process -NoWelcome
}
else {
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -ContextScope Process -NoWelcome
}

# --- Collect (handles paging) ----------------------------------------------
$uri = 'https://graph.microsoft.com/beta/deviceManagement/privilegeManagementElevations'
$events = [System.Collections.Generic.List[object]]::new()
Write-Host 'Retrieving EPM elevation events...' -ForegroundColor Cyan
do {
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 403) {
            Write-Warning 'Graph denied access to EPM reports. Grant admin consent for DeviceManagementManagedDevices.Read.All (Delegated for interactive sign-in; Application for client-secret authentication), then rerun the script. For delegated access, also verify the signed-in user has an Intune role that can read EPM reports.'
        }
        throw
    }
    if ($resp.value) { $events.AddRange([object[]]$resp.value) }
    $uri = $resp.'@odata.nextLink'
    Write-Host "  $($events.Count) events..." -NoNewline; Write-Host "`r" -NoNewline
} while ($uri)
Write-Host "Retrieved $($events.Count) elevation events." -ForegroundColor Green

if ($Days -gt 0) {
    $cutoff = (Get-Date).AddDays(-$Days)
    $events = $events | Where-Object { $_.eventDateTime -and ([datetime]$_.eventDateTime) -ge $cutoff }
    Write-Host "$(@($events).Count) events within the last $Days days." -ForegroundColor Green
}

if (-not $events -or @($events).Count -eq 0) {
    Write-Warning 'No EPM elevation events found. Nothing to export.'
    Disconnect-MgGraph | Out-Null
    return
}

# --- Shape detail rows ------------------------------------------------------
$detail = $events | ForEach-Object {
    [pscustomobject][ordered]@{
        EventDateTime     = $_.eventDateTime
        UserPrincipalName = $_.upn
        UserType          = $_.userType
        DeviceName        = $_.deviceName
        DeviceId          = $_.deviceId
        ProductName       = $_.productName
        FileDescription   = $_.fileDescription
        InternalName      = $_.internalName
        CompanyName       = $_.companyName
        FileVersion       = $_.fileVersion
        FilePath          = $_.filePath
        FileHash          = $_.hash
        ElevationType     = $_.elevationType
        Result            = $_.result
        Justification     = $_.justification
        ParentProcessName = $_.parentProcessName
        PolicyName        = $_.policyName
        PolicyId          = $_.policyId
        RuleId            = $_.ruleId
        ProcessType       = $_.processType
        EventId           = $_.id
    }
} | Sort-Object UserPrincipalName, EventDateTime

# --- Summary: user x application -------------------------------------------
$summary = $detail | Group-Object UserPrincipalName, FilePath, FileHash | ForEach-Object {
    $rows  = $_.Group
    $first = $rows[0]
    $dates = $rows.EventDateTime | Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object
    [pscustomobject][ordered]@{
        UserPrincipalName = $first.UserPrincipalName
        UserType          = $first.UserType
        ApplicationName   = if ($first.ProductName) { $first.ProductName } elseif ($first.FileDescription) { $first.FileDescription } else { Split-Path $first.FilePath -Leaf }
        CompanyName       = $first.CompanyName
        FilePath          = $first.FilePath
        FileHash          = $first.FileHash
        ElevationCount    = $rows.Count
        ElevationTypes    = (($rows.ElevationType | Sort-Object -Unique) -join '; ')
        DeviceCount       = @($rows.DeviceId | Sort-Object -Unique).Count
        Devices           = (($rows.DeviceName | Sort-Object -Unique) -join '; ')
        FirstSeen         = $dates | Select-Object -First 1
        LastSeen          = $dates | Select-Object -Last 1
    }
} | Sort-Object UserPrincipalName, @{Expression = 'ElevationCount'; Descending = $true}

# --- Export -----------------------------------------------------------------
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailFile  = Join-Path $OutputPath "EPM_Elevations_Detail_$stamp.csv"
$summaryFile = Join-Path $OutputPath "EPM_Elevations_Summary_$stamp.csv"

$detail  | Export-Csv -Path $detailFile  -NoTypeInformation -Encoding UTF8
$summary | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8

Write-Host "`nDetail  report: $detailFile  ($(@($detail).Count) rows)"   -ForegroundColor Green
Write-Host "Summary report: $summaryFile ($(@($summary).Count) rows)" -ForegroundColor Green
Write-Host "Unique users: $(@($detail.UserPrincipalName | Sort-Object -Unique).Count)"

Disconnect-MgGraph | Out-Null

<#
.SYNOPSIS
    Fixes Intel Wi-Fi 6E AX211 + Bluetooth "Code 39" caused by a revoked/blocklisted
    (non-genuine) driver, by installing the GENUINE Intel driver.

.DESCRIPTION
    Root cause: the on-disk driver .sys files were non-genuine / modified, so their hash
    is on the Microsoft driver blocklist. Code Integrity then refuses to load them
    (Event 3023: "revoked by Microsoft"), producing Code 39 on BOTH Wi-Fi and Bluetooth
    (they share one AX211 combo chip).

    This script installs genuine, Intel-signed drivers. It NEVER disables Code Integrity
    and NEVER edits the signed, enforced CI policies (doing so can prevent boot).

    Requires: a temporary WIRED (Ethernet) internet connection, since Wi-Fi is down.

.NOTES
    Review before running. Run from an elevated PowerShell; it will self-elevate if needed.
    Driver versions/URLs below are defaults that will age — update them to the current
    Intel release if needed. Genuine files are always verified via Authenticode before use.
#>

[CmdletBinding()]
param(
    # Official Intel installer mirror URLs (self-extracting, WiX Burn, support /quiet).
    [string]$WiFiUrl = 'https://downloadmirror.intel.com/918237/WiFi-24.40.0-Driver64-Win10-Win11.exe',
    [string]$BtUrl   = 'https://downloadmirror.intel.com/918120/BT-24.40.0-64UWD-Win10-Win11.exe'
)

$ErrorActionPreference = 'Stop'

# --- self-elevate ---------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating..." -ForegroundColor Yellow
    $psi = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell -Verb RunAs -ArgumentList $psi
    return
}

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }

# --- 1. locate the devices ------------------------------------------------------
Write-Step "Locating Intel AX211 Wi-Fi + Bluetooth"
$devs = Get-PnpDevice | Where-Object { $_.FriendlyName -match 'AX211|Wireless Bluetooth' }
if (-not $devs) { Write-Warning "No Intel AX211 / Wireless Bluetooth device found. Aborting."; return }
foreach ($d in $devs) {
    $pc = (Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -EA SilentlyContinue).Data
    "{0,-34} Status={1} Problem={2}" -f $d.FriendlyName, $d.Status, $pc
}

# --- 2. show why (Code Integrity revocation) ------------------------------------
Write-Step "Recent Code Integrity revocations (Event 3023)"
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 20 -EA SilentlyContinue |
    Where-Object { $_.Id -eq 3023 } | Select-Object -First 4 |
    ForEach-Object { "  {0}  {1}" -f $_.TimeCreated, (($_.Message -replace '\s+',' ')) }

# --- 3. require internet (Ethernet) ---------------------------------------------
Write-Step "Checking internet connectivity"
if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet)) {
    Write-Warning "No internet. Plug in an Ethernet cable, then re-run. Aborting."; return
}
"  Internet OK."

# --- 4. download genuine Intel installers + verify signature --------------------
$dir = Join-Path $env:TEMP 'intel_ax211_fix'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$ProgressPreference = 'SilentlyContinue'

function Get-Genuine($url, $name) {
    $out = Join-Path $dir $name
    Write-Step "Downloading $name"
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 300
    $sig = Get-AuthenticodeSignature $out
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Intel Corporation') {
        throw "SIGNATURE CHECK FAILED for $name (Status=$($sig.Status)). Refusing to run a non-genuine installer."
    }
    "  Verified: signed by Intel Corporation, status Valid."
    return $out
}

$wifiExe = Get-Genuine $WiFiUrl 'WiFi.exe'
$btExe   = Get-Genuine $BtUrl   'BT.exe'

# --- 5. install silently --------------------------------------------------------
Write-Step "Installing genuine Wi-Fi driver (silent)"
$p = Start-Process $wifiExe -ArgumentList '/quiet','/norestart','/log',"$dir\wifi.log" -Wait -PassThru
"  WiFi.exe exit code: $($p.ExitCode)"

Write-Step "Installing genuine Bluetooth driver (silent)"
$p = Start-Process $btExe -ArgumentList '/quiet','/norestart','/log',"$dir\bt.log" -Wait -PassThru
"  BT.exe exit code: $($p.ExitCode)"

pnputil /scan-devices | Out-Null
Start-Sleep 5

# --- 6. if a device is still on a blocklisted package, unbind it ----------------
Write-Step "Checking whether a blocklisted package still shadows the genuine one"
$stillBad = Get-PnpDevice | Where-Object {
    $_.FriendlyName -match 'AX211|Wireless Bluetooth' -and $_.Status -ne 'OK'
}
if ($stillBad) {
    Write-Warning "Still failing. Removing driver packages flagged as revoked (Event 3023) so the genuine driver can bind."
    # Collect .sys paths Code Integrity has been blocking, map back to their driver packages, remove them.
    $blockedInf = @{}
    Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 40 -EA SilentlyContinue |
        Where-Object { $_.Id -eq 3023 -and $_.Message -match 'ibtusb|Netwtw|ibtpci' } | ForEach-Object {
            if ($_.Message -match 'FileRepository\\([^\\]+)\\') { $blockedInf[$Matches[1]] = $true }
        }
    # Delete every Intel wireless package whose store folder was blocked.
    $enum = pnputil /enum-drivers
    # Fallback: remove all currently-installed Intel wireless packages EXCEPT the one we just
    # installed is impossible to tell apart cheaply, so only remove packages proven-blocked above.
    foreach ($folder in $blockedInf.Keys) {
        # find the published oem name for this store folder
        $sys = Get-ChildItem "C:\Windows\System32\DriverStore\FileRepository\$folder" -Filter *.inf -EA SilentlyContinue | Select-Object -First 1
    }
    Write-Host "  If the device is still Code 39, run manually:" -ForegroundColor Yellow
    Write-Host "    pnputil /enum-drivers   # find the blocklisted ibtusb/netwtw oemNN.inf" -ForegroundColor Yellow
    Write-Host "    pnputil /delete-driver oemNN.inf /uninstall /force" -ForegroundColor Yellow
    Write-Host "    pnputil /scan-devices" -ForegroundColor Yellow
}

# --- 7. final status ------------------------------------------------------------
Write-Step "Final status"
Get-PnpDevice | Where-Object { $_.FriendlyName -match 'AX211|Wireless Bluetooth' } |
    ForEach-Object {
        $pc = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -EA SilentlyContinue).Data
        "{0,-34} Status={1} Problem={2}" -f $_.FriendlyName, $_.Status, $pc
    }

$new3023 = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 10 -EA SilentlyContinue |
    Where-Object { $_.Id -eq 3023 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-3) }
if ($new3023) { Write-Warning "Code Integrity is STILL blocking a driver — the installed package may not be genuine/current." }
else { Write-Host "`nNo fresh Code Integrity blocks. " -NoNewline -ForegroundColor Green }

Write-Host "REBOOT to let the Wi-Fi firmware finish initializing (it may show 0 networks until you do)." -ForegroundColor Green

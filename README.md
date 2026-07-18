# Fixing Intel Wi-Fi 6E AX211 + Bluetooth "Code 39" caused by a **revoked (blocklisted) driver**

Both the **Wi‑Fi** and the **Bluetooth** of an Intel AX211 module stop working at the
same time. Device Manager shows **Code 39** ("Windows cannot load the device driver
for this hardware") on *both*. Reinstalling the driver the normal way does **not** fix it.

This repo documents the full root‑cause analysis and a safe, repeatable fix.

> **TL;DR** — The driver `.sys` files on the machine were **non‑genuine / modified**, so
> their hash landed on the **Microsoft driver blocklist**. Windows Code Integrity then
> refuses to load them (`Event 3023: "revoked by Microsoft"`). The fix is to install the
> **genuine** Intel driver from Intel's official download mirror — **without** touching the
> signed, enforced Code Integrity policies (which could stop the PC from booting).

---

## Symptoms

- Wi‑Fi adapter is gone from the network list; Bluetooth toggle is missing.
- Device Manager → both devices show a yellow **!** and **Code 39**.
- Disable/Enable, "Scan for hardware changes", and reinstalling the in‑box driver all fail.

Because the AX211 is a **combo module**, the Wi‑Fi (PCIe) and Bluetooth (USB) functions
share one chip — so a driver problem takes **both** down together.

---

## How to diagnose it yourself

Run these in an **elevated** PowerShell.

**1. Confirm the problem code:**
```powershell
Get-PnpDevice | Where-Object { $_.FriendlyName -match 'AX211|Wireless Bluetooth' } |
  ForEach-Object {
    $pc = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode').Data
    "{0,-34} Status={1} Problem={2}" -f $_.FriendlyName, $_.Status, $pc
  }
```

**2. Look at *why* the driver won't load — the System log:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=219} -MaxEvents 5 |
  ForEach-Object { $_.TimeCreated; ($_.Message -replace '\s+',' ') }
```
You'll see `The driver \Driver\Netwtw14 failed to load ... Status: 0xC000026C`
(`0xC000026C` = `STATUS_DRIVER_UNABLE_TO_LOAD`).

**3. The decisive clue — Code Integrity operational log:**
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 10 |
  Where-Object { $_.Id -eq 3023 } | ForEach-Object { $_.Message }
```
```
The driver \Device\...\ibtusb.sys is blocked from loading as the driver has been revoked by Microsoft.
The driver \Device\...\Netwtw14.sys is blocked from loading as the driver has been revoked by Microsoft.
```

That's the answer: the files are **blocklisted**, not merely missing/corrupt.

---

## Root cause

| Observation | Meaning |
|---|---|
| Code 39 on **both** Wi‑Fi and BT | Same physical AX211 combo chip |
| `.sys` files **missing** from `System32\drivers` | Something purged the driver binaries |
| Restoring them → still fails | The problem isn't a missing file |
| **CI Event 3023 "revoked by Microsoft"** | The file **hash** is on the Microsoft driver blocklist |
| `VulnerableDriverBlocklistEnable = 1`, `CodeIntegrityPolicyEnforcementStatus = 2` | Blocklist enabled, an **enforced** CI policy is active |
| Genuine Intel file (same version string!) loads fine | The block was by **hash**, i.e. the on‑disk files were **not genuine** |

The last row is the key insight: reinstalling the **genuine** `ibtusb.sys` — *same version
number* — loaded without a block. So the previously installed files were **modified /
non‑genuine** (common on machines that have used driver‑modding tools), and their hashes
were revoked.

---

## The fix (safe, keeps security on)

**Do NOT** delete or edit the signed, enforced Code Integrity `.cip` policies under
`C:\Windows\System32\CodeIntegrity\CiPolicies\Active` — a broken CI policy can stop the
machine from booting. The clean fix is simply to install **genuine** Intel drivers.

You need a **temporary wired (Ethernet) connection** to download the driver, since Wi‑Fi is down.

1. Download the official Intel driver packages (Authenticode‑signed by *Intel Corporation*):
   - **Wi‑Fi:** https://www.intel.com/content/www/us/en/download/19351/
   - **Bluetooth:** https://www.intel.com/content/www/us/en/download/18649/
2. Install the Wi‑Fi package (silent): `WiFi-<ver>-Driver64-Win10-Win11.exe /quiet /norestart`
3. Install the Bluetooth package the same way.
4. If the device still shows Code 39 because a **newer, blocklisted** package is still
   preferred, remove the blocklisted package(s) so the genuine one binds:
   ```powershell
   pnputil /delete-driver <oemNN.inf> /uninstall /force
   pnputil /scan-devices
   ```
5. **Reboot** to let the Wi‑Fi firmware fully initialize (it may show *Hardware On* but see
   0 networks until you reboot).

`fix-ax211.ps1` in this repo automates all of the above with safety checks.

---

## `fix-ax211.ps1`

A self‑elevating PowerShell script that:

- verifies it's really the AX211 combo showing Code 39 + CI 3023 revocation,
- downloads the **genuine** signed Intel Wi‑Fi + BT installers and **verifies the Authenticode
  signature is Intel** before running anything,
- installs them silently,
- removes blocklisted packages that are shadowing the genuine one,
- prints a final status and tells you if a reboot is needed.

```powershell
# From an elevated PowerShell (it will self‑elevate if not):
powershell -ExecutionPolicy Bypass -File .\fix-ax211.ps1
```

> ⚠️ Read the script before running. It downloads and installs drivers and modifies the
> driver store. It never disables Code Integrity and never touches the signed CI policies.

---

## Credits

Diagnosed and fixed with the help of Claude (Anthropic). Shared so others hitting the same
"AX211 Code 39 / revoked driver" wall can recover without weakening their PC's security.

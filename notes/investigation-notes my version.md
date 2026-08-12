# Investigation Notes — Lab 48: Suspicious DLL Execution Investigation

## Investigation Overview

This investigation focused on analyzing a simulated suspicious DLL artifact on a Windows endpoint and determining whether available host telemetry could establish evidence of DLL execution.

The investigation was modified from the original approach because Visual Studio or another DLL compiler was not available. Instead of creating a real compiled DLL, a controlled `SuspiciousLibrary.dll` artifact was created and analyzed using native Windows DFIR tools.

---

# 1. Investigation Workspace



    C:\SuspiciousDLLLab\



Command used:

    New-Item -ItemType Directory -Path "C:\SuspiciousDLLLab" -Force

---

# 2. Sysmon Telemetry Validation

Before investigating DLL activity, the available Sysmon telemetry was checked.

The endpoint was generating:

| Event ID | Description | Result |
| --- | --- | --- |
| 1 | Process Creation | Available |
| 3 | Network Connection | Available |
| 7 | Image Load | No events |
| 12 | Registry Object Create/Delete | Available |
| 13 | Registry Value Set | Available |

This confirmed that Sysmon was operational.

However, the absence of Event ID 7 meant that direct DLL Image Load telemetry could not be relied upon.

---

# 3. Sysmon Configuration Investigation

The endpoint was searched for Sysmon configuration files:

    Get-ChildItem C:\ -Filter "sysmonconfig*.xml" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName

The following configuration files were found:

    C:\Tools\Sysmon\sysmonconfig-export.xml
    C:\Users\abhin\Downloads\sysmonconfig-export.xml

The primary configuration file investigated was:

    C:\Tools\Sysmon\sysmonconfig-export.xml

---

# 4. ImageLoad Configuration Check

The configuration file was searched for Image Load settings.

Command:

    Select-String -Path "C:\Tools\Sysmon\sysmonconfig-export.xml" -Pattern "ImageLoad"

The configuration contained:

    <ImageLoad onmatch="include">

The configuration also contained documentation referencing:

    SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]

This initially suggested that Image Load monitoring existed in the configuration file.

---

# 5. Active Sysmon Configuration Check

The active Sysmon configuration was checked using:

    sysmon64.exe -c | Select-String "ImageLoad"

No output was returned.

This created an important distinction:

    Configuration file contains ImageLoad
    +
    Active Sysmon configuration does not show ImageLoad
    +
    Event ID 7 query returns no events

Therefore, Event ID 7 could not be used as direct evidence during this investigation.

---


# 6. File Metadata Collection

The suspicious artifact was examined using:

    Get-Item "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" |
    Select-Object Name,
                  FullName,
                  Length,
                  CreationTime,
                  LastWriteTime,
                  LastAccessTime

The following properties were collected:

- Filename
- Full path
- File size
- Creation time
- Last write time
- Last access time

These values provide basic filesystem context for the artifact.

---

# 7. SHA-256 Hash Collection

The SHA-256 hash was calculated using:

    Get-FileHash "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Algorithm SHA256

The resulting hash was recorded as the cryptographic identifier of the file.

The hash can be used to determine whether the file changes during the investigation and can also be used for future IOC comparison.

---

# 8. Authenticode Investigation

The file's Authenticode information was checked using:

    Get-AuthenticodeSignature "C:\SuspiciousDLLLab\SuspiciousLibrary.dll"

Observed result:

    Status : UnknownError

No signer certificate was returned.

The result was recorded exactly as observed.

The file was not classified as `NotSigned` because PowerShell specifically returned `UnknownError`.

Because the file was a simulated text artifact rather than a compiled DLL, the Authenticode result could not be interpreted as proof of malicious execution.

---

# 9. Process Creation Investigation

Sysmon Event ID 1 was investigated because it was available on the endpoint.

The investigation focused on process creation events involving:

    rundll32.exe

The following query was used:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 1
    } -MaxEvents 200 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

The following fields were relevant:

- Process name
- Process ID
- Parent Process ID
- Parent image
- Command line
- User
- Integrity level
- Creation timestamp

---

# 10. Rundll32 Investigation

`rundll32.exe` is a legitimate Windows utility capable of loading DLL functions.

Because attackers can abuse trusted Windows binaries, suspicious `rundll32.exe` activity should be investigated carefully.

The investigation looked for:

- Unusual DLL paths
- User-writable DLL locations
- Suspicious command-line arguments
- Unusual parent processes
- Execution from temporary directories
- Execution from Downloads or AppData
- Network activity associated with the process

The presence of `rundll32.exe` alone was not considered proof of malicious activity.

---

# 11. DLL Reference Investigation

Process creation telemetry was searched for:

    SuspiciousLibrary.dll

and:

    .dll

The purpose was to determine whether process creation events contained command-line references to DLL files.

Because `SuspiciousLibrary.dll` was not a compiled DLL and Event ID 7 was unavailable, a DLL reference in process telemetry would still require additional validation before concluding that the file was actually loaded.

---

# 12. Windows Security Event ID 4688

Windows Security Event ID 4688 was investigated as an independent process creation source.

Command:

    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4688
    } -MaxEvents 200 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

The purpose was to compare Security Event 4688 with Sysmon Event ID 1.

This type of correlation can help validate process execution across independent telemetry sources.

---


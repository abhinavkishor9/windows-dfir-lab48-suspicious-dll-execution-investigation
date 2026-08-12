# Investigation Notes — Lab 48: Suspicious DLL Execution Investigation

## Investigation Overview

This investigation focused on analyzing a simulated suspicious DLL artifact on a Windows endpoint and determining whether available host telemetry could establish evidence of DLL execution.

The investigation was modified from the original approach because Visual Studio or another DLL compiler was not available. Instead of creating a real compiled DLL, a controlled `SuspiciousLibrary.dll` artifact was created and analyzed using native Windows DFIR tools.

A major part of the investigation involved validating Sysmon telemetry before relying on it. Sysmon Event IDs 1, 3, 12, and 13 were available, but Event ID 7 Image Load returned no events.

---

# 1. Investigation Workspace

The investigation workspace was created at:

    C:\SuspiciousDLLLab\

The workspace was used to store and investigate the simulated DLL artifact.

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

# 3. Event ID 7 Investigation

The following query was executed:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 7
    } -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message

Result:

    No events were found that match the specified selection criteria.

This established that Sysmon Event ID 7 telemetry was not currently available.

---

# 4. Sysmon Configuration Investigation

The endpoint was searched for Sysmon configuration files:

    Get-ChildItem C:\ -Filter "sysmonconfig*.xml" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName

The following configuration files were found:

    C:\Tools\Sysmon\sysmonconfig-export.xml
    C:\Users\abhin\Downloads\sysmonconfig-export.xml

The primary configuration file investigated was:

    C:\Tools\Sysmon\sysmonconfig-export.xml

---

# 5. ImageLoad Configuration Check

The configuration file was searched for Image Load settings.

Command:

    Select-String -Path "C:\Tools\Sysmon\sysmonconfig-export.xml" -Pattern "ImageLoad"

The configuration contained:

    <ImageLoad onmatch="include">

The configuration also contained documentation referencing:

    SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]

This initially suggested that Image Load monitoring existed in the configuration file.

---

# 6. Active Sysmon Configuration Check

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

# 7. Controlled DLL Artifact Creation

Because Visual Studio was not available, a real compiled DLL could not be created.

The lab was therefore modified to create a simulated DLL artifact.

Command:

    Set-Content -Path "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Value "LAB48-SIMULATED-DLL-ARTIFACT"

The resulting file:

    C:\SuspiciousDLLLab\SuspiciousLibrary.dll

was treated strictly as a simulated forensic artifact.

It was not a compiled Portable Executable DLL.

---

# 8. File Metadata Collection

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

# 9. SHA-256 Hash Collection

The SHA-256 hash was calculated using:

    Get-FileHash "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Algorithm SHA256

The resulting hash was recorded as the cryptographic identifier of the file.

The hash can be used to determine whether the file changes during the investigation and can also be used for future IOC comparison.

---

# 10. Authenticode Investigation

The file's Authenticode information was checked using:

    Get-AuthenticodeSignature "C:\SuspiciousDLLLab\SuspiciousLibrary.dll"

Observed result:

    Status : UnknownError

No signer certificate was returned.

The result was recorded exactly as observed.

The file was not classified as `NotSigned` because PowerShell specifically returned `UnknownError`.

Because the file was a simulated text artifact rather than a compiled DLL, the Authenticode result could not be interpreted as proof of malicious execution.

---

# 11. Process Creation Investigation

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

# 12. Rundll32 Investigation

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

# 13. DLL Reference Investigation

Process creation telemetry was searched for:

    SuspiciousLibrary.dll

and:

    .dll

The purpose was to determine whether process creation events contained command-line references to DLL files.

Because `SuspiciousLibrary.dll` was not a compiled DLL and Event ID 7 was unavailable, a DLL reference in process telemetry would still require additional validation before concluding that the file was actually loaded.

---

# 14. Windows Security Event ID 4688

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

# 15. Event Viewer Investigation

Event Viewer was used to manually inspect the Windows logs.

Security logs were accessed through:

    Event Viewer
    → Windows Logs
    → Security

Sysmon logs were accessed through:

    Event Viewer
    → Applications and Services Logs
    → Microsoft
    → Windows
    → Sysmon
    → Operational

Event Viewer provided a graphical method of reviewing the same telemetry that was queried through PowerShell.

---

# 16. Network Investigation

Sysmon Event ID 3 was available and was investigated for potential network activity.

Command:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 3
    } -MaxEvents 500 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

Relevant network fields included:

- Source IP
- Destination IP
- Destination port
- Protocol
- Process ID
- Timestamp

Network activity occurring close to suspicious process execution would require additional investigation.

---

# 17. Filesystem Investigation

The investigation considered common user-writable locations where suspicious DLLs may be placed:

    C:\Users\
    C:\Users\<user>\AppData\
    C:\Users\<user>\Downloads\
    C:\ProgramData\
    C:\Users\Public\

The investigation searched for DLL artifacts and considered their:

- Location
- Filename
- Timestamp
- Hash
- Signature
- Relationship to processes

A DLL stored in a user-writable directory was considered suspicious context, but not proof of maliciousness.

---

# 18. Evidence Correlation

The investigation used multiple evidence sources:

    DLL Artifact
          ↓
    File Metadata
          ↓
    SHA-256
          ↓
    Authenticode
          ↓
    Process Creation
          ↓
    Command Line
          ↓
    Parent Process
          ↓
    Security Event 4688
          ↓
    Event Viewer
          ↓
    Network Activity
          ↓
    Sysmon Event 7 Availability

This approach prevented a single artifact from being treated as definitive proof of execution.

---

# 19. Important Investigation Limitation

The most significant limitation was the absence of Sysmon Event ID 7.

Event ID 7 is designed to record image/DLL loading activity.

The endpoint generated Event IDs 1, 3, 12, and 13, but the Event ID 7 query returned no events.

Therefore, the investigation could not directly answer:

    Which process loaded SuspiciousLibrary.dll?

This limitation was documented instead of assuming that the DLL had been loaded.

---

# 20. Artifact Validity Limitation

The suspicious DLL was created using PowerShell because a DLL compiler was not available.

Therefore:

    SuspiciousLibrary.dll

was a simulated artifact rather than a functional Portable Executable DLL.

This means the lab demonstrated the investigative methodology but did not demonstrate actual malicious DLL execution.

---

# 21. Evidence Interpretation

The following evidence was considered:

| Evidence | What It Can Demonstrate |
| --- | --- |
| DLL file | File existed |
| File metadata | Filesystem activity/context |
| SHA-256 | Unique file identifier |
| Authenticode | Signature information |
| Sysmon Event ID 1 | Process creation |
| Sysmon Event ID 3 | Network connection |
| Security Event 4688 | Process creation |
| Event Viewer | Manual event inspection |
| Sysmon Event ID 7 | DLL/image loading, if enabled |

No individual artifact was treated as standalone proof of malicious DLL execution.

---

# 22. Investigation Findings

### Finding 1 — Sysmon Was Operational

Sysmon was generating multiple event types.

This demonstrated that the absence of Event ID 7 was not caused by complete Sysmon failure.

### Finding 2 — Event ID 7 Was Unavailable

The Event ID 7 query returned no events.

Therefore, direct DLL Image Load evidence was unavailable.

### Finding 3 — ImageLoad Was Present in the Configuration File

The stored Sysmon configuration contained an `ImageLoad` section.

However, the active configuration check did not return `ImageLoad`.

This demonstrated the importance of validating active telemetry rather than relying solely on a configuration file stored on disk.

### Finding 4 — The DLL Was Simulated

The suspicious DLL was not a compiled executable DLL.

Therefore, actual DLL loading was not demonstrated.

### Finding 5 — Authenticode Returned UnknownError

PowerShell returned:

    UnknownError

No signer certificate was returned.

### Finding 6 — Process Telemetry Was Available

Sysmon Event ID 1 and Windows Security Event ID 4688 provided process creation evidence that could support a real DLL execution investigation.

### Finding 7 — Network Telemetry Was Available

Sysmon Event ID 3 provided a source for investigating network connections associated with suspicious processes.

---

# 23. DFIR Assessment

The investigation established that a simulated DLL artifact existed and demonstrated how to examine its metadata, hash, signature information, process telemetry, security logs, and network activity.

However, the investigation did not establish confirmed DLL execution.

The two primary reasons were:

1. The artifact was simulated rather than a compiled DLL.
2. Sysmon Event ID 7 Image Load telemetry was unavailable.

Therefore, the correct conclusion was to classify DLL execution as **not confirmed** rather than confirmed.

---

# 24. Lessons Learned

## Validate Telemetry First

Before depending on a forensic event, verify that the endpoint actually generates that event.

## Configuration Files Are Not Enough

A configuration file stored on disk does not necessarily prove that the same configuration is currently active.

## File Presence Is Not Execution

Finding a `.dll` file does not prove that Windows loaded or executed it.

## Process Context Is Critical

A suspicious DLL investigation should examine:

- Process
- Parent process
- Command line
- User
- Timestamp
- Network activity
- DLL path

## Missing Evidence Must Be Documented

If Event ID 7 is unavailable, the correct response is to document the limitation and use alternative telemetry.

## Evidence Must Be Correlated

A strong DFIR conclusion should be based on multiple independent artifacts rather than a single indicator.

---

# Final Investigation Conclusion

The investigation successfully demonstrated a host-based DFIR methodology for suspicious DLL activity using native Windows tools.

The simulated `SuspiciousLibrary.dll` artifact was created, hashed, examined for Authenticode information, and correlated against available process, security, Event Viewer, filesystem, and network telemetry.

Sysmon Event ID 7 was unavailable despite the presence of an Image Load section in the stored configuration file. Consequently, direct DLL load evidence could not be obtained.

The investigation therefore concluded that the presence of the suspicious DLL was confirmed, but actual DLL execution was **not confirmed**.

This distinction is critical in DFIR investigations because investigators must clearly separate what the evidence proves from what the evidence merely suggests.

# windows-dfir-lab48-suspicious-dll-execution-investigation

## Overview

DLL execution is an important area of Windows DFIR because attackers can abuse DLLs and trusted Windows utilities to execute malicious code. Investigating suspicious DLL activity requires correlation between the DLL artifact, file metadata, hashes, digital signatures, process creation events, command-line arguments, parent-child process relationships, network activity, and DLL loading telemetry.

In this hands-on DFIR lab, a controlled `SuspiciousLibrary.dll` artifact was created and investigated on a Windows endpoint. Because Visual Studio or another DLL compiler was not available, the original lab was modified to use a simulated DLL artifact rather than a compiled executable DLL.

The investigation focused on validating Sysmon telemetry, examining the Sysmon configuration for Image Load monitoring, collecting file metadata and SHA-256 information, checking Authenticode status, investigating process creation activity, examining `rundll32.exe`, reviewing Windows Security Event ID 4688, using Event Viewer, and investigating available network telemetry.

A key finding during the investigation was that Sysmon Event ID 7 Image Load telemetry was not available on the endpoint. Although the Sysmon configuration file contained an `ImageLoad` section, the active configuration did not return Image Load information when queried. The investigation was therefore adapted to use the telemetry that was actually available.

---

# Executive Summary

This investigation examined a simulated suspicious DLL artifact and evaluated whether the available Windows telemetry could establish evidence of DLL execution.

The artifact was created inside `C:\SuspiciousDLLLab\` and analyzed using file metadata, SHA-256 hashing, and Authenticode validation.

Sysmon was then investigated to determine the available telemetry. Event IDs 1, 3, 12, and 13 were available, while Event ID 7 did not return any events. The existing Sysmon configuration file contained an `ImageLoad` section, but the active Sysmon configuration did not return Image Load information.

Because the simulated DLL was a text-based artifact rather than a compiled Portable Executable DLL, actual DLL loading was not performed. Process creation, Windows Security Event ID 4688, Event Viewer, filesystem evidence, and network telemetry were instead used to demonstrate how a real suspicious DLL investigation could be approached while clearly documenting the limitations of the available evidence.

---

# Investigation Objectives

- Understand suspicious DLL execution from a DFIR perspective.
- Understand the role of `rundll32.exe` in DLL execution investigations.
- Validate Sysmon telemetry before beginning the investigation.
- Determine whether Sysmon Event ID 7 Image Load telemetry is available.
- Examine the Sysmon configuration.
- Create a controlled suspicious DLL artifact.
- Collect DLL file metadata.
- Calculate the SHA-256 hash.
- Examine Authenticode signature information.
- Investigate Sysmon Event ID 1 process creation events.
- Investigate `rundll32.exe` activity.
- Review process command-line information.
- Examine Windows Security Event ID 4688.
- Review relevant events through Event Viewer.
- Investigate Sysmon Event ID 3 network activity.
- Search the filesystem for DLL artifacts.
- Correlate the available evidence.
- Identify telemetry limitations.
- Determine whether DLL execution can actually be confirmed.

---

# Skills Demonstrated

- Windows DFIR
- DLL Execution Investigation
- Windows Process Investigation
- Sysmon Analysis
- Sysmon Event ID 1 Analysis
- Sysmon Event ID 3 Analysis
- Windows Security Event ID 4688 Analysis
- Event Viewer Investigation
- Process Tree Analysis
- Command-Line Analysis
- File Metadata Analysis
- SHA-256 Hashing
- Authenticode Analysis
- Filesystem Investigation
- Artifact Correlation
- Telemetry Validation
- Evidence Assessment
- DFIR Documentation

---

# Tools Used

- Windows
- PowerShell
- Sysmon
- Windows Event Viewer
- File Explorer
- Windows Security Event Logs

---

# Lab Environment

| Component | Details |
| --- | --- |
| Operating System | Windows |
| Investigation Type | Host-Based DFIR |
| Primary Investigation | Suspicious DLL Execution |
| Primary Artifact | `SuspiciousLibrary.dll` |
| Investigation Directory | `C:\SuspiciousDLLLab\` |
| Primary Sysmon Event | Event ID 1 |
| Supporting Sysmon Event | Event ID 3 |
| Windows Security Event | 4688 |
| Analysis Tool | Event Viewer |

---

# Investigation Scenario

A SOC analyst discovers a suspicious DLL on a Windows workstation. The file is located in a user-controlled investigation directory and requires investigation to determine whether it represents malicious DLL activity.

The analyst must determine whether the file is a legitimate DLL, whether it has a valid digital signature, what its SHA-256 hash is, whether a Windows process referenced the DLL, whether `rundll32.exe` was involved, whether suspicious process relationships existed, and whether any related network activity occurred.

During telemetry validation, the analyst discovers that Sysmon Event ID 7 Image Load telemetry is unavailable on the endpoint. The investigation must therefore rely on other available evidence sources and explicitly document the limitation rather than assuming that DLL execution occurred.

---

# Investigation Workflow

1. Validate Sysmon.
2. Identify available Sysmon event IDs.
3. Test Sysmon Event ID 7.
4. Locate the Sysmon configuration file.
5. Check the configuration for `ImageLoad`.
6. Check the active Sysmon configuration.
7. Create the investigation workspace.
8. Examine a legitimate Windows DLL.
9. Calculate the legitimate DLL hash.
10. Check the legitimate DLL signature.
11. Create the simulated suspicious DLL.
12. Collect suspicious DLL metadata.
13. Calculate the suspicious DLL SHA-256 hash.
14. Check the suspicious DLL Authenticode status.
15. Investigate Sysmon Event ID 1.
16. Investigate `rundll32.exe`.
17. Search process command lines for DLL references.
18. Investigate Windows Security Event ID 4688.
19. Review relevant events through Event Viewer.
20. Investigate Sysmon Event ID 3.
21. Search the filesystem for DLL artifacts.
22. Recalculate the suspicious DLL hash.
23. Correlate the evidence.
24. Document the Event ID 7 telemetry limitation.
25. Determine whether execution can be confirmed.
26. Document the investigation timeline.

---

# Sysmon Telemetry Validation

The first step was validating whether Sysmon was functioning correctly.

The endpoint was found to generate the following Sysmon events:

| Event ID | Description | Availability |
| --- | --- | --- |
| 1 | Process Creation | Available |
| 3 | Network Connection | Available |
| 7 | Image Load | Not Available |
| 12 | Registry Object Create/Delete | Available |
| 13 | Registry Value Set | Available |

This confirmed that Sysmon was operational even though Event ID 7 telemetry was unavailable.

---

# Event ID 7 Investigation

The following command was used:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 7
    } -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message

The query returned no matching events.

This meant that direct Sysmon Image Load evidence was not available for the investigation.

---

# Sysmon Configuration Investigation

The endpoint was searched for Sysmon configuration files:

    Get-ChildItem C:\ -Filter "sysmonconfig*.xml" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName

The following files were identified:

    C:\Tools\Sysmon\sysmonconfig-export.xml
    C:\Users\abhin\Downloads\sysmonconfig-export.xml

The configuration file at:

    C:\Tools\Sysmon\sysmonconfig-export.xml

was examined for Image Load configuration.

The following command was used:

    Select-String -Path "C:\Tools\Sysmon\sysmonconfig-export.xml" -Pattern "ImageLoad"

The configuration contained an Image Load section:

    <ImageLoad onmatch="include">

The configuration also contained documentation identifying Event ID 7 as:

    SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]

However, the active Sysmon configuration was checked using:

    sysmon64.exe -c | Select-String "ImageLoad"

No output was returned.

Therefore, the investigation documented the difference between the configuration file stored on disk and the telemetry actively exposed by Sysmon.

---

# Simulated DLL Creation

A real compiled DLL could not be created because Visual Studio or another DLL compiler was not available.

The lab was therefore modified to create a controlled simulated artifact.

The investigation directory was created:

    New-Item -ItemType Directory -Path "C:\SuspiciousDLLLab" -Force

The simulated DLL was created using:

    Set-Content -Path "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Value "LAB48-SIMULATED-DLL-ARTIFACT"

The resulting file was intentionally treated as a simulated DLL artifact.

It was not a compiled Portable Executable DLL and was not treated as proof of DLL execution.

---

# File Metadata Investigation

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
- Creation timestamp
- Last write timestamp
- Last access timestamp

These properties were used as supporting filesystem evidence.

---

# SHA-256 Analysis

The SHA-256 hash was calculated using:

    Get-FileHash "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Algorithm SHA256

The resulting hash was recorded as the unique cryptographic identifier for the artifact.

The hash was later recalculated to determine whether the file changed during the investigation.

---

# Authenticode Analysis

The simulated DLL was examined using:

    Get-AuthenticodeSignature "C:\SuspiciousDLLLab\SuspiciousLibrary.dll"

The observed result was:

    Status : UnknownError

No signer certificate was returned.

The result was documented exactly as observed.

The file was not classified as `NotSigned` because the actual PowerShell output returned `UnknownError`.

Because the artifact was a simulated text file rather than a compiled DLL, the Authenticode result was treated as supporting file-type evidence rather than proof of maliciousness.

---

# Process Investigation

Sysmon Event ID 1 was used to investigate process creation activity.

The investigation focused on processes potentially associated with DLL execution, particularly `rundll32.exe`.

The following command was used:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 1
    } -MaxEvents 200 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

The investigation focused on:

- Process name
- Process ID
- Parent Process ID
- Parent image
- Command line
- User
- Integrity level
- Process creation timestamp

---

# DLL Reference Investigation

Process creation telemetry was searched for references to:

    SuspiciousLibrary.dll

and:

    .dll

The purpose was to determine whether any process creation event contained evidence linking a process to the suspicious artifact.

Because the artifact was not a real DLL and Event ID 7 was unavailable, the investigation did not claim that the DLL was actually loaded.

---

# Windows Security Event ID 4688

Windows Security Event ID 4688 was used as an independent process creation evidence source.

The following command was used:

    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4688
    } -MaxEvents 200 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

The purpose was to compare Windows Security process creation evidence with Sysmon Event ID 1.

---

# Event Viewer Investigation

Event Viewer was used during the investigation to manually inspect Windows telemetry.

The Security log was accessed through:

    Event Viewer
    → Windows Logs
    → Security

Sysmon telemetry was accessed through:

    Event Viewer
    → Applications and Services Logs
    → Microsoft
    → Windows
    → Sysmon
    → Operational

Event Viewer provided a graphical method of examining the same underlying Windows event data queried through PowerShell.

---

# Network Investigation

Sysmon Event ID 3 was investigated to identify network activity associated with suspicious processes.

The following command was used:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 3
    } -MaxEvents 500 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

The investigation considered:

- Source IP
- Destination IP
- Destination port
- Protocol
- Process ID
- Timestamp

Network activity would be treated as supporting evidence if it occurred in close temporal proximity to suspicious process activity.

---

# Filesystem Investigation

The investigation searched common user-writable locations for DLL artifacts:

- `C:\Users\`
- `C:\Users\<user>\AppData\`
- `C:\Users\<user>\Downloads\`
- `C:\ProgramData\`
- `C:\Users\Public\`

The purpose was to identify DLL files stored outside expected Windows system directories.

File location alone was not treated as proof of maliciousness.

---

# Evidence Correlation

The investigation correlated multiple evidence sources:

    Suspicious DLL
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
    Security Event ID 4688
          ↓
    Event Viewer
          ↓
    Network Activity
          ↓
    Sysmon Event ID 7 Availability

This approach prevented the investigation from relying on a single artifact.

---

# Investigation Findings

## Finding 1 — Sysmon Was Operational

Sysmon was generating multiple event types, including Event IDs 1, 3, 12, and 13.

Therefore, the absence of Event ID 7 was not caused by a complete Sysmon failure.

## Finding 2 — Event ID 7 Was Not Available

The Event ID 7 query returned no events.

Although the Sysmon configuration file contained an `ImageLoad` section, the active configuration did not return `ImageLoad` when queried.

Therefore, direct Sysmon DLL Image Load evidence was unavailable.

## Finding 3 — The DLL Was a Simulated Artifact

`SuspiciousLibrary.dll` was created as a controlled text artifact.

It was not a compiled executable DLL.

Therefore, actual DLL loading or execution was not performed.

## Finding 4 — Authenticode Returned UnknownError

The simulated DLL returned `UnknownError` when checked with `Get-AuthenticodeSignature`.

No signer certificate was returned.

## Finding 5 — Process Telemetry Was Available

Sysmon Event ID 1 and Windows Security Event ID 4688 provided process creation telemetry that could be used to investigate potential DLL execution mechanisms.

## Finding 6 — Network Telemetry Was Available

Sysmon Event ID 3 was available for investigating network connections associated with suspicious processes.

---

# Telemetry Limitation

The investigation demonstrated an important DFIR limitation.

The endpoint had:

| Telemetry | Status |
| --- | --- |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 3 | Available |
| Sysmon Event ID 7 | Unavailable |
| Sysmon Event ID 12 | Available |
| Sysmon Event ID 13 | Available |
| Security Event ID 4688 | Available |

Event ID 7 would have provided direct evidence of a process loading a DLL.

Because it was unavailable, the investigation had to rely on indirect evidence such as process creation, command lines, parent-child relationships, filesystem artifacts, and network activity.

---

# MITRE ATT&CK Mapping

| Technique | Description | Relevance |
| --- | --- | --- |
| T1218.011 | Rundll32 | Relevant to DLL execution through a trusted Windows binary |
| T1059.001 | PowerShell | Used for investigation and controlled artifact creation |
| T1105 | Ingress Tool Transfer | Relevant to real-world malicious DLL delivery |
| T1071 | Application Layer Protocol | Relevant when suspicious DLL activity generates network communication |

The techniques above represent the investigative scenario and relevant attacker behavior. The controlled lab did not demonstrate a confirmed malicious execution chain.

---

# Evidence Collected

- `SuspiciousLibrary.dll`
- File metadata
- SHA-256 hash
- Authenticode output
- Sysmon configuration file
- Sysmon Event ID 1
- Sysmon Event ID 3
- Windows Security Event ID 4688
- Event Viewer observations
- Filesystem evidence
- Investigation timeline
- Telemetry validation results

---

# Key DFIR Lessons

## A DLL File Is Not Proof of Execution

The presence of `SuspiciousLibrary.dll` only proves that the file existed.

It does not prove that the file was loaded or executed.

## A DLL Extension Does Not Prove DLL Validity

A file can have a `.dll` extension without being a valid Portable Executable DLL.

## Process Context Matters

A suspicious DLL should be investigated together with:

- Loading process
- Parent process
- Command line
- User
- Process ID
- Timestamp
- Network activity

## Telemetry Must Be Validated

Investigators should verify what event types an endpoint actually generates before relying on them.

## Missing Telemetry Is a Finding

The absence of Event ID 7 directly affected the investigation and was therefore documented as a telemetry limitation.

---

# Final Assessment

The investigation confirmed the presence and characteristics of a simulated suspicious DLL artifact and demonstrated how Windows file, process, security, Event Viewer, and network telemetry can be used during DLL investigations.

However, actual DLL execution could not be confirmed because the artifact was intentionally simulated rather than compiled as an executable DLL, and Sysmon Event ID 7 Image Load telemetry was unavailable.

The investigation therefore demonstrates an important DFIR principle:

**Evidence should be reported according to what it proves, not according to what the investigator expects it to prove.**

---

# Key Takeaway

A suspicious DLL investigation should correlate:

    File
    +
    Hash
    +
    Signature
    +
    Process
    +
    Command Line
    +
    Parent Process
    +
    Security Event 4688
    +
    Network Activity
    +
    DLL Load Telemetry

When one telemetry source is unavailable, the correct approach is to document the limitation and use the remaining evidence sources rather than assuming execution occurred.

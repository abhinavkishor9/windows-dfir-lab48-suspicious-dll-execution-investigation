# windows-dfir-lab48-suspicious-dll-execution-investigation
## Overview

DLL stands for Dynamic Link Library.

A DLL contains code and resources that can be used by other Windows processes.

Unlike a normal executable:

program.exe

a DLL normally isn't launched by double-clicking it.

Instead, another process loads it:

program.exe
      ↓
loads
      ↓
library.dll

For example, Windows applications routinely load DLLs from:

C:\Windows\System32\

This is completely normal.

The important point is:

A DLL can contain executable code even though it is not itself an .exe process.

So an attacker can potentially place malicious code inside a DLL and have another process load it.

The process that appears to be running may therefore look legitimate.

For example:

explorer.exe
      ↓
rundll32.exe
      ↓
suspicious.dll

The investigator may initially see:

rundll32.exe

and need to determine what DLL it loaded.

That is why DLL-loading telemetry is valuable.

A DLL is generally loaded into the address space of a process.

So rather than thinking:

suspicious.dll
      ↓
executes independently

think:

Process
   ↓
loads DLL
   ↓
DLL code executes within that process

This distinction is important in DFIR.

For this lab, when we say "DLL execution", we're investigating the execution of code through a DLL-loading process.


A potentially suspicious DLL is discovered on a Windows endpoint. The SOC needs to determine whether the DLL was associated with execution activity, which process was responsible, how that process was launched, and whether any additional activity occurred around the same time.

Because the endpoint does not currently collect Sysmon Event ID 7, the investigation will use process creation, command-line analysis, parent-child relationships, file metadata, hashes, signatures, network telemetry, and Windows Security logs to reconstruct the activity.

---

# Executive Summary

This investigation examined a simulated suspicious DLL artifact and evaluated whether the available Windows telemetry could establish evidence of DLL execution.

The artifact was created inside `C:\SuspiciousDLLLab\` and analyzed using file metadata, SHA-256 hashing, and Authenticode validation.

Sysmon was then investigated to determine the available telemetry. Event IDs 1, 3, 12, and 13 were available, while Event ID 7 did not return any events. The existing Sysmon configuration file contained an `ImageLoad` section, but the active Sysmon configuration did not return Image Load information.


---

# Investigation Objectives

- Determine whether SuspiciousLibrary.dll represents a genuine executable DLL or only a suspicious file artifact.
- Establish when and where the DLL appeared on the endpoint.
- Examine the file's metadata, cryptographic hash, and signing information for indicators of legitimacy or tampering.
- Determine whether any process activity references the suspicious DLL.
- Investigate rundll32.exe for possible abuse as a trusted Windows execution utility.
- Correlate Sysmon process creation data with Windows Security Event ID 4688.
- Examine parent-child process relationships and command-line arguments for suspicious execution patterns.
- Investigate available network connections for activity associated with suspicious processes.
- Determine whether Sysmon Image Load telemetry is actually available on the endpoint.
- Compare the stored Sysmon configuration with the telemetry currently being generated.
- Identify gaps that prevent direct confirmation of DLL loading.
- Correlate filesystem, process, registry, security, and network evidence before reaching a conclusion.
- Clearly distinguish file presence, process execution, and DLL loading as separate forensic claims.
- Determine whether the available evidence supports confirmed DLL execution, suspected execution, or insufficient evidence.

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

A potentially suspicious DLL is discovered on a Windows endpoint. The SOC needs to determine whether the DLL was associated with execution activity, which process was responsible, how that process was launched, and whether any additional activity occurred around the same time.

Because the endpoint does not currently collect Sysmon Event ID 7, the investigation will use process creation, command-line analysis, parent-child relationships, file metadata, hashes, signatures, network telemetry, and Windows Security logs to reconstruct the activity.


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
23. Document the Event ID 7 telemetry limitation.


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


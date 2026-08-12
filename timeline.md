# Timeline — Lab 48: Suspicious DLL Execution Investigation

## Investigation Timeline

| Step | Activity | Evidence / Result |
| --- | --- | --- |
| 1 | Investigation started | Suspicious DLL execution investigation initiated |
| 2 | Sysmon validated | Sysmon confirmed operational |
| 3 | Available Sysmon events identified | Events 1, 3, 12, and 13 available |
| 4 | Event ID 7 tested | No Image Load events returned |
| 5 | Sysmon configuration files located | Configuration files found in `C:\Tools\Sysmon\` and Downloads |
| 6 | ImageLoad configuration searched | `ImageLoad` section identified in stored configuration |
| 7 | Active Sysmon configuration checked | `sysmon64.exe -c | Select-String "ImageLoad"` returned no output |
| 8 | Investigation workspace created | `C:\SuspiciousDLLLab\` created |
| 9 | DLL artifact created | `SuspiciousLibrary.dll` created as a simulated artifact |
| 10 | File metadata collected | Filename, path, size, and timestamps recorded |
| 11 | SHA-256 calculated | Cryptographic hash generated for the artifact |
| 12 | Authenticode checked | Status returned as `UnknownError`; no signer certificate returned |
| 13 | Sysmon Event ID 1 investigated | Process creation telemetry reviewed |
| 14 | `rundll32.exe` activity investigated | Process activity searched for potential DLL execution context |
| 15 | DLL references searched | Process telemetry examined for `.dll` and `SuspiciousLibrary.dll` references |
| 16 | Security Event ID 4688 investigated | Windows process creation telemetry reviewed |
| 17 | Event Viewer reviewed | Security and Sysmon Operational logs examined |
| 18 | Sysmon Event ID 3 investigated | Network connection telemetry reviewed |
| 19 | Filesystem investigated | DLL artifacts and suspicious locations considered |
| 20 | Evidence correlated | File, process, security, network, and telemetry evidence compared |
| 21 | Event ID 7 limitation documented | Direct DLL Image Load telemetry unavailable |
| 22 | Artifact limitation documented | `SuspiciousLibrary.dll` confirmed as simulated, not compiled |
| 23 | Execution assessment performed | Actual DLL execution could not be confirmed |
| 24 | Investigation concluded | Evidence-supported findings documented |

---

# Detailed Timeline

## Phase 1 — Environment and Telemetry Validation

### T+00 — Investigation Initiated

The suspicious DLL investigation was started with the objective of determining whether a DLL artifact could be associated with suspicious execution activity.

### T+05 — Sysmon Validated

Sysmon telemetry was checked to confirm that the endpoint was generating security events.

The available events included:

- Event ID 1 — Process Creation
- Event ID 3 — Network Connection
- Event ID 12 — Registry Object Create/Delete
- Event ID 13 — Registry Value Set

This confirmed that Sysmon was operational.

### T+10 — Event ID 7 Tested

Sysmon Event ID 7 was queried:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 7
    } -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message

Result:

    No events were found that match the specified selection criteria.

This established that Image Load telemetry was not available.

---

# Phase 2 — Sysmon Configuration Investigation

### T+15 — Configuration Files Located

The endpoint was searched for Sysmon configuration files.

Files identified:

    C:\Tools\Sysmon\sysmonconfig-export.xml
    C:\Users\abhin\Downloads\sysmonconfig-export.xml

### T+20 — ImageLoad Configuration Identified

The primary configuration file was searched for `ImageLoad`.

The configuration contained:

    <ImageLoad onmatch="include">

The file also contained documentation identifying Event ID 7 as Image Load telemetry.

### T+25 — Active Configuration Checked

The active Sysmon configuration was checked:

    sysmon64.exe -c | Select-String "ImageLoad"

No output was returned.

The discrepancy between the stored configuration and active telemetry was documented.

---

# Phase 3 — Suspicious DLL Artifact

### T+30 — Investigation Workspace Created

The investigation directory was created:

    C:\SuspiciousDLLLab\

### T+35 — Simulated DLL Created

Because Visual Studio or another DLL compiler was unavailable, a simulated artifact was created:

    C:\SuspiciousDLLLab\SuspiciousLibrary.dll

The file was intentionally treated as a simulated artifact and not as a functional DLL.

### T+40 — File Metadata Collected

The artifact's:

- Name
- Path
- Size
- Creation time
- Last write time
- Last access time

were examined.

---

# Phase 4 — File Analysis

### T+45 — SHA-256 Hash Generated

The following command was used:

    Get-FileHash "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Algorithm SHA256

The resulting SHA-256 hash was recorded.

### T+50 — Authenticode Checked

The following command was executed:

    Get-AuthenticodeSignature "C:\SuspiciousDLLLab\SuspiciousLibrary.dll"

Observed result:

    Status : UnknownError

No signer certificate was returned.

The result was recorded without changing the status to `NotSigned`.

---

# Phase 5 — Process Investigation

### T+55 — Sysmon Event ID 1 Investigated

Process creation telemetry was reviewed using Sysmon Event ID 1.

The investigation focused on:

- Process name
- Process ID
- Parent Process ID
- Parent image
- Command line
- User
- Timestamp

### T+60 — `rundll32.exe` Investigated

The investigation searched for `rundll32.exe` activity.

The purpose was to identify possible DLL execution context involving a legitimate Windows binary commonly associated with DLL execution.

### T+65 — DLL References Investigated

Process creation telemetry was searched for:

    SuspiciousLibrary.dll

and:

    .dll

No conclusion of actual DLL loading was made solely from a filename reference.

---

# Phase 6 — Windows Security Investigation

### T+70 — Security Event ID 4688 Investigated

Windows Security Event ID 4688 was examined as an independent process creation source.

The investigation searched for process activity involving:

    rundll32.exe

The purpose was to correlate Windows Security process creation evidence with Sysmon Event ID 1.

### T+75 — Event Viewer Investigation

Event Viewer was opened to manually inspect:

    Windows Logs
    → Security

and:

    Applications and Services Logs
    → Microsoft
    → Windows
    → Sysmon
    → Operational

This provided graphical validation of available telemetry.

---

# Phase 7 — Network Investigation

### T+80 — Sysmon Event ID 3 Investigated

Sysmon Event ID 3 was examined for network activity associated with suspicious processes.

The investigation considered:

- Source IP
- Destination IP
- Destination port
- Protocol
- Process ID
- Timestamp

Network activity was treated as supporting evidence rather than direct proof of DLL execution.

---

# Phase 8 — Evidence Correlation

### T+85 — Filesystem Evidence Reviewed

The investigation considered DLL artifacts in common user-writable locations, including:

    C:\Users\
    C:\Users\<user>\AppData\
    C:\Users\<user>\Downloads\
    C:\ProgramData\
    C:\Users\Public\

### T+90 — Evidence Correlated

The following evidence sources were correlated:

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
    Security Event 4688
    ↓
    Event Viewer
    ↓
    Network Activity
    ↓
    Sysmon Event 7 Availability

---

# Phase 9 — Final Assessment

### T+95 — Telemetry Limitation Documented

The investigation documented that Sysmon Event ID 7 was unavailable.

This prevented direct confirmation of:

    Which process loaded the DLL

### T+100 — Artifact Limitation Documented

The investigation confirmed that:

    SuspiciousLibrary.dll

was a simulated text artifact rather than a compiled Portable Executable DLL.

### T+105 — Execution Assessment

Actual DLL execution was classified as:

    NOT CONFIRMED

The investigation did not claim execution based solely on the existence of the `.dll` file.

### T+110 — Investigation Completed

The investigation concluded with evidence-supported findings and documented limitations.

---

# Final Timeline Summary

| Phase | Key Event | Result |
| --- | --- | --- |
| 1 | Sysmon validation | Sysmon operational |
| 2 | Event ID 7 query | No Image Load events |
| 3 | Configuration review | `ImageLoad` present in stored configuration |
| 4 | Active configuration check | `ImageLoad` not returned |
| 5 | Artifact creation | Simulated DLL created |
| 6 | File analysis | Metadata and SHA-256 collected |
| 7 | Authenticode | `UnknownError` observed |
| 8 | Process investigation | Event ID 1 reviewed |
| 9 | Rundll32 investigation | Potential DLL execution context examined |
| 10 | Security investigation | Event ID 4688 reviewed |
| 11 | Event Viewer | Security and Sysmon logs reviewed |
| 12 | Network investigation | Event ID 3 reviewed |
| 13 | Evidence correlation | Multiple evidence sources compared |
| 14 | Final assessment | DLL execution not confirmed |

---

# Investigation Conclusion

The timeline demonstrates that the investigation followed an evidence-driven approach.

The endpoint was first validated for available telemetry, followed by Sysmon configuration analysis, artifact creation, file analysis, process investigation, Security Event 4688 analysis, Event Viewer review, network investigation, and evidence correlation.

The investigation ultimately determined that the suspicious DLL artifact existed, but actual DLL execution could not be confirmed because the artifact was simulated and Sysmon Event ID 7 Image Load telemetry was unavailable.

The missing telemetry was documented as an investigation limitation rather than being treated as evidence that execution did not occur.

# Troubleshooting Notes — Lab 48: Suspicious DLL Execution Investigation

## Purpose

This document records the issues encountered while performing the Suspicious DLL Execution Investigation and explains how each issue was analyzed and handled.

The troubleshooting process was important because the lab had to be modified based on the actual Windows environment and available telemetry.

---

# 1. Visual Studio Was Not Available

## Problem

The original lab approach required creating a real DLL using Visual Studio or another compiler.

Visual Studio was not installed on the Windows system.

## Impact

A compiled Portable Executable DLL could not be created using the original method.

Creating a real DLL was therefore not possible with the available tools.

## Resolution

The lab was modified to create a controlled simulated DLL artifact using PowerShell.

Command used:

    Set-Content -Path "C:\SuspiciousDLLLab\SuspiciousLibrary.dll" -Value "LAB48-SIMULATED-DLL-ARTIFACT"

The resulting file was treated as a forensic artifact rather than a functional DLL.

## DFIR Lesson

A lab should be adapted to the available environment without falsely claiming that a simulated file represents a real executable.

---

# 2. Sysmon Event ID 7 Returned No Events

## Problem

The investigation attempted to query Sysmon Event ID 7:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 7
    } -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message

The query returned:

    No events were found that match the specified selection criteria.

## Initial Concern

Because Event ID 7 represents Image Load activity, the lack of events initially raised the question of whether Sysmon was functioning correctly.

## Investigation

Other Sysmon event IDs were checked.

The endpoint was generating:

    Event ID 1  → Process Creation
    Event ID 3  → Network Connection
    Event ID 12 → Registry Object Create/Delete
    Event ID 13 → Registry Value Set

Therefore, Sysmon itself was operational.

## Resolution

The issue was treated specifically as an Event ID 7 telemetry limitation rather than a complete Sysmon failure.

## DFIR Lesson

If one event type is missing, investigators should first verify whether other Sysmon events are being generated before concluding that Sysmon is not working.

---

# 3. ImageLoad Was Present in the Sysmon Configuration File

## Problem

The stored Sysmon configuration appeared to contain Image Load monitoring.

The configuration file was:

    C:\Tools\Sysmon\sysmonconfig-export.xml

The following command was used:

    Select-String -Path "C:\Tools\Sysmon\sysmonconfig-export.xml" -Pattern "ImageLoad"

The output showed:

    <ImageLoad onmatch="include">

The configuration also contained:

    SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]

## Confusion

The configuration file suggested that Image Load monitoring existed, but Event ID 7 still returned no events.

## Resolution

The active Sysmon configuration was checked using:

    sysmon64.exe -c | Select-String "ImageLoad"

No output was returned.

This demonstrated that the configuration file stored on disk should not automatically be treated as proof that the same configuration was currently active.

## DFIR Lesson

Always distinguish between:

    Configuration stored on disk

and:

    Configuration actively applied to the security sensor

---

# 4. Multiple Sysmon Configuration Files Were Found

## Problem

The system contained more than one Sysmon configuration file.

The following command was used:

    Get-ChildItem C:\ -Filter "sysmonconfig*.xml" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName

The search returned:

    C:\Tools\Sysmon\sysmonconfig-export.xml
    C:\Users\abhin\Downloads\sysmonconfig-export.xml

## Risk

It would have been incorrect to assume that every configuration file found on disk represented the active Sysmon configuration.

## Resolution

The investigation focused on the configuration file located at:

    C:\Tools\Sysmon\sysmonconfig-export.xml

The active configuration was then checked separately using:

    sysmon64.exe -c | Select-String "ImageLoad"

## DFIR Lesson

The presence of a configuration file does not prove that the configuration is currently being used.

---

# 5. Authenticode Returned UnknownError

## Problem

The suspicious DLL was checked using:

    Get-AuthenticodeSignature "C:\SuspiciousDLLLab\SuspiciousLibrary.dll"

The result was:

    Status : UnknownError

No signer certificate was returned.

## Potential Mistake

It would have been tempting to describe the result as:

    NotSigned

However, this would not accurately represent the observed PowerShell output.

## Resolution

The result was documented exactly as:

    UnknownError

The file was not classified as `NotSigned`.

## Additional Context

The artifact was a simulated text file rather than a compiled Portable Executable DLL.

Therefore, the Authenticode result was treated as supporting evidence about the artifact rather than proof of maliciousness.

## DFIR Lesson

Record the actual forensic output instead of replacing unexpected results with assumptions.

---

# 6. Simulated DLL Was Not a Real Executable DLL

## Problem

The file:

    C:\SuspiciousDLLLab\SuspiciousLibrary.dll

was created using PowerShell.

Although the filename had a `.dll` extension, the file was not compiled as a Portable Executable DLL.

## Impact

The artifact could not demonstrate actual DLL loading or execution.

## Resolution

The investigation documentation explicitly identified the file as a simulated DLL artifact.

The investigation therefore focused on:

- File metadata
- Hash
- Authenticode
- Process telemetry
- Security Event 4688
- Event Viewer
- Network telemetry
- Sysmon configuration

## DFIR Lesson

A filename extension alone does not establish the actual file type or execution behavior.

---

# 7. Event ID 7 Could Not Be Used as Direct Evidence

## Problem

The original investigation relied heavily on Sysmon Event ID 7 to identify DLL loading.

However:

    Event ID 7 → No events

was observed.

## Impact

The investigation could not directly determine which process loaded the DLL.

## Resolution

The investigation was modified to use available telemetry:

    Sysmon Event ID 1
    Sysmon Event ID 3
    Security Event ID 4688
    Event Viewer
    Filesystem metadata
    File hash
    Authenticode information

These sources were treated as supporting evidence rather than direct substitutes for Event ID 7.

## DFIR Lesson

When a primary telemetry source is unavailable, use alternative evidence while clearly documenting the limitation.

---

# 8. Process Creation Was Used as Alternative Evidence

## Problem

Direct DLL Image Load telemetry was unavailable.

## Resolution

Sysmon Event ID 1 was used to investigate process creation.

The investigation focused particularly on:

    rundll32.exe

Example query:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 1
    } -MaxEvents 200 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

Relevant fields included:

- Process ID
- Parent Process ID
- Parent image
- Command line
- User
- Timestamp

## DFIR Lesson

Process creation telemetry can provide valuable context, but it should not automatically be interpreted as proof that a specific DLL was loaded.

---

# 9. Windows Security Event 4688 Was Used for Correlation

## Problem

The investigation required an independent process creation source.

## Resolution

Windows Security Event ID 4688 was investigated.

Command:

    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4688
    } -MaxEvents 200 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

This provided an additional source for process creation evidence.

## DFIR Lesson

Correlating Sysmon process creation with Security Event 4688 can strengthen confidence in observed process activity.

---

# 10. Event Viewer Was Used for Manual Validation

## Problem

PowerShell queries alone do not always provide the easiest way to visually inspect events.

## Resolution

Event Viewer was used to manually review:

    Windows Logs
    → Security

and:

    Applications and Services Logs
    → Microsoft
    → Windows
    → Sysmon
    → Operational

This provided graphical validation of the available telemetry.

## DFIR Lesson

Native graphical tools and PowerShell can complement each other during endpoint investigations.

---

# 11. Network Telemetry Was Used as Supporting Evidence

## Problem

The investigation could not rely on Event ID 7.

## Resolution

Sysmon Event ID 3 was used to investigate network activity associated with suspicious processes.

Example query:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 3
    } -MaxEvents 500 |
    Where-Object {
        $_.Message -match "rundll32.exe"
    } |
    Select-Object TimeCreated, Message

Relevant information included:

- Source IP
- Destination IP
- Destination port
- Protocol
- Process ID
- Timestamp

## DFIR Lesson

Network telemetry can provide useful supporting context when investigating suspicious process activity.

---

# 12. File Extension Was Not Treated as Proof

## Problem

The artifact was named:

    SuspiciousLibrary.dll

The `.dll` extension could create the assumption that the file was a real DLL.

## Resolution

The investigation explicitly treated the file as a simulated artifact.

The investigation did not claim:

    "The DLL executed."

Instead, the correct assessment was:

    "The simulated DLL artifact existed, but DLL execution was not confirmed."

## DFIR Lesson

Forensic conclusions must be based on evidence rather than filenames.

---

# 13. Investigation Was Modified Instead of Forcing the Original Procedure

The original lab design assumed:

    Real DLL
    +
    Visual Studio
    +
    DLL Compilation
    +
    DLL Execution
    +
    Sysmon Event ID 7

The actual environment provided:

    No Visual Studio
    +
    Simulated DLL
    +
    Sysmon Event ID 7 unavailable
    +
    Sysmon Events 1, 3, 12 and 13 available

The investigation was therefore redesigned around the telemetry and tools that were actually available.

This produced a more realistic DFIR lesson:

    Validate the environment
            ↓
    Identify available telemetry
            ↓
    Adapt the investigation
            ↓
    Document limitations
            ↓
    Avoid unsupported conclusions

---

# 14. Final Troubleshooting Assessment

The primary technical issues encountered during Lab 48 were:

| Issue | Resolution |
| --- | --- |
| Visual Studio unavailable | Created simulated DLL artifact |
| Event ID 7 returned no events | Used available Sysmon and Windows telemetry |
| ImageLoad present in stored configuration | Verified active configuration separately |
| Multiple Sysmon configuration files | Distinguished stored files from active configuration |
| Authenticode returned `UnknownError` | Recorded exact observed result |
| Simulated DLL was not executable | Documented artifact limitation |
| Direct DLL load evidence unavailable | Used process, security, filesystem, and network evidence |
| Need for independent process evidence | Investigated Security Event ID 4688 |
| Need for graphical validation | Used Event Viewer |

---

# Key Troubleshooting Lessons

## 1. Validate Before Investigating

Always determine which telemetry sources are actually available before building an investigation around them.

## 2. Do Not Confuse Configuration With Telemetry

A configuration file can contain an event definition without the currently active sensor configuration producing that event.

## 3. Document Unexpected Results

`UnknownError` should be documented as `UnknownError`, not converted into an assumed status.

## 4. Adapt the Lab to the Environment

If a required compiler or tool is unavailable, modify the methodology rather than fabricating evidence.

## 5. Separate Artifact Existence From Execution

A suspicious file proves that the file existed. It does not automatically prove execution.

## 6. Use Evidence Correlation

When direct telemetry is unavailable, correlate:

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

## 7. Missing Telemetry Is Itself a Finding

The absence of Sysmon Event ID 7 became an important finding because it directly limited the ability to confirm DLL loading.

---

# Final Lesson

The most important troubleshooting lesson from Lab 48 was that a DFIR investigation must follow the evidence actually available on the endpoint.

The investigation encountered missing Image Load telemetry, multiple configuration files, an unexpected Authenticode result, and the absence of a DLL compiler. Instead of forcing the original procedure, the investigation was modified and the limitations were documented.

This reflects a real SOC and DFIR workflow:

**Validate the telemetry → investigate the evidence → correlate artifacts → document limitations → make only evidence-supported conclusions.**

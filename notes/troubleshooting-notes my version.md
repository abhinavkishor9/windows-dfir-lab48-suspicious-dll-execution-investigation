# Troubleshooting Notes 
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

# 3. Authenticode Returned UnknownError

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

# 4. Simulated DLL Was Not a Real Executable DLL

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

# 5. Event ID 7 Could Not Be Used as Direct Evidence

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


# 6. File Extension Was Not Treated as Proof

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


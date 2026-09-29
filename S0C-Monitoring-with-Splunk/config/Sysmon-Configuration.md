# Sysmon Configuration

## Overview

Sysmon (System Monitor) is a Windows system monitoring component from Microsoft Sysinternals.

In this Home SOC Lab, Sysmon is used to collect detailed Windows telemetry that can be analyzed using Splunk Enterprise.

The main focus of this project is Sysmon Process Creation telemetry.

## 1. Role of Sysmon

Windows Event Logs provide important system and security information, but Sysmon provides additional process-level telemetry that is useful for security monitoring.

Sysmon can provide information such as:

* Process creation
* Process image
* User
* Parent process
* Command line
* Process ID
* Event timestamp

This information helps a SOC analyst understand how processes were executed on the Windows endpoint.

## 2. Sysmon Installation

Sysmon was installed on the Windows 11 VM as part of the SOC monitoring environment.

After installation, Sysmon runs as a Windows service and generates events in the Sysmon Operational event log.

The relevant Windows Event Viewer path is:

```text
Applications and Services Logs
└── Microsoft
    └── Windows
        └── Sysmon
            └── Operational
```

## 3. Sysmon Event Log

The main Sysmon log used in this project is:

```text
Microsoft-Windows-Sysmon/Operational
```

Splunk receives this telemetry using the corresponding sourcetype:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

A basic Splunk search is:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

## 4. Process Creation Monitoring

The primary Sysmon event used in this project is:

**EventCode 1 — Process Creation**

This event provides information about processes created on the Windows endpoint.

A typical Process Creation event can contain fields such as:

* `_time`
* `User`
* `Image`
* `ParentImage`
* `CommandLine`
* `EventCode`

These fields allow the analyst to investigate process execution.

## 5. Process Creation Detection

The following SPL query was used to search for Sysmon Process Creation events:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

This search retrieves Process Creation events from the Sysmon Operational log.

## 6. PowerShell Monitoring

PowerShell process activity was monitored using Sysmon Process Creation events.

### SPL Query

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell*" | table _time User ParentImage CommandLine
```

The query focuses on:

* Process timestamp
* User
* Parent process
* PowerShell executable
* Command line

### MITRE ATT&CK

**T1059.001 — PowerShell**

## 7. CMD Monitoring

Windows Command Shell activity was also monitored through Sysmon Process Creation events.

### SPL Query

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*cmd.exe*"
```

This search identifies CMD-related process activity.

### MITRE ATT&CK

**T1059.003 — Windows Command Shell**

## 8. Parent-Child Process Analysis

Sysmon provides parent process information that can help analysts understand process execution relationships.

The following search was used:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by ParentImage, Image
| sort - count
```

This allows the analyst to examine which processes launched other processes.

Parent-child relationships can provide useful context during security investigations.

## 9. Process Frequency Analysis

Frequently observed processes were analyzed using:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count by Image
```

This helps establish an understanding of normal process activity within the lab.

Processes that appear unexpectedly or behave differently from the normal baseline may require further investigation.

## 10. Sysmon EventCode Analysis

The distribution of Sysmon EventCodes was analyzed using:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by EventCode
```

This provides an overview of which Sysmon event types are being generated and collected.

## 11. Detection Testing

Controlled process activity was generated on the Windows 11 VM to validate Sysmon telemetry.

### PowerShell Test

```powershell
Write-Host "SOC Detection Test"
```

The PowerShell process itself was visible through Sysmon Process Creation telemetry.

The text displayed by `Write-Host` does not create a separate process event, so searching for the displayed text as a Process Creation command did not produce a separate event.

### CMD Test

```cmd
echo SOC_CMD_TEST
```

The CMD process activity was captured through Sysmon Process Creation telemetry and was visible in Splunk.

## 12. Telemetry Flow

The Sysmon telemetry flow in the Home SOC Lab is:

```text
Windows Process Activity
        ↓
      Sysmon
        ↓
Sysmon Operational Log
        ↓
Windows Event Log Collection
        ↓
      Splunk
        ↓
       SPL
        ↓
Detection & Investigation
```

Sysmon therefore acts as an important telemetry collection layer between Windows activity and the SIEM.

## 13. SOC Investigation Use

Sysmon telemetry allows an analyst to investigate questions such as:

* Which process was executed?
* When was it executed?
* Which user executed it?
* Which process launched it?
* What command line was used?
* Is the process expected?
* Does the process relationship require investigation?

This makes Sysmon useful for endpoint-focused SOC monitoring.

## 14. Security Monitoring Use Cases

The Sysmon telemetry collected in this project supports investigation of:

* Process creation
* PowerShell execution
* CMD execution
* Parent-child process relationships
* Process frequency
* Command-line activity
* EventCode distribution

These use cases form the foundation of the Home SOC monitoring workflow.

## 15. Limitations

This project primarily focuses on Sysmon Process Creation telemetry.

Not every Sysmon EventCode was configured or analyzed as a separate detection use case.

The project also does not claim that every possible endpoint threat can be detected using the current Sysmon configuration.

Detection effectiveness depends on:

* Sysmon configuration
* Windows logging
* Splunk data collection
* Field extraction
* Detection logic
* Analyst investigation

## 16. Security Considerations

Before publishing the project publicly, screenshots and exported logs should be reviewed for sensitive information.

The following should not be published:

* Passwords
* Authentication tokens
* API keys
* Private keys
* Sensitive command-line values
* Personal information
* VM credentials

## Conclusion

Sysmon provides detailed Windows endpoint telemetry for the Home SOC Lab.

The collected Process Creation events allow Splunk to monitor PowerShell, CMD, process relationships, command-line activity, and other endpoint behavior.

The overall monitoring flow is:

```text
Windows Activity
      ↓
    Sysmon
      ↓
Windows Event Logs
      ↓
    Splunk
      ↓
 SPL Detection
      ↓
Investigation
```

Sysmon therefore provides the endpoint telemetry required for the SOC monitoring and investigation workflow implemented in this project.

# Splunk Configuration

## Overview

This document describes the Splunk Enterprise configuration used in the Home SOC Monitoring Lab.

Splunk Enterprise acts as the SIEM platform responsible for collecting, indexing, searching, and analyzing Windows and Sysmon security telemetry.

## Environment

### Splunk Platform

* Splunk Enterprise 10.4.0
* Operating System: Windows 11 VM
* Web Interface: `http://127.0.0.1:8000`
* Main Index: `main`

## Monitored Data

The lab collects:

* Windows Event Logs
* Sysmon Operational logs
* Windows Security events
* Process creation telemetry
* Authentication events

## 1. Splunk Web Interface

Splunk Web was accessed through:

```text
http://127.0.0.1:8000
```

The Splunk Web interface was used to:

* Search events
* Create SPL searches
* Build dashboards
* Review indexed data
* Investigate Windows security events
* Analyze Sysmon telemetry

## 2. Splunk Index

The primary index used in the project was:

```text
main
```

The `main` index contains the Windows and Sysmon telemetry used for detection and investigation.

A basic search to verify collected data is:

```spl
index=main
```

## 3. Sysmon Sourcetype

The main Sysmon sourcetype used in the project was:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

This sourcetype identifies events collected from the Windows Sysmon Operational log.

A basic Sysmon search is:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

## 4. Sysmon Process Creation

Sysmon EventCode 1 represents Process Creation.

The following search was used to investigate process creation:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

### Important Fields

* `_time`
* `User`
* `Image`
* `ParentImage`
* `CommandLine`
* `EventCode`

These fields provide context about how a process was executed.

## 5. PowerShell Monitoring

PowerShell process activity was monitored using Sysmon Process Creation events.

### SPL Query

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell*" | table _time User ParentImage CommandLine
```

This search helps identify PowerShell processes and provides additional execution context.

### MITRE ATT&CK

**T1059.001 — PowerShell**

## 6. Windows Command Shell Monitoring

CMD activity was monitored using Sysmon Process Creation events.

### SPL Query

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*cmd.exe*"
```

This search identifies Windows Command Shell process activity.

### MITRE ATT&CK

**T1059.003 — Windows Command Shell**

## 7. Sysmon EventCode Analysis

The distribution of collected Sysmon events was analyzed using:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by EventCode
```

This provides an overview of the types of Sysmon events being collected.

## 8. Process Frequency Analysis

Frequently observed processes were analyzed using:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count by Image
```

The results can help an analyst understand normal process activity and identify processes that may require additional investigation.

## 9. Parent-Child Process Analysis

Parent-child process relationships were analyzed using:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by ParentImage, Image
| sort - count
```

This provides additional context about how processes were launched.

## 10. Windows Authentication Monitoring

Windows authentication events were also investigated.

### Successful Logon

**Event ID 4624**

Represents a successful Windows logon.

### Failed Logon

**Event ID 4625**

Represents a failed Windows logon.

A combined search was used to investigate both events:

```spl
index=main (EventCode=4624 OR EventCode=4625)
```

## 11. Failed Logon Investigation

Failed authentication events were investigated using:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| table _time ComputerName Account_Name Logon_Type Process_Name
| sort - _time
```

This search provides useful context about failed authentication activity.

## 12. Failed Logon Statistics

Failed authentication activity was summarized using:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Logon_Type
```

This allows the analyst to group failed logons by account and logon type.

## 13. Dashboard Configuration

A Splunk dashboard named **SOC Monitoring Dashboard** was created.

The dashboard contains panels for:

* PowerShell Process Monitoring
* CMD Process Monitoring
* Process Creation Monitoring
* Sysmon EventCode Monitoring

The dashboard provides a centralized monitoring view for the Home SOC Lab.

Detailed dashboard information is documented separately in:

```text
Dashboard/Dashboard-Documentation.md
```

## 14. Detection vs Alerting

Detection searches were successfully implemented in the lab.

A detection search identifies security-relevant activity in collected telemetry.

An alert adds an automated notification or response when a defined condition is met.

The current lab environment uses Splunk Free, and automated alert creation was not enabled.

Therefore, this project documents detection and dashboard monitoring without claiming automated alerting was implemented.

## 15. Splunk Configuration Validation

The Splunk configuration was validated by confirming that:

1. Splunk Web was accessible.
2. Windows Event Logs were available.
3. Sysmon events were indexed.
4. Sysmon Process Creation events could be searched.
5. PowerShell activity could be investigated.
6. CMD activity could be investigated.
7. Windows authentication events could be investigated.
8. SPL queries returned relevant telemetry.
9. The SOC Monitoring Dashboard displayed collected data.

## 16. Troubleshooting Notes

During the project, the following configuration issues were investigated.

### Splunk Web

Splunk Web was accessed through:

```text
http://127.0.0.1:8000
```

### Splunk Restart

Splunk services were restarted when required during configuration troubleshooting.

After restarting, Splunk Web and Search & Reporting functionality were verified.

### Alert Creation

The available Splunk Free environment did not provide the expected alert-creation workflow through the Search & Reporting interface.

Therefore, alert automation was not included as an implemented project feature.

## 17. Security Considerations

The following information should not be published in a public GitHub repository:

* Splunk passwords
* Windows passwords
* API keys
* Authentication tokens
* License files
* VM disk files
* Private keys
* Sensitive command-line values
* Personally identifiable information

Screenshots should be reviewed before publication and sensitive values should be cropped or blurred.

## Conclusion

Splunk Enterprise was configured as the SIEM platform for the Home SOC Lab.

The configuration successfully supported:

```text
Log Collection
      ↓
   Indexing
      ↓
  SPL Searc
```

# Detection Queries

## Overview

This document contains the Splunk SPL queries used in the Home SOC Monitoring Lab.

The queries were developed to search, detect, summarize, and investigate Windows and Sysmon telemetry collected from the Windows 11 monitored endpoint.

The main data sources are:

 Sysmon Operational logs

 Windows Security logs

 Process Creation events

 Authentication events

## 1. All Sysmon Events

### Purpose

View Sysmon events collected by Splunk.

### SPL

```spl id="a8f2kd"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"

```
### Use

This query provides a general view of the Sysmon telemetry available in Splunk.

## 2. Sysmon Process Creation

### Purpose

Search for Sysmon Process Creation events.

### SPL

```spl id="m7q4vx"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

```
## Event

Sysmon EventCode 1 — Process Creation

### Important Fields

 `_time`

 `User`

 `Image`

 `ParentImage`

 `CommandLine`

 `EventCode`

## 3. PowerShell Process Monitoring

### Purpose

Identify PowerShell process activity.

### SPL

```spl id="r5n8tc"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*powershell\*" | table \_time User ParentImage CommandLine

```
### MITRE ATT\&CK

T1059.001 — PowerShell

### Investigation

The results can be investigated using:

 Timestamp

 User

 Parent process

 Process image

 Command line

## 4. Windows CMD Monitoring

### Purpose

Identify Windows Command Shell activity.

### SPL

```spl id="u3k6pz"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*cmd.exe\*"

```
### MITRE ATT\&CK

T1059.003 — Windows Command Shell

### Investigation

The process creation event can be examined to determine when CMD was executed and which user or parent process was associated with it.

## 5. Sysmon EventCode Statistic

### Purpose

Understand the distribution of Sysmon event types.

### SPL

```spl id="j9v2lm"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by EventCode

```

### Use

This query helps identify which Sysmon EventCodes are being generated and collected.

## 6. Process Frequency Analysis

### Purpose

Identify frequently observed processes.

### SPL

```spl id="p4x7qb"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count by Image

```
### Investigation

This query can help establish an understanding of normal process activity within the lab.

Processes that appear unexpectedly can be investigated further

## 7. Parent-Child Process Analysis

### Purpose

Analyze relationships between parent and child processes.

### SPL

```spl id="c6w3hs"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

| stats count by ParentImage, Image

| sort - count

```

### Investigation

Parent-child relationships help the analyst understand how a process was launched.

## 8. Windows Authentication Monitoring

### Purpose

Search for successful and failed Windows authentication events.

### SPL

```spl id="e2n9rk"

index=main (EventCode=4624 OR EventCode=4625)

```
### Event IDs

 `4624` — Successful logon

 `4625` — Failed logon

## 9. Successful Logon Monitoring

### Purpose

Search for successful Windows authentication events.

### SPL

```spl id="q7m4yd"

index=main sourcetype="WinEventLog:Security" EventCode=4624

```
### Investigation

Useful fields can include:

 Timestamp

 Account

 Logon Type

 Process

 Computer

## 10. Failed Logon Monitoring

### Purpose

Search for failed Windows authentication events.

### SPL

```spl id="v8t2ka"

index=main sourcetype="WinEventLog:Security" EventCode=4625

```
### Investigation

Failed authentication events should be investigated in context rather than automatically treated as malicious.

## 11. Failed Logon Investigation

### Purpose

Display important fields from failed authentication events.

### SPL

```spl id="n5c8wf"

index=main sourcetype="WinEventLog:Security" EventCode=4625

| table \_time ComputerName Account\_Name Logon\_Type Process\_Name

| sort - \_time

```

### Important Fields

 `_time`

 `ComputerName`

 `Account\_Name`

 `Logon\_Type`

 `Process\_Name`

## 12. Failed Logon Statistics

### Purpose

Group failed authentication events by account and logon type.

### SPL

```spl id="k3p6rz"

index=main sourcetype="WinEventLog:Security" EventCode=4625

| stats count by Account\_Name, Logon\_Type

```
### Use

This query provides a summarized view of failed authentication activity observed in the lab.

## 13. Main Process Investigation Query

### Purpose

Provide a compact view of important Process Creation fields.

### SPL

```spl id="s8y4mb"

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

| table \_time User Image ParentImage CommandLine

| sort - \_time

```
### Use

This query is useful during manual investigation of process activity.

## 14. Process Investigation Workflow

Process-related investigation follows:

```text

Sysmon EventCode 1

       ↓

Identify Process

      ↓

Check User

      ↓

Check Parent Process

      ↓

Check Command Line

       ↓

Review Timestamp

       ↓

Determine Expected / Unexpected Activity

      ↓

Investigate Further

```

## 15. Authentication Investigation Workflow

Authentication investigation follows:

```text

Event ID 4624 / 4625

      ↓

Identify Account

      ↓

Check Logon Type

      ↓

Check Process

      ↓

Check Timestamp

       ↓

Validate Activity

      ↓

Document Finding

```
## 16. Query Reference

| Query | Purpose | Main Data |
| --- | --- | --- |
| All Sysmon Events | View Sysmon telemetry | Sysmon |
| Process Creation | Monitor process creation | Sysmon EventCode 1 |
| PowerShell | Monitor PowerShell | Sysmon |
| CMD | Monitor CMD | Sysmon |
| EventCode Statistics | Analyze event distribution | Sysmon |
| Process Frequency | Identify common processes | Sysmon |
| Parent-Child Analysis | Analyze process relationships | Sysmon |
| Authentication Monitoring | Monitor logons | Security |
| Successful Logon | Investigate 4624 | Security |
| Failed Logon | Investigate 4625 | Security |
| Failed Logon Investigation | Analyze failed logons | Security |
| Failed Logon Statistics | Summarize failed logons | Security |
| Main Process Investigation | Detailed process analysis | Sysmon |

## 17. Detection vs Investigation

Not every SPL query in this document is a detection rule.

Queries are used for different purposes, including:

 Detection

 Investigation

 Statistics

 Baseline analysis

 Event validation

For example, the PowerShell query identifies PowerShell activity, while the parent-child process query provides additional context during investigation.

## 18. Detection vs Alerting

A detection search identifies security-relevant activity in collected telemetry.

An alert adds an automated notification or response when a defined condition is met.

In this project:

 Detection searches were implemented.

 Dashboard monitoring was implemented.

 Automated alert creation was not enabled in the current Splunk Free lab environment.

Therefore, this project does not claim automated alerting was implemented.

## 19. Query Safety

These SPL searches are read-only searches against indexed Splunk data.

Running these queries does not:

 Modify Windows files

 Start or stop processes

 Delete events

 Change Windows configuration

 Execute commands on the Windows endpoint

The queries search and analyze telemetry that has already been collected.

## Conclusion

The SPL queries in this project provide the detection and investigation layer of the Home SOC Lab.

The overall workflow is:

```text

Telemetry

   ↓

SPL Search

  ↓

Detection

   ↓

Investigation

   ↓

Validation

   ↓

Documentation

```

These queries demonstrate practical use of Splunk SPL for Windows and Sysmon security monitoring.




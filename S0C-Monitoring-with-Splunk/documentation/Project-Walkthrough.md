# Project Walkthrough

## 1. Lab Setup

The SOC lab was created using VirtualBox with two virtual machines:

* Windows 11 — monitored endpoint
* Kali Linux — authorized security testing machine

Splunk Enterprise was installed on the Windows 11 environment.

## 2. Sysmon Configuration

Sysmon was installed on the Windows 11 VM to collect detailed process and system telemetry.

The main telemetry used in this project includes:

* Process Creation
* Process Image
* User
* Parent Process
* Command Line
* Event Timestamp

## 3. Log Collection

Windows Event Logs and Sysmon Operational logs were collected and indexed by Splunk.

The main Sysmon sourcetype used for analysis was:

```text id="h9c6zi"
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

## 4. Detection Development

SPL queries were created to identify and analyze:

* Process Creation
* PowerShell activity
* Windows Command Shell activity
* Sysmon EventCodes
* Windows authentication events
* Failed authentication attempts
* Parent-child process relationships

## 5. Dashboard

A Splunk dashboard named `SOC Monitoring Dashboard` was created to provide a centralized view of important security telemetry.

The dashboard includes monitoring panels for:

* PowerShell Process Monitoring
* CMD Process Monitoring
* Process Creation Monitoring
* Sysmon EventCode Monitoring

## 6. Controlled Security Testing

Kali Linux was used to perform authorized tests against the Windows 11 lab environment.

Tests included:

* ICMP connectivity testing
* Network service discovery using Nmap
* SMB share enumeration
* SMB protocol enumeration
* HTTP service verification

All testing was performed inside the isolated lab environment.

## 7. Authentication Investigation

Windows Security Event IDs 4624 and 4625 were investigated.

* Event ID 4624 — successful logon
* Event ID 4625 — failed logon

A controlled incorrect-password test was performed on the Windows 11 VM to generate a 4625 event.

## 8. Incident Investigation

Detected events were investigated using Splunk by examining available fields such as:

* Timestamp
* Account
* Logon Type
* Process
* Parent Process
* Command Line
* Event Code

The investigation process focused on understanding what happened, when it happened, and whether the activity was expected within the lab.

## 9. MITRE ATT&CK Mapping

Relevant lab activities were mapped to MITRE ATT&CK techniques:

* PowerShell — T1059.001
* Windows Command Shell — T1059.003
* Network Service Scanning — T1046
* Network Share Discovery — T1135

The single controlled failed-login test was documented as authentication telemetry and was not classified as brute-force activity.

## 10. Alert Limitation

Detection searches and dashboard monitoring were successfully implemented.

Automated alert creation was not enabled in the current Splunk Free lab environment. Therefore, the project documents detection and investigation capabilities without claiming automated alerting was implemented.

## 11. Project Outcome

The completed lab demonstrates a basic SOC workflow:

```text id="5r8c3m"
Telemetry Collection
        ↓
Detection
        ↓
Investigation
        ↓
Controlled Security Testing
        ↓
Incident Analysis
        ↓
MITRE ATT&CK Mapping
        ↓
Documentation
```

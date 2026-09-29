\# Home SOC Monitoring Lab



\## Project Overview



This project is a home-based Security Operations Center (SOC) monitoring lab built using Splunk Enterprise, Sysmon, Windows 11, Kali Linux, and VirtualBox.



The main objective of this project is to simulate a basic SOC environment where Windows security telemetry is collected, analyzed, detected, investigated, and documented.



\## Technologies Used



\* Windows 11

\* Splunk Enterprise 10.4.0

\* Sysmon

\* Kali Linux

\* VirtualBox

\* SPL (Search Processing Language)

\* MITRE ATT\&CK



\## Project Objectives



\* Collect Windows security and system telemetry.

\* Monitor process creation and PowerShell activity.

\* Detect CMD and suspicious process activity.

\* Monitor Windows authentication events.

\* Perform controlled security testing using Kali Linux.

\* Investigate security events using Splunk.

\* Map relevant activities to MITRE ATT\&CK techniques.

\* Build a practical SOC monitoring workflow.



\## SOC Workflow



```text

Windows 11

&#x20;   ↓

Sysmon

&#x20;   ↓

Windows Event Logs

&#x20;   ↓

Splunk

&#x20;   ↓

SPL Detection

&#x20;   ↓

Investigation

&#x20;   ↓

Incident Response

&#x20;   ↓

MITRE ATT\&CK Mapping

```




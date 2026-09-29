# Home SOC Monitoring Lab with Splunk

A hands-on Home Security Operations Center (SOC) monitoring lab built using Splunk Enterprise 10.4.0, Sysmon, Windows 11, Kali Linux, and VirtualBox.

The project demonstrates how security telemetry can be collected from a Windows endpoint, analyzed using Splunk SPL queries, investigated as security events, and mapped to relevant MITRE ATT\&CK techniques.

##  Project Overview

This project simulates a basic SOC environment in a controlled virtual lab.

The Windows 11 virtual machine acts as the monitored endpoint. Sysmon collects detailed process and system telemetry, while Splunk Enterprise acts as the SIEM platform for log collection, searching, analysis, and dashboard visualization.

Kali Linux is used to perform authorized and controlled security-testing activities against the Windows lab environment.

## SOC Workflow

```text

Windows 11 VM

    ↓

  Sysmon

    ↓

Windows Event Logs

    ↓

  Splunk

    ↓

 SPL Queries

    ↓

 Detection

    ↓

Investigation

    ↓

Incident Response

    ↓

MITRE ATT\&CK Mapping

```
## Project Objectives

 Collect Windows security and system telemetry.

 Monitor Windows process creation.

 Monitor PowerShell activity.

 Monitor Windows Command Shell activity.

 Monitor Windows authentication events.

 Investigate successful and failed logon events.

 Perform controlled security testing using Kali Linux.

 Analyze security events using Splunk SPL.

 Build a SOC monitoring dashboard.

 Perform basic incident investigation and response.

 Map observed activities to MITRE ATT\&CK techniques.

 Document the complete SOC workflow.

## Technologies Used

 Technology                Purpose                             

| ------------------------ | ----------------------------------- |

| Windows 11               | Monitored endpoint                  |

| Splunk Enterprise 10.4.0 | SIEM and log analysis               |

| Sysmon                   | Windows security telemetry          |

| Kali Linux               | Authorized security testing         |

| VirtualBox               | Virtual lab environment             |

| SPL                      | Detection and investigation queries |

| MITRE ATT\&CK             | Technique mapping                   |

## Lab Architecture

```text

                  ┌─────────────────┐

                  │   Kali Linux    │

                  │  Security Test  │

                  └────────┬────────┘

                           │

                           │ Authorized Testing

                           ↓
                   ┌─────────────────┐

                   │    Windows 11   │

                   │   Monitored VM  │

                   └────────┬────────┘

                            │

                     │ Sysmon + Windows Events

                            ↓
                   ┌─────────────────┐

                   │      Splunk     │

                   │      SIEM       │

                   └────────┬────────┘

                            │
                           
                     │ SPL Queries

                           ↓

                  ┌─────────────────┐

                  │ Detection \&     │

                  │ Investigation   │

                  └────────┬────────┘

                           ↓

                  ┌─────────────────┐

                  │ Incident        │

                  │ Response        │

                  └────────┬────────┘

                           ↓

                  ┌─────────────────┐

                   │ MITRE ATT\&CK    │

                   │ Mapping         │

                   └─────────────────┘

```
## Monitoring \& Detection

The lab monitors several important Windows security activities.

### Process Creation

Sysmon EventCode 1 is used to monitor process creation events.

Important fields include:

 Timestamp

 User

 Process Image

 Parent Process

 Command Line

### PowerShell Monitoring

PowerShell process activity is monitored using Sysmon telemetry and SPL queries.

Example:

```spl

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*powershell\*"

| table \_time User ParentImage CommandLine

```
### CMD Monitoring

Windows Command Shell activity is monitored using Sysmon Process Creation events.

```spl

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*cmd.exe\*"

```
### Authentication Monitoring

Windows Security Event IDs are monitored:

 `4624` → Successful logon

 `4625` → Failed logon

These events are investigated using account, logon type, process, and other available event fields.

## SOC Monitoring Dashboard

A Splunk dashboard named `SOC Monitoring Dashboard` was created to provide centralized visibility into Windows security telemetry.

The dashboard includes monitoring panels for:

 PowerShell Process Monitoring

 CMD Process Monitoring

 Process Creation Monitoring

 Sysmon EventCode Monitoring

The dashboard provides a quick way for an analyst to review relevant security activity without manually running every query.

## Controlled Security Testing

Security testing was performed only inside the authorized virtual lab environment.

### Network Connectivity Test

```bash

ping -c 4 192.168.56.101

```
### Network Service Scanning

```bash

nmap -sT -Pn 192.168.56.101

```

The scan identified services exposed by the Windows lab machine.

### SMB Share Enumeration

```bash

smbclient -L //192.168.56.101 -N

```
Anonymous SMB access was denied by the Windows environment.

### SMB Protocol Enumeration

```bash

nmap -p 445 --script smb-protocols 192.168.56.101

```
### Splunk HTTP Verification

```bash

curl -I http://192.168.56.101:8000

```
### PowerShell Detection Test

```powershell

Write-Host "SOC Detection Test"

```
### CMD Detection Test

```cmd

echo SOC\_CMD\_TEST

```
### Authentication Test

A controlled incorrect-password attempt was performed on the Windows VM to generate a 4625 failed logon event, followed by a successful login.

## MITRE ATT\&CK Mapping

The following techniques were mapped based on activities actually performed in the lab.

| Activity              | MITRE ATT\&CK Technique            |

| --------------------- | --------------------------------- |

| PowerShell execution  | T1059.001 – PowerShell            |

| Windows Command Shell | T1059.003 – Windows Command Shell |

| Nmap network scanning | T1046 – Network Service Scanning  |

| SMB share enumeration | T1135 – Network Share Discovery   |

Authentication events such as 4624 and 4625 were treated as security telemetry for investigation.

The single controlled failed-login test was not classified as brute-force activity.

## Incident Response Workflow

The project follows a basic SOC incident-response workflow:

```text

1\. Identify

    ↓

2\. Investigate

     ↓

3\. Validate

     ↓

4\. Respond

     ↓

5\. Document

```
### Identify

Detect potentially relevant activity using Splunk searches.

### Investigate

Review:

 Timestamp

 User

 Process

 Parent Process

 Command Line

 EventCode

 Logon Type

### Validate

Determine whether the activity is expected, controlled testing, or potentially suspicious.

### Respond

Document the activity and determine appropriate response actions within the lab environment.

### Document

Record findings, evidence, detection queries, and MITRE ATT\&CK mappings.

## Detection vs Alerting

This project demonstrates detection and investigation using Splunk SPL.

Detection searches identify relevant security events from collected telemetry.

Example:

```text

PowerShell process detected

      ↓

Splunk SPL search

      ↓

Event returned

      ↓

Analyst investigates

```
Automated alert creation was not enabled in the current Splunk Free lab environment.

Therefore, this project does not claim automated alerting or notification functionality.

## Project Structure

```text

SOC-Monitoring-with-Splunk/

│

├── README.md

│

├── Config/

│   ├── Splunk-Configuration.md

│   ├── Sysmon-Configuration.md

│   └── Windows-Event-Log-Configuration.md

│

├── Dashboard/

│   └── Dashboard-Documentation.md

│

├── Documentation/

│   ├── Project-Overview.md

│   ├── Architecture.md

│   ├── Project-Walkthrough.md

│   ├── MITRE-ATTACK-Mapping.md

│   ├── Detection-Rules.md

│   ├── Incident-Response.md

│   └── Attack-Simulation.md

│

├── Queries/

│   └── Detection-Queries.md

│

└── Screenshot/

```
## Security \& Lab Scope

All testing was performed in an isolated and authorized virtual environment.

The project does not involve:

 Unauthorized systems

 Malware deployment
 
 Credential theft

 Destructive attacks

 Data exfiltration

 Persistence against real systems

The Kali Linux activities were limited to controlled security-testing exercises against the Windows lab VM.

## Screenshots

Screenshots documenting the Splunk dashboard, detections, investigations, and lab activities are available in the:

```text

Screenshot/

```
directory.

## Documentation

Detailed documentation is available in the following directories:

 `Config/` → Environment and configuration documentation

 `Dashboard/` → Splunk dashboard documentation

 `Documentation/` → Project, architecture, detection, attack simulation, incident response, and MITRE documentation

 `Queries/` → Splunk SPL detection and investigation queries

 `Screenshot/` → Project evidence and screenshots

## Future Improvements

Possible future enhancements include:

 Automated alerting and notification

 Additional Sysmon event monitoring

 More Windows authentication detections

 Additional MITRE ATT\&CK mappings

 More advanced correlation rules

 Linux log monitoring

 Threat-intelligence integration

 Automated incident-response workflows

## Project Outcome

This Home SOC project demonstrates a practical security-monitoring workflow:

```text

Collect

 ↓

Index

 ↓

Search

 ↓

Detect

 ↓

Investigate

 ↓

Validate

 ↓

Document

 ↓

Map to MITRE ATT\&CK

```
The project provides hands-on experience with SIEM monitoring, Windows telemetry, Sysmon, SPL detection, security investigation, controlled attack simulation, incident response, and MITRE ATT\&CK mapping.

## Author

Cybersecurity Student | Aspiring SOC Analyst



This project was developed as a hands-on cybersecurity portfolio project to demonstrate practical SOC monitoring and security-analysis skills.




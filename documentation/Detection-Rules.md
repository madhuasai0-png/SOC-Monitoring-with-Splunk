# Attack Simulation

## Overview

This document describes the controlled security testing performed in the isolated Home SOC Lab.

The testing was performed from the Kali Linux VM against the Windows 11 VM. The purpose was to generate realistic security telemetry and understand how common network discovery activities can be investigated.

All testing was authorized and limited to the lab environment.

## Lab Target

Windows 11 VM: `192.168.56.101`

Testing Machine: Kali Linux VM

## 1. Network Connectivity Test

### Command

```bash

ping -c 4 192.168.56.101

```
### Result

The Windows 11 VM responded successfully to all four ICMP requests.

This confirmed network connectivity between the Kali Linux and Windows 11 virtual machines.

## 2. Network Service Discovery

### Objective

Identify TCP services exposed by the Windows 11 lab machine.

### Command

```bash

nmap -sT -Pn 192.168.56.101

```
### Observed Services

The scan identified the following accessible TCP ports:

```text

135/tcp

139/tcp

445/tcp

5432/tcp

8000/tcp

8089/tcp

```
### MITRE ATT\&CK

T1046 — Network Service Scanning

### SOC Relevance

Network service scanning can provide information about services exposed by an endpoint. In an enterprise environment, unexpected scanning activity may require investigation.

## 3. SMB Share Enumeration

### Objective

Test whether SMB shares could be enumerated anonymously.

### Command

```bash

smbclient -L //192.168.56.101 -N

```
### Result

The Windows 11 host returned:

```text

NT\_STATUS\_ACCESS\_DENIED

```
Anonymous SMB share access was therefore denied.

### MITRE ATT\&CK

T1135 — Network Share Discovery

### SOC Relevance

SMB share enumeration can reveal information about network resources. Even when access is denied, the attempted activity can be relevant during security investigation.

## 4. SMB Protocol Enumeration

### Objective

Identify the SMB protocol versions supported by the Windows 11 host.

### Command

```bash

nmap -p 445 --script smb-protocols 192.168.56.101

```
### Observed SMB Dialects

The following SMB dialects were observed:

```text

SMB 2.0.2

SMB 2.1

SMB 3.0

SMB 3.0.2

SMB 3.1.1

```
### SOC Relevance

Protocol enumeration provides additional information about the configuration of a network service and can be useful during authorized security assessment.

## 5. Splunk HTTP Service Verification

### Objective

Verify that the Splunk Web service running on the Windows 11 VM was reachable from Kali Linux.

### Command

```bash

curl -I http://192.168.56.101:8000

```
### Result

The HTTP request returned a `303` redirect to:

```text

/en-US/

```

This confirmed that the Splunk Web service was reachable from the Kali Linux VM.

### SOC Relevance

This test demonstrated that services running on the monitored endpoint can be accessed from another system on the lab network.

## 6. PowerShell Activity Simulation

### Objective

Generate normal PowerShell process activity so that Sysmon could record process creation telemetry.

### Test

A PowerShell command was executed on the Windows 11 VM:

```powershell

Write-Host "SOC Detection Test"

```
### Observation

The command executed successfully.

The PowerShell process itself was visible through Sysmon Process Creation telemetry.

### Important Note

The text printed by `Write-Host` does not create a separate process event. Therefore, searching specifically for the string `SOC Detection Test` in a Sysmon Process Creation event did not produce a separate matching process event.

The PowerShell process activity itself was successfully observed.

### MITRE ATT\&CK

T1059.001 — PowerShell

## 7. Windows Command Shell Activity Simulation

### Objective

Generate CMD process activity and verify that it could be detected using Sysmon.

### Command

```cmd

echo SOC\_CMD\_TEST

```
### Observation

The CMD process activity was captured by Sysmon Process Creation telemetry and was visible through Splunk.

### MITRE ATT\&CK

T1059.003 — Windows Command Shell

## 8. Controlled Failed Logon Test

### Objective

Generate a controlled Windows failed-authentication event for investigation.

### Test Procedure

The Windows 11 VM was locked using the Windows lock-screen function.

An incorrect password was entered once, followed by the correct password.

### Observed Event

The failed authentication generated:

Event ID 4625 — An account failed to log on

The controlled interactive test produced a Logon Type 2 event.

A separate network authentication event with Logon Type 3 was also observed during the lab testing.

### Investigation

The events were investigated in Splunk using Windows Security logs.

Relevant fields included:

 Timestamp

 Account

 Logon Type

 Process

 Computer

 Event Code

### Important Limitation

Only a single controlled incorrect-password attempt was performed.

Therefore, this activity was not classified as brute-force activity because repeated credential guessing was not performed.

## 9. Successful Authentication Investigation

### Objective

Investigate a successful Windows authentication event.

### Event

Event ID 4624 — An account was successfully logged on

A service logon with the following details was observed during the investigation:

```text

Logon Type: 5

Account: SYSTEM

Process: C:\\Windows\\System32\\services.exe

```

### SOC Relevance

Authentication events provide useful information for understanding how accounts and services interact with a Windows endpoint.

## 10. Splunk Detection Verification

The simulated activities were investigated using Splunk searches.

### Process Creation

```spl

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

```
### PowerShell

```spl

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*powershell\*" | table \_time User ParentImage CommandLine

```
### CMD

```spl

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*cmd.exe\*"

```
### Authentication

```spl

index=main (EventCode=4624 OR EventCode=4625)

```
These searches were used to investigate the telemetry generated during the lab activities.

## 11. MITRE ATT\&CK Mapping

The following activities were mapped to MITRE ATT\&CK techniques based on the behavior actually performed:

| Activity | MITRE ATT&CK Technique | ID |
| --- | --- | --- |
| PowerShell execution | PowerShell | T1059.001 |
| CMD execution | Windows Command Shell | T1059.003 |
| Nmap scanning | Network Service Scanning | T1046 |
| SMB share enumeration | Network Share Discovery | T1135 |

The 4624 and 4625 authentication events were treated as authentication telemetry and investigation evidence.

The single failed-password test was not mapped to Brute Force because repeated credential guessing was not performed.

## 12. Overall Investigation Flow

The attack simulations followed this workflow:

```text

Controlled Test

     ↓

Windows Activity

     ↓

Sysmon / Windows Event Logs

     ↓

Splunk Ingestion

     ↓

SPL Detection

     ↓

Event Investigation

     ↓

MITRE ATT\&CK Mapping

     ↓

Documentation

```

The purpose of the simulations was to understand how security-related activity becomes telemetry and how a SOC analyst can investigate that telemetry.

## 13. Safety and Scope

All testing was performed against the user's own virtual machines in an isolated lab environment.

The project did not include:

 Malware deployment

 Credential theft

 Persistence mechanisms

 Destructive attacks

 Data exfiltration

 Unauthorized systems

 Real-world targets

The simulations were intentionally limited to safe network discovery, service enumeration, process activity, and controlled authentication testing.

## Conclusion

The attack simulations provided practical examples of how network, process, and authentication activity can be generated and investigated in a SOC environment.

The tests demonstrated the complete relationship between:

Security Testing → Telemetry Collection → Detection → Investigation → MITRE ATT\&CK Mapping → Documentation



The results were used to validate the monitoring capabilities of the Home SOC Lab and improve understanding of how a SOC analyst investigates security-relevant activity.




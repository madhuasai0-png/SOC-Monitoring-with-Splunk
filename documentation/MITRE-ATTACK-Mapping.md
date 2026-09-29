\# MITRE ATT\&CK Mapping



\## Overview



This document maps the security activities performed in the Home SOC Lab to relevant MITRE ATT\&CK techniques.



The mapping is based only on activities that were actually performed and observed in the lab.



\## Technique Mapping



| Lab Activity                 | MITRE ATT\&CK Technique   | Technique ID |

| ---------------------------- | ------------------------ | ------------ |

| PowerShell process execution | PowerShell               | T1059.001    |

| Windows CMD execution        | Windows Command Shell    | T1059.003    |

| Nmap network scanning        | Network Service Scanning | T1046        |

| SMB share enumeration        | Network Share Discovery  | T1135        |



\## 1. PowerShell



\*\*Technique:\*\* PowerShell

\*\*Technique ID:\*\* T1059.001



PowerShell activity was monitored using Sysmon Process Creation events and Splunk SPL queries.



The investigation focused on process image, user, parent process, command line, and timestamp fields.



\## 2. Windows Command Shell



\*\*Technique:\*\* Windows Command Shell

\*\*Technique ID:\*\* T1059.003



CMD process execution was monitored through Sysmon Process Creation events.



Splunk was used to identify CMD-related process activity and investigate the associated telemetry.



\## 3. Network Service Scanning



\*\*Technique:\*\* Network Service Scanning

\*\*Technique ID:\*\* T1046



Nmap was used from the Kali Linux VM to perform authorized network service discovery against the Windows 11 lab machine.



The scan identified services exposed by the test environment.



\## 4. Network Share Discovery



\*\*Technique:\*\* Network Share Discovery

\*\*Technique ID:\*\* T1135



SMB share enumeration was performed from Kali Linux against the Windows 11 lab machine.



The test demonstrated how network share discovery activity can be observed during security testing.



\## Authentication Events



Windows Security Event ID 4624 and Event ID 4625 were investigated during the project.



\* \*\*4624:\*\* Successful logon

\* \*\*4625:\*\* Failed logon



A single controlled incorrect-password attempt was performed to generate a 4625 event.



This activity was treated as authentication telemetry and was \*\*not classified as Brute Force\*\*, because repeated credential guessing was not performed.



\## Mapping Limitations



MITRE ATT\&CK mappings in this project are limited to techniques supported by the activities actually performed in the isolated lab environment.



No technique was assigned solely because an event could theoretically be associated with that technique.




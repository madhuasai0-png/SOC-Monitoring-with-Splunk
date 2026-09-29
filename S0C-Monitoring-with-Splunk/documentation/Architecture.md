# SOC Lab Architecture

## Environment

The Home SOC Lab consists of a Windows 11 monitored endpoint, Sysmon for detailed telemetry, Splunk Enterprise for log collection and analysis, and Kali Linux for authorized security testing.

## Architecture Flow

```text
Kali Linux VM
       |
       | Authorized Security Testing
       v
Windows 11 VM
       |
       | Windows Events + Sysmon Telemetry
       v
Splunk Enterprise
       |
       | SPL Queries
       v
Detection & Analysis
       |
       v
Incident Investigation
       |
       v
MITRE ATT&CK Mapping
```

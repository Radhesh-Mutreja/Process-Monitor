# NOIR // PROCESS MONITOR

> A PowerShell-based suspicious process detector for Windows — flags malicious names, unsigned executables, processes running from temp directories, and high resource usage.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-00B4D8?style=flat-square&logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-b967ff?style=flat-square)

---

## Features

- **Process Enumeration** — lists all running processes with PID, CPU, memory, and executable path
- **Threat Detection**
  - Known malicious process names (Mimikatz, Meterpreter, netcat, XMRig, etc.)
  - Processes running from suspicious directories (Temp, AppData, Public)
  - Unsigned or unverifiable executables
  - Processes with no detectable path (possible hollowing/injection)
  - High CPU / memory usage flagging
- **Color-coded console output** — Red = Critical, Yellow = Warning, Green = Clean
- **HTML report export** — noir-themed, matches the toolkit aesthetic
- **TXT report export** — plain text for logging or piping

---

## Usage

```powershell
# Basic scan (console output only)
.\noir-procmon.ps1

# Export HTML report to Desktop
.\noir-procmon.ps1 -ExportHTML

# Export TXT report
.\noir-procmon.ps1 -ExportTXT

# Export both to a custom path
.\noir-procmon.ps1 -ExportHTML -ExportTXT -OutputPath "C:\Reports"
```

### First run — execution policy

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## Detection Rules

| Flag | Trigger | Severity |
|------|---------|----------|
| `KNOWN_MALICIOUS_NAME` | Process name matches known tools (mimikatz, nc, xmrig, etc.) | Critical |
| `SUSPICIOUS_PATH` | Executable running from Temp, AppData, Public, ProgramData | Warning |
| `UNSIGNED` | Executable has no valid Authenticode signature | Warning |
| `NO_PATH_DETECTED` | Process has no retrievable executable path | Warning |
| `HIGH_CPU` | CPU time exceeds 80s | Warning |
| `HIGH_MEM` | Memory usage exceeds 500MB | Info |
| `CLEAN` | No flags triggered | Normal |

---

## Part of the Noir Toolkit

| Tool | Description |
|------|-------------|
| Noir IDS | Log monitoring & intrusion detection |
| Noir Packet Analyzer | Live capture + PCAP analysis |
| **Noir Process Monitor** | You are here |
| ReconX | OSINT framework |
| NETRUNNER | Network toolkit |

---

## Disclaimer

For educational and authorized use only. Run only on systems you own or have explicit permission to monitor.

---

## Author

**Radhesh Mutreja** — MSc DFIS, National Forensic Sciences University  
GitHub: [@nullRdx](https://github.com/Radhesh-Mutreja)

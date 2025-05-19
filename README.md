# 🔍 Sysmon Detection Guide

A curated guide to essential Sysmon Event IDs for threat hunting, blue teaming, and SOC operations.  
Includes detailed detection notes with **use cases**, **event tags**, **real-world examples**, and **practical detection tips** to improve Windows telemetry visibility.

---

## ✅ Top Priority (Must Monitor – High Detection Value)

| Event ID | Name                   | Reason to Monitor |
|----------|------------------------|-------------------|
| 1        | Process Creation       | Core visibility for execution |
| 3        | Network Connection     | Outbound connection monitoring |
| 7        | Image Loaded           | DLL injection/hijack detection |
| 8        | CreateRemoteThread     | Process injection tracking |
| 11       | File Created           | Malware/ransomware drops |
| 12/13/14 | Registry Events        | Persistence and credential abuse |
| 15       | FileCreateStreamHash   | Alternate Data Streams detection |
| 22       | DNS Query              | Suspicious DNS and C2 domains |
| 25       | Process Tampering      | PEB spoofing, hollowing, etc. |

---

## 🧠 Detection Notes (Use Cases, Tags, Examples, Tips)

### 🔹 Event ID 1 – Process Creation

- **Use Case**: Detect suspicious process execution.
- **Tags**: `Image`, `CommandLine`, `ParentImage`
- **Example**: `powershell.exe -enc ...`, `cmd.exe /c whoami`
- **Detection Tip**: Exclude common system processes (e.g., `svchost.exe`) to reduce noise.

---

### 🔹 Event ID 3 – Network Connection

- **Use Case**: Identify C2 connections, scanning, or exfiltration.
- **Tags**: `Image`, `DestinationIP`, `DestinationPort`, `Protocol`
- **Example**: `nmap.exe` contacting port `4444`
- **Detection Tip**: Alert on known C2 ports (e.g., 4444, 8080) or internal IPs reached by suspicious tools.

---

### 🔹 Event ID 7 – Image Loaded

- **Use Case**: Detect DLL injection or hijacking attempts.
- **Tags**: `Image`, `ImageLoaded`, `Signed`, `Signature`
- **Example**: Unsigned DLLs from `C:\Users\Public\Temp`
- **Detection Tip**: Monitor DLLs loaded from temp folders or with missing digital signatures.

---

### 🔹 Event ID 8 – CreateRemoteThread

- **Use Case**: Detect memory injection or code execution across processes.
- **Tags**: `SourceImage`, `TargetImage`, `StartAddress`, `StartFunction`
- **Example**: `explorer.exe` injecting into `lsass.exe`
- **Detection Tip**: Alert if thread starts at odd or suspicious memory addresses (e.g., ending in `0B80`).

---

### 🔹 Event ID 11 – File Created

- **Use Case**: Detect ransomware or dropped malware payloads.
- **Tags**: `TargetFilename`
- **Example**: Files like `README_RECOVER_FILES.txt`, `.locky`
- **Detection Tip**: Flag uncommon file types in user folders or mass file creation in short time.

---

### 🔹 Event IDs 12 / 13 / 14 – Registry Events

- **Use Case**: Detect persistence mechanisms or credential theft.
- **Tags**: `TargetObject`, `Details`
- **Example**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Detection Tip**: Monitor autorun keys, LSASS-related changes, or scripts in `System\Scripts`.

---

### 🔹 Event ID 15 – FileCreateStreamHash (ADS)

- **Use Case**: Detect hidden malware in Alternate Data Streams.
- **Tags**: `TargetFilename`, `Hash`
- **Example**: `notepad.exe:hidden.hta`
- **Detection Tip**: Flag `.hta`, `.bat`, or `.ps1` stored in ADS.

---

### 🔹 Event ID 22 – DNS Query

- **Use Case**: Monitor suspicious or dynamic DNS requests.
- **Tags**: `QueryName`
- **Example**: Domains like `evil-update.xyz`, `xyz[.]ngrok[.]io`
- **Detection Tip**: Exclude known domains like `*.microsoft.com` and whitelist CDNs to reduce noise.

---

### 🔹 Event ID 25 – Process Tampering

- **Use Case**: Detect PEB spoofing, hollowing, etc.
- **Tags**: `Image`, `TamperType`
- **Example**: `svchost.exe` showing tamper type `Process Hollowing`
- **Detection Tip**: Alert on tampering of trusted processes or mismatched image names.

---

## 🟨 Useful in Context (Medium Signal)

| Event ID | Name                     | Notes |
|----------|--------------------------|-------|
| 10       | Process Access           | Detect LSASS access (mimikatz, procdump) |
| 2        | FileTime Changed         | Timestomping |
| 5        | Process Terminated       | Tracks suspicious process shutdown |
| 6        | Driver Loaded            | Detect unsigned or suspicious drivers |
| 16       | Sysmon Config Change     | Alert on tampering with config |
| 23       | File Delete              | File deletion tracking |
| 26       | File Delete Detected     | Detect API-level delete operations |

---

## 🟩 Optional (Low Signal-to-Noise Ratio)

| Event ID | Name             | Purpose |
|----------|------------------|---------|
| 4        | Sysmon Service State | Rarely useful |
| 9        | RawAccessRead        | Low frequency, may detect disk reads |
| 17-19    | Pipe Events          | Lateral movement or malware IPC |
| 20/21    | WMI Events           | WMI persistence or recon |
| 24       | Clipboard Events     | Insider threat scenarios |

---

## 📌 Summary: Core Detection Set

If you’re short on resources, prioritize the following:
1, 3, 7, 8, 11, 12, 13, 14, 15, 22, 25

**tips:**

Add Event ID **10** for credential dumping detection.  
Add Event ID **23/26** for anti-forensic behavior.  
Add Event ID **6** for rootkit or driver-based detection.

---

## 🔗 Resources

- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sigma Rules for Sysmon](https://github.com/SigmaHQ/sigma)

# 🔍 Sysmon Event ID Cheatsheet for Blue Teamers

This repository provides a concise and categorized overview of important [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) Event IDs, their use cases, tags, and detection examples.

---

## ✅ Top Priority (Must Monitor – High Detection Value)

| Event ID | Name                   | Purpose / Use Case |
|----------|------------------------|---------------------|
| 1        | **Process Creation**       | Detect suspicious processes and command lines. |
| 3        | **Network Connection**     | Monitor outbound connections (C2, scanning). |
| 7        | **Image Loaded**           | Detect DLL injection/hijacking. |
| 8        | **CreateRemoteThread**     | Detect process injection (e.g. Cobalt Strike). |
| 11       | **File Created**           | Detect ransomware or malware drops. |
| 12/13/14 | **Registry Events**        | Detect persistence or credential theft. |
| 15       | **FileCreateStreamHash**   | Detect use of Alternate Data Streams (ADS). |
| 22       | **DNS Query**              | Detect suspicious or dynamic DNS traffic. |
| 25       | **Process Tampering**      | Detect hollowing, PEB spoofing, etc. |

---

## 🟨 Useful in Context (Good to Monitor – Medium Value)

| Event ID | Name                     | Purpose / Use Case |
|----------|--------------------------|---------------------|
| 10       | **Process Access**         | Detect credential dumping (LSASS access). |
| 2        | **FileTime Changed**       | Detect timestomping. |
| 5        | **Process Terminated**     | Track end of suspicious processes. |
| 6        | **Driver Loaded**          | Detect unsigned or malicious drivers. |
| 16       | **Sysmon Config Change**   | Detect tampering with logging settings. |
| 23       | **File Delete**            | Detect attacker cleanup / anti-forensics. |
| 26       | **File Delete Detected**   | Detect API-based file deletions.

---

## 🟩 Optional (Use With Filters – Low Signal-to-Noise Ratio)

| Event ID | Name                 | Purpose / Use Case |
|----------|----------------------|---------------------|
| 4        | **Sysmon Service State**   | Rarely used, service state changes. |
| 9        | **RawAccessRead**          | Detects disk read access by tools like Mimikatz. |
| 17–19    | **Pipe Events**            | Detect named pipe communication (used by some malware). |
| 20/21    | **WMI Events**             | Detect WMI-based persistence or lateral movement. |
| 24       | **Clipboard Events**       | Insider threat scenarios.

---

## 🧠 Detailed Notes (with Tags & Examples)

### **Event ID 1: Process Creation**
- **Tags**: `CommandLine`, `Image`
- **Example**: Exclude common processes like `svchost.exe`.

---

### **Event ID 3: Network Connection**
- **Tags**: `Image`, `DestinationPort`
- **Example**: Alert if `nmap.exe` runs or port `4444` is opened.

---

### **Event ID 7: Image Loaded**
- **Tags**: `Image`, `ImageLoaded`, `Signed`, `Signature`
- **Example**: Detect DLLs loaded from paths like `\Temp\`.

---

### **Event ID 8: CreateRemoteThread**
- **Tags**: `SourceImage`, `TargetImage`, `StartAddress`
- **Example**: Thread starts at suspicious address (e.g., ends in `0B80`).

---

### **Event ID 11: File Created**
- **Tags**: `TargetFilename`
- **Example**: Detect files like `HELP_TO_SAVE_FILES`.

---

### **Event IDs 12/13/14: Registry Events**
- **Tags**: `TargetObject`
- **Example**: Changes under `Windows\System\Scripts`.

---

### **Event ID 15: FileCreateStreamHash**
- **Tags**: `TargetFilename`
- **Example**: Detect `.hta` files stored in ADS.

---

### **Event ID 22: DNS Query**
- **Tags**: `QueryName`
- **Example**: Exclude queries to `.microsoft.com`.

---

### **Event ID 25: Process Tampering**
- **Tags**: `TamperType`, `Image`
- **Example**: Detect hollowing of trusted processes.

---

### Other Useful Events
- **ID 10** – Detect access to LSASS by suspicious processes.
- **ID 2** – File modification time changes (e.g., timestomping).
- **ID 5** – Process termination tracking.
- **ID 6** – Driver loading for rootkit detection.
- **ID 16** – Sysmon config modifications.
- **ID 23/26** – File deletions for anti-forensics.

---

## 📌 Conclusion

### 💡 **Core Event IDs for Detection**:
`1, 3, 7, 8, 11, 12, 13, 14, 15, 22, 25`

### 🧩 Additional Based on Use Case:
- Add **ID 10** for **credential dumping**.
- Add **ID 6, 20, 21** for **rootkits/persistence**.
- Add **ID 23, 26** for **evasion and anti-forensics**.

---

## 📎 Resources
- 🔗 [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- 🔧 [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- 🛡️ [Sigma Rules for Sysmon](https://github.com/SigmaHQ/sigma)

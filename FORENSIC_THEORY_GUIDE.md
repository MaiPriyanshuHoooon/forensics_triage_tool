# Forensic Theory & Methodology Guide

**Windows Forensic Triage Tool**
**Educational Resource for Digital Forensics**
**Version:** 1.0
**Last Updated:** December 11, 2025

---

## Table of Contents

1. [Introduction to Digital Forensics](#1-introduction-to-digital-forensics)
2. [Forensic Principles & Methodology](#2-forensic-principles--methodology)
3. [Windows Operating System Architecture](#3-windows-operating-system-architecture)
4. [File Systems & Storage Forensics](#4-file-systems--storage-forensics)
5. [Memory & Volatile Data](#5-memory--volatile-data)
6. [Network Forensics](#6-network-forensics)
7. [Timeline Analysis](#7-timeline-analysis)
8. [Artifact Analysis](#8-artifact-analysis)
9. [Anti-Forensics & Evasion](#9-anti-forensics--evasion)
10. [Legal & Ethical Considerations](#10-legal--ethical-considerations)

---

## 1. Introduction to Digital Forensics

### 1.1 What is Digital Forensics?

**Definition:**
Digital forensics is the science of identifying, preserving, analyzing, and presenting digital evidence in a manner that is legally admissible in a court of law.

**Key Objectives:**
1. **Identification** - Recognize potential evidence
2. **Preservation** - Maintain evidence integrity
3. **Analysis** - Extract meaningful information
4. **Documentation** - Record findings systematically
5. **Presentation** - Communicate results clearly

### 1.2 Types of Digital Forensics

#### Computer Forensics
- Examination of computer systems and storage media
- Analysis of file systems, logs, and artifacts
- Recovery of deleted or hidden data

#### Network Forensics
- Monitoring and analysis of network traffic
- Investigation of intrusions and attacks
- Packet capture and protocol analysis

#### Mobile Forensics
- Extraction from smartphones and tablets
- SIM card and memory analysis
- App data and communications

#### Cloud Forensics
- Investigation of cloud storage and services
- Multi-tenant environment challenges
- Distributed data collection

#### Memory Forensics
- Analysis of RAM dumps
- Volatile data extraction
- Malware detection in memory

### 1.3 The Forensic Process

```
┌──────────────┐
│ Preparation  │ - Training, tools, procedures
└──────┬───────┘
       │
┌──────▼───────┐
│ Identification│ - Locate potential evidence
└──────┬───────┘
       │
┌──────▼───────┐
│ Preservation │ - Secure and protect evidence
└──────┬───────┘
       │
┌──────▼───────┐
│  Collection  │ - Acquire data systematically
└──────┬───────┘
       │
┌──────▼───────┐
│  Examination │ - Process and extract data
└──────┬───────┘
       │
┌──────▼───────┐
│   Analysis   │ - Interpret findings
└──────┬───────┘
       │
┌──────▼───────┐
│Presentation  │ - Report and testify
└──────────────┘
```

### 1.4 Locard's Exchange Principle

**"Every contact leaves a trace"**

In digital forensics:
- Every action on a computer creates artifacts
- File access updates timestamps
- Network connections leave logs
- Deleted files leave remnants
- Memory retains recent activity

**Practical Applications:**
- Browser history shows visited websites
- Event logs record system activities
- Registry tracks program installations
- Prefetch files indicate executed programs
- MFT entries preserve file metadata

---

## 2. Forensic Principles & Methodology

### 2.1 Chain of Custody

**Definition:**
A documented trail showing the seizure, custody, control, transfer, analysis, and disposition of evidence.

**Components:**
```
┌─────────────────────────────────────────┐
│ Chain of Custody Documentation          │
├─────────────────────────────────────────┤
│ • Who collected the evidence?           │
│ • When was it collected?                │
│ • Where was it found?                   │
│ • How was it collected?                 │
│ • Who has handled it?                   │
│ • What changes were made?               │
│ • Why were changes necessary?           │
└─────────────────────────────────────────┘
```

**Best Practices:**
1. **Document Everything**
   - Photographs of original state
   - Serial numbers and identifiers
   - Date/time stamps
   - Personnel involved

2. **Minimize Handling**
   - Limit the number of people with access
   - Use proper storage containers
   - Maintain environmental controls

3. **Maintain Integrity**
   - Cryptographic hashing (MD5, SHA-256)
   - Write blockers for storage devices
   - Read-only access when possible

### 2.2 Evidence Integrity

#### Hash Values

**What is a Hash?**
A cryptographic hash is a fixed-size string computed from data of any size. Any change to the data results in a completely different hash.

**Common Hash Algorithms:**

| Algorithm | Bits | Security | Use Case |
|-----------|------|----------|----------|
| MD5 | 128 | Weak | Legacy verification |
| SHA-1 | 160 | Weak | Older systems |
| SHA-256 | 256 | Strong | Current standard |
| SHA-512 | 512 | Strong | High security |

**Example:**
```
File: evidence.txt
Content: "Hello World"

MD5:     ed076287532e86365e841e92bfc50d8c
SHA-256: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e

Content: "Hello World!" (added !)

MD5:     86fb269d190d2c85f6e0468ceca42a20
SHA-256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
```

**Notice:** Even one character change completely alters the hash!

#### Write Protection

**Concept:** Prevent any modifications to original evidence

**Methods:**
1. **Hardware Write Blockers**
   - Physical device between storage and computer
   - Allows reading but blocks all write commands
   - Forensically sound acquisition

2. **Software Write Blockers**
   - Operating system level protection
   - Registry modifications (Windows)
   - Mount options (Linux: ro, noexec)

3. **Imaging**
   - Create bit-by-bit copy
   - Work on copy, not original
   - Verify with hash values

### 2.3 Order of Volatility

**RFC 3227 Guidelines:**
Evidence should be collected from most volatile to least volatile.

```
HIGH VOLATILITY (disappears quickly)
  ↓
  ├─ CPU Registers & Cache
  ├─ Routing Tables, ARP Cache, Process Table
  ├─ RAM (Memory)
  ├─ Temporary File Systems
  ├─ Hard Disk
  ├─ Remote Logging Data
  ├─ Physical Configuration, Network Topology
  └─ Archival Media
  ↓
LOW VOLATILITY (persistent)
```

**Collection Priority:**

**Tier 1: Immediate (seconds to minutes)**
- Network connections (netstat)
- Running processes (tasklist)
- Logged-in users (query user)
- Open files and ports
- Clipboard contents
- RAM contents

**Tier 2: Short-term (minutes to hours)**
- System information
- Network configuration
- Command history
- Recent documents
- Temporary files

**Tier 3: Long-term (persistent)**
- Event logs
- Registry hives
- File system artifacts
- Installed programs
- User profiles

### 2.4 Live Forensics vs. Dead Forensics

#### Live Forensics (Hot Acquisition)

**Advantages:**
- Capture volatile data (RAM, processes)
- Access encrypted volumes (if mounted)
- Observe running malware
- Network connections visible

**Disadvantages:**
- System state changes during collection
- Footprint left by collection tools
- Potential for data corruption
- Malware may detect tools

**When to Use:**
- System cannot be powered down
- Encrypted disks are mounted
- Critical services must continue
- Network investigation required

#### Dead Forensics (Cold Acquisition)

**Advantages:**
- No changes to evidence
- Complete disk imaging
- Controlled environment
- No anti-forensic interference

**Disadvantages:**
- Loss of volatile data
- Encrypted volumes inaccessible
- Running processes unknown
- Current network state lost

**When to Use:**
- System can be powered down
- Full disk analysis needed
- Time is not critical
- Maximum integrity required

---

## 3. Windows Operating System Architecture

### 3.1 Windows Architecture Layers

```
┌─────────────────────────────────────────┐
│         User Applications                │ User Mode
├─────────────────────────────────────────┤
│      Subsystem DLLs (kernel32.dll)      │
├─────────────────────────────────────────┤
│      Windows API (Win32 API)            │
├═════════════════════════════════════════┤
│      Executive Services                  │
├─────────────────────────────────────────┤ Kernel Mode
│      Windows Kernel (ntoskrnl.exe)      │
├─────────────────────────────────────────┤
│      Hardware Abstraction Layer (HAL)   │
├─────────────────────────────────────────┤
│           Hardware                       │
└─────────────────────────────────────────┘
```

### 3.2 Windows Registry

**What is the Registry?**
A hierarchical database storing Windows configuration settings, user preferences, and application data.

**Registry Structure:**

```
Registry
├── HKEY_CLASSES_ROOT (HKCR)
│   └── File associations, COM objects
│
├── HKEY_CURRENT_USER (HKCU)
│   └── Current user settings
│
├── HKEY_LOCAL_MACHINE (HKLM)
│   ├── SOFTWARE - Installed applications
│   ├── SYSTEM - System configuration
│   ├── HARDWARE - Hardware info
│   └── SAM - Security Accounts Manager
│
├── HKEY_USERS (HKU)
│   └── All user profiles
│
└── HKEY_CURRENT_CONFIG (HKCC)
    └── Current hardware profile
```

**Forensically Important Keys:**

**1. Autorun Locations**
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
- Programs that start automatically
- Common malware persistence mechanism

**2. Recent Documents**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
- Recently opened files
- File extensions and names

**3. UserAssist**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```
- GUI program execution tracking
- ROT13 encoded names
- Execution count and last run time

**4. USB Device History**
```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKLM\SYSTEM\CurrentControlSet\Enum\USB
```
- All USB devices ever connected
- Vendor ID, Product ID, Serial Number
- First and last connection times

**5. Network History**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```
- Wi-Fi networks connected
- Network names and connection times

### 3.3 Windows Event Logs

**Event Log System:**
Windows logs system, security, and application events in .evtx files.

**Location:**
```
C:\Windows\System32\winevt\Logs\
```

**Major Log Files:**

**1. Security.evtx**
- Logon/logoff events
- Account management
- Policy changes
- Object access

**2. System.evtx**
- Service start/stop
- System startup/shutdown
- Driver loading
- Hardware events

**3. Application.evtx**
- Application crashes
- Application events
- Database operations

**Critical Event IDs:**

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4672 | Security | Admin privileges assigned |
| 4720 | Security | User account created |
| 4732 | Security | User added to security group |
| 4756 | Security | Member added to security-enabled group |
| 7045 | System | Service installed |
| 1074 | System | System shutdown initiated |
| 6005 | System | Event log service started (boot) |
| 6006 | System | Event log service stopped (shutdown) |
| 6008 | System | Unexpected shutdown |

**Logon Types (Event 4624):**

| Type | Description | Example |
|------|-------------|---------|
| 2 | Interactive | Local keyboard/screen logon |
| 3 | Network | Network share access |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Screen unlock |
| 10 | Remote Interactive | Remote Desktop |
| 11 | Cached Interactive | Cached domain credentials |

### 3.4 Windows Prefetch

**Purpose:** Speed up application loading by caching information about program execution.

**Location:**
```
C:\Windows\Prefetch\
```

**Format:**
```
[EXECUTABLE_NAME]-[HASH].pf
Example: CHROME.EXE-A1B2C3D4.pf
```

**Forensic Value:**
- Proves program execution
- Last run time (up to 8 times in Windows 10)
- Files and directories accessed
- Number of executions

**Limitations:**
- Only first 128 characters of path
- Disabled on SSD systems (sometimes)
- Can be cleared by user/malware

### 3.5 Windows Artifacts Summary

| Artifact | Location | Information |
|----------|----------|-------------|
| Prefetch | C:\Windows\Prefetch\ | Program execution |
| Recent Docs | C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\ | Recently opened files |
| Jump Lists | C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ | Recent items per app |
| ShellBags | Registry: HKCU\Software\Microsoft\Windows\Shell | Folder views and access |
| LNK Files | Various | File shortcuts, metadata |
| Recycle Bin | $Recycle.Bin | Deleted files |
| SRUM | C:\Windows\System32\sru\SRUDB.dat | System Resource Usage |
| Amcache | C:\Windows\AppCompat\Programs\Amcache.hve | Program execution history |

---

## 4. File Systems & Storage Forensics

### 4.1 NTFS (New Technology File System)

**Why NTFS for Forensics?**
- Rich metadata (timestamps, permissions)
- Journaling (change logs)
- Alternate Data Streams (hidden data)
- File system supports large volumes
- Widely used on Windows

**NTFS Structure:**

```
┌─────────────────────────────────────┐
│    Partition Boot Sector (PBS)      │
├─────────────────────────────────────┤
│    Master File Table (MFT)          │ ← Most important!
├─────────────────────────────────────┤
│    System Files ($Boot, $LogFile)   │
├─────────────────────────────────────┤
│    File Data Area                    │
└─────────────────────────────────────┘
```

### 4.2 Master File Table (MFT)

**What is MFT?**
A database containing an entry for every file and directory on an NTFS volume.

**MFT Entry Structure:**

```
MFT Entry (1024 bytes)
├── Header (42 bytes)
│   ├── Signature: "FILE"
│   ├── Sequence Number
│   ├── Hard Link Count
│   └── Flags (In use/Deleted)
│
└── Attributes
    ├── $STANDARD_INFORMATION (0x10)
    │   ├── Created Time
    │   ├── Modified Time
    │   ├── MFT Modified Time
    │   ├── Accessed Time
    │   └── File Attributes
    │
    ├── $FILE_NAME (0x30)
    │   ├── Parent Directory Reference
    │   ├── File Name
    │   ├── Created Time
    │   ├── Modified Time
    │   ├── MFT Modified Time
    │   └── Accessed Time
    │
    ├── $DATA (0x80)
    │   └── File Content (or pointers)
    │
    └── $ATTRIBUTE_LIST (0x20)
        └── Extended attributes
```

**Forensic Significance:**

**1. Timestamps (MACB)**
- **M**odified - Content changed
- **A**ccessed - File read
- **C**reated - File created
- **B**irth (MFT Entry) - Entry created

**2. Two Sets of Timestamps**
- $STANDARD_INFORMATION - Can be modified by user
- $FILE_NAME - More reliable, harder to modify

**3. File Recovery**
- Deleted files remain in MFT
- "In Use" flag set to 0
- Data may still be in clusters

**4. Timeline Construction**
- All file activity with exact times
- Chronological sequence of events
- Correlation with other artifacts

### 4.3 Deleted File Recovery

**How Deletion Works:**

```
Step 1: User deletes file
  ↓
Step 2: File moved to Recycle Bin
  ↓
Step 3: User empties Recycle Bin
  ↓
Step 4: MFT entry marked as "deleted"
  ↓
Step 5: Clusters marked as "available"
  ↓
Step 6: File still physically exists!
  ↓
Step 7: New file may overwrite clusters
```

**Recovery Techniques:**

**1. MFT Analysis**
```
IF MFT_Entry.Flags == DELETED AND
   MFT_Entry.DataRuns_Exist THEN

   File_Can_Be_Recovered = TRUE
```

**2. File Carving**
- Search for file signatures (headers/footers)
- Reconstruct files from unallocated space
- No MFT entry needed

**Common File Signatures:**

| File Type | Header (Hex) | Footer (Hex) |
|-----------|--------------|--------------|
| JPEG | FF D8 FF | FF D9 |
| PNG | 89 50 4E 47 | 49 45 4E 44 AE 42 60 82 |
| PDF | 25 50 44 46 | 25 25 45 4F 46 |
| ZIP | 50 4B 03 04 | 50 4B 05 06 or 50 4B 07 08 |
| EXE | 4D 5A | - |
| DOC | D0 CF 11 E0 | - |

**3. Shadow Copies (Volume Shadow Service)**
```
Location: System Volume Information
Purpose: Windows backup snapshots
Access: vssadmin list shadows
```

### 4.4 Alternate Data Streams (ADS)

**What are ADS?**
NTFS feature allowing multiple data streams per file. Often used to hide data!

**Syntax:**
```
filename.ext:streamname
```

**Example:**
```cmd
# Create ADS
echo "Secret data" > legitimate.txt:hidden

# View main file
type legitimate.txt
Output: (shows normal content)

# View ADS
type legitimate.txt:hidden
Output: Secret data

# File size unchanged!
dir legitimate.txt
Shows: Size of main stream only
```

**Forensic Detection:**
```cmd
# PowerShell
Get-Item -Path C:\test\* -Stream *

# Command Line
dir /r C:\test\
```

**Malicious Uses:**
- Hide malware code
- Conceal stolen data
- Store malicious scripts
- Bypass antivirus

### 4.5 File System Timestamps

**Windows FILETIME:**
- 64-bit value
- Number of 100-nanosecond intervals
- Since January 1, 1601 UTC

**Timestamp Manipulation Detection:**

**Red Flags:**
1. **$STANDARD_INFORMATION ≠ $FILE_NAME**
   - User likely used timestomp tool
   - $FILE_NAME more reliable

2. **Created > Modified**
   - File copied from another location
   - Timestamps preserved from source

3. **All timestamps identical**
   - Suspicious, especially for modified files
   - Possible anti-forensic activity

4. **Future timestamps**
   - System clock manipulated
   - File from different timezone

5. **Timestamps before OS install**
   - File predates system
   - Copied from backup/another system

---

## 5. Memory & Volatile Data

### 5.1 Memory Forensics Concepts

**Why Memory Forensics?**

```
Disk Forensics          Memory Forensics
     │                       │
     ├── Past Activity       ├── Current Activity
     ├── Deleted Files       ├── Running Processes
     ├── Historical Logs     ├── Open Network Connections
     ├── Stored Data         ├── Decrypted Data
     └── Static State        ├── Loaded Malware
                            ├── Passwords in Plain Text
                            └── Dynamic State
```

**Memory Contents:**

**1. Process Memory**
- Executable code
- Loaded DLLs
- Heap data
- Stack data
- Environment variables
- Command-line arguments

**2. Kernel Memory**
- Driver code
- Kernel data structures
- System call tables
- Memory management data

**3. Cached Data**
- Recently accessed files
- Network buffers
- Clipboard contents
- Encryption keys

### 5.2 Memory Acquisition

**Methods:**

**1. Physical Memory Dump**
```
Tools: FTK Imager, DumpIt, WinPmem
Output: RAM.raw (complete memory image)
Size: Equal to installed RAM
```

**2. Hibernation File**
```
Location: C:\hiberfil.sys
Content: Complete RAM snapshot
When: System hibernates
```

**3. Page File**
```
Location: C:\pagefile.sys
Content: Swapped memory pages
Persistence: Until overwritten
```

**4. Crash Dump**
```
Location: C:\Windows\MEMORY.DMP
Content: Kernel memory (minimum)
When: System crash (BSOD)
```

### 5.3 Pagefile Analysis Theory

**What is a Pagefile?**

When RAM is full, Windows moves inactive memory pages to disk (pagefile.sys).

**Pagefile Characteristics:**

```
┌─────────────────────────────────────┐
│          Physical RAM (8 GB)        │
├─────────────────────────────────────┤
│  Active Processes: 6 GB             │
│  Cached Files: 2 GB                 │
└──────────────┬──────────────────────┘
               │
               ▼ (RAM full, need more)
┌─────────────────────────────────────┐
│       Pagefile.sys (on disk)        │
├─────────────────────────────────────┤
│  Inactive memory pages: 4 GB        │
│  Swapped process memory             │
│  Old cached data                    │
└─────────────────────────────────────┘
```

**Forensic Value:**

**1. Historical Data**
- Pages may persist for weeks
- Deleted programs' memory
- Old network connections
- Previous user activity

**2. Sensitive Information**
- Passwords in plain text
- Encryption keys
- Private keys (SSL/SSH)
- Documents in memory
- Browser form data

**3. Malware Artifacts**
- Malware code fragments
- C2 server addresses
- Decrypted payloads
- Configuration data

**String Extraction Technique:**

```python
# Pseudocode
def scan_pagefile():
    chunk_size = 10 MB

    while data_remaining:
        chunk = read_chunk(pagefile, chunk_size)

        # Find printable strings (min 8 chars)
        strings = find_ascii_strings(chunk, min_length=8)
        strings += find_unicode_strings(chunk, min_length=8)

        # Pattern matching
        for string in strings:
            if matches_email_pattern(string):
                save_finding("EMAIL", string)
            if matches_url_pattern(string):
                save_finding("URL", string)
            if matches_password_pattern(string):
                save_finding("PASSWORD", string)
```

**Patterns to Search:**

```regex
Email:     [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
URL:       https?://[^\s]+
IP:        \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
Password:  password[:\s=]+[\S]+
Key:       -----BEGIN .* PRIVATE KEY-----
Credit Card: \d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}
SSN:       \d{3}-\d{2}-\d{4}
```

---

## 6. Network Forensics

### 6.1 Network Connections

**Connection States:**

```
LISTENING    - Port open, waiting for connection
ESTABLISHED  - Active connection
CLOSE_WAIT   - Remote side closed, local closing
TIME_WAIT    - Connection closed, waiting for packets
SYN_SENT     - Connection attempt in progress
```

**Forensic Interpretation:**

**Suspicious Indicators:**
1. **Unknown Listening Ports**
   - Malware backdoor
   - Unauthorized service

2. **Connections to Foreign IPs**
   - Data exfiltration
   - Command & Control (C2)

3. **High Port Numbers (>49152)**
   - Ephemeral ports (normal for clients)
   - But suspicious for servers

4. **Unusual Protocols**
   - IRC on corporate network
   - Tor connections
   - Bitcoin mining

### 6.2 DNS Cache Analysis

**What is DNS Cache?**
Temporary storage of domain name → IP address mappings.

**Forensic Value:**
- Websites visited (even if browser history cleared)
- Malware domains contacted
- Phishing sites accessed
- Approximate access times (TTL-based estimation)

**DNS Cache Contents:**

```
Record Type: A (Address)
Name: www.example.com
IP: 93.184.216.34
TTL: 300 seconds (5 minutes)
Timestamp: When cached (estimated)
```

**Malicious Domain Indicators:**
- Newly registered domains (< 30 days)
- Random-looking names (DGA - Domain Generation Algorithm)
- Unusual TLDs (.tk, .ml, .ga - common for malware)
- Known C2 domains (threat intelligence)

### 6.3 ARP Cache Analysis

**ARP (Address Resolution Protocol):**
Maps IP addresses to MAC addresses on local network.

**ARP Cache:**
```
Interface: 192.168.1.100
Internet Address      Physical Address      Type
192.168.1.1          00-11-22-33-44-55     dynamic
192.168.1.50         AA-BB-CC-DD-EE-FF     dynamic
```

**Forensic Value:**
- Devices on network
- Lateral movement (attacker moving between systems)
- Unauthorized devices
- MAC address spoofing detection

### 6.4 Firewall Logs

**Windows Firewall:**
```
Location: C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

**Log Entry Fields:**
```
date time action protocol src-ip dst-ip src-port dst-port size
2025-12-11 10:30:15 ALLOW TCP 192.168.1.100 93.184.216.34 49152 443 1024
```

**Analysis:**
- **Blocked connections** - Attempted unauthorized access
- **Allowed connections** - Successful communications
- **Port scans** - Multiple connection attempts to sequential ports
- **DDoS attempts** - High volume from single source

---

## 7. Timeline Analysis

### 7.1 Timeline Theory

**Purpose:**
Reconstruct the sequence of events on a system to understand "what happened, when, and in what order."

**Timeline Components:**

```
Timestamp | Source | Event Type | Description
----------|--------|------------|-------------
10:00:00  | File   | Created    | malware.exe created
10:00:05  | Reg    | Modified   | Run key added
10:00:10  | Event  | 7045       | Service installed
10:00:15  | Net    | Connect    | Connection to C2 server
10:00:20  | File   | Deleted    | Log file removed
```

### 7.2 Super Timeline

**Concept:**
Combine all temporal artifacts into one comprehensive timeline.

**Data Sources:**

**1. File System**
- MFT timestamps (MACB)
- File creation/modification
- File deletion

**2. Registry**
- Key modifications
- Last write times
- UserAssist data

**3. Event Logs**
- System events
- Security events
- Application events

**4. Browser History**
- URL visits
- Downloads
- Searches

**5. Prefetch**
- Program execution
- Last run times

**6. Network**
- Connection times
- DNS queries
- ARP changes

**7. Email**
- Sent/received times
- Attachment opens

**Timeline Analysis Process:**

```
Step 1: Collect all temporal data
   ↓
Step 2: Normalize timestamps (UTC)
   ↓
Step 3: Sort chronologically
   ↓
Step 4: Filter relevant timeframe
   ↓
Step 5: Identify patterns
   ↓
Step 6: Correlate events
   ↓
Step 7: Build narrative
```

### 7.3 Timestamp Analysis Techniques

**1. Temporal Proximity**
Events close in time are likely related.

**Example:**
```
10:00:00 - malware.exe created
10:00:02 - malware.exe executed (Prefetch)
10:00:05 - Registry Run key modified
10:00:08 - Network connection established
```
**Conclusion:** Malware installed and established persistence.

**2. Temporal Gaps**
Large gaps may indicate:
- System powered off
- Anti-forensic log deletion
- User inactivity

**3. Temporal Clustering**
Multiple events in short period:
- User session activity
- Automated script execution
- Attack sequence

**4. Temporal Anomalies**
- Activity during off-hours
- Weekend/holiday activity
- Rapid sequential file access

---

## 8. Artifact Analysis

### 8.1 Browser Forensics Theory

**Why Browser Forensics?**
Browsers store extensive user activity data:
- Websites visited
- Search queries
- Downloads
- Passwords
- Form data
- Session data

**Browser Data Storage:**

**SQLite Databases:**
```
Browser: Chrome
Database: History
Location: %LocalAppData%\Google\Chrome\User Data\Default\History

Tables:
- urls: URL, title, visit_count, last_visit_time
- visits: URL, visit_time, from_visit, transition
- downloads: target_path, start_time, received_bytes
```

**Chrome Timestamp Format:**
```
Format: Microseconds since January 1, 1601 UTC
Example: 13318448400000000

Conversion:
datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
= 2025-12-11 10:30:00
```

**Privacy Mode (Incognito/Private) Forensics:**

**Myth:** "Private browsing leaves no traces"

**Reality:** Traces remain in:
- DNS cache
- Prefetch files (if browser launched)
- Pagefile/hiberfil (in memory)
- Network logs (router level)
- ISP logs
- Destination website logs

### 8.2 Email Forensics

**Email Headers:**
Critical for authenticity verification and tracking.

**Key Headers:**
```
From: sender@example.com (claimed sender)
To: recipient@example.com
Date: Wed, 11 Dec 2025 10:30:00 +0000
Subject: Important Document
Message-ID: <unique-id@mail.server.com>
Received: from mail.example.com (IP: 93.184.216.34)
  by mail.recipient.com
X-Originating-IP: [93.184.216.34]
```

**Forensic Analysis:**

**1. Received Headers (bottom to top)**
Show actual email path:
```
Received: from client.example.com [192.168.1.100]
  Wed, 11 Dec 2025 10:30:00 +0000
Received: from mail.example.com [93.184.216.34]
  Wed, 11 Dec 2025 10:30:05 +0000
Received: from mail.recipient.com [198.51.100.1]
  Wed, 11 Dec 2025 10:30:10 +0000
```

**2. SPF/DKIM/DMARC Verification**
```
Authentication-Results: pass
  spf=pass smtp.mailfrom=example.com;
  dkim=pass header.d=example.com;
  dmarc=pass header.from=example.com
```

**3. Attachment Analysis**
- Hash values for malware checking
- Metadata (author, creation date)
- Hidden data (steganography)

### 8.3 USB Device Forensics

**Device Connection Tracking:**

**Registry Keys:**
```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
  └── [VendorID&ProductID]
      └── [SerialNumber]
          ├── FriendlyName: "Kingston DataTraveler 3.0"
          ├── FirstInstall: 2025-12-01 14:30:00
          └── LastArrival: 2025-12-11 10:30:00
```

**Forensic Questions Answered:**
1. **What devices were connected?**
   - Vendor, Model, Serial Number

2. **When first connected?**
   - FirstInstall timestamp

3. **When last connected?**
   - LastArrival timestamp

4. **What drive letter assigned?**
   - MountPoints2 registry key

5. **What files accessed?**
   - LNK files, ShellBags, Recent files

**USB Detection Without Device:**
Even without physical device:
- Registry preserves all information
- Event logs show connections (Event ID 20001, 20003)
- Driver installation records
- Setupapi.dev.log shows installation details

### 8.4 Shellbags

**What are Shellbags?**
Registry keys storing folder view preferences and access times.

**Location:**
```
HKCU\Software\Microsoft\Windows\Shell\Bags
HKCU\Software\Microsoft\Windows\Shell\BagMRU
```

**Forensic Value:**
- Folders accessed (even if deleted)
- Folder customization
- Access times
- Window size/position
- USB drive folders

**Example:**
```
BagMRU Entry:
Path: E:\SecretDocuments
LastWrite: 2025-12-11 10:30:00
ViewMode: Details
SortBy: Name
```

**Even if:**
- USB drive disconnected
- Folder deleted
- File system formatted

**Shellbags persist!**

---

## 9. Anti-Forensics & Evasion

### 9.1 Anti-Forensic Techniques

**Definition:**
Methods used to make forensic analysis difficult or impossible.

**Categories:**

**1. Data Destruction**
- Secure deletion (overwriting)
- File shredding
- Disk wiping

**2. Data Hiding**
- Steganography
- Alternate Data Streams
- Slack space
- Encryption

**3. Trail Obfuscation**
- Log deletion/modification
- Timestamp manipulation
- Registry key deletion

**4. Anti-Analysis**
- Encryption
- Compression
- Packing
- Obfuscation

### 9.2 Timestamp Manipulation

**Tools:** Timestomp, NewFileTime, BulkFileChanger

**Detection Methods:**

**1. $STANDARD_INFORMATION vs $FILE_NAME**
```
File: malware.exe
$SI Created:  2020-01-01 00:00:00 (suspicious)
$FN Created:  2025-12-11 10:30:00 (actual)
```

**2. Born Before OS**
```
OS Install:   2025-01-01
File Created: 2020-01-01 (impossible!)
```

**3. Accessed Before Created**
```
Created:  2025-12-11 10:30:00
Accessed: 2025-12-11 10:00:00 (impossible!)
```

**4. Journal Analysis**
NTFS $LogFile records actual operations, harder to manipulate.

### 9.3 Encryption & Forensics

**Full Disk Encryption (FDE):**

**Technologies:**
- BitLocker (Windows)
- VeraCrypt
- FileVault (Mac)

**Forensic Challenges:**
- Cannot access data without key
- Cold boot attacks may work (RAM remanence)
- Live forensics required if system on

**Forensic Opportunities:**
- Memory dumps (if system running)
- Recovery keys (BitLocker)
- Hibernation file (before encryption)
- TPM analysis

**File-Level Encryption:**
- EFS (Encrypting File System)
- Individual file encryption
- Certificate-based

**Detection:**
```
File attributes: Encrypted bit set
Extension: .encrypted, .locked
High entropy (randomness)
```

### 9.4 Defeating Anti-Forensics

**1. Multiple Data Sources**
- Cross-reference artifacts
- Timeline correlation
- External logs (router, cloud)

**2. Forensic Imaging**
- Work on copies
- Preserve original
- Use write blockers

**3. Memory Analysis**
- Capture before shutdown
- Keys in RAM
- Decrypted data visible

**4. Cloud/Network Evidence**
- Cloud backups
- Email server logs
- ISP records
- Social media

---

## 10. Legal & Ethical Considerations

### 10.1 Legal Framework

**Types of Investigations:**

**1. Criminal Investigation**
- Law enforcement
- Search warrants required
- Chain of custody critical
- Admissibility in court

**2. Civil Investigation**
- Corporate investigations
- eDiscovery
- HR matters
- Less stringent requirements

**3. Internal Investigation**
- Company policy violations
- Acceptable use policy
- Employee monitoring
- Privacy considerations

### 10.2 Legal Concepts

**1. Reasonable Expectation of Privacy**
- Employee work computer: Low expectation
- Personal device: High expectation
- Company network: Low expectation
- Personal email: High expectation

**2. Consent**
```
Explicit Consent:
"I authorize the examination of my computer"
✓ Signed document
✓ Witnessed
✓ Date/time stamped

Implied Consent:
"Use of company equipment constitutes consent"
✓ Acceptable Use Policy
✓ Login banner
✓ Employment agreement
```

**3. Scope of Authorization**
```
Search Warrant:
"Examine computer for evidence of fraud"

Allowed:
✓ Financial documents
✓ Email related to fraud
✓ Accounting software

Not Allowed:
✗ Personal photos (unless relevant)
✗ Unrelated emails
✗ Medical records
```

### 10.3 Evidence Admissibility

**Federal Rules of Evidence (US):**

**Rule 401: Relevance**
- Evidence must be relevant to case
- Must prove or disprove fact

**Rule 702: Expert Testimony**
- Forensic examiner as expert witness
- Qualified by knowledge/experience
- Testimony based on reliable methods

**Rule 901: Authentication**
- Evidence is what proponent claims
- Hash values prove authenticity
- Chain of custody shows handling

**Rule 1002: Best Evidence (Original)**
- Original preferred
- Forensic copies acceptable if authenticated
- Hash values prove copy = original

### 10.4 Ethical Considerations

**Professional Ethics:**

**1. Competence**
- Work within expertise
- Continuing education
- Use validated tools
- Peer review

**2. Integrity**
- Honest reporting
- Document limitations
- No bias
- Accurate conclusions

**3. Confidentiality**
- Protect sensitive data
- NDAs
- Secure storage
- Need-to-know basis

**4. Objectivity**
- Evidence-based conclusions
- No predetermined outcome
- Report exculpatory evidence
- Independent analysis

**Professional Organizations:**
- IACIS (International Association of Computer Investigative Specialists)
- HTCIA (High Technology Crime Investigation Association)
- SANS GIAC Certifications
- EnCase Certified Examiner (EnCE)

### 10.5 Documentation Requirements

**Minimum Documentation:**

**1. Case Information**
- Case number
- Date/time
- Examiner name
- Authorization

**2. Evidence Description**
- Type of evidence
- Serial numbers
- Make/model
- Physical condition

**3. Acquisition**
- Method used
- Tools used (version)
- Hash values (before/after)
- Write blocker info

**4. Examination**
- Procedures followed
- Tools used
- Searches performed
- Findings

**5. Analysis**
- Interpretation
- Conclusions
- Limitations
- Supporting evidence

**6. Chain of Custody**
- Who, what, when, where
- Every transfer
- Storage location
- Access log

---

## 11. Incident Response Integration

### 11.1 Incident Response Lifecycle

```
┌─────────────────────────────────────────┐
│         1. Preparation                   │
│  - Policies, procedures, tools           │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│      2. Identification/Detection         │
│  - Alert, anomaly, report                │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         3. Containment                   │
│  - Isolate, limit damage                 │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         4. Eradication                   │
│  - Remove malware, close vulnerabilities │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│          5. Recovery                     │
│  - Restore systems, validate              │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│      6. Lessons Learned                  │
│  - Report, improve, update                │
└─────────────────────────────────────────┘
```

### 11.2 Forensic Triage in IR

**Triage Purpose:**
Quickly assess the situation to:
1. Determine incident scope
2. Prioritize response actions
3. Collect critical evidence
4. Make containment decisions

**Our Tool's Role:**
```
Incident Detected
      ↓
Deploy Triage Tool (Our Tool)
      ↓
Collect System State (5-15 min)
      ├── Processes & Network
      ├── User Activity
      ├── File System
      ├── Registry
      └── Event Logs
      ↓
Analyze Findings
      ↓
Decision Point:
      ├── False Positive → Document, close
      ├── True Positive → Full investigation
      └── Escalate → Involve law enforcement
```

**Live Response vs. Full Forensics:**

| Triage (Our Tool) | Full Forensics |
|-------------------|----------------|
| 5-15 minutes | Hours to days |
| Running system | Offline analysis |
| Critical data | Complete data |
| IR decision support | Court admissible |
| Minimal footprint | Comprehensive |

---

## 12. Threat Intelligence Integration

### 12.1 Indicators of Compromise (IOCs)

**Definition:**
Artifacts that indicate a potential intrusion.

**IOC Types:**

**1. Atomic Indicators**
- File hashes (MD5, SHA-1, SHA-256)
- IP addresses
- Domain names
- Email addresses

**2. Computed Indicators**
- File size + hash
- Registry key + value
- File path + hash

**3. Behavioral Indicators**
- Network pattern
- File operations sequence
- Process relationships

**IOC Example:**
```
Indicator Type: File Hash
Value: 44d88612fea8a8f36de82e1278abb02f
Hash Type: MD5
Malware Family: Emotet
Threat Level: High
First Seen: 2025-11-01
Source: VirusTotal
```

### 12.2 Threat Intelligence Sources

**1. Commercial TI Feeds**
- Paid subscriptions
- Curated, verified
- Real-time updates
- Contextual information

**2. Open Source Intelligence (OSINT)**
- Public databases
- Security blogs
- Malware repositories
- Community sharing

**3. ISAC/ISAOs**
- Information Sharing Organizations
- Sector-specific (Finance, Healthcare)
- Trusted peer sharing

**4. Government Sources**
- US-CERT
- FBI InfraGard
- DHS CISA

**Popular Platforms:**
- MISP (Malware Information Sharing Platform)
- AlienVault OTX
- Threat Connect
- VirusTotal

### 12.3 IOC Scanning Process

**Our Tool's Implementation:**

```
Step 1: Load IOC Database
  ├── File hashes
  ├── IP addresses
  ├── Domains
  └── Registry keys

Step 2: System Scanning
  ├── Compute file hashes
  ├── Check running processes
  ├── Analyze network connections
  └── Examine registry

Step 3: Matching
  IF system_artifact IN ioc_database THEN
    ALERT: Match found
    LOG: IOC details
    SCORE: Threat level

Step 4: Reporting
  ├── List all matches
  ├── Threat assessment
  ├── Recommended actions
  └── Additional context
```

**Match Confidence Levels:**

```
High Confidence (90-100%):
- Exact hash match
- Known malware sample
- Verified C2 server IP

Medium Confidence (50-89%):
- IP in suspicious range
- Domain similar to known bad
- File location suspicious

Low Confidence (1-49%):
- Generic indicator
- Potential false positive
- Circumstantial evidence
```

---

## 13. Malware Analysis Fundamentals

### 13.1 Malware Classification

**By Behavior:**

**1. Virus**
- Infects other files
- Requires host program
- Spreads through execution

**2. Worm**
- Self-replicating
- No host needed
- Network propagation

**3. Trojan**
- Disguised as legitimate
- No self-replication
- User-initiated

**4. Ransomware**
- Encrypts files
- Demands payment
- Crypto-ransomware

**5. Spyware**
- Collects information
- Keyloggers
- Screen capture

**6. Rootkit**
- Hides presence
- Kernel-level access
- Difficult to detect

**7. Backdoor**
- Remote access
- Bypasses authentication
- Command & Control

### 13.2 Static Analysis

**Without Executing:**

**1. File Properties**
```
Name: invoice.pdf.exe
Size: 1,234,567 bytes
Hash: 44d88612fea8a8f36de82e1278abb02f
Created: 2025-12-11 10:30:00
Digital Signature: None (suspicious)
```

**2. String Analysis**
```
Strings found:
- http://malicious-c2-server.com
- cmd.exe /c del
- password123
- admin@company.com
```

**3. PE Header Analysis**
```
Imports:
- CreateRemoteThread (code injection)
- WriteProcessMemory (code injection)
- RegSetValueEx (persistence)
- InternetOpenUrl (network communication)

Suspicious Imports:
✓ Process manipulation
✓ Registry modification
✓ Network communication
→ Likely malware
```

**4. Packing Detection**
```
High Entropy Section: .text
Entropy: 7.8 (0-8 scale, >7.5 suspicious)
Indication: Packed/encrypted
Tool: UPX, ASPack, Themida
```

### 13.3 Dynamic Analysis

**Safe Execution in Sandbox:**

**Observable Behaviors:**

**1. File System**
- Files created
- Files modified
- Files deleted
- Locations accessed

**2. Registry**
- Keys created/modified
- Persistence mechanisms
- Configuration storage

**3. Network**
- Connections initiated
- Data sent/received
- Protocols used
- C2 communication

**4. Process**
- Child processes spawned
- DLLs loaded
- Memory allocation
- Code injection

**Example Analysis:**
```
Execution: malware.exe

Timestamp: 0.0s
Action: Created file C:\Windows\Temp\update.exe
Analysis: Copies itself

Timestamp: 0.5s
Action: Registry key created
Key: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Value: "update" = "C:\Windows\Temp\update.exe"
Analysis: Persistence mechanism

Timestamp: 1.0s
Action: Network connection
Destination: 192.0.2.100:8080
Protocol: HTTP
Analysis: C2 communication

Timestamp: 1.5s
Action: Process injection
Target: explorer.exe
Analysis: Hiding in legitimate process

Conclusion: Backdoor malware with persistence
Threat Level: High
Recommendation: Isolate system, remove malware
```

---

## 14. Report Writing

### 14.1 Report Structure

**Executive Summary**
- High-level overview
- Key findings
- Recommendations
- Non-technical language

**Methodology**
- Tools used
- Procedures followed
- Limitations
- Standards followed

**Findings**
- Detailed analysis
- Evidence presented
- Screenshots
- Interpretations

**Timeline**
- Chronological events
- Correlation
- Narrative

**Conclusions**
- Answer investigation questions
- Supported by evidence
- Objective statements

**Recommendations**
- Security improvements
- Training needs
- Policy changes

**Appendices**
- Tool outputs
- Log files
- Chain of custody
- Technical details

### 14.2 Effective Communication

**Know Your Audience:**

**Technical Audience:**
- Detailed methodology
- Tool outputs
- Technical terminology
- Complete data

**Management Audience:**
- Executive summary
- Business impact
- Risk assessment
- Cost implications

**Legal Audience:**
- Facts, not opinions
- Chain of custody
- Authentication
- Admissibility

**Writing Guidelines:**

**DO:**
- Use clear language
- Define technical terms
- Present facts
- Include supporting evidence
- Be objective
- Organize logically

**DON'T:**
- Use jargon unnecessarily
- Make assumptions
- Omit exculpatory evidence
- Express personal opinions
- Rush conclusions
- Skip documentation

---

## 15. Continuous Learning

### 15.1 Keeping Current

**Why Constant Learning?**

**Technology Changes:**
- New operating systems
- Updated file formats
- Emerging protocols
- Novel malware techniques

**Legal Changes:**
- New laws
- Court precedents
- Admissibility standards
- Privacy regulations

**Tool Evolution:**
- Software updates
- New forensic tools
- Improved techniques
- Automation advances

### 15.2 Resources

**Certifications:**
- GCFE (GIAC Certified Forensic Examiner)
- GCFA (GIAC Certified Forensic Analyst)
- EnCE (EnCase Certified Examiner)
- CHFI (Computer Hacking Forensic Investigator)
- CFCE (Certified Forensic Computer Examiner)

**Training:**
- SANS Institute
- Digital Forensics Summit
- HTCIA Conferences
- Black Hat / DEF CON

**Practice:**
- CTF Challenges
- Forensic test images
- Personal lab setup
- Case studies

**Communities:**
- Reddit: r/computerforensics
- Digital Forensics Discord
- ForensicFocus Forums
- LinkedIn Groups

**Reading:**
- "File System Forensic Analysis" - Brian Carrier
- "The Art of Memory Forensics" - Ligh et al.
- "Practical Forensic Imaging" - Bruce Nikkel
- "Malware Analyst's Cookbook" - Ligh et al.

**Blogs & Websites:**
- DFIR.it
- ForensicFocus.com
- 13Cubed (YouTube)
- SANS Digital Forensics Blog

---

## Conclusion

Digital forensics is a complex, multidisciplinary field requiring:

✅ **Technical Knowledge**
- Operating systems
- File systems
- Networking
- Programming

✅ **Investigative Skills**
- Critical thinking
- Pattern recognition
- Attention to detail
- Documentation

✅ **Legal Understanding**
- Evidence rules
- Privacy laws
- Court procedures
- Chain of custody

✅ **Continuous Learning**
- Technology evolution
- New techniques
- Tool proficiency
- Industry standards

This guide provides theoretical foundations for understanding the Windows Forensic Triage Tool and digital forensics principles. Combine this knowledge with practical experience, ethical standards, and rigorous methodology to become an effective forensic practitioner.

---

**Remember:**

> "In forensics, we don't prove guilt or innocence.
> We collect and analyze evidence objectively,
> document our findings thoroughly,
> and present facts clearly.
> The evidence tells the story."

---

**Document Version:** 1.0
**Last Updated:** December 11, 2025
**Educational Use Only**
**Always obtain proper authorization before forensic examination**

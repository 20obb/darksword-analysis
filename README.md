# 🗡️ DarkSword — iOS Full-Chain Exploit Analysis

**Reference:** [Google Cloud Blog — The Proliferation of DarkSword](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)  
**Analysis Date:** April 2026

---

## Overview

**DarkSword** is a full-chain exploit targeting Apple iOS devices running versions 18.4 through 18.7. It was discovered by the Google Threat Intelligence Group (GTIG) starting November 2025. The chain uses 6 different vulnerabilities (3 of which are Zero-Days) to achieve full device compromise, starting from a web page visit and escalating all the way to kernel-level privileges.

What makes this chain notable is that every stage is implemented entirely in JavaScript, eliminating the need to bypass protections like PPL (Page Protection Layer) or SPTM (Secure Page Table Monitor).

---

## How to Run

```bash
# Start the server
python3 server.py
or "python server.py"
# Open in browser
http://[IP_ADDRESS]/frame.html
```

## File Structure

```
DarkSword/
├── README.md                 # This file (English)
├── index.html                # Landing page — initial entry point
├── frame.html                # Intermediate loader, loads main orchestrator
├── rce_loader.js             # Main orchestrator — determines iOS version, coordinates stages
├── rce_module.js             # RCE module for iOS 18.4 (offsets table + exploit config)
├── rce_module_18.6.js        # Placeholder module for iOS 18.6+
├── rce_worker.js             # RCE Web Worker for iOS 18.4 + PAC bypass
├── rce_worker_18.6.js        # RCE Web Worker for iOS 18.6+ (CVE-2025-43529)
├── sbx0_main_18.4.js         # Sandbox Escape #1 (WebContent → GPU process)
├── sbx1_main.js              # Sandbox Escape #2 (GPU → mediaplaybackd)
└── pe_main.js                # Privilege Escalation to kernel
```

| File | Size | Role |
|------|------|------|
| `pe_main.js` | 778 KB | Privilege escalation to kernel |
| `rce_worker_18.6.js` | 526 KB | RCE + PAC bypass (iOS 18.6+) |
| `sbx0_main_18.4.js` | 425 KB | Sandbox escape — WebContent process |
| `sbx1_main.js` | 318 KB | Sandbox escape — GPU process |
| `rce_module.js` | 173 KB | Main RCE module (offsets + config) |
| `rce_worker.js` | 43 KB | RCE worker for iOS 18.4 |
| `rce_loader.js` | 7 KB | Main orchestrator |
| `index.html` | 689 B | Landing page |
| `frame.html` | 252 B | Intermediate loader |

---

## Attack Flow

```
Victim visits compromised website
        │
        ▼
[widgets.js] injects hidden iframe (1px × 1px, opacity 0.01, offset -9999px)
        │
        ▼
[index.html] sets session UID, creates second hidden iframe
        │
        ▼
[frame.html] dynamically writes <script> loading rce_loader.js
        │
        ▼
[rce_loader.js] extracts iOS version from User-Agent
        │
        ├──► iOS 18.4–18.5 ──► rce_module.js + rce_worker.js (CVE-2025-31277)
        │
        └──► iOS 18.6+     ──► rce_module_18.6.js + rce_worker_18.6.js (CVE-2025-43529)
                │
                ▼
        PAC Bypass via dyld (CVE-2026-20700)
                │
                ▼
        [sbx0_main_18.4.js] WebContent → GPU Sandbox Escape (CVE-2025-14174)
                │
                ▼
        [sbx1_main.js] GPU → mediaplaybackd Sandbox Escape (CVE-2025-43510)
                │
                ▼
        [pe_main.js] Privilege Escalation to Kernel (CVE-2025-43520)
                │
                ▼
        Malware deployment (GHOSTBLADE / GHOSTKNIFE / GHOSTSABER)
```

---

## Exploit Chain Stages

### Stage 0 — Delivery
**Files:** `index.html` → `frame.html` → `rce_loader.js`

The compromised website contains a script tag that injects a hidden iframe. `index.html` sets a `uid` key in sessionStorage (with a Russian-language comment) and creates a hidden iframe loading `frame.html`, which dynamically writes a script tag loading `rce_loader.js`.

The iframe is designed to be invisible: dimensions are `1px × 1px`, opacity is `0.01`, and it's offset `-9999px` off-screen.

### Stage 1 — Remote Code Execution (RCE)
**Files:** `rce_module.js` + `rce_worker.js` (or `rce_worker_18.6.js`)

The iOS version is extracted from `navigator.userAgent`, then Web Workers are created for dynamic library loading. A memory corruption vulnerability in JavaScriptCore is exploited to build primitives:

- `addrof(object)` — get the memory address of any JS object
- `fakeobj(address)` — create a fake JS object at an arbitrary address
- `read64(address)` — read 8 bytes from any memory address
- `write64(address, value)` — write 8 bytes to any memory address

For iOS 18.4: CVE-2025-31277 (JIT optimization / type confusion)  
For iOS 18.6+: CVE-2025-43529 (DFG JIT Garbage Collection bug)

### Stage 2 — PAC Bypass
**Vulnerability:** CVE-2026-20700

Modern iOS devices (A12+) use Pointer Authentication to sign code pointers. A bug in dyld is exploited to sign arbitrary pointers using `pacia` and `pacib`, then a JOP (Jump-Oriented Programming) chain is built to call arbitrary system functions.

After this stage, the attacker can:
- `dlopen(path, flags)` — load dynamic libraries
- `dlsym(handle, symbol)` — get function addresses
- `fcall(address, ...args)` — call any function with WebContent-level privileges

### Stage 3 — Sandbox Escape #1 (WebContent → GPU)
**File:** `sbx0_main_18.4.js`  
**Vulnerability:** CVE-2025-14174

An ANGLE vulnerability (the graphics library translating WebGL to Metal/OpenGL) is exploited. Insufficient validation of parameters in a specific WebGL operation leads to out-of-bounds memory operations in Safari's GPU process.

### Stage 4 — Sandbox Escape #2 (GPU → mediaplaybackd)
**File:** `sbx1_main.js`  
**Vulnerability:** CVE-2025-43510

A Copy-on-Write vulnerability in the XNU kernel is exploited to transition from the GPU process to `mediaplaybackd`, which has broader privileges. A copy of the JavaScriptCore engine is loaded inside mediaplaybackd to execute the next stage.

### Stage 5 — Privilege Escalation
**File:** `pe_main.js`  
**Vulnerability:** CVE-2025-43520

A race condition in XNU's VFS (Virtual File System) implementation is exploited to build kernel memory read/write primitives. After success, the attacker gains full kernel privileges and deploys the final malware payload.

Key components in `pe_main.js`:
- **Native** — low-level memory access (`read`, `write`, `callSymbol`, `mem`)
- **Chain** — kernel read/write operations and offset management
- **Task** — Mach task traversal and port manipulation
- **Thread** — thread state manipulation and guard exception injection
- **Exception** — Mach exception port creation and message handling
- **RemoteCall** — remote function calls in target processes via exception hijacking
- **Sandbox** — sandbox extension token issuing and consumption
- **VM** — virtual memory mapping and shared memory between processes
- **PAC** — pointer authentication code signing for remote threads
- **PortRightInserter** — Mach port right insertion into task spaces

---

## Vulnerabilities (CVEs)

| # | CVE | Module | Type | Zero-Day? | Patched In |
|---|-----|--------|------|-----------|------------|
| 1 | CVE-2025-31277 | `rce_module.js` + `rce_worker.js` | Memory corruption in JavaScriptCore | No | iOS 18.6 |
| 2 | CVE-2025-43529 | `rce_worker_18.6.js` | DFG JIT GC bug in JavaScriptCore | Yes | iOS 18.7.3, 26.2 |
| 3 | CVE-2026-20700 | `rce_worker*.js` | PAC bypass in dyld | Yes | iOS 26.3 |
| 4 | CVE-2025-14174 | `sbx0_main_18.4.js` | Memory corruption in ANGLE (WebGL) | Yes | iOS 18.7.3, 26.2 |
| 5 | CVE-2025-43510 | `sbx1_main.js` | Copy-on-Write bug in XNU | No | iOS 18.7.2, 26.1 |
| 6 | CVE-2025-43520 | `pe_main.js` | Race condition in VFS (XNU) | No | iOS 18.7.2, 26.1 |

---

## Targeted Devices

Based on the offsets table in `rce_module.js` (Build 22F76 = iOS 18.5):

| Device ID | Device Name | SoC |
|-----------|-------------|-----|
| `iPhone11,2` | iPhone XS | A12 Bionic |
| `iPhone11,8` | iPhone XR | A12 Bionic |
| `iPhone12,1` | iPhone 11 | A13 Bionic |
| `iPhone12,3` / `12,5` | iPhone 11 Pro / Max | A13 Bionic |
| `iPhone12,8` | iPhone SE (2nd gen) | A13 Bionic |
| `iPhone13,1` – `13,4` | iPhone 12 family | A14 Bionic |
| `iPhone14,2` – `14,8` | iPhone 13 / 14 family | A15 Bionic |
| `iPhone15,2` + | iPhone 14 Pro / 15 / 16 series | A16 / A17 / A18 |

Offsets differ per device model due to memory layout variations.

---

## Threat Actors

Three separate threat actors were observed using DarkSword:

### 1. UNC6748
- **Target:** Users in Saudi Arabia
- **Method:** Fake Snapchat-themed website (`snapshare[.]chat`)
- **Malware:** GHOSTKNIFE — full backdoor with audio recording, screenshots, file download
- **Period:** November 2025

### 2. PARS Defense (Turkish commercial surveillance vendor)
- **Target:** Users in Turkey and Malaysia
- **Method:** ECDH+AES encrypted communications, code obfuscation
- **Malware:** GHOSTSABER — backdoor with device enumeration, SQLite queries, arbitrary JS execution
- **Period:** November 2025 – January 2026

### 3. UNC6353 (suspected Russian espionage group)
- **Target:** Users in Ukraine via compromised Ukrainian websites
- **Method:** Watering Hole attacks via `static.cdncounter[.]net`
- **Malware:** GHOSTBLADE — dataminer collecting messages, calls, photos, passwords, crypto wallets
- **Period:** December 2025 – March 2026
- **Note:** This is the variant present in this repository

---

## Malware Payloads

### GHOSTBLADE (present in this repository)
- **Type:** Dataminer
- **Language:** Webpack-bundled JavaScript
- **Collected Data:**
  - iMessage, Telegram, WhatsApp messages
  - Call history and contacts
  - Saved WiFi passwords
  - Photos, Notes, Calendar
  - Crypto wallets
  - Safari history and bookmarks
  - Location data and Find My iPhone
  - Health databases
- **Exfiltration:** HTTPS to `sqwas.shapelie[.]com`

### GHOSTKNIFE
- **Type:** Full backdoor
- **Capabilities:** Audio recording, screenshots, file download, settings update
- **Protocol:** Binary protocol encrypted with ECDH+AES over HTTP

### GHOSTSABER
- **Type:** Backdoor
- **Capabilities:** Device enumeration, file listing, arbitrary JS execution, SQLite queries

---

## Lab Testing & Analysis

### Requirements for Real Execution
1. iPhone device running iOS 18.4 – 18.6 with a supported model
2. HTTPS web server serving the exploit files
3. Valid SSL certificate for the serving domain
4. Target must visit the page via Safari (not Chrome or Firefox)




### Dynamic Analysis
- **Corellium** — cloud-based iOS simulator running real iOS
- **Frida** — instrumentation tool for real-time function call monitoring
- **AST Explorer** — for analyzing JavaScript code structure

### Why It Won't Work on Desktop

| Reason | Explanation |
|--------|-------------|
| **OS** | Targets iOS only — Linux/macOS/Windows are not affected |
| **Browser** | Requires Safari on iOS with JavaScriptCore engine |
| **Offsets** | Hardcoded addresses for specific iPhone models and builds |
| **ASLR** | Needs real-time ASLR slide calculation on the target device |
| **PAC** | Pointer Authentication is exclusive to ARM (A12+ chips) |
| **C2 Servers** | Distribution and exfiltration servers are no longer active |

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Indicator | Actor | Context |
|-----------|-------|---------|
| `snapshare[.]chat` | UNC6748 | DarkSword distribution (Saudi Arabia) |
| `62.72.21[.]10` | UNC6748 | GHOSTKNIFE C2 |
| `72.60.98[.]48` | UNC6748 | GHOSTKNIFE C2 |
| `sahibndn[.]io` | PARS Defense | DarkSword distribution (Turkey) |
| `e5.malaymoil[.]com` | PARS Defense | DarkSword distribution (Malaysia) |
| `static.cdncounter[.]net` | UNC6353 | DarkSword distribution (Ukraine) | #is replaced in frame.html:7-12 line with url "https://htmlyou-should-add-your-url-here/assets/rce_loader.js?"
and in rce_loader:8 and 26 line with "https://rce_loader-you-should-add-your-url-here/404.html"
| `sqwas.shapelie[.]com` | UNC6353 | GHOSTBLADE exfiltration server |
in pe_main:line 1375, 1439 , 1455 "pe_main-you-should-add-your-u&rl-here.com"


### YARA Rule

```yara
rule G_Datamine_GHOSTBLADE_1 {
    meta: author = "Google Threat Intelligence Group (GTIG)"
    strings:
        $ = "/private/var/tmp/wifi_passwords.txt"
        $ = "/private/var/tmp/wifi_passwords_securityd.txt"
        $ = "/.com.apple.mobile_container_manager.metadata.plist"
        $ = "X-Device-UUID: ${"
        $ = "/installed_apps.txt"
        $ = "icloud_dump_"
    condition:
        filesize < 10MB and 3 of them
}
```

---

## Defensive Measures

### For Users
1. Update iOS immediately to the latest version (iOS 26.3+ patches all vulnerabilities)
2. Enable Lockdown Mode on high-risk devices
3. Avoid visiting suspicious links from untrusted sources

### For Security Researchers
1. Use GTIG-provided YARA rules for malware detection
2. Monitor IOCs in network traffic
3. Check crash reports on suspected compromised iOS devices

---

## Conclusion

DarkSword represents an advanced model of modern exploit chains:

1. Operates entirely from the browser without user interaction
2. Uses JavaScript only across all stages
3. Chains 6 vulnerabilities: RCE → PAC Bypass → 2x Sandbox Escape → Privilege Escalation
4. Proliferated across multiple actors (government-linked and commercial)

All vulnerabilities were reported to Apple by GTIG and have been patched in subsequent updates.

---

## Special thanks to

- [Google Threat Intelligence Group (GTIG)](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)

- [Google Project Zero](https://googleprojectzero.blogspot.com/)        

- [dr1408](https://github.com/dr1408)        

----

- [Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)

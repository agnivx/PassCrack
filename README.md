# ⚡ PassCrack

> A modern, hardware-accelerated password recovery & hash analysis GUI built with **Python**, **CustomTkinter**, and powered by **Hashcat**.

---

## 📖 Overview

**PassCrack** bridges the raw speed of [Hashcat](https://hashcat.net/hashcat/) with a modern, intuitive desktop interface. It allows security researchers, penetration testers, and system administrators to perform high-performance dictionary and brute-force attacks across various hashing algorithms with real-time logging, GPU/CPU device management, and intelligent mask optimizations.

---

## ✨ Features

- **🚀 Hardware Accelerated**: Seamlessly interfaces with Hashcat for multi-threaded CPU and GPU (OpenCL/CUDA) accelerated cracking.
- **🎨 Modern Dark UI**: Clean, responsive interface built with CustomTkinter.
- **⚔️ Dual Attack Modes**:
  - **Dictionary Attack**: Test against customized wordlists.
  - **Brute-Force (Mask) Attack**: Customizable charsets and length ranges (1–14 characters).
- **🎯 Confirmed Position Hints**: Pin known characters at specific indices (e.g., `p?ssw?rd`) to drastically shrink the search space for long hashes.
- **🔄 Local Fallback**: Integrated Python CPU fallback for hashing/encoding schemes not natively handled by standard modes (e.g., Base64).
- **📜 Live Log Streaming & Abort**: Real-time progress updates, device status, and one-click execution termination.
- **💾 Automatic Export**: Instant logging of cracked hashes and parameters directly to `PassCrack_Results.txt`.

---

## 🔐 Supported Algorithms & Charsets

### Hash Algorithms
| Algorithm | Hashcat Mode (`-m`) | Backend Engine |
| :--- | :---: | :--- |
| **MD4** | `900` | Hashcat GPU / CPU |
| **MD5** | `0` | Hashcat GPU / CPU |
| **SHA1** | `100` | Hashcat GPU / CPU |
| **SHA256** | `1400` | Hashcat GPU / CPU |
| **SHA512** | `1700` | Hashcat GPU / CPU |
| **RIPEMD160** | `600` | Hashcat GPU / CPU |
| **Base64 / Custom** | — | Local Python Fallback |

### Charset Options
- `Alphabetic (a-z)` / `Alphabetic (A-Z)` / `Alphabetic (a-z, A-Z)`
- `Numeric (0-9)`
- `Alphanumeric (a-zA-Z0-9)`
- `Alphanumeric + Special Characters`
- `HEX (0-9a-f)`

---

## 🛠️ Prerequisites

1. **Python**: Python 3.9 or higher.
2. **Hashcat**: Download the latest release from [hashcat.net](https://hashcat.net/hashcat/) and extract it on your system.
3. **GPU Drivers** *(Optional, recommended)*: Ensure your NVIDIA/AMD/Intel OpenCL or CUDA drivers are up-to-date for GPU acceleration.

---

## 📦 Installation & Setup

### 1. Clone or Download the Repository
```bash
git clone https://github.com/yourusername/PassCrack.git
cd PassCrack
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install customtkinter bcrypt
```

### 4. Configure Hashcat Path
Open [`passCrack.py`](passCrack.py) and update the `HASHCAT_PATH` variable (line 42) with the absolute path to your Hashcat binary:

```python
# Windows Example:
HASHCAT_PATH = r"C:\path\to\hashcat\hashcat.exe"

# Linux / macOS Example:
HASHCAT_PATH = r"/usr/bin/hashcat"
```

---

## 🚀 How to Run

Launch the application by running:

```bash
python passCrack.py
```

---

## 🖥️ Usage Guide

### 1. Dictionary Attack
1. Paste the target hash into the **Hash Value** input.
2. Choose the corresponding **Algorithm** from the dropdown (e.g., `sha256`, `md5`).
3. Set **Attack Type** to `Dictionary`.
4. Click **Browse** under **Dictionary File** and select your wordlist (e.g., `rockyou.txt`).
5. Select your compute **Device** (Auto, CPU, or specific GPU).
6. Click **▶ Start**.

### 2. Brute-Force / Mask Attack
1. Enter the target **Hash Value** and select the **Algorithm**.
2. Set **Attack Type** to `Brute-Force`.
3. Choose the target **Charset** and set the **Max Length** (1–14).
4. *(For lengths > 8)*: A dialog will prompt you to enter **Confirmed Positions** (known character hints at specific indices).
5. Click **▶ Start**.

### 3. Aborting & Viewing Results
- Click **⛔ Abort** at any time to terminate the running process.
- Successful recoveries will be displayed on screen and appended to [`PassCrack_Results.txt`](PassCrack_Results.txt).

---

## 📂 Project Structure

```text
PassCrack/
├── passCrack.py            # Main application GUI and execution engine
└── PassCrack_Results.txt   # Output file for recovered credentials
```

---

## ⚠️ Disclaimer

> **For Educational and Authorized Testing Purposes Only**  
> This software is designed to assist security researchers and authorized administrators in assessing password strength and validating security controls. Unauthorized use of this tool against targets without explicit, prior permission is strictly illegal.

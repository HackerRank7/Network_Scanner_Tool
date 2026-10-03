# Network Recon & Vulnerability Lookup Tool

A simple, beginner-friendly Python tool that:

1. **Scans a target IP/hostname for open ports**
2. **Detects the service and version** running on each open port (banner grabbing)
3. **Guesses the operating system** using a TTL-based heuristic
4. **Looks up known vulnerabilities (CVEs)** for the detected service/version using the free, official [NVD (National Vulnerability Database)](https://nvd.nist.gov/) API

This tool was built for **beginners** — it has an **interactive mode** that just asks you questions one by one, so you don't need to memorize any command-line flags.

---

## ⚠️ Legal Notice — Read Before Using

**Only scan systems and networks that you own, or that you have explicit written permission to test.**

Scanning systems without authorization is **illegal** in most countries (for example, under the IT Act 2000 in India, and the CFAA in the United States). This tool does not exploit anything — it only reports open ports, service banners, and publicly known CVE references, so you can patch/secure your own systems.

A safe, legal practice target to try this on is **`scanme.nmap.org`** — a host the Nmap project has set up specifically to be scanned for testing and learning.

---

## 📋 What You Need Before Starting

- A computer running **Windows** or **Linux** (macOS also works, steps are almost identical to Linux)
- **Python 3.8 or newer** installed
- An internet connection (needed for the vulnerability lookup step)

That's it — this tool doesn't need any paid software or API keys.

---

## 🔧 Installing Git (Optional but Recommended)

Git lets you download (`clone`) this repository with a single command, and makes it easy to get future updates. If you'd rather not install anything extra, skip this section and just use the **"Download ZIP"** method shown in the setup steps below.

### Windows

1. Go to [git-scm.com/download/win](https://git-scm.com/download/win) — the download will start automatically.
2. Run the installer and click **Next** through all the steps, keeping the default options (no need to change any settings).
3. Click **Install**, then **Finish**.
4. **Important:** Close any open Command Prompt / PowerShell window and open a new one — this is required for Windows to recognize the new `git` command.
5. Verify the installation:
```powershell
   git --version
```
   You should see something like `git version 2.45.0.windows.1`.

### Don't want to install Git?

No problem — you can download this project as a ZIP file instead:
1. Click the green **Code** button at the top of this repository page.
2. Click **Download ZIP**.
3. Extract the ZIP file anywhere on your computer and continue with the setup steps below.
   
## 🪟 How to Set Up and Use on Windows

### Step 1 — Install Python

1. Go to [python.org/downloads](https://www.python.org/downloads/) and download the latest Python version.
2. Run the installer.
3. **Important:** On the first install screen, tick the checkbox that says **"Add python.exe to PATH"** before clicking Install. This step is easy to miss and causes most beginner errors later.
4. Finish the installation.

### Step 2 — Verify Python is installed

Open **PowerShell** or **Command Prompt** (search for it in the Start Menu) and type:

```powershell
python --version
```

If it prints something like `Python 3.12.0`, you're good. If you get an error like `'python' is not recognized`, Python wasn't added to PATH — reinstall Python and make sure to tick that checkbox.

### Step 3 — Download this project

**Option A — Using Git (recommended):**
```powershell
git clone https://github.com/HackerRank7/Network_Scanner_Tool.git
cd Network_Scanner_Tool
python NetScan.py
```

**Option B — Without Git:**
1. On the GitHub page, click the green **Code** button → **Download ZIP**
2. Extract the ZIP file anywhere (e.g. your Desktop)
3. Open PowerShell and navigate into that folder:
   ```powershell
   cd C:\Users\pc\Downloads\Network_Scanner_Tool-main\Network_Scanner_Tool-main
   ```

### Step 4 — (Optional) Install colorama for colored output

This tool prints open ports/results in blue and "not found" results in red. On modern Windows Terminal, PowerShell 7+, or VS Code's terminal, colors work automatically. On very old `cmd.exe`, install this helper library:

```powershell
pip install colorama
```

### Step 5 — Run the tool

```powershell
python NetScan.py
```

The tool will now ask you questions one by one:
```
Enter target IP or hostname (e.g. 192.168.1.10 or scanme.nmap.org): scanme.nmap.org

Which ports do you want to scan?
  1) Common ports (fast, ~21 well-known ports)
  2) All ports (1-65535, this will take a long time)
  3) Custom range (e.g. 1-1000)
  4) Custom list (e.g. 22,80,443)
Choose an option (1-4): 1

Do you also want to check for vulnerabilities (CVEs)? [Y/n]: y

Threads (press Enter for default 100):
```

Just answer each question and press Enter — the scan will start automatically.

### Common Windows Errors and Fixes

| Error | Why it happens | Fix |
|---|---|---|
| `'python' is not recognized` | Python not added to PATH | Reinstall Python, tick "Add to PATH" |
| `can't open file '...': No such file or directory` | You're in the wrong folder | Use `cd` to go to the folder where `network_scanner.py` is saved |
| No colors shown in old cmd.exe | Old terminal doesn't support ANSI colors | `pip install colorama`, or use Windows Terminal/PowerShell instead |
| Windows Defender Firewall popup appears | Windows is asking permission for network access | Click **Allow** |

---

## 🐧 How to Set Up and Use on Linux

### Step 1 — Check if Python is already installed

Most Linux distributions come with Python pre-installed. Check with:

```bash
python3 --version
```

If it's missing, install it:

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install python3 python3-pip -y

# Fedora
sudo dnf install python3 python3-pip -y

# Arch
sudo pacman -S python python-pip
```

### Step 2 — Download this project

**Option A — Using Git (recommended):**
```bash
git clone https://github.com/HackerRank7/Network_Scanner_Tool.git
cd Network_Scanner_Tool
python3 NetScan.py
```

**Option B — Without Git:**
Download the ZIP from GitHub, then:
```bash
unzip Network_Scanner_Tool-main.zip
cd Network_Scanner_Tool-main
```

### Step 3 — Make sure `ping` is available (needed for OS detection)

Most Linux systems already have it. If not:
```bash
sudo apt install iputils-ping -y
```

### Step 4 — Run the tool

```bash
python3 NetScan.py
```

Just like on Windows, it will ask you the same questions interactively — enter your target, choose a port option, decide on vulnerability checking, and press Enter for the default thread count.

### Common Linux Errors and Fixes

| Error | Why it happens | Fix |
|---|---|---|
| `python: command not found` | Linux uses `python3`, not `python` | Use `python3 network_scanner.py` |
| `Permission denied` | Script isn't marked executable (only happens if running with `./`) | `chmod +x network_scanner.py` |
| `ping: command not found` | `ping` utility missing | `sudo apt install iputils-ping` |
| `ModuleNotFoundError` | Shouldn't normally happen — this tool only uses Python's standard library | Make sure you're using Python 3.8+ |

---

## 🖥️ Advanced Usage — Command-Line Mode

If you don't want the step-by-step questions (for example, if you're scripting or automating scans), you can pass everything as command-line flags instead:

```bash
python3 NetScan.py -t <target> -p <ports> [options]
```

| Flag | Meaning | Example |
|---|---|---|
| `-t` / `--target` | Target IP or hostname | `-t scanme.nmap.org` |
| `-p` / `--ports` | `common`, `all`, a range, or a list | `-p 1-1000` or `-p 22,80,443` |
| `--no-vuln` | Skip the CVE lookup step | `--no-vuln` |
| `--threads` | Number of parallel scan threads (default: 100) | `--threads 300` |

**Examples:**
```bash
# Scan common ports with vulnerability lookup
python3 NetScan.py -t scanme.nmap.org -p common

# Scan a specific port range, skip vulnerability lookup
python3 NetScan.py -t 192.168.1.10 -p 1-1000 --no-vuln

# Scan a custom list of ports with more threads
python3 NetScan.py -t 192.168.1.10 -p 22,80,443,3306 --threads 200

# Scan every possible port (slow!)
python3 NetScan.py -t 192.168.1.10 -p all
```

If you run the tool with **no flags at all**, it automatically switches to the beginner-friendly interactive mode described above.

---

## 📖 How the Tool Works (For Curious Beginners)

1. **Port scanning** — The tool tries to open a TCP connection to each port. If the connection succeeds, the port is "open."
2. **Banner grabbing** — Many services announce themselves right after connecting (e.g. `SSH-2.0-OpenSSH_8.2`). The tool reads this text to figure out what's running.
3. **OS guessing** — The tool pings the target and looks at the TTL (Time To Live) value in the reply. Linux/Unix systems typically reply with TTL ≤ 64, Windows with TTL ≤ 128. This is just a rough guess, not 100% certain.
4. **Vulnerability lookup** — If a specific version was detected (e.g. "Apache 2.4.7"), the tool searches the NVD database for known CVEs related to that version. If only a generic name is detected (e.g. just "http" with no version), the tool skips this step to avoid showing misleading, unrelated results.

### Understanding the Colors

- 🔵 **Blue** text = something was found (an open port, or a known CVE)
- 🔴 **Red** text = nothing was found (no open ports, no CVEs, or a version couldn't be detected)

---

## ❓ Frequently Asked Questions

**Q: Is this a hacking tool?**
A: No. This tool only reports information — it does not exploit or attack anything. It's the same category of tool as Nmap, used for authorized security testing and learning.

**Q: Can I scan any website I want?**
A: No. Only scan systems you own, or have explicit permission to test. Use `scanme.nmap.org` to practice safely and legally.

**Q: Why didn't it detect the OS correctly?**
A: OS detection here uses a simple TTL heuristic, which can be inaccurate if a firewall modifies or blocks ping replies. For more accurate detection, dedicated tools like Nmap's `-O` flag use much more complex techniques.

**Q: Why are some CVE results irrelevant?**
A: The NVD search works by keyword. If the tool only detects a generic service name (like "http") instead of a specific version, searching for that generic word can return unrelated, often very old CVEs. That's why the tool skips vulnerability lookup when no specific version is found.

---

## 🤝 Contributing

Found a bug or want to add a feature? Feel free to open an issue or submit a pull request. This project is intentionally kept simple and beginner-friendly, so please keep additions easy to understand.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ✍️ Author
  [![Gaurav Bharty](https://img.shields.io/badge/Gaurav%20Bharty-orange)]()

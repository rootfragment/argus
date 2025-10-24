# Kernel vs Userspace Port Comparison: Hidden Port Detection

## Overview

The kernel module `/proc/open_ports` outputs all open ports in the system:

```
[kports] pid=2082 comm=firefox source port=40862 destination port=443
[kports] pid=2082 comm=firefox source port=34262 destination port=443
[kports] pid=2082 comm=firefox source port=54218 destination port=443
```

The helper script reads this information, compares it with ports visible from userspace using `ss`, and reports any discrepancies.

---

## How the Helper Script Works

### 1. Kernel Ports Parsing

The kernel-space module outputs each open port along with its process ID (PID) and process name (`comm`). The Python script reads the `/proc/open_ports` file and extracts:

* `pid` → Process ID
* `comm` → Process name
* `source port` → Port number

Using regex:

```python
entries = re.findall(r"pid=(\d+)\s+comm=([\w\.\-]+)\s+source port=(\d+)", data)
```

It then builds:

* A **set of `(port, pid)` tuples** to use in comparisons
* A **mapping `(port, pid) → process_name`** for reporting

### 2. Userspace Ports Detection

Userspace ports are detected via the `ss` command:

```bash
ss -tanup
```

Flags used:

* `-t` → TCP
* `-a` → all sockets (listening + established + ephemeral)
* `-n` → numeric ports
* `-u` → UDP
* `-p` → display process info

The script parses the output and builds a **set of `(port, pid)` tuples** representing all visible userspace ports.

---

### 3. Comparing Kernel and Userspace

The script computes:

```python
hidden_from_userspace = kernel_ports - userspace_ports
```

* Ports present in kernel-space but missing in userspace are flagged as **potential hidden ports**.

---

## Why Root User is Required

* Many system processes (e.g., NetworkManager) run as `root`.
* Normal users cannot see all ports due to permission restrictions.
* Running the helper script with `sudo` ensures **all processes and ports are visible**:

```bash
sudo python3 helper.py
```

---

## Example Output

```text
[!] Hidden ports detected (visible in kernel, not in userspace):

    → Port 68 | Process: NetworkManager (PID 629)
    → Port 34518 | Process: firefox (PID 2623)
```

After using `ss -tanup` with `sudo`, most false positives are eliminated, leaving only **truly hidden ports** for investigation.

---

## Key Takeaways

1. Comparing kernel-space and userspace ports is effective for detecting hidden or malicious services.
2. Root privileges are essential for accurate detection.
3. Mapping ports to `(pid, process_name)` helps identify which process owns a hidden port.

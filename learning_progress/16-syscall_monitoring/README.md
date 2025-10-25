#  Syscall Monitor Kernel Module

## Overview
`syscall_monitor` is a lightweight Linux kernel module that uses **kprobes** to dynamically hook into specific **system call entry points** and log their usage.  
It records essential process information every time one of the targeted syscalls is invoked, storing the logs in a ring buffer accessible via `/proc/syscall_monitor`.

This tool is primarily intended for **security monitoring**, **rootkit behavior analysis**, and **runtime syscall tracing** — all while keeping kernel overhead low and avoiding permanent modifications.

---

##  Key Features
- Hooks into a **defined set of syscalls** (e.g., module loading, file operations, process creation, privilege changes).
- Records minimal but crucial metadata:
  - Timestamp (seconds since epoch)
  - Process ID (`pid`)
  - Thread group ID (`tgid`)
  - User ID (`uid`)
  - Process name (`comm`)
  - Syscall name
- Logs stored in a **fixed-size circular buffer** to prevent memory exhaustion.
- Accessible via `/proc/syscall_monitor` for user-space tools or scripts.
- Automatic cleanup on module unload — no residual kernel traces.

---

## How It Works

### 1. **Kprobe Registration**
At initialization, the module:
- Iterates through a predefined list of syscall entry symbols (like `__x64_sys_execve`, `__x64_sys_openat`, etc.).
- Registers a **kprobe** on each symbol.
- Assigns a pre-handler function that triggers **just before** the syscall executes.

### 2. **Event Logging**
Whenever a hooked syscall is invoked:
- The pre-handler logs relevant process information into a shared **ring buffer**.
- Synchronization is managed using a **spinlock** to ensure thread safety in concurrent syscall activity.
- Each log entry is compact and fixed in size, preventing uncontrolled kernel memory growth.

### 3. **/proc Interface**
The module exposes its data via a read-only proc entry:
```
/proc/syscall_monitor
```
Reading this file outputs newline-separated entries in CSV format:
```
<timestamp>,<pid>,<tgid>,<uid>,<comm>,<syscall>
```
Example output:
```
1730058801,1204,1204,1000,bash,__x64_sys_execve
1730058802,1204,1204,1000,bash,__x64_sys_openat
```

### 4. **Buffer Management**
- The log buffer can hold up to **1024 entries**.
- Once full, it **overwrites the oldest data** (circular behavior).
- Optionally, the buffer can be cleared after each `/proc` read, controlled by a flag (`clear_on_read`).

### 5. **Cleanup**
On module removal:
- All registered kprobes are unregistered.
- The `/proc/syscall_monitor` file is deleted.
- The system state returns to normal with no persistent hooks.

---

## 🔧 Usage

### 1. Build
```bash
make
```

### 2. Load the module
```bash
sudo insmod syscall_monitor.ko
```

### 3. View collected logs
```bash
cat /proc/syscall_monitor
```

### 4. Unload the module
```bash
sudo rmmod syscall_monitor
```

### 5. Check kernel messages
```bash
dmesg | grep syscall_monitor
```

---

## Monitored Syscalls
The module tracks key syscalls commonly involved in system-level or potentially suspicious activities:

- `init_module`, `finit_module`, `delete_module`  
- `execve` (program execution)  
- `openat`, `ioctl`, `mmap`, `read`, `write`, `close`  
- `clone` (process creation)  
- `ptrace` (process inspection)  
- `setuid` (privilege changes)

---

##  Safety Notes
- The module is **read-only** and does **not modify syscall behavior**.
- The kprobes are automatically cleaned up on exit.
- For safety, avoid deploying on **production systems** without strict control, as high syscall volume could fill the log buffer rapidly.
- Ideal for **research**, **monitoring**, or **security analytics** in controlled environments.

---

##  Example Use Cases
- Detecting unusual kernel module load/unload events.
- Tracking execution of privileged binaries.
- Observing runtime process creation behavior.
- Feeding data into user-space monitoring agents for forensic analysis.

---

##  Requirements
- Linux kernel ≥ 5.4 (with kprobes and `/proc` support)
- Root privileges to load/unload the module
- GCC and kernel headers for building

---

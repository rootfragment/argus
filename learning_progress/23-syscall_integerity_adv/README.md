# Syscall Integrity Detector

This directory contains a Linux kernel module (`23-syscall_integerity.c`) and a userspace Python script (`user.py`) designed to monitor and detect syscall table tampering. This setup can be used to identify modifications to the kernel's syscall table, which is a common technique employed by rootkits.

## Components

### 1. `23-syscall_integerity.c` (Syscall Integrity Detector LKM)

This is a Linux Kernel Module that serves as a syscall integrity checker.

**Functionality:**
*   **Snapshot:** Upon loading, it takes a snapshot of the kernel's `sys_call_table`.
*   **`/proc/syscall_integrity`:** Creates a `/proc` entry that, when read, reports on the integrity of the syscall table.
    *   Returns `0` if no syscalls have been tampered with since module load.
    *   Returns `-1` followed by the names of tampered syscalls if discrepancies are found.

### 2. `user.py` (Userspace Monitoring Script)

This Python script continuously monitors the syscall table integrity.

**Functionality:**
*   Reads the `/proc/syscall_integrity` file every 10 seconds.
*   Reports whether the syscall table is clean or if any syscalls have been hooked (tampered with).
*   If tampering is detected, it lists the names of the hooked syscalls.

## How to Build and Use

### Building `23-syscall_integerity.c` (Syscall Integrity Detector)

1.  Navigate to the `syscall_userspace` directory (current directory).
2.  Compile the module using the provided `Makefile`:
    ```bash
    make
    ```
3.  Load the module (as root):
    ```bash
    sudo insmod 23-syscall_integerity.ko
    ```
    *To remove:* `sudo rmmod 23-syscall_integerity`

### Running `user.py` (Userspace Monitor)

1.  Ensure `23-syscall_integerity.ko` is loaded.
2.  Run the Python script:
    ```bash
    python3 user.py
    ```

## Example Usage

1.  Load `23-syscall_integerity.ko`.
2.  Start `user.py` in a terminal. It should initially report "No issues with the syscall table since module load."
3.  *To simulate tampering (e.g., with a separate rootkit like `Diamorphine` found in other projects), load a kernel module that hooks syscalls.*
4.  Observe `user.py` detecting the hooked syscalls.
5.  Unload any tampering modules.
6.  Observe `user.py` returning to "No issues with the syscall table...".
7.  Unload `23-syscall_integerity.ko`.

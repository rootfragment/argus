# System integerity checker

This kernel module is a simple detector for Direct Kernel Object Manipulation (DKOM) attacks that target the system call table (`sys_call_table`). It works by periodically checking for unauthorized modifications to the syscall handlers.

## How It Works

The detector operates as a Linux Kernel Module (LKM) and performs the following steps:

1.  **Initialization:**
    *   Upon loading, the module finds the memory address of the kernel's `sys_call_table`.
    *   It creates a "golden" snapshot by copying the entire original `sys_call_table` into a separate, protected memory location. This snapshot serves as a trusted baseline.
    *   A kernel timer is started, configured to fire periodically (every 5 seconds by default).

2.  **Periodic Verification:**
    *   Each time the timer fires, the detector iterates through every entry in the live `sys_call_table`.
    *   It compares the address of each live system call handler with the corresponding address stored in its "golden" snapshot.
    *   If any address does not match, it indicates that the system call has been hooked or tampered with.

3.  **Alerting:**
    *   When a mismatch is detected, the module prints a warning message to the kernel log buffer (`dmesg`). The message includes the syscall number that was altered and shows both the original (golden) and the new (tampered) address.

## Detecting Diamorphine LKM

The **Diamorphine** rootkit, like many other kernel-level rootkits, achieves its malicious goals (e.g., hiding files, processes, or network connections) by hooking critical system calls.

For instance, to hide itself, Diamorphine might replace the pointer for the `getdents64` syscall in the `sys_call_table` with a pointer to its own custom function. This custom function would call the original `getdents64` function, receive the real list of directory entries, filter out any entries related to the rootkit, and then return the sanitized list to the user.

This detector effectively catches such modifications. When Diamorphine overwrites the address in the `sys_call_table`, this module will spot the change on its next check because the new address will no longer match the one in the "golden" table.

## How to Compile and Run

1.  **Compile the module:**
    Ensure you have the kernel headers installed for your running kernel.
    ```sh
    make
    ```

2.  **Load the module:**
    ```sh
    sudo insmod 22-sycall_integerity_checker.ko
    ```

3.  **Monitor for detections:**
    You can view the kernel log to see the module's output and any warnings.
    ```sh
    dmesg -wH
    ```
    If a syscall is tampered with while the module is running, a message like this will appear:
    ```
    [  +5.000123] Syscall integerity checker: Syscall 61 tampered! Original: ffffffff814a6b90, New: ffffffffc0a3e0c0
    ```

4.  **Unload the module:**
    ```sh
    sudo rmmod 22-sycall_integerity_checker
    ```

## Disadvantages and Limitations

This detection method is simple and effective against basic rootkits, but it has significant limitations:

1.  **Vulnerable to Race Conditions:** The detector is only effective if it is loaded **before** the rootkit. If a rootkit like Diamorphine is already active when this module is loaded, the "golden" table will be created from the *already tampered* system call table, rendering the detector useless.

2.  **Does Not Stop Advanced Hooking:** This module only checks for direct overwrites in the `sys_call_table` array. More sophisticated rootkits can use other hooking mechanisms like ftrace or kprobes to intercept system calls without ever modifying the table itself. This detector is blind to those techniques.

3.  **Detection, Not Prevention:** The module only logs a warning. It does not prevent the rootkit from executing or attempt to restore the original system call handler (which would be unsafe and could lead to system instability).

4.  **Easily Defeated:** A slightly more advanced rootkit could easily defeat this detector. It could be designed to find and unload the `dkom_detector` module, or even find the `golden_syscall_table` in memory and tamper with it to match the hooked `sys_call_table`.

5.  **Kernel Version Dependent:** The code relies on finding `sys_call_table` via `kallsyms_lookup_name`, which is generally stable but could fail if future kernel versions change how symbols are exported or protected (e.g., via Kernel Page Table Isolation).

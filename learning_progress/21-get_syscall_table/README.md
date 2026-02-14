# Syscall Table Address finder

## Description

This lkm is designed to retrive the address of the syscall table from the memory (RAM), here kprobes are assigned to first find the `kallsyms_lookup_name` and then it is used to find the adress of other required systemcalls.
This technique is often used by rootkits and other malicious software to intercept and manipulate system calls, allowing them to hide their presence and control the system. This code is intended for educational purposes only and should not be used on production systems.

## How it Works

The core of this module's functionality relies on the ability to resolve kernel symbols, specifically `kallsyms_lookup_name`. Here's a step-by-step breakdown of the process:

1.  **Resolving `kallsyms_lookup_name`**:
    *   Since kernel version 2.6, the `kallsyms_lookup_name` function, which allows looking up the address of any kernel symbol by name, is not exported for modules to use directly. This is a security measure to make it harder for malicious modules to find critical kernel structures.
    *   To get around this, the module uses a `kprobe` to find the address of `kallsyms_lookup_name`. A `kprobe` is a debugging mechanism that can be set on almost any kernel instruction. The module registers a `kprobe` for the `kallsyms_lookup_name` symbol, retrieves its address, and then immediately unregisters the `kprobe`.

2.  **Finding the Syscall Table**:
    *   Once the address of `kallsyms_lookup_name` is resolved, it can be used to find the address of the `sys_call_table`. The `sys_call_table` is an array of function pointers, where each element points to the handler for a specific system call.
    *   The module calls `kallsyms_lookup_name("sys_call_table")` to get the memory address of this table.

3.  **Reading Syscall Addresses**:
    *   With the address of the `sys_call_table`, the module can then access the pointers to individual system calls using their syscall numbers (e.g., `__NR_read`, `__NR_write`).
    *   The module prints the addresses of the `read`, `write`, and `execve` system calls to the kernel log (`dmesg`).

## Requirements and Compatibility

This code's ability to run is highly dependent on the kernel version and its configuration. On modern Linux kernels, several security features are enabled by default to prevent this kind of manipulation. To get this code to run, you might need to disable the following:

*   **Kernel Lockdown**: On many modern distributions, the kernel is "locked down," which prevents even the root user from modifying the kernel. This can prevent loading unsigned modules and can restrict access to kernel memory and symbols. You might need to disable lockdown in your bootloader settings.
*   **`kprobes` restrictions**: Some kernels may restrict the use of `kprobes`.
*   **Read-only `sys_call_table`**: On many architectures, the `sys_call_table` is located in read-only memory. While this module only reads the table, any attempt to modify it (as a rootkit would) would cause a kernel panic.

Due to these security features, this code is more likely to work on older kernels (e.g., 2.6.x) or on custom-built kernels where these security features have been explicitly disabled.

## Compilation and Usage

### Compilation

To compile the kernel module, you will need to have the kernel headers installed for your running kernel. You can then use the provided `Makefile`:

```sh
make
```

This will produce a `get_syscall_table.ko` file.

### Usage

To load the module, use the `insmod` command:

```sh
sudo insmod get_syscall_table.ko
```

To see the output of the module, check the kernel log:

```sh
dmesg | tail
```

You should see output similar to this:

```
[xxxx.xxxxxx] LKM: Module loaded
[xxxx.xxxxxx] LKM: kallsyms_lookup_name resolved at ffffffff81c0c2a0
[xxxx.xxxxxx] LKM: sys_call_table at ffffffff82000200
[xxxx.xxxxxx] sys_read  -> ffffffff81a1b1b0
[xxxx.xxxcxx] sys_write -> ffffffff81a1b2b0
[xxxx.xxxxxx] sys_execve -> ffffffff818a7d70
```

To unload the module, use the `rmmod` command:

```sh
sudo rmmod get_syscall_table
```

## Security Implications and Rootkit Potential

**This technique is extremely dangerous and is a hallmark of kernel-level rootkits.**

By obtaining the address of the `sys_call_table`, a malicious actor can overwrite the pointers to legitimate system calls with pointers to their own malicious functions. This is known as "syscall hijacking."

For example, a rootkit could:

*   **Hijack `sys_read` or `sys_write`**: To intercept data being read from or written to files, potentially stealing sensitive information.
*   **Hijack `sys_execve`**: To control which programs are executed or to modify their behavior.
*   **Hijack `getdents` or `getdents64`**: To hide files or directories from user-space applications like `ls`.
*   **Hijack `kill`**: To prevent processes from being killed.

Because the `sys_call_table` is no longer exported and is often in read-only memory, this technique is more difficult to execute on modern systems. However, vulnerabilities are always being discovered, and this remains a powerful technique for compromising a system at the deepest level.

## Disclaimer

This code is for educational and research purposes only. Do not attempt to run this on any production system. The author is not responsible for any damage caused by the use of this code.

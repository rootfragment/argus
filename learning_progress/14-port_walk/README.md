# Kernel Open Ports Module

## Overview

This Linux kernel module is designed to traverse the kernel’s process list and report active network sockets associated with each process. The output includes the process ID (PID), command name, and both source and destination ports of each socket. It exposes this information via the `/proc` filesystem for userspace access, making it useful for system monitoring, debugging, or security auditing.

---

## Features

* Enumerates all processes currently running in the kernel.
* Traverses the file descriptors of each process to find open sockets.
* Supports both IPv4 and IPv6 sockets.
* Provides source and destination port information for each socket.
* Exposes results through a `/proc` entry for easy userspace reading.

---

## How the Module Works

1. **Initialization**
   When the module is inserted into the kernel, it creates a `/proc` entry named `open_ports`. This allows userspace applications to read kernel socket information safely.

2. **Process Traversal**
   The module uses the `for_each_process` macro to iterate over all tasks in the system. Each task corresponds to a running process.

3. **Accessing Open Files**
   For each process, the module accesses its `files_struct`, which holds the process's open file descriptors. It locks this structure with a spinlock to ensure safe concurrent access.

4. **Detecting Sockets**
   Each file descriptor is checked to determine if it is a socket. If it is a socket, the module retrieves the corresponding `struct socket` and `struct sock` structures.

5. **Filtering for Network Sockets**
   The module filters out non-network sockets by checking the `sk_family` field. Only IPv4 and IPv6 sockets are considered.

6. **Extracting Port Information**
   Using the `inet_sk` helper, the module extracts the source and destination ports from the socket. These are converted from network byte order to host byte order for proper reporting.

7. **Reporting via `/proc`**
   The collected information is printed in a structured format using `seq_printf`, which is then accessible through `/proc/open_ports`. Userspace tools like `cat` or `less` can read this information sequentially.

8. **Concurrency Safety**
   The module uses Read-Copy-Update (RCU) locking to safely traverse the process list and spinlocks to safely access each process's file descriptor table. This prevents race conditions or inconsistencies while the system is running.

9. **Cleanup**
   When the module is removed, the `/proc` entry is unregistered, and all locks are released, ensuring no resources are left behind.

---

## Usage

After inserting the module, you can use the following command to view all active network sockets for all processes:

```bash
cat /proc/open_ports
```

Example output:

```
[kports] pid=1234 comm=nginx source port=8080 destination port=443
[kports] pid=5678 comm=ssh source port=22 destination port=51234
```

* `pid` – Process ID
* `comm` – Process name
* `source port` – Local port
* `destination port` – Remote port

---

## Security Considerations

* Only privileged users can read `/proc/open_ports`, as it exposes detailed kernel-level socket information.
* The module is read-only and does not modify any kernel state outside of safe, temporary locks.

---

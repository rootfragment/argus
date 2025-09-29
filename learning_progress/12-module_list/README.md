# Kernel Module: Loaded Modules Lister

## Overview

This project demonstrates a **Linux kernel module** that provides a way to list all currently loaded kernel modules. It achieves this by exposing the module list through the **`/proc` filesystem**, making it accessible to user-space programs.

The module uses **RCU-safe list traversal** to ensure it safely iterates over the kernel's linked list of loaded modules, even in a live kernel environment.

---

## Features

* **Proc Interface:** Creates a `/proc/loaded_mods` file that can be read to see all loaded modules.
* **Safe Traversal:** Uses RCU (Read-Copy Update) mechanisms to traverse the kernel module list without risking race conditions.
* **Lightweight:** Minimal impact on system performance.
* **Logging:** Prints informational messages to the kernel log when loaded and unloaded.

---

## How It Works

1. **Module Initialization**

   * The module creates a proc file named `loaded_mods`.
   * It registers custom **file operations** for the proc file, linking read requests to a function that lists modules.

2. **Listing Modules**

   * The module iterates over the kernel's internal list of loaded modules.
   * Uses **RCU read lock** to safely traverse the list while other kernel operations may be modifying it.
   * For each module, its name is written to the proc file using the **seq_file interface**.

3. **Module Cleanup**

   * On unloading, the module removes the proc entry.
   * Prints a message to the kernel log to indicate successful removal.

---

## Usage

1. **Build the Module**

   * Use `make` with a suitable kernel build environment.
   * Example:

     ```bash
     make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
     ```

2. **Load the Module**

   ```bash
   sudo insmod loaded_mods.ko
   ```

3. **Check Loaded Modules**

   ```bash
   cat /proc/loaded_mods
   ```

4. **Unload the Module**

   ```bash
   sudo rmmod loaded_mods
   ```

5. **View Kernel Logs**

   ```bash
   dmesg | tail
   ```

---

## Implementation Highlights

* **`seq_file` Interface:** Provides a convenient and efficient way to output sequential data to `/proc`.
* **RCU List Traversal:** Ensures safety when accessing shared kernel structures.
* **Proc File Operations:** Uses modern `proc_ops` instead of the older `file_operations` for procfs compatibility.
* **Modular Design:** Initialization and cleanup are cleanly separated using `module_init` and `module_exit`.

---

## Benefits

* Helps in **monitoring loaded kernel modules**.
* Useful for **rootkit detection** by comparing kernel and user-space module listings.
* Provides a **safe example of kernel list traversal and procfs usage** for learning purposes.

---

# Dual-View Module list Comparison



## Features

* **Kernel and User Space Comparison:**
  Walks through the kernel's process and module lists and compares them to the user-space equivalents to detect hidden entities.


* **Logging & Reporting:**
  Logs detected discrepancies for offline analysis.

---

## How It Works

1. **Kernel-Space View:**

   * The framework loads as a Linux kernel module.
   * It traverses kernel data structures (`task_struct` for processes, module lists for loaded modules).
   * Collects detailed metadata about running processes and loaded kernel modules.
 

2. **User-Space View:**

   * Reads module information from `/proc/modules` or equivalent user-space interfaces.
   * Builds sets of module names for comparison.

3. **Dual-View Comparison:**

   * Converts kernel-space and user-space data into comparable sets.
   * Identifies missing processes or modules in user-space that exist in kernel-space (a hallmark of rootkits).

4. **Reporting:**

   * Discrepancies and suspicious findings are logged to the kernel log (`dmesg`) or exported to user-space for further analysis.
   * Example findings include hidden processes, unauthorized kernel modules, and tampered modules.




---

## Usage

1. Load the module as root.
2. The module automatically collects kernel-space process/module data.
3. Run the companion user-space script (if available) to gather `/proc` data.
4. The module will log discrepancies in the kernel log.
5. Analyze logs for potential rootkits or tampered modules.

---

## Design Considerations

* **Security:** Module hashing helps detect attempts to modify the detection module itself.
* **Compatibility:** Written for modern Linux kernels, with fallbacks for deprecated interfaces.
* **Performance:** Efficient traversal of kernel data structures using safe iteration methods (`list_for_each_entry_rcu` for module list, `for_each_process` for tasks).
* **Extensibility:** Can be extended to monitor network sockets, file descriptors, and other kernel resources.

---

## Limitations

* Does not automatically remove detected rootkits.
* User-space data may be incomplete if certain kernel-level rootkits intercept `/proc` operations.
* Kernel module must match the running kernel version; mismatched builds may fail to load.

---

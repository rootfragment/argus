# Procfs Control Module

## Overview

This project demonstrates a lkm that creates a dynamic, interactive entry in the `/proc` filesystem. This module provides a mechanism to control the module's behavior from user-space by writing commands to its `/proc` file and to read back system information—specifically, a list of all running processes.

It serves as a practical example of kernel-to-user-space communication, process iteration within the kernel, and dynamic control of an LKM without requiring it to be reloaded.

## Features

*   **Dynamic `/proc` File:** Creates a file at `/proc/proc_demo` upon loading the module.
*   **User-Space Control:** The module's behavior can be altered by writing specific strings to the `/proc` file.
*   **Process Listing:** When enabled, it lists the Process ID (PID) and command name for all tasks currently managed by the kernel.
*   **Safe & Efficient Reading:** Utilizes the `seq_file` interface, which is the standard, safe, and efficient method for generating large sequential files from the kernel.
*   **Clean Shutdown:** Properly removes the `/proc` entry when the module is unloaded.

## How It Works

The module's core functionality revolves around the `/proc` filesystem, which acts as the communication bridge between the kernel-space module and user-space utilities.

### The `/proc` Interface

A file named `proc_demo` is created in the `/proc` directory when the module is initialized. The module implements a set of file operations (`proc_ops`) that define what happens when a user reads from, writes to, or opens this file.

*   **Write Operation (`proc_write`):** This function is the control mechanism. When a user writes to `/proc/proc_demo` (e.g., using `echo "process" > /proc/proc_demo`), the kernel executes this function. It copies the string from the user, validates it, and sets an internal flag (`show_process`). This flag determines whether the process list should be displayed on a subsequent read. Writing any string other than "process" will disable the feature.

*   **Read Operation (`proc_read`):** This function is triggered when a user reads the file (e.g., with `cat /proc/proc_demo`). It uses the `seq_file` API for safe and robust output generation.
    *   First, it checks the `show_process` flag.
    *   If the flag is true, it iterates through all running processes using the `for_each_process` macro. This macro safely traverses the kernel's list of `task_struct` objects.
    *   For each task, it extracts the PID (`task->pid`) and the command name (`task->comm`) and formats them into a clean, tabular output.
    *   If the flag is false, it simply prints a message instructing the user on how to enable the process list.

## Usage

To use this module, you will need a Linux system with the appropriate kernel headers installed to build kernel modules.

### 1. Building the Module

Navigate to the directory containing the source code and a corresponding `Makefile`. Run the `make` command to compile the module.

```sh
make
```

This will produce a kernel object file named `control_module.ko`.

### 2. Loading the Module

Load the compiled module into the kernel using `insmod`. This requires root privileges.

```sh
sudo insmod control_module.ko
```

After loading, a new file will be available at `/proc/proc_demo`.

### 3. Interacting with the Module

1.  **Check Initial State:** By default, the process list is disabled. Reading the file will show an instructional message.
    ```sh
    cat /proc/proc_demo
    ```

2.  **Enable Process Listing:** Write the string "process" to the `/proc` file.
    ```sh
    echo "process" | sudo tee /proc/proc_demo
    ```

3.  **View Processes:** Now, reading the file will display a list of all running processes.
    ```sh
    cat /proc/proc_demo
    ```

4.  **Disable Process Listing:** Write any other string (or an empty one) to disable the feature.
    ```sh
    echo "disable" | sudo tee /proc/proc_demo
    ```

### 4. Unloading the Module

When you are finished, unload the module using `rmmod`. This will automatically remove the `/proc/proc_demo` file.

```sh
sudo rmmod control_module
```

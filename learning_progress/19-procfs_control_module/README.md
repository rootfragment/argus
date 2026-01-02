# Kernel Module Controller via /proc Filesystem

The module creates an interface in the `/proc` filesystem which is aimed at giving an insight to the working of the proc filesystem and how a module which is running can be manipulated from userspace by writing a specific command into the proc file 

## How It Works

The core of this module is to provide a simple control mechanism from user-space to the kernel-space.

1.  **Initialization**: When the module is loaded into the kernel, it creates a file named `controller` within the `/proc` directory. This file is the primary interface for interacting with the module.

2.  **Control Interface**: The `/proc/controller` file is write-only. Users can send commands to the module by writing specific strings to this file.

3.  **Command Handling**: The module listens for two commands:
    *   `start`: Writing "start" to `/proc/controller` sets an internal flag (`process_scan_enable`) to `true`. This is intended to begin a process scanning operation.
    *   `stop`: Writing "stop" to `/proc/controller` sets the same internal flag to `false`, signaling the scanning process to halt.

4.  **Feedback**: The module provides feedback by printing messages to the kernel log buffer. These messages confirm whether the `start` or `stop` command was received, or if an unknown command was sent. You can view these messages using the `dmesg` command.

5.  **Cleanup**: When the module is unloaded, it cleans up after itself by removing the `controller` file from the `/proc` filesystem.

## Interacting with the Module

To control the module, you can use a simple shell command to write to the proc file. You will need appropriate permissions to do this.

*   **To start the process scan:**
    ```sh
    echo "start" | sudo tee /proc/controller
    ```

*   **To stop the process scan:**
    ```sh
    echo "stop" | sudo tee /proc/controller
    ```

After each command, you can check the kernel's log to see the module's response:
```sh
dmesg | tail
```

## Key Concepts and Functions

This module utilizes several important concepts and functions from the Linux kernel API:

*   **Linux Kernel Module (LKM)**: A piece of code that can be dynamically loaded into and unloaded from the Linux kernel. This allows for extending the kernel's functionality without needing to recompile the entire kernel or reboot the system.

*   **/proc Filesystem**: A virtual filesystem that provides a window into the kernel's internal data structures and state. It's a common way for kernel modules to communicate information and receive commands from user-space applications.

*   `module_init` & `module_exit`: These are macros that specify which functions are to be run when the module is loaded (`init`) and unloaded (`exit`), respectively.

*   `proc_create`: This function is used to create a new entry (a file) in the `/proc` filesystem. The function takes the name of the file, its permissions, and a pointer to a `proc_ops` structure.

*   `remove_proc_entry`: This function is called during the module's exit routine to remove the file from the `/proc` filesystem.

*   `struct proc_ops`: A structure that defines the file operations (like read, write, open, etc.) for a `/proc` entry. In this module, only the `.proc_write` operation is implemented.

*   `copy_from_user`: A crucial security function used to safely copy data from the user's memory space into the kernel's memory space. It's essential to use this function to avoid security vulnerabilities when handling user input.

*   `pr_info`: A function used for logging informational messages from the kernel. These messages can be viewed with `dmesg`.
